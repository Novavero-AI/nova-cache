-- | Bounded xz decompression for untrusted cache data.
--
-- cache.nixos.org serves NARs xz-compressed, and substitution
-- decompresses bytes that arrive from the network BEFORE any hash can
-- vouch for them, so the decoder must not be steerable into unbounded
-- allocation.  The consumer knows the narinfo's declared NarSize
-- before decompressing: decompression takes that bound and fails past
-- it ('xzMaxOutputBytes'), so a small compressed input cannot expand
-- to arbitrary memory ahead of the hash check.  The decoder's own
-- state is capped as well ('xzMaxDecoderMemoryBytes') - upstream
-- passes no limit there; the divergence is deliberate hardening and
-- the cap is a parameter.
--
-- Concatenated streams decode as one output, matching upstream's
-- @LZMA_CONCATENATED@ decoder in libutil's compression sink.
--
-- This module lives in the public @nova-cache:xz@ sublibrary.  The
-- @lzma-static@ dependency bundles liblzma's C sources, so no system
-- library is needed on any platform - but it is still an extra C
-- build that consumers without foreign-cache needs should not pay
-- for, and a default-on compression dependency broke downstream
-- installs once already (0.5.0.0).  Consumers that substitute from
-- foreign caches depend on @nova-cache:xz@; everyone else never
-- builds it.
module NovaCache.Xz
  ( XzLimits (..),
    defaultXzDecoderMemoryBytes,
    XzError (..),
    decompress,
    withXzSource,
  )
where

import qualified Codec.Compression.Lzma as Lzma
import Control.Exception (Exception, throwIO)
-- decompressST runs in lazy ST (the upstream package's own lazy
-- API drives it the same way); the driver's accumulator bangs and
-- guard-before-recurse keep the bound checks strict regardless.
import Control.Monad.ST.Lazy (runST)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import Data.Word (Word64)

-- ---------------------------------------------------------------------------
-- Limits
-- ---------------------------------------------------------------------------

-- | What a decode run may cost.  Both bounds are inclusive: output of
-- exactly 'xzMaxOutputBytes' passes, one byte more fails - a narinfo's
-- NarSize is exact, so the declared size itself must be reachable.
data XzLimits = XzLimits
  { -- | Maximum decompressed output, in bytes: the narinfo's declared
    -- NarSize.
    xzMaxOutputBytes :: !Word64,
    -- | Maximum decoder-state memory liblzma may allocate.  Decoder
    -- memory tracks the stream's declared dictionary size, an
    -- attacker-chosen number read from the compressed header.
    xzMaxDecoderMemoryBytes :: !Word64
  }
  deriving (Eq, Show)

-- | A decoder-memory cap for callers without an opinion: 1 GiB.  The
-- largest standard preset (@xz -9@) declares a 64 MiB dictionary and
-- needs about 65 MiB to decode, so this refuses only hand-rolled
-- dictionaries past 1 GiB.  Upstream passes no limit at all; a
-- consumer matching that exactly can pass 'maxBound'.
defaultXzDecoderMemoryBytes :: Word64
defaultXzDecoderMemoryBytes = 1024 * 1024 * 1024

-- ---------------------------------------------------------------------------
-- Errors
-- ---------------------------------------------------------------------------

-- | Everything a bounded decode can refuse.  The pure 'decompress'
-- returns these in 'Left'; the pull source behind 'withXzSource'
-- throws them (see the 'Exception' instance).
data XzError
  = -- | The compressed stream is malformed, truncated, or carries
    -- trailing garbage (liblzma's status, rendered).
    XzStreamError !String
  | -- | Decompressed output would exceed the bound (carried here).
    XzOutputOverBound !Word64
  | -- | The stream declares a dictionary needing more decoder memory
    -- than the bound (carried here).
    XzMemoryOverBound !Word64
  deriving (Eq, Show)

-- | Thrown by the pull source 'withXzSource' hands its continuation;
-- a chunk convention has no error channel, and a throwing pull
-- composes with consumers built around one (the store's streaming
-- write cleans up via its exception path).
instance Exception XzError

-- ---------------------------------------------------------------------------
-- Pure bounded decode
-- ---------------------------------------------------------------------------

-- | Decompress one xz blob under the given limits.  Output stops
-- accumulating the moment it would pass the bound, so a
-- high-expansion input costs at most the bound plus one decoder
-- buffer, never what it claims to hold.
decompress :: XzLimits -> ByteString -> Either XzError ByteString
decompress limits input = runST $ do
  start <- Lzma.decompressST (decompressParams limits)
  drive (Just input) 0 [] start
  where
    bound = xzMaxOutputBytes limits
    drive pending !produced acc step = case step of
      -- The whole input feeds on the first request; the second request
      -- gets the empty string, liblzma's end-of-input signal.
      Lzma.DecompressInputRequired supply -> case pending of
        Just bytes -> drive Nothing produced acc =<< supply bytes
        Nothing -> drive Nothing produced acc =<< supply BS.empty
      Lzma.DecompressOutputAvailable out next
        | grown > bound -> pure (Left (XzOutputOverBound bound))
        | otherwise -> drive pending grown (out : acc) =<< next
        where
          grown = produced + fromIntegral (BS.length out)
      Lzma.DecompressStreamEnd leftover
        | BS.null leftover -> pure (Right (BS.concat (reverse acc)))
        | otherwise -> pure (Left (XzStreamError trailingDataMessage))
      Lzma.DecompressStreamError ret -> pure (Left (mapRet limits ret))

-- ---------------------------------------------------------------------------
-- Streaming bounded decode (IO boundary)
-- ---------------------------------------------------------------------------

-- | What the pull source is doing between calls.  The 'IORef' holding
-- this is the module's one piece of mutable state - the same
-- deliberate, documented boundary as the streaming NAR source.
data XzSourceState
  = XzStreaming !(Lzma.DecompressStream IO) !Word64
  | XzDrained

-- | Decompress a chunk source into a chunk source, under the limits.
-- The continuation's pull yields decompressed chunks; the empty chunk
-- means end of output and repeats on further pulls.  The compressed
-- source follows the same convention on its side.  Pairs with the
-- incremental NAR parser and hashing, so a substituter can fetch,
-- decompress, hash, and unpack in one bounded pass.
--
-- Limit violations and malformed input are thrown as 'XzError' from
-- the pull.
withXzSource :: XzLimits -> IO ByteString -> (IO ByteString -> IO a) -> IO a
withXzSource limits compressedSource consume = do
  start <- Lzma.decompressIO (decompressParams limits)
  stateRef <- newIORef (XzStreaming start 0)
  consume (pullDecompressed limits compressedSource stateRef)

-- | Produce the next decompressed chunk.
pullDecompressed :: XzLimits -> IO ByteString -> IORef XzSourceState -> IO ByteString
pullDecompressed limits compressedSource stateRef = advance =<< readIORef stateRef
  where
    bound = xzMaxOutputBytes limits
    advance XzDrained = pure BS.empty
    advance (XzStreaming step produced) = case step of
      Lzma.DecompressInputRequired supply -> do
        chunk <- compressedSource
        next <- supply chunk
        advance (XzStreaming next produced)
      Lzma.DecompressOutputAvailable out nextAction -> do
        let grown = produced + fromIntegral (BS.length out)
        if grown > bound
          then do
            writeIORef stateRef XzDrained
            throwIO (XzOutputOverBound bound)
          else do
            next <- nextAction
            writeIORef stateRef (XzStreaming next grown)
            -- liblzma may hand back an empty buffer at stream
            -- boundaries; returning it would read as end of output.
            if BS.null out
              then advance (XzStreaming next grown)
              else pure out
      Lzma.DecompressStreamEnd leftover -> do
        writeIORef stateRef XzDrained
        if BS.null leftover
          then pure BS.empty
          else throwIO (XzStreamError trailingDataMessage)
      Lzma.DecompressStreamError ret -> do
        writeIORef stateRef XzDrained
        throwIO (mapRet limits ret)

-- ---------------------------------------------------------------------------
-- Shared decoder configuration
-- ---------------------------------------------------------------------------

-- | Decoder parameters under the limits: concatenated-stream decoding
-- as upstream, memory capped, everything else at the library default.
decompressParams :: XzLimits -> Lzma.DecompressParams
decompressParams limits =
  Lzma.defaultDecompressParams
    { Lzma.decompressConcatenated = True,
      Lzma.decompressMemLimit = xzMaxDecoderMemoryBytes limits
    }

-- | Map liblzma's status to the error vocabulary.
mapRet :: XzLimits -> Lzma.LzmaRet -> XzError
mapRet limits ret = case ret of
  Lzma.LzmaRetMemlimitError -> XzMemoryOverBound (xzMaxDecoderMemoryBytes limits)
  other -> XzStreamError (show other)

trailingDataMessage :: String
trailingDataMessage = "trailing data after the xz stream"
