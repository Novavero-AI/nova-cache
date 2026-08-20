-- | Bounded zstd decompression, and compression for the push path.
--
-- The modern caches (Cachix, attic, FlakeHub) serve NARs
-- zstd-compressed, and a cache of our own wants the same: near-xz
-- ratio on binaries with decompression an order of magnitude
-- faster.  Substitution decompresses bytes that arrive from the
-- network BEFORE any hash can vouch for them, so the decoder must
-- not be steerable into unbounded allocation.  The consumer knows
-- the narinfo's declared NarSize before decompressing:
-- decompression takes that bound and fails past it
-- ('zstdMaxOutputBytes'), so a small compressed input cannot expand
-- to arbitrary memory ahead of the hash check.
--
-- Decoder state is bounded differently from 'NovaCache.Xz': the
-- @zstd@ binding exposes no window-limit parameter, but libzstd
-- itself refuses any frame declaring a window past its default
-- @ZSTD_WINDOWLOG_LIMIT_DEFAULT@ (2^27, 128 MiB), so decoder memory
-- is capped by the library rather than by a caller-chosen number.
-- Take the tunable cap here too if the binding ever exposes
-- @ZSTD_d_windowLogMax@.
--
-- A truncated input yields truncated output at this layer rather
-- than an error: the binding's stream driver cannot observe
-- libzstd's more-input-expected state at end of input.  The signed
-- NarSize and NarHash checks above this layer are the arbiter of
-- completeness - the same layering upstream relies on.
--
-- Everything here is IO: the binding's streaming interface is
-- IO-native, unlike lzma's lazy-ST driver under 'NovaCache.Xz'.
--
-- This module lives in the public @nova-cache:zstandard@ sublibrary
-- (a component named @zstd@ would shadow the @zstd@ dependency), the
-- same solver-visible opt-in as @nova-cache:xz@: the @zstd@ package
-- bundles libzstd's C sources (no system library on any platform),
-- and consumers that do not need the codec never build them.
module NovaCache.Zstd
  ( ZstdLimits (..),
    ZstdError (..),
    decompress,
    compress,
    defaultCompressionLevel,
    withZstdSource,
  )
where

import qualified Codec.Compression.Zstd as OneShot
import qualified Codec.Compression.Zstd.Streaming as S
import Control.Exception (Exception, throwIO)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import Data.Word (Word64)

-- ---------------------------------------------------------------------------
-- Limits
-- ---------------------------------------------------------------------------

-- | What a decode run may cost.  The bound is inclusive: output of
-- exactly 'zstdMaxOutputBytes' passes, one byte more fails - a
-- narinfo's NarSize is exact, so the declared size itself must be
-- reachable.  Decoder-state memory is capped by libzstd's default
-- window limit (see the module header), not by a field here.
newtype ZstdLimits = ZstdLimits
  { -- | Maximum decompressed output, in bytes: the narinfo's declared
    -- NarSize.
    zstdMaxOutputBytes :: Word64
  }
  deriving (Eq, Show)

-- ---------------------------------------------------------------------------
-- Errors
-- ---------------------------------------------------------------------------

-- | Everything a bounded decode can refuse.  The pure-shaped
-- 'decompress' returns these in 'Left'; the pull source behind
-- 'withZstdSource' throws them (see the 'Exception' instance).
data ZstdError
  = -- | The compressed stream is malformed (libzstd's error name,
    -- rendered with the failing call site).
    ZstdStreamError !String
  | -- | Decompressed output would exceed the bound (carried here).
    ZstdOutputOverBound !Word64
  deriving (Eq, Show)

-- | Thrown by the pull source 'withZstdSource' hands its
-- continuation; a chunk convention has no error channel, and a
-- throwing pull composes with consumers built around one.
instance Exception ZstdError

-- ---------------------------------------------------------------------------
-- Bounded decode
-- ---------------------------------------------------------------------------

-- | Decompress one zstd payload under the given limits.  Output
-- stops accumulating the moment it would pass the bound, so a
-- high-expansion input costs at most the bound plus one decoder
-- buffer, never what it claims to hold.  Concatenated frames decode
-- as one output, as upstream's decompression sink accepts.
decompress :: ZstdLimits -> ByteString -> IO (Either ZstdError ByteString)
decompress limits input = drive (Just input) 0 [] =<< S.decompress
  where
    bound = zstdMaxOutputBytes limits
    drive pending !produced acc step = case step of
      -- The whole input feeds on the first request; the second
      -- request gets the empty string, the driver's end-of-input
      -- signal.
      S.Consume supply -> case pending of
        Just bytes -> drive Nothing produced acc =<< supply bytes
        Nothing -> drive Nothing produced acc =<< supply BS.empty
      S.Produce out next
        | grown > bound -> pure (Left (ZstdOutputOverBound bound))
        | otherwise -> drive pending grown (out : acc) =<< next
        where
          grown = produced + fromIntegral (BS.length out)
      S.Done out
        | produced + fromIntegral (BS.length out) > bound ->
            pure (Left (ZstdOutputOverBound bound))
        | otherwise -> pure (Right (BS.concat (reverse (out : acc))))
      S.Error site name -> pure (Left (renderError site name))

-- | One libzstd failure in this module's error vocabulary.
renderError :: String -> String -> ZstdError
renderError site name = ZstdStreamError (site <> ": " <> name)

-- ---------------------------------------------------------------------------
-- Compression (push path)
-- ---------------------------------------------------------------------------

-- | Compress one payload at the given level (1 to the library
-- maximum).  The produced frame records its content size, so
-- consumers with a one-shot decoder can allocate exactly.  The
-- binding's one-shot API is pure and total for in-range levels.
compress :: Int -> ByteString -> ByteString
compress = OneShot.compress

-- | libzstd's own default (level 3): the ratio/speed point the
-- library authors tuned for, and far cheaper than xz at push time.
defaultCompressionLevel :: Int
defaultCompressionLevel = 3

-- ---------------------------------------------------------------------------
-- Streaming bounded decode (IO boundary)
-- ---------------------------------------------------------------------------

-- | What the pull source is doing between calls.  The 'IORef'
-- holding this is the module's one piece of mutable state - the
-- same deliberate, documented boundary as the xz source.
data ZstdSourceState
  = ZstdStreaming !S.Result !Word64
  | ZstdDrained

-- | Decompress a chunk source into a chunk source, under the
-- limits.  The continuation's pull yields decompressed chunks; the
-- empty chunk means end of output and repeats on further pulls.
-- The compressed source follows the same convention on its side.
-- Pairs with the incremental NAR parser and hashing, so a
-- substituter can fetch, decompress, hash, and unpack in one
-- bounded pass.
--
-- Limit violations and malformed input are thrown as 'ZstdError'
-- from the pull.
withZstdSource :: ZstdLimits -> IO ByteString -> (IO ByteString -> IO a) -> IO a
withZstdSource limits compressedSource consume = do
  start <- S.decompress
  stateRef <- newIORef (ZstdStreaming start 0)
  consume (pullDecompressed limits compressedSource stateRef)

-- | Produce the next decompressed chunk.
pullDecompressed :: ZstdLimits -> IO ByteString -> IORef ZstdSourceState -> IO ByteString
pullDecompressed limits compressedSource stateRef = advance =<< readIORef stateRef
  where
    bound = zstdMaxOutputBytes limits
    advance ZstdDrained = pure BS.empty
    advance (ZstdStreaming step produced) = case step of
      S.Consume supply -> do
        chunk <- compressedSource
        next <- supply chunk
        advance (ZstdStreaming next produced)
      S.Produce out nextAction -> do
        let grown = produced + fromIntegral (BS.length out)
        if grown > bound
          then do
            writeIORef stateRef ZstdDrained
            throwIO (ZstdOutputOverBound bound)
          else do
            next <- nextAction
            writeIORef stateRef (ZstdStreaming next grown)
            -- The driver may hand back an empty buffer at frame
            -- boundaries; returning it would read as end of output.
            if BS.null out
              then advance (ZstdStreaming next grown)
              else pure out
      S.Done out -> do
        writeIORef stateRef ZstdDrained
        if produced + fromIntegral (BS.length out) > bound
          then throwIO (ZstdOutputOverBound bound)
          else pure out
      S.Error site name -> do
        writeIORef stateRef ZstdDrained
        throwIO (renderError site name)
