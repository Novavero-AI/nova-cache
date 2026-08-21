-- EmptyDataDecls for the opaque 'BzStream' tag alone: the C struct
-- has no Haskell values, and a placeholder constructor would be
-- unused by construction (which -Werror rightly refuses).
{-# LANGUAGE EmptyDataDecls #-}

-- | Bounded bzip2 decompression for untrusted cache data.
--
-- Historical cache.nixos.org narinfos declare @Compression: bzip2@,
-- and upstream C++ Nix reads an absent @Compression@ field as bzip2
-- (nova-cache's narinfo parser defaults the same way), so
-- substituting those paths needs this decoder.  Substitution
-- decompresses bytes that arrive from the network BEFORE any hash
-- can vouch for them, so the decoder must not be steerable into
-- unbounded allocation.  The consumer knows the narinfo's declared
-- NarSize before decompressing: decompression takes that bound and
-- fails past it ('bzip2MaxOutputBytes').
--
-- There is no decoder-memory knob like the xz codec's
-- @xzMaxDecoderMemoryBytes@: bzip2 carries no attacker-chosen
-- dictionary size, and decoding allocates a fixed small amount -
-- about 4 MiB at the format's largest block size (900k) - so decoder
-- memory is a constant of the format, not a parameter.
--
-- Concatenated streams decode as one output: upstream's bzip2
-- decompression sink re-initializes the decoder at stream end while
-- input remains, and this module does the same.  Trailing bytes that
-- do not start a valid stream are refused, as is truncated input.
--
-- Everything here is IO: the decoder is libbz2, driven over the FFI.
-- The binding goes directly over @bzip2-clib@ (nothing but the
-- bundled C sources) because no existing binding bundles them on
-- every platform - @bzlib@ links the system library outside Windows
-- - and the codec sublibraries promise no system library anywhere.
--
-- This module lives in the public @nova-cache:bzip2@ sublibrary, the
-- same solver-visible opt-in as @nova-cache:xz@: consumers that
-- substitute bzip2 paths depend on it; everyone else never builds
-- the bundled libbz2.
module NovaCache.Bzip2
  ( Bzip2Limits (..),
    Bzip2Error (..),
    decompress,
    withBzip2Source,
  )
where

import Control.Exception (Exception, SomeException, throwIO, toException, try)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import Data.Maybe (fromMaybe)
import Data.Word (Word64)
import Foreign.C.Types (CChar, CInt (..), CUInt (..))
import Foreign.ForeignPtr (FinalizerPtr, ForeignPtr, newForeignPtr, withForeignPtr)
import Foreign.Marshal.Alloc (alloca, allocaBytes)
import Foreign.Ptr (Ptr)
import Foreign.Storable (peek)

-- ---------------------------------------------------------------------------
-- Limits
-- ---------------------------------------------------------------------------

-- | What a decode run may cost.  The bound is inclusive: output of
-- exactly 'bzip2MaxOutputBytes' passes, one byte more fails - a
-- narinfo's NarSize is exact, so the declared size itself must be
-- reachable.  Decoder-state memory is a small format constant (see
-- the module header), not a field here.
newtype Bzip2Limits = Bzip2Limits
  { -- | Maximum decompressed output, in bytes: the narinfo's declared
    -- NarSize.
    bzip2MaxOutputBytes :: Word64
  }
  deriving (Eq, Show)

-- ---------------------------------------------------------------------------
-- Errors
-- ---------------------------------------------------------------------------

-- | Everything a bounded decode can refuse.  'decompress' returns
-- these in 'Left'; the pull source behind 'withBzip2Source' throws
-- them (see the 'Exception' instance).
data Bzip2Error
  = -- | The compressed stream is malformed, truncated, or carries
    -- trailing bytes that do not start a valid stream (libbz2's
    -- status, rendered).
    Bzip2StreamError !String
  | -- | Decompressed output would exceed the bound (carried here).
    Bzip2OutputOverBound !Word64
  deriving (Eq, Show)

-- | Thrown by the pull source 'withBzip2Source' hands its
-- continuation; a chunk convention has no error channel, and a
-- throwing pull composes with consumers built around one.
instance Exception Bzip2Error

-- ---------------------------------------------------------------------------
-- Bounded decode
-- ---------------------------------------------------------------------------

-- | Decompress one bzip2 payload under the given limits.  Output
-- stops accumulating the moment it would pass the bound, so a
-- high-expansion input costs at most the bound plus one decoder
-- buffer, never what it claims to hold.
decompress :: Bzip2Limits -> ByteString -> IO (Either Bzip2Error ByteString)
decompress limits input = do
  opened <- newDecoder
  case opened of
    Left err -> pure (Left err)
    Right decoder -> do
      -- The IORef makes the whole input a one-shot chunk source
      -- (input, then the empty end marker), so the strict path
      -- drives the same engine as the streaming one.
      remainingRef <- newIORef input
      let source = do
            held <- readIORef remainingRef
            writeIORef remainingRef BS.empty
            pure held
      collect source decoder []
  where
    collect source decoder acc = do
      outcome <- nextDecodedChunk limits source decoder
      case outcome of
        Left err -> pure (Left err)
        Right Nothing -> pure (Right (BS.concat (reverse acc)))
        Right (Just (chunk, next)) -> collect source next (chunk : acc)

-- ---------------------------------------------------------------------------
-- Streaming bounded decode
-- ---------------------------------------------------------------------------

-- | What the pull source is doing between calls.  The 'IORef'
-- holding this is a deliberate, documented mutable boundary, the
-- same as the xz and zstd sources.  A failure is a state of its own:
-- once a pull has thrown, every later pull rethrows - never the
-- empty chunk, which would let a consumer that catches and retries
-- mistake a failed transfer for complete output.
data Bzip2SourceState
  = Bzip2Streaming !Decoder
  | Bzip2Drained
  | Bzip2Failed !SomeException

-- | Decompress a chunk source into a chunk source, under the
-- limits.  The continuation's pull yields decompressed chunks; the
-- empty chunk means end of output and repeats on further pulls.
-- The compressed source follows the same convention on its side.
-- Pairs with the incremental NAR parser and hashing, so a
-- substituter can fetch, decompress, hash, and unpack in one
-- bounded pass.
--
-- Limit violations and malformed input are thrown as 'Bzip2Error'
-- from the pull.  A pull that fails latches: every later pull
-- rethrows the same exception, so a catch-and-retry consumer can
-- never mistake an aborted transfer for a clean end of output.
withBzip2Source :: Bzip2Limits -> IO ByteString -> (IO ByteString -> IO a) -> IO a
withBzip2Source limits compressedSource consume = do
  opened <- newDecoder
  stateRef <- newIORef (either (Bzip2Failed . toException) Bzip2Streaming opened)
  consume (pullDecompressed limits compressedSource stateRef)

-- | Produce the next decompressed chunk.
pullDecompressed :: Bzip2Limits -> IO ByteString -> IORef Bzip2SourceState -> IO ByteString
pullDecompressed limits compressedSource stateRef = advance =<< readIORef stateRef
  where
    advance state = case state of
      Bzip2Drained -> pure BS.empty
      Bzip2Failed failure -> throwIO failure
      Bzip2Streaming decoder -> do
        outcome <- tryPull (nextDecodedChunk limits compressedSource decoder)
        case outcome of
          Left failure -> do
            writeIORef stateRef (Bzip2Failed failure)
            throwIO failure
          Right (Left err) -> do
            writeIORef stateRef (Bzip2Failed (toException err))
            throwIO err
          Right (Right Nothing) -> do
            writeIORef stateRef Bzip2Drained
            pure BS.empty
          Right (Right (Just (chunk, next))) -> do
            writeIORef stateRef (Bzip2Streaming next)
            pure chunk

-- | 'try' at 'SomeException', monomorphic so the catch-all needs no
-- annotation at the call site.  Any exception escaping a pull - the
-- compressed source failing included - leaves the transfer
-- unfinishable, and the only sound later answer is the same failure
-- again, so the caller latches whatever this catches.
tryPull ::
  IO (Either Bzip2Error (Maybe (ByteString, Decoder))) ->
  IO (Either SomeException (Either Bzip2Error (Maybe (ByteString, Decoder))))
tryPull = try

-- ---------------------------------------------------------------------------
-- Shared decoder engine
-- ---------------------------------------------------------------------------

-- | Decoder identity threaded between engine steps: the C stream,
-- input handed over but not yet consumed, output produced so far
-- (the bound's basis), and whether the decoder sits at a stream
-- boundary.
data Decoder = Decoder
  { decoderStream :: !(ForeignPtr BzStream),
    decoderLeftover :: !ByteString,
    decoderProduced :: !Word64,
    decoderPhase :: !DecoderPhase
  }

-- | 'AtStreamBoundary' means a stream just ended cleanly: end of
-- input here is a clean end of output, while more input means a
-- concatenated stream follows.  Anywhere else, end of input is
-- truncation.
data DecoderPhase = MidStream | AtStreamBoundary

-- | A freshly initialized decoder.  Failure here is libbz2 refusing
-- to initialize (or the allocation failing, which the shim folds
-- into the same status), rendered as a stream error.
newDecoder :: IO (Either Bzip2Error Decoder)
newDecoder = do
  rawStream <- cStreamNew
  stream <- newForeignPtr cStreamDestroy rawStream
  status <- withForeignPtr stream cDecompressInit
  pure $
    if status == statusOk
      then
        Right
          Decoder
            { decoderStream = stream,
              decoderLeftover = BS.empty,
              decoderProduced = 0,
              decoderPhase = MidStream
            }
      else Left (Bzip2StreamError (renderStatus status))

-- | Advance the decoder to its next decompressed chunk: 'Nothing'
-- is the clean end of output, 'Just' carries a nonempty chunk and
-- the decoder to continue from.  Both 'decompress' and
-- 'withBzip2Source' drive this engine, so the bound arithmetic and
-- the stream-boundary rules exist once.
nextDecodedChunk ::
  Bzip2Limits ->
  IO ByteString ->
  Decoder ->
  IO (Either Bzip2Error (Maybe (ByteString, Decoder)))
nextDecodedChunk limits compressedSource = advance
  where
    advance decoder = case decoderPhase decoder of
      AtStreamBoundary
        | BS.null (decoderLeftover decoder) -> do
            chunk <- compressedSource
            if BS.null chunk
              then pure (Right Nothing)
              else reopen decoder {decoderLeftover = chunk}
        | otherwise -> reopen decoder
      MidStream
        | BS.null (decoderLeftover decoder) -> do
            chunk <- compressedSource
            if BS.null chunk
              then pure (Left (Bzip2StreamError truncatedInputMessage))
              else advance decoder {decoderLeftover = chunk}
        | otherwise -> decodeStep decoder

    -- Input after a clean stream end: re-initialize and decode it as
    -- the next concatenated stream.  Garbage fails the re-initialized
    -- decoder's magic check, which is the trailing-garbage refusal.
    reopen decoder = do
      status <- withForeignPtr (decoderStream decoder) cDecompressReinit
      if status == statusOk
        then advance decoder {decoderPhase = MidStream}
        else pure (Left (Bzip2StreamError (renderStatus status)))

    decodeStep decoder = do
      (status, consumedCount, outChunk) <-
        runDecompressStep (decoderStream decoder) (decoderLeftover decoder)
      let remaining = BS.drop consumedCount (decoderLeftover decoder)
          finished = status == statusStreamEnd
      if status /= statusOk && not finished
        then pure (Left (Bzip2StreamError (renderStatus status)))
        else case growWithinBound limits (decoderProduced decoder) (BS.length outChunk) of
          Left err -> pure (Left err)
          Right grown ->
            let continued =
                  decoder
                    { decoderLeftover = remaining,
                      decoderProduced = grown,
                      decoderPhase = if finished then AtStreamBoundary else MidStream
                    }
             in -- An empty step (input absorbed, nothing produced
                -- yet) must not surface as the end-of-output chunk.
                if BS.null outChunk
                  then advance continued
                  else pure (Right (Just (outChunk, continued)))

-- | The one place the output bound is enforced: the produced count
-- grown by a chunk, refused past the bound.  Inclusive - reaching
-- the bound exactly passes, because a narinfo's NarSize is exact.
growWithinBound :: Bzip2Limits -> Word64 -> Int -> Either Bzip2Error Word64
growWithinBound limits produced chunkLength
  | grown > bound = Left (Bzip2OutputOverBound bound)
  | otherwise = Right grown
  where
    bound = bzip2MaxOutputBytes limits
    grown = produced + fromIntegral chunkLength

-- | One BZ2_bzDecompress call through the shim: feed at most
-- 'stepBufferBytes' of the input against a fresh output buffer, and
-- yield the status, the count of input bytes consumed, and the
-- bytes produced.
runDecompressStep :: ForeignPtr BzStream -> ByteString -> IO (CInt, Int, ByteString)
runDecompressStep stream input =
  withForeignPtr stream $ \streamPtr ->
    unsafeUseAsCStringLen (BS.take stepBufferBytes input) $ \(inputPtr, inputLength) ->
      allocaBytes stepBufferBytes $ \outputPtr ->
        alloca $ \consumedPtr ->
          alloca $ \producedPtr -> do
            status <-
              cDecompressStep
                streamPtr
                inputPtr
                (fromIntegral inputLength)
                outputPtr
                (fromIntegral stepBufferBytes)
                consumedPtr
                producedPtr
            consumedCount <- peek consumedPtr
            producedCount <- peek producedPtr
            outChunk <- BS.packCStringLen (outputPtr, fromIntegral producedCount)
            pure (status, fromIntegral consumedCount, outChunk)

-- | Per-step transfer size, for both the input fed across the FFI
-- and the output buffer: bounds one unsafe C call's work, and keeps
-- the lengths within CUInt on every platform however large a chunk
-- the source hands over.
stepBufferBytes :: Int
stepBufferBytes = 64 * 1024

truncatedInputMessage :: String
truncatedInputMessage = "input ends inside a bzip2 stream"

-- ---------------------------------------------------------------------------
-- FFI boundary
-- ---------------------------------------------------------------------------

-- | Opaque tag for libbz2's @bz_stream@; the struct lives behind
-- the shim and is never inspected from Haskell.
data BzStream

-- | libbz2's status names by return code, as bzlib.h declares them.
statusNames :: [(CInt, String)]
statusNames =
  [ (0, "BZ_OK"),
    (1, "BZ_RUN_OK"),
    (2, "BZ_FLUSH_OK"),
    (3, "BZ_FINISH_OK"),
    (4, "BZ_STREAM_END"),
    (-1, "BZ_SEQUENCE_ERROR"),
    (-2, "BZ_PARAM_ERROR"),
    (-3, "BZ_MEM_ERROR"),
    (-4, "BZ_DATA_ERROR"),
    (-5, "BZ_DATA_ERROR_MAGIC"),
    (-6, "BZ_IO_ERROR"),
    (-7, "BZ_UNEXPECTED_EOF"),
    (-8, "BZ_OUTBUFF_FULL"),
    (-9, "BZ_CONFIG_ERROR")
  ]

statusOk :: CInt
statusOk = 0

statusStreamEnd :: CInt
statusStreamEnd = 4

-- | Render a libbz2 status by its bzlib.h name.
renderStatus :: CInt -> String
renderStatus status =
  fromMaybe ("bzip2 status " <> show status) (lookup status statusNames)

foreign import ccall unsafe "nova_bzip2_stream_new"
  cStreamNew :: IO (Ptr BzStream)

foreign import ccall unsafe "&nova_bzip2_stream_destroy"
  cStreamDestroy :: FinalizerPtr BzStream

foreign import ccall unsafe "nova_bzip2_decompress_init"
  cDecompressInit :: Ptr BzStream -> IO CInt

foreign import ccall unsafe "nova_bzip2_decompress_reinit"
  cDecompressReinit :: Ptr BzStream -> IO CInt

foreign import ccall unsafe "nova_bzip2_decompress_step"
  cDecompressStep ::
    Ptr BzStream ->
    Ptr CChar ->
    CUInt ->
    Ptr CChar ->
    CUInt ->
    Ptr CUInt ->
    Ptr CUInt ->
    IO CInt
