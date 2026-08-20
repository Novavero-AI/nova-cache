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
-- The decoder drives @ZSTD_decompressStream@ through the binding's
-- FFI module rather than its high-level streaming driver, for two
-- properties the driver cannot give:
--
-- * The decompression context is created and freed in a bracket
--   ('withDecoder'), so its window buffer - sized by the incoming
--   frame header, i.e. by the peer, up to libzstd's 128 MiB default
--   ceiling - is released deterministically on every exit: success,
--   bound violation, corrupt frame, or an exception in the
--   consumer.  The driver frees contexts only when the GC runs a
--   finalizer.
--
-- * The stream's end state is observable: @ZSTD_decompressStream@
--   returns 0 exactly when a frame is completely decoded and fully
--   flushed.  Input that ends anywhere else - a frame cut off
--   mid-way, or trailing bytes the decoder buffered as a
--   prospective next frame header - refuses with 'ZstdStreamError',
--   the same complete-stream contract as 'NovaCache.Xz'.  The
--   driver discards this return value at end of input and reports a
--   clean end regardless.
--
-- Decoder window memory is bounded by libzstd itself: the binding
-- exposes no window-limit parameter, but the streaming decoder
-- refuses any frame declaring a window past its default
-- @ZSTD_WINDOWLOG_LIMIT_DEFAULT@ (2^27, 128 MiB), so decoder memory
-- is capped by the library rather than by a caller-chosen number.
-- Take the tunable cap here too if the binding ever exposes
-- @ZSTD_d_windowLogMax@.
--
-- Everything here is IO: streaming decompression is stateful C
-- calls against a bracketed context, unlike lzma's lazy-ST driver
-- under 'NovaCache.Xz'.
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
    ZstdCompressionLevel,
    zstdCompressionLevel,
    maxCompressionLevel,
    defaultCompressionLevel,
    withZstdSource,
  )
where

import qualified Codec.Compression.Zstd as OneShot
import Codec.Compression.Zstd.FFI (Buffer (..), In, Out)
import qualified Codec.Compression.Zstd.FFI as FFI
import Control.Exception (Exception, bracket, throwIO, try)
import Control.Monad (when)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Unsafe as BSU
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import Data.Word (Word64, Word8)
import Foreign.Marshal.Alloc (free, malloc, mallocBytes)
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.Storable (peek, poke)

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
  = -- | The compressed stream is unacceptable: malformed (libzstd's
    -- error name, rendered with the failing call site), or ended
    -- anywhere but exactly between frames (truncated mid-frame, or
    -- trailing bytes after the last frame).
    ZstdStreamError !String
  | -- | Decompressed output would exceed the bound (carried here).
    ZstdOutputOverBound !Word64
  deriving (Eq, Show)

-- | Thrown by the pull source 'withZstdSource' hands its
-- continuation; a chunk convention has no error channel, and a
-- throwing pull composes with consumers built around one.
instance Exception ZstdError

-- | One libzstd failure in this module's error vocabulary.
renderError :: String -> String -> ZstdError
renderError site name = ZstdStreamError (site <> ": " <> name)

-- | Call sites named in 'ZstdStreamError' messages.
dstreamCreateSite, dstreamInitSite, decompressStreamSite, endOfInputSite :: String
dstreamCreateSite = "ZSTD_createDStream"
dstreamInitSite = "ZSTD_initDStream"
decompressStreamSite = "ZSTD_decompressStream"
endOfInputSite = "end of input"

-- | The refusal for a stream that ends anywhere but exactly between
-- frames.  One error covers both shapes deliberately: libzstd
-- buffers a truncated frame header and one to three trailing
-- garbage bytes identically (either could be the start of a next
-- frame), so the two are not distinguishable here.
incompleteStreamError :: ZstdError
incompleteStreamError = renderError endOfInputSite "truncated frame or trailing bytes"

-- ---------------------------------------------------------------------------
-- Compression levels
-- ---------------------------------------------------------------------------

-- | A compression level the binding accepts: 'lowestCompressionLevel'
-- through 'maxCompressionLevel'.  The constructor is not exported, so
-- an out-of-range level is unrepresentable and 'compress' is total;
-- the binding's own compress calls 'error' (under unsafePerformIO)
-- on a level outside this range.
newtype ZstdCompressionLevel = ZstdCompressionLevel Int
  deriving (Eq, Ord, Show)

-- | Validate a level into 'ZstdCompressionLevel'; 'Nothing' outside
-- the accepted range.
zstdCompressionLevel :: Int -> Maybe ZstdCompressionLevel
zstdCompressionLevel level
  | level >= lowestCompressionLevel && level <= maxCompressionLevel =
      Just (ZstdCompressionLevel level)
  | otherwise = Nothing

-- | The highest level libzstd supports (@ZSTD_maxCLevel@; 22 in
-- current releases).
maxCompressionLevel :: Int
maxCompressionLevel = FFI.maxCLevel

-- | The lowest level the binding accepts.  libzstd itself reads 0 as
-- "use the default" and negative values as the fast modes, but the
-- binding's compress rejects anything below 1, so 1 is the floor of
-- the representable range.
lowestCompressionLevel :: Int
lowestCompressionLevel = 1

-- | libzstd's own default (level 3): the ratio/speed point the
-- library authors tuned for, and far cheaper than xz at push time.
defaultCompressionLevel :: ZstdCompressionLevel
defaultCompressionLevel = ZstdCompressionLevel 3

-- ---------------------------------------------------------------------------
-- Compression (push path)
-- ---------------------------------------------------------------------------

-- | Compress one payload at the given level.  The produced frame
-- records its content size, so consumers with a one-shot decoder can
-- allocate exactly.  Total by construction: 'ZstdCompressionLevel'
-- cannot hold a level the binding's pure one-shot API would reject.
compress :: ZstdCompressionLevel -> ByteString -> ByteString
compress (ZstdCompressionLevel level) = OneShot.compress level

-- ---------------------------------------------------------------------------
-- Bounded decode
-- ---------------------------------------------------------------------------

-- | Decompress one zstd payload under the given limits.  Output
-- stops accumulating the moment it would pass the bound, so a
-- high-expansion input costs at most the bound plus one decoder
-- buffer, never what it claims to hold.  Concatenated frames decode
-- as one output, as upstream's decompression sink accepts; input
-- that ends mid-frame or carries trailing bytes refuses (see the
-- module header).
decompress :: ZstdLimits -> ByteString -> IO (Either ZstdError ByteString)
decompress limits input = do
  remainingRef <- newIORef (Just input)
  try (withZstdSource limits (oneShotSource remainingRef) drainSource)

-- | Yield the held payload on the first pull, the end-of-input empty
-- chunk on every later one.
oneShotSource :: IORef (Maybe ByteString) -> IO ByteString
oneShotSource remainingRef = do
  remaining <- readIORef remainingRef
  case remaining of
    Nothing -> pure BS.empty
    Just bytes -> do
      writeIORef remainingRef Nothing
      pure bytes

-- | Collect a pull source's chunks into one strict ByteString.
drainSource :: IO ByteString -> IO ByteString
drainSource pull = collect []
  where
    collect acc = do
      chunk <- pull
      if BS.null chunk
        then pure (BS.concat (reverse acc))
        else collect (chunk : acc)

-- ---------------------------------------------------------------------------
-- Streaming bounded decode (IO boundary)
-- ---------------------------------------------------------------------------

-- | Decompress a chunk source into a chunk source, under the
-- limits.  The continuation's pull yields decompressed chunks; the
-- empty chunk means end of output and repeats on further pulls.
-- The compressed source follows the same convention on its side.
-- Pairs with the incremental NAR parser and hashing, so a
-- substituter can fetch, decompress, hash, and unpack in one
-- bounded pass.
--
-- Limit violations and unacceptable input are thrown as 'ZstdError'
-- from the pull, and every pull after a failure rethrows it.  The
-- decompression context lives exactly as long as the continuation.
withZstdSource :: ZstdLimits -> IO ByteString -> (IO ByteString -> IO a) -> IO a
withZstdSource limits compressedSource consume =
  withDecoder $ \decoder -> do
    stateRef <- newIORef (ZstdStreaming initialProgress)
    consume (pullDecompressed limits compressedSource decoder stateRef)

-- | What the pull source is doing between calls.  The 'IORef'
-- holding this is the module's one piece of mutable state - the
-- same deliberate, documented boundary as the xz source.  A failure
-- is remembered: a consumer that catches the error and pulls again
-- gets it rethrown, never a phantom clean end of stream.
data ZstdSourceState
  = ZstdStreaming !DecodeProgress
  | ZstdFailed !ZstdError
  | ZstdDrained

-- | Where a decode stands between pulls.
data DecodeProgress = DecodeProgress
  { -- | Compressed bytes handed over by the source but not yet
    -- consumed by the decoder (the output buffer filled first).
    pendingCompressed :: !ByteString,
    -- | Decompressed bytes delivered so far, for the bound check.
    producedBytes :: !Word64,
    -- | The last @ZSTD_decompressStream@ call returned 0, or none
    -- has run: the decoder sits exactly between frames, the only
    -- state in which end of input is a clean end of stream.
    atFrameBoundary :: !Bool,
    -- | The compressed source has delivered its empty end chunk.
    sourceExhausted :: !Bool
  }

initialProgress :: DecodeProgress
initialProgress = DecodeProgress BS.empty 0 True False

-- | Produce the next decompressed chunk.
pullDecompressed :: ZstdLimits -> IO ByteString -> ZstdDecoder -> IORef ZstdSourceState -> IO ByteString
pullDecompressed limits compressedSource decoder stateRef =
  dispatch =<< readIORef stateRef
  where
    bound = zstdMaxOutputBytes limits

    dispatch ZstdDrained = pure BS.empty
    dispatch (ZstdFailed err) = throwIO err
    dispatch (ZstdStreaming progress) = advance progress

    refuse err = do
      writeIORef stateRef (ZstdFailed err)
      throwIO err

    advance progress
      | not (BS.null (pendingCompressed progress)) = decodeStep progress
      | sourceExhausted progress = finishStep progress
      | otherwise = do
          chunk <- compressedSource
          if BS.null chunk
            then finishStep progress {sourceExhausted = True}
            else decodeStep progress {pendingCompressed = chunk}

    decodeStep progress =
      deliver progress =<< decodeChunk decoder (pendingCompressed progress)

    -- End of input.  Between frames it is the clean end of stream.
    -- Inside a frame, first flush what the decoder still buffers
    -- (bounded by one block per call); a flush that yields nothing
    -- short of a frame boundary means the remaining state is a
    -- frame cut off mid-way or buffered trailing bytes - refuse.
    finishStep progress
      | atFrameBoundary progress = do
          writeIORef stateRef ZstdDrained
          pure BS.empty
      | otherwise = do
          outcome <- decodeChunk decoder BS.empty
          case outcome of
            Right step
              | BS.null (stepOutput step) && not (stepAtBoundary step) ->
                  refuse incompleteStreamError
            _ -> deliver progress outcome

    deliver _ (Left err) = refuse err
    deliver progress (Right step)
      | grown > bound = refuse (ZstdOutputOverBound bound)
      | BS.null (stepOutput step) = advance nextProgress
      | otherwise = do
          writeIORef stateRef (ZstdStreaming nextProgress)
          pure (stepOutput step)
      where
        grown = producedBytes progress + fromIntegral (BS.length (stepOutput step))
        nextProgress =
          progress
            { pendingCompressed = stepRemaining step,
              producedBytes = grown,
              atFrameBoundary = stepAtBoundary step
            }

-- ---------------------------------------------------------------------------
-- Decoder plumbing (FFI boundary)
-- ---------------------------------------------------------------------------

-- | A bracketed @ZSTD_DStream@ with the reusable buffers one
-- @ZSTD_decompressStream@ call needs.
data ZstdDecoder = ZstdDecoder
  { decoderStream :: !(Ptr FFI.DStream),
    decoderInBuffer :: !(Ptr (Buffer In)),
    decoderOutBuffer :: !(Ptr (Buffer Out)),
    decoderOutBytes :: !(Ptr Word8)
  }

-- | Output capacity per @ZSTD_decompressStream@ call:
-- @ZSTD_DStreamOutSize@, sized by libzstd so one call can always
-- flush a full decoded block.
outputBufferBytes :: Int
outputBufferBytes = fromIntegral FFI.dstreamOutSize

-- | Run an action with a decompression context and its buffers,
-- freeing all four allocations on any exit.  This bracket is the
-- point of driving the FFI directly: the context grows a window
-- buffer sized by the incoming frame header, and 'FFI.freeDStream'
-- here releases it the moment the action ends instead of at a GC
-- finalizer's leisure.
withDecoder :: (ZstdDecoder -> IO a) -> IO a
withDecoder action =
  bracket (FFI.checkAlloc dstreamCreateSite FFI.createDStream) FFI.freeDStream $ \stream ->
    bracket malloc free $ \inBuffer ->
      bracket malloc free $ \outBuffer ->
        bracket (mallocBytes outputBufferBytes) free $ \outBytes -> do
          initRet <- FFI.initDStream stream
          when (FFI.isError initRet) $
            throwIO (renderError dstreamInitSite (FFI.getErrorName initRet))
          action (ZstdDecoder stream inBuffer outBuffer outBytes)

-- | What one @ZSTD_decompressStream@ call yielded.
data DecodeStep = DecodeStep
  { -- | Decompressed bytes flushed into the output buffer.
    stepOutput :: !ByteString,
    -- | The unconsumed tail of the fed input.
    stepRemaining :: !ByteString,
    -- | The call returned 0, the library's only signal that a frame
    -- is completely decoded AND fully flushed.
    stepAtBoundary :: !Bool
  }

-- | One @ZSTD_decompressStream@ call: feed a chunk (empty for a pure
-- flush), collect whatever fits in the output buffer.  The output is
-- copied out immediately, so the shared buffer can be reused.
decodeChunk :: ZstdDecoder -> ByteString -> IO (Either ZstdError DecodeStep)
decodeChunk decoder input =
  supplyInput (decoderInBuffer decoder) input $ do
    poke
      (decoderOutBuffer decoder)
      (Buffer (decoderOutBytes decoder) (fromIntegral outputBufferBytes) 0)
    ret <-
      FFI.decompressStream
        (decoderStream decoder)
        (decoderOutBuffer decoder)
        (decoderInBuffer decoder)
    if FFI.isError ret
      then pure (Left (renderError decompressStreamSite (FFI.getErrorName ret)))
      else do
        -- The binding hides its FFI.Types module, so the filled and
        -- consumed positions are read by peeking the whole (three
        -- field) struct rather than its exposed peekPos helper.
        outFilled <- bufPos <$> peek (decoderOutBuffer decoder)
        inConsumed <- bufPos <$> peek (decoderInBuffer decoder)
        output <- BS.packCStringLen (castPtr (decoderOutBytes decoder), fromIntegral outFilled)
        pure (Right (DecodeStep output (BS.drop (fromIntegral inConsumed) input) (ret == 0)))

-- | Point the input buffer at the chunk for the duration of the
-- action.  An empty chunk becomes a null zero-length buffer -
-- libzstd reads nothing from a zero-size buffer, and this is the
-- shape its own examples use for a flush call.
supplyInput :: Ptr (Buffer In) -> ByteString -> IO a -> IO a
supplyInput inBuffer bytes action
  | BS.null bytes = do
      poke inBuffer (Buffer (nullPtr :: Ptr Word8) 0 0)
      action
  | otherwise = BSU.unsafeUseAsCStringLen bytes $ \(inPtr, inLen) -> do
      poke inBuffer (Buffer inPtr (fromIntegral inLen) 0)
      action
