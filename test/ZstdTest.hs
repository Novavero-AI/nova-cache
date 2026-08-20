-- | Tests for the bounded zstd codec.  A separate suite because the
-- codec lives in the nova-cache:zstandard sublibrary.  Most
-- compressed fixtures come from the sublibrary's own pure
-- 'Zstd.compress'; two frames are embedded as bytes produced offline
-- by the reference zstd CLI (v1.5.7), grounding the decoder against
-- the reference encoder - no external tool runs at test time.
module Main (main) where

import Control.Exception (try)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.IORef (newIORef, readIORef, writeIORef)
import Data.Maybe (isJust, isNothing)
import Data.Word (Word8)
import qualified NovaCache.Zstd as Zstd
import System.Exit (exitFailure, exitSuccess)
import System.IO (hFlush, stdout)

-- ---------------------------------------------------------------------------
-- Harness (mirrors test/XzTest.hs)
-- ---------------------------------------------------------------------------

test :: String -> IO Bool -> IO Bool
test name action = do
  putStr ("  " ++ name ++ "... ")
  hFlush stdout
  result <- action
  putStrLn (if result then "OK" else "FAILED")
  pure result

assertEqual :: (Eq a, Show a) => String -> a -> a -> IO Bool
assertEqual label expected actual
  | expected == actual = pure True
  | otherwise = do
      putStrLn ""
      putStrLn ("    " ++ label)
      putStrLn ("    expected: " ++ show expected)
      putStrLn ("    actual:   " ++ show actual)
      pure False

assertTrue :: String -> Bool -> IO Bool
assertTrue _ True = pure True
assertTrue label False = do
  putStrLn ""
  putStrLn ("    " ++ label ++ ": expected True")
  pure False

-- ---------------------------------------------------------------------------
-- Fixtures
-- ---------------------------------------------------------------------------

-- | Compressible ASCII payload, 2048 bytes.
payload :: ByteString
payload = BS.concat (replicate 64 "nova-cache zstd fixture payload\n")

payloadSize :: Word
payloadSize = fromIntegral (BS.length payload)

limitsOf :: Word -> Zstd.ZstdLimits
limitsOf n = Zstd.ZstdLimits {Zstd.zstdMaxOutputBytes = fromIntegral n}

compressedPayload :: ByteString
compressedPayload = Zstd.compress Zstd.defaultCompressionLevel payload

-- | A byte no zstd magic number starts with, for trailing-garbage
-- tails.
garbageByte :: Word8
garbageByte = 0x47

-- | What 'referenceFrame' decompresses to: 16 copies of the
-- reference line, 544 bytes.
referencePayload :: ByteString
referencePayload = BS.concat (replicate 16 "nova-cache zstd reference fixture\n")

-- | 'referencePayload' compressed offline by the reference CLI
-- (@zstd -3@ over a pipe, so the header carries no content size and
-- an XXH64 content checksum), byte for byte.
referenceFrame :: ByteString
referenceFrame =
  BS.pack
    [ 0x28,
      0xb5,
      0x2f,
      0xfd,
      0x04,
      0x58,
      0x5d,
      0x01,
      0x00,
      0x24,
      0x02,
      0x6e,
      0x6f,
      0x76,
      0x61,
      0x2d,
      0x63,
      0x61,
      0x63,
      0x68,
      0x65,
      0x20,
      0x7a,
      0x73,
      0x74,
      0x64,
      0x20,
      0x72,
      0x65,
      0x66,
      0x65,
      0x72,
      0x65,
      0x6e,
      0x63,
      0x65,
      0x20,
      0x66,
      0x69,
      0x78,
      0x74,
      0x75,
      0x72,
      0x65,
      0x0a,
      0x01,
      0x00,
      0xda,
      0x2f,
      0xaa,
      0x7a,
      0x02,
      0xd1,
      0x58,
      0x21,
      0xe9
    ]

-- | A frame whose header declares a 1 GiB window (@zstd --long=30@
-- over a pipe, offline): past libzstd's default window limit
-- (@ZSTD_WINDOWLOG_LIMIT_DEFAULT@, 2^27 = 128 MiB), so the decoder
-- must refuse rather than allocate what the peer's header asks for.
wideWindowFrame :: ByteString
wideWindowFrame =
  BS.pack
    [ 0x28,
      0xb5,
      0x2f,
      0xfd,
      0x04,
      0xa0,
      0x69,
      0x00,
      0x00,
      0x77,
      0x69,
      0x6e,
      0x64,
      0x6f,
      0x77,
      0x20,
      0x70,
      0x72,
      0x6f,
      0x62,
      0x65,
      0x0a,
      0x46,
      0x3e,
      0x21,
      0x43
    ]

-- | A pull source yielding the given chunks, then empty forever.
chunkSource :: [ByteString] -> IO (IO ByteString)
chunkSource chunks = do
  ref <- newIORef chunks
  pure $ do
    remaining <- readIORef ref
    case remaining of
      [] -> pure BS.empty
      (c : cs) -> writeIORef ref cs >> pure c

-- | Split a payload into bounded chunks so the streaming path sees
-- many small feeds, as a network body would deliver.
chunksOf :: Int -> ByteString -> [ByteString]
chunksOf n bs
  | BS.null bs = []
  | otherwise = BS.take n bs : chunksOf n (BS.drop n bs)

-- | Drain a decompressed pull source into one strict ByteString.
collectSource :: IO ByteString -> IO ByteString
collectSource pull = go []
  where
    go acc = do
      chunk <- pull
      if BS.null chunk
        then pure (BS.concat (reverse acc))
        else go (chunk : acc)

isStreamError :: Either Zstd.ZstdError a -> Bool
isStreamError (Left (Zstd.ZstdStreamError _)) = True
isStreamError _ = False

-- ---------------------------------------------------------------------------
-- Tests
-- ---------------------------------------------------------------------------

main :: IO ()
main = do
  putStrLn "zstd"
  results <-
    sequence
      [ test "roundtrip under the exact bound" $ do
          out <- Zstd.decompress (limitsOf payloadSize) compressedPayload
          assertEqual "roundtrip" (Right payload) out,
        test "one byte under the real size refuses" $ do
          out <- Zstd.decompress (limitsOf (payloadSize - 1)) compressedPayload
          assertEqual "over-bound" (Left (Zstd.ZstdOutputOverBound (fromIntegral (payloadSize - 1)))) out,
        test "garbage refuses" $ do
          out <- Zstd.decompress (limitsOf 64) "not a zstd stream"
          assertTrue "stream error" (isStreamError out),
        test "concatenated frames decode as one output" $ do
          let second = BS.concat (replicate 8 "second frame\n")
              joined = compressedPayload <> Zstd.compress Zstd.defaultCompressionLevel second
          out <- Zstd.decompress (limitsOf (payloadSize + fromIntegral (BS.length second))) joined
          assertEqual "concatenated" (Right (payload <> second)) out,
        test "trailing garbage after a frame refuses" $ do
          out <- Zstd.decompress (limitsOf (payloadSize + 64)) (compressedPayload <> "trailing garbage")
          assertTrue "trailing" (isStreamError out),
        test "trailing garbage of one to four bytes refuses" $ do
          outs <-
            mapM
              ( \n ->
                  Zstd.decompress
                    (limitsOf (payloadSize + 64))
                    (compressedPayload <> BS.replicate n garbageByte)
              )
              [1 .. 4]
          assertTrue "each tail refuses" (all isStreamError outs),
        test "truncated input refuses" $ do
          out <- Zstd.decompress (limitsOf payloadSize) (BS.dropEnd 5 compressedPayload)
          assertTrue "truncated" (isStreamError out),
        test "empty input is empty output" $ do
          out <- Zstd.decompress (limitsOf 0) BS.empty
          assertEqual "empty" (Right BS.empty) out,
        test "reference CLI frame roundtrips" $ do
          out <-
            Zstd.decompress
              (limitsOf (fromIntegral (BS.length referencePayload)))
              referenceFrame
          assertEqual "reference" (Right referencePayload) out,
        test "window past the default limit refuses" $ do
          out <- Zstd.decompress (limitsOf 4096) wideWindowFrame
          assertTrue "wide window" (isStreamError out),
        test "compression level constructor enforces the range" $
          pure
            ( isNothing (Zstd.zstdCompressionLevel 0)
                && isJust (Zstd.zstdCompressionLevel 1)
                && isJust (Zstd.zstdCompressionLevel Zstd.maxCompressionLevel)
                && isNothing (Zstd.zstdCompressionLevel (Zstd.maxCompressionLevel + 1))
            ),
        test "roundtrip at a constructed level" $
          case Zstd.zstdCompressionLevel 19 of
            Nothing -> assertTrue "level 19 representable" False
            Just level -> do
              out <- Zstd.decompress (limitsOf payloadSize) (Zstd.compress level payload)
              assertEqual "constructed level" (Right payload) out,
        test "source: chunked roundtrip" $ do
          source <- chunkSource (chunksOf 7 compressedPayload)
          out <- Zstd.withZstdSource (limitsOf payloadSize) source collectSource
          assertEqual "source roundtrip" payload out,
        test "source: over-bound throws" $ do
          source <- chunkSource (chunksOf 7 compressedPayload)
          out <- try (Zstd.withZstdSource (limitsOf (payloadSize - 1)) source collectSource)
          assertEqual "source over-bound" (Left (Zstd.ZstdOutputOverBound (fromIntegral (payloadSize - 1)))) out,
        test "source: garbage throws" $ do
          source <- chunkSource ["not a zstd stream"]
          out <- try (Zstd.withZstdSource (limitsOf 64) source collectSource) :: IO (Either Zstd.ZstdError ByteString)
          assertTrue "source garbage" (isStreamError out),
        test "source: truncated input throws" $ do
          source <- chunkSource (chunksOf 7 (BS.dropEnd 5 compressedPayload))
          out <- try (Zstd.withZstdSource (limitsOf payloadSize) source collectSource) :: IO (Either Zstd.ZstdError ByteString)
          assertTrue "source truncated" (isStreamError out),
        test "source: pull after an error keeps throwing" $ do
          source <- chunkSource ["not a zstd stream"]
          Zstd.withZstdSource (limitsOf 64) source $ \pull -> do
            first <- try pull :: IO (Either Zstd.ZstdError ByteString)
            second <- try pull :: IO (Either Zstd.ZstdError ByteString)
            initial <- assertTrue "first pull throws" (isStreamError first)
            repeated <- assertEqual "second pull rethrows the same error" first second
            pure (initial && repeated)
      ]
  if and results then exitSuccess else exitFailure
