-- | Tests for the bounded zstd codec.  A separate suite because the
-- codec lives in the nova-cache:zstandard sublibrary; the compressed
-- fixtures come from the sublibrary's own pure 'Zstd.compress', so
-- no external tool runs at test time.
module Main (main) where

import Control.Exception (try)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.IORef (newIORef, readIORef, writeIORef)
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
          assertTrue "stream error" $ case out of
            Left (Zstd.ZstdStreamError _) -> True
            _ -> False,
        test "concatenated frames decode as one output" $ do
          let second = BS.concat (replicate 8 "second frame\n")
              joined = compressedPayload <> Zstd.compress Zstd.defaultCompressionLevel second
          out <- Zstd.decompress (limitsOf (payloadSize + fromIntegral (BS.length second))) joined
          assertEqual "concatenated" (Right (payload <> second)) out,
        test "trailing garbage after a frame refuses" $ do
          out <- Zstd.decompress (limitsOf (payloadSize + 64)) (compressedPayload <> "trailing garbage")
          assertTrue "trailing" $ case out of
            Left (Zstd.ZstdStreamError _) -> True
            _ -> False,
        test "empty input is empty output" $ do
          out <- Zstd.decompress (limitsOf 0) BS.empty
          assertEqual "empty" (Right BS.empty) out,
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
          assertTrue "source garbage" $ case out of
            Left (Zstd.ZstdStreamError _) -> True
            _ -> False
      ]
  if and results then exitSuccess else exitFailure
