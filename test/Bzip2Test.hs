-- | Tests for the bounded bzip2 decoder.  A separate suite because
-- the decoder lives in the nova-cache:bzip2 sublibrary; the fixtures
-- are real @bzip2 -9@ output embedded as hex, so no external tool
-- runs at test time.
module Main (main) where

import Control.Exception (throwIO, try)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Char (isDigit)
import Data.IORef (newIORef, readIORef, writeIORef)
import qualified NovaCache.Bzip2 as Bzip2
import System.Exit (exitFailure, exitSuccess)
import System.IO (hFlush, stdout)
import System.IO.Error (isUserError)

-- ---------------------------------------------------------------------------
-- Harness (mirrors test/Main.hs)
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

-- | Decode a hex fixture literal.  Fixtures are constants, so a
-- malformed one decodes short and the assertions fail loudly.
unhex :: String -> ByteString
unhex = BS.pack . pairs
  where
    pairs (hi : lo : rest) = case (hexVal hi, hexVal lo) of
      (Just h, Just l) -> fromIntegral (h * 16 + l) : pairs rest
      _ -> []
    pairs _ = []
    hexVal c
      | isDigit c = Just (fromEnum c - fromEnum '0')
      | c >= 'a' && c <= 'f' = Just (fromEnum c - fromEnum 'a' + 10)
      | otherwise = Nothing

-- | @bzip2 -9@ of "nova-cache bzip2 fixture\n" (25 bytes of output).
textBz2 :: ByteString
textBz2 =
  unhex
    "425a6839314159265359c032547900000859800010400210003b61d750200022\
    \8326862687a85309a680d3112446fdca60e188c3b44780043e2ee48a70a12180\
    \64a8f2"

-- | The bytes 'textBz2' decompresses to.
textPlain :: ByteString
textPlain = "nova-cache bzip2 fixture\n"

-- | @bzip2 -9@ of 65536 zero bytes: 43 bytes in, 64 KiB out - the
-- expansion shape the output bound exists for.
zerosBz2 :: ByteString
zerosBz2 =
  unhex
    "425a6839314159265359d771e9eb000080c000c000000820003080291a01a403\
    \8bb9229c28486bb8f4f580"

-- | Output size of 'zerosBz2'.
zerosLength :: Word
zerosLength = 65536

-- | A generous bound for the happy paths.
openLimits :: Bzip2.Bzip2Limits
openLimits = boundedTo (1024 * 1024)

-- | Limits with the given output bound.
boundedTo :: Word -> Bzip2.Bzip2Limits
boundedTo bound = Bzip2.Bzip2Limits {Bzip2.bzip2MaxOutputBytes = fromIntegral bound}

-- | Split a byte string into fixed-size pieces.
chunksOf :: Int -> ByteString -> [ByteString]
chunksOf n bs
  | BS.null bs = []
  | otherwise = case BS.splitAt n bs of
      (piece, rest) -> piece : chunksOf n rest

-- | A chunk source over a fixed list (empty chunk on exhaustion),
-- for feeding 'Bzip2.withBzip2Source'.
listSource :: [ByteString] -> IO (IO ByteString)
listSource chunks = scriptedSource (map pure chunks)

-- | A chunk source that performs the given actions in order and
-- returns the empty chunk after they run out; an action may throw,
-- which is how the errored-source tests stage a failure.
scriptedSource :: [IO ByteString] -> IO (IO ByteString)
scriptedSource steps = do
  remaining <- newIORef steps
  pure $ do
    held <- readIORef remaining
    case held of
      [] -> pure BS.empty
      (act : rest) -> do
        writeIORef remaining rest
        act

-- ---------------------------------------------------------------------------
-- Tests
-- ---------------------------------------------------------------------------

main :: IO ()
main = do
  putStrLn "nova-cache bzip2 test suite"
  putStrLn "==========================="
  results <-
    sequence
      [ test "roundtrip under the exact output bound" $ do
          -- NarSize is exact, so output == bound must pass.
          outcome <- Bzip2.decompress (boundedTo (fromIntegral (BS.length textPlain))) textBz2
          assertEqual "text fixture" (Right textPlain) outcome,
        test "high-expansion input inflates fully under an open bound" $ do
          outcome <- Bzip2.decompress openLimits zerosBz2
          case outcome of
            Left err -> do
              putStrLn ("    unexpected error: " ++ show err)
              pure False
            Right out -> do
              ok1 <- assertEqual "length" zerosLength (fromIntegral (BS.length out))
              ok2 <- assertTrue "all zero" (BS.all (== 0) out)
              pure (ok1 && ok2),
        test "output over the bound is refused" $ do
          outcome <- Bzip2.decompress (boundedTo 1000) zerosBz2
          assertEqual "far bound" (Left (Bzip2.Bzip2OutputOverBound 1000)) outcome,
        test "one byte under the true size is refused" $ do
          outcome <- Bzip2.decompress (boundedTo (zerosLength - 1)) zerosBz2
          assertEqual
            "tight bound"
            (Left (Bzip2.Bzip2OutputOverBound (fromIntegral (zerosLength - 1))))
            outcome,
        test "garbage input is a stream error" $ do
          outcome <- Bzip2.decompress openLimits "not a bzip2 stream"
          assertTrue "garbage" (isStreamError outcome),
        test "a truncated stream is a stream error" $ do
          outcome <- Bzip2.decompress openLimits (BS.take 20 textBz2)
          assertTrue "truncated" (isStreamError outcome),
        test "concatenated streams decode as one output" $ do
          -- Upstream's sink re-initializes at stream end while input
          -- remains; two streams back-to-back are one valid input.
          outcome <- Bzip2.decompress openLimits (textBz2 <> textBz2)
          assertEqual "two text streams" (Right (textPlain <> textPlain)) outcome,
        -- Upstream Nix decompresses bzip2 through libarchive, which
        -- ignores whatever follows the last stream unless it begins
        -- another one.  Measured against libarchive 3.8.2 driven exactly
        -- as Nix drives it (filter_all + format_raw + format_empty): all
        -- four of these decode to the payload there, and all four were
        -- refused here before.
        test "trailing bytes that are not a stream end the output" $ do
          let trailers = ["garbage!", "\0\0\0\0", "\n", "BZh"]
          results <-
            mapM
              ( \trailer -> do
                  outcome <- Bzip2.decompress openLimits (textBz2 <> trailer)
                  assertEqual ("trailer " <> show trailer) (Right textPlain) outcome
              )
              trailers
          pure (and results),
        test "a truncated concatenated stream is still refused" $ do
          -- The safe half of the rule: bytes that DO begin a stream are
          -- decoded as one, and a truncated one fails rather than
          -- silently truncating the output.
          outcome <- Bzip2.decompress openLimits (textBz2 <> BS.take 40 textBz2)
          assertTrue "truncated second stream" (isStreamError outcome),
        test "withBzip2Source decompresses a chunked source" $ do
          source <- listSource (chunksOf 7 textBz2)
          out <- Bzip2.withBzip2Source openLimits source drainSource
          assertEqual "streamed output" textPlain out,
        test "withBzip2Source decompresses one-byte chunks" $ do
          source <- listSource (chunksOf 1 textBz2)
          out <- Bzip2.withBzip2Source openLimits source drainSource
          assertEqual "byte-fed output" textPlain out,
        test "withBzip2Source succeeds at the exact output bound" $ do
          source <- listSource (chunksOf 16 zerosBz2)
          out <-
            Bzip2.withBzip2Source
              (boundedTo (fromIntegral zerosLength))
              source
              drainSource
          assertEqual "streamed length" zerosLength (fromIntegral (BS.length out)),
        test "withBzip2Source throws past the output bound" $ do
          source <- listSource (chunksOf 16 zerosBz2)
          outcome <-
            try (Bzip2.withBzip2Source (boundedTo 1000) source drainSource) ::
              IO (Either Bzip2.Bzip2Error ByteString)
          assertEqual "thrown" (Left (Bzip2.Bzip2OutputOverBound 1000)) outcome,
        test "withBzip2Source keeps returning empty after the end" $ do
          source <- listSource [textBz2]
          ends <- Bzip2.withBzip2Source openLimits source $ \pull -> do
            _ <- drainSource pull
            endA <- pull
            endB <- pull
            pure (endA, endB)
          assertEqual "stable end" ("", "") ends,
        test "a thrown decode error repeats on later pulls" $ do
          source <- listSource (chunksOf 16 zerosBz2)
          Bzip2.withBzip2Source (boundedTo 1000) source $ \pull -> do
            first <- try (drainSource pull) :: IO (Either Bzip2.Bzip2Error ByteString)
            again <- try pull :: IO (Either Bzip2.Bzip2Error ByteString)
            ok1 <- assertEqual "first pull" (Left (Bzip2.Bzip2OutputOverBound 1000)) first
            ok2 <- assertEqual "later pull" (Left (Bzip2.Bzip2OutputOverBound 1000)) again
            pure (ok1 && ok2),
        test "a source failure never becomes a clean end" $ do
          -- The source delivers a full stream, errors on the pull
          -- that would confirm the end, then reads as exhausted.  An
          -- unlatched decoder would answer the retry with the empty
          -- chunk - a failed transfer posing as complete output.
          source <-
            scriptedSource [pure textBz2, throwIO (userError sourceFailureText)]
          Bzip2.withBzip2Source openLimits source $ \pull -> do
            chunk <- pull
            first <- try pull :: IO (Either IOError ByteString)
            again <- try pull :: IO (Either IOError ByteString)
            ok1 <- assertEqual "decoded chunk" textPlain chunk
            ok2 <- assertTrue "first pull throws" (either isUserError (const False) first)
            ok3 <- assertTrue "later pull throws" (either isUserError (const False) again)
            pure (ok1 && ok2 && ok3)
      ]
  if and results
    then do
      putStrLn ""
      putStrLn ("All " ++ show (length results) ++ " tests passed.")
      exitSuccess
    else do
      putStrLn ""
      putStrLn "Some tests FAILED."
      exitFailure
  where
    sourceFailureText = "staged transfer failure"
    isStreamError outcome = case outcome of
      Left (Bzip2.Bzip2StreamError _) -> True
      _ -> False
    drainSource pull = go []
      where
        go acc = do
          chunk <- pull
          if BS.null chunk
            then pure (BS.concat (reverse acc))
            else go (chunk : acc)
