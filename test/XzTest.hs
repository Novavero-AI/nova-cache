-- | Tests for the bounded xz decoder.  A separate suite because the
-- decoder lives in the nova-cache:xz sublibrary; the fixtures are real @xz -6@
-- output embedded as hex, so no external tool runs at test time.
module Main (main) where

import Control.Exception (throwIO, try)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Char (isDigit)
import Data.IORef (newIORef, readIORef, writeIORef)
import qualified NovaCache.Xz as Xz
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

-- | @xz -6@ of "nova-cache xz fixture\n" (22 bytes of output).
textXz :: ByteString
textXz =
  unhex
    "fd377a585a000004e6d6b44604c01a162101160000000000000000001caa3b74\
    \0100156e6f76612d636163686520787a20666978747572650a0000002c84d5d2\
    \3c233719000136160f914e5d1fb6f37d010000000004595a"

-- | The bytes 'textXz' decompresses to.
textPlain :: ByteString
textPlain = "nova-cache xz fixture\n"

-- | @xz -6@ of 65536 zero bytes: 148 bytes in, 64 KiB out - the
-- expansion shape the output bound exists for.  The stream declares
-- an 8 MiB dictionary, which the memory-bound test leans on.
zerosXz :: ByteString
zerosXz =
  unhex
    "fd377a585a000004e6d6b44604c05480800421011600000000000000e6b515ff\
    \e0ffff004c5d00006ffdffffa3b7ff473e481572396151b89228e6a38607f9ee\
    \e41e82d32fc53a3c014bb17ec98a8a4d2fa30dd97fa6e38c231153e05918c575\
    \8ae277f8b6947f0c6ac0de7449645c9e3ad100005e654f49ca09af2600017080\
    \800400006977c193b1c467fb020000000004595a"

-- | Output size of 'zerosXz'.
zerosLength :: Word
zerosLength = 65536

-- | Generous limits for the happy paths.
openLimits :: Xz.XzLimits
openLimits =
  Xz.XzLimits
    { Xz.xzMaxOutputBytes = 1024 * 1024,
      Xz.xzMaxDecoderMemoryBytes = Xz.defaultXzDecoderMemoryBytes
    }

-- | 'openLimits' with the output bound replaced.
boundedTo :: Word -> Xz.XzLimits
boundedTo bound = openLimits {Xz.xzMaxOutputBytes = fromIntegral bound}

-- | Split a byte string into fixed-size pieces.
chunksOf :: Int -> ByteString -> [ByteString]
chunksOf n bs
  | BS.null bs = []
  | otherwise = case BS.splitAt n bs of
      (piece, rest) -> piece : chunksOf n rest

-- | A chunk source over a fixed list (empty chunk on exhaustion), for
-- feeding 'Xz.withXzSource'.
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
  putStrLn "nova-cache xz test suite"
  putStrLn "========================"
  results <-
    sequence
      [ test "roundtrip under the exact output bound" $
          -- NarSize is exact, so output == bound must pass.
          assertEqual
            "text fixture"
            (Right textPlain)
            (Xz.decompress (boundedTo (fromIntegral (BS.length textPlain))) textXz),
        test "high-expansion input inflates fully under an open bound" $
          case Xz.decompress openLimits zerosXz of
            Left err -> do
              putStrLn ("    unexpected error: " ++ show err)
              pure False
            Right out -> do
              ok1 <- assertEqual "length" zerosLength (fromIntegral (BS.length out))
              ok2 <- assertTrue "all zero" (BS.all (== 0) out)
              pure (ok1 && ok2),
        test "output over the bound is refused" $
          assertEqual
            "far bound"
            (Left (Xz.XzOutputOverBound 1000))
            (Xz.decompress (boundedTo 1000) zerosXz),
        test "one byte under the true size is refused" $
          assertEqual
            "tight bound"
            (Left (Xz.XzOutputOverBound (fromIntegral (zerosLength - 1))))
            (Xz.decompress (boundedTo (zerosLength - 1)) zerosXz),
        test "garbage input is a stream error" $
          assertTrue "garbage" (isStreamError (Xz.decompress openLimits "not an xz stream")),
        test "a truncated stream is diagnosed as truncated" $
          -- The binding reports truncation as LzmaRetBufError (or
          -- LzmaRetOK); the message must be the diagnosis, not the
          -- raw constructor.
          assertEqual
            "truncated"
            (Left (Xz.XzStreamError Xz.truncatedInputMessage))
            (Xz.decompress openLimits (BS.take 40 textXz)),
        test "empty input is diagnosed as truncated" $
          -- Zero bytes drive the decoder straight to end of input
          -- while the binding still reports LzmaRetOK, which shown
          -- raw would read as success.
          assertEqual
            "empty input"
            (Left (Xz.XzStreamError Xz.truncatedInputMessage))
            (Xz.decompress openLimits BS.empty),
        test "concatenated streams decode as one output" $
          -- Upstream decodes with LZMA_CONCATENATED; two streams
          -- back-to-back are one valid input.
          assertEqual
            "two text streams"
            (Right (textPlain <> textPlain))
            (Xz.decompress openLimits (textXz <> textXz)),
        test "trailing garbage after the stream is refused" $
          assertTrue
            "trailing garbage"
            (isStreamError (Xz.decompress openLimits (textXz <> "garbage!"))),
        test "a dictionary past the memory bound is refused" $
          -- zerosXz declares an 8 MiB dictionary; cap the decoder at 1 MiB.
          assertEqual
            "memory bound"
            (Left (Xz.XzMemoryOverBound smallMemory))
            (Xz.decompress openLimits {Xz.xzMaxDecoderMemoryBytes = smallMemory} zerosXz),
        test "withXzSource decompresses a chunked source" $ do
          source <- listSource (chunksOf 7 textXz)
          out <- Xz.withXzSource openLimits source drainSource
          assertEqual "streamed output" textPlain out,
        test "withXzSource succeeds at the exact output bound" $ do
          -- NarSize is exact, so the streaming path must accept
          -- output == bound just as the pure path does.
          source <- listSource (chunksOf 7 textXz)
          out <-
            Xz.withXzSource
              (boundedTo (fromIntegral (BS.length textPlain)))
              source
              drainSource
          assertEqual "exact-bound streamed output" textPlain out,
        test "withXzSource throws past the output bound" $ do
          source <- listSource (chunksOf 16 zerosXz)
          outcome <-
            try (Xz.withXzSource (boundedTo 1000) source drainSource) ::
              IO (Either Xz.XzError ByteString)
          assertEqual "thrown" (Left (Xz.XzOutputOverBound 1000)) outcome,
        test "withXzSource keeps returning empty after the end" $ do
          source <- listSource [textXz]
          ends <- Xz.withXzSource openLimits source $ \pull -> do
            _ <- drainSource pull
            endA <- pull
            endB <- pull
            pure (endA, endB)
          assertEqual "stable end" ("", "") ends,
        test "withXzSource re-throws the same error on pulls after a failure" $ do
          -- A caught error must not turn the next pull into the empty
          -- chunk, the clean-end signal; a failed source stays failed.
          source <- listSource (chunksOf 16 zerosXz)
          Xz.withXzSource (boundedTo 1000) source $ \pull -> do
            firstPull <- try (drainSource pull) :: IO (Either Xz.XzError ByteString)
            secondPull <- try pull :: IO (Either Xz.XzError ByteString)
            okFirst <-
              assertEqual "first pull" (Left (Xz.XzOutputOverBound 1000)) firstPull
            okSecond <-
              assertEqual "later pull" (Left (Xz.XzOutputOverBound 1000)) secondPull
            pure (okFirst && okSecond),
        test "a source failure never becomes a clean end" $ do
          -- The source delivers a full stream, errors on the pull
          -- that would confirm the end, then reads as exhausted.  An
          -- unlatched decoder would answer the retry with the empty
          -- chunk - a failed transfer posing as complete output.
          source <-
            scriptedSource [pure textXz, throwIO (userError sourceFailureText)]
          Xz.withXzSource openLimits source $ \pull -> do
            chunk <- pull
            firstPull <- try pull :: IO (Either IOError ByteString)
            laterPull <- try pull :: IO (Either IOError ByteString)
            okChunk <- assertEqual "decoded chunk" textPlain chunk
            okFirst <- assertTrue "first pull throws" (either isUserError (const False) firstPull)
            okLater <- assertTrue "later pull throws" (either isUserError (const False) laterPull)
            pure (okChunk && okFirst && okLater)
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
    smallMemory = 1024 * 1024
    sourceFailureText = "staged transfer failure"
    isStreamError outcome = case outcome of
      Left (Xz.XzStreamError _) -> True
      _ -> False
    drainSource pull = go []
      where
        go acc = do
          chunk <- pull
          if BS.null chunk
            then pure (BS.concat (reverse acc))
            else go (chunk : acc)
