{-# LANGUAGE LambdaCase #-}

module Main (main) where

import Control.Exception (SomeException, try)
import qualified Crypto.PubKey.Ed25519 as Ed25519
import Data.Bits (shiftR, (.&.))
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Lazy as BL
import Data.Either (isLeft)
import Data.IORef (atomicModifyIORef', newIORef)
import Data.List (sort)
import Data.Maybe (isJust)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Word (Word8)
import qualified Network.HTTP.Types as HTTP
import Network.Wai (RequestBodyLength (..), defaultRequest, pathInfo, requestBodyLength, requestHeaders, requestMethod)
import qualified Network.Wai.Test as WT
import qualified NovaCache.Base32 as Base32
import qualified NovaCache.Hash as Hash
import qualified NovaCache.NAR as NAR
import qualified NovaCache.NAR.Stream as Stream
import qualified NovaCache.NarInfo as NarInfo
import qualified NovaCache.Server as Server
import qualified NovaCache.Signing as Signing
import qualified NovaCache.Store as Store
import qualified NovaCache.StorePath as StorePath
import qualified NovaCache.Validate as Validate
import System.Directory (createDirectory, getTemporaryDirectory, listDirectory, removeDirectoryRecursive)
import System.Exit (exitFailure, exitSuccess)
import System.IO (hFlush, stdout)
import qualified System.Info

-- ---------------------------------------------------------------------------
-- Test harness (hand-rolled, no framework)
-- ---------------------------------------------------------------------------

-- | Run a named test, short-circuit on first failure.
test :: String -> IO Bool -> IO Bool
test name action = do
  putStr ("  " ++ name ++ "... ")
  hFlush stdout
  result <- action
  if result
    then do
      putStrLn "OK"
      pure True
    else do
      putStrLn "FAILED"
      pure False

-- | Assert equality.
assertEqual :: (Eq a, Show a) => String -> a -> a -> IO Bool
assertEqual label expected actual
  | expected == actual = pure True
  | otherwise = do
      putStrLn ""
      putStrLn ("    " ++ label)
      putStrLn ("    expected: " ++ show expected)
      putStrLn ("    actual:   " ++ show actual)
      pure False

-- | Assert a Right value matches.
assertRight :: (Eq a, Show a) => String -> a -> Either String a -> IO Bool
assertRight label expected (Right actual) = assertEqual label expected actual
assertRight label _ (Left err) = do
  putStrLn ""
  putStrLn ("    " ++ label)
  putStrLn ("    expected Right, got Left: " ++ err)
  pure False

-- | Assert a Left (error case).
assertLeft :: (Show a) => String -> Either String a -> IO Bool
assertLeft _ (Left _) = pure True
assertLeft label (Right val) = do
  putStrLn ""
  putStrLn ("    " ++ label)
  putStrLn ("    expected Left, got Right: " ++ show val)
  pure False

-- | Assert a Bool is True.
assertTrue :: String -> Bool -> IO Bool
assertTrue _ True = pure True
assertTrue label False = do
  putStrLn ""
  putStrLn ("    " ++ label ++ ": expected True")
  pure False

-- | Assert a Bool is False.
assertFalse :: String -> Bool -> IO Bool
assertFalse _ False = pure True
assertFalse label True = do
  putStrLn ""
  putStrLn ("    " ++ label ++ ": expected False")
  pure False

-- | Run a group of tests, stopping at first failure.
runGroup :: String -> [IO Bool] -> IO Bool
runGroup name tests = do
  putStrLn (name ++ ":")
  go tests
  where
    go [] = pure True
    go (t : ts) = do
      ok <- t
      if ok then go ts else pure False

-- | Run all test groups.
runAll :: [IO Bool] -> IO ()
runAll groups = do
  results <- sequence groups
  let passed = length (filter id results)
      total = length results
  putStrLn ""
  if and results
    then do
      putStrLn ("All " ++ show total ++ " groups passed.")
      exitSuccess
    else do
      putStrLn (show passed ++ "/" ++ show total ++ " groups passed.")
      exitFailure

main :: IO ()
main = do
  putStrLn "nova-cache test suite"
  putStrLn "======================"
  putStrLn ""
  runAll
    [ testBase32,
      testHash,
      testStorePath,
      testNAR,
      testStream,
      testNarInfo,
      testSigning,
      testFileStore,
      testValidate,
      testServer
    ]

-- ---------------------------------------------------------------------------
-- Base32 tests
-- ---------------------------------------------------------------------------

testBase32 :: IO Bool
testBase32 =
  runGroup
    "Base32"
    [ test "encode empty" $
        assertEqual "encode empty" "" (Base32.encode BS.empty),
      test "decode empty" $
        assertRight "decode empty" BS.empty (Base32.decode ""),
      test "encode/decode roundtrip (single byte)" $
        let bs = BS.singleton 0xFF
            encoded = Base32.encode bs
         in assertRight "roundtrip 0xFF" bs (Base32.decode encoded),
      test "encode/decode roundtrip (known SHA-256)" $
        let bs = BS.pack [0 .. 31]
            encoded = Base32.encode bs
         in assertRight "roundtrip 32 bytes" bs (Base32.decode encoded),
      test "encode/decode roundtrip (all zeros)" $
        let bs = BS.replicate 32 0
            encoded = Base32.encode bs
         in assertRight "roundtrip zeros" bs (Base32.decode encoded),
      test "encode/decode roundtrip (all 0xFF)" $
        let bs = BS.replicate 32 0xFF
            encoded = Base32.encode bs
         in assertRight "roundtrip 0xFF*32" bs (Base32.decode encoded),
      test "decode invalid character" $
        assertLeft "invalid char" (Base32.decode "hello!"),
      test "encode length for 32 bytes" $
        -- 32 bytes gives ceil(32*8/5) = ceil(51.2) = 52 chars
        let bs = BS.replicate 32 0x42
            encoded = Base32.encode bs
         in assertEqual "encoded length" 52 (T.length encoded),
      test "nix known vector" $
        -- SHA-256 of the empty string exactly as real Nix renders it.  A
        -- wrong alphabet or bit order stays self-consistent in roundtrips;
        -- only an external vector catches it.
        assertEqual
          "sha256 of empty in nix-base32"
          "sha256:0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73"
          (Hash.formatNixHash (Hash.hashBytes BS.empty)),
      test "decode rejects nonzero padding bits" $
        -- 52 chars carry 260 bits for a 256-bit value; the 4 spare bits
        -- must be zero in canonical nix-base32.
        assertLeft "nonzero padding" (Base32.decode (T.replicate 52 "z"))
    ]

-- ---------------------------------------------------------------------------
-- Hash tests
-- ---------------------------------------------------------------------------

testHash :: IO Bool
testHash =
  runGroup
    "Hash"
    [ test "hashBytes deterministic" $
        let h1 = Hash.hashBytes (BS.pack [1, 2, 3])
            h2 = Hash.hashBytes (BS.pack [1, 2, 3])
         in assertEqual "deterministic" h1 h2,
      test "hashBytes different inputs differ" $
        let h1 = Hash.hashBytes (BS.pack [1, 2, 3])
            h2 = Hash.hashBytes (BS.pack [4, 5, 6])
         in assertTrue "different" (h1 /= h2),
      test "hashBytes is 32 bytes" $
        let Hash.NixHash raw = Hash.hashBytes BS.empty
         in assertEqual "32 bytes" 32 (BS.length raw),
      test "formatNixHash prefix" $
        let formatted = Hash.formatNixHash (Hash.hashBytes BS.empty)
         in assertTrue "sha256: prefix" (T.isPrefixOf "sha256:" formatted),
      test "formatNixHash/parseNixHash roundtrip" $
        let h = Hash.hashBytes (BS.pack [42])
            formatted = Hash.formatNixHash h
         in assertRight "roundtrip" h (Hash.parseNixHash formatted),
      test "parseNixHash bad prefix" $
        assertLeft "bad prefix" (Hash.parseNixHash "md5:abc"),
      test "parseNixHash bad base32" $
        assertLeft "bad base32" (Hash.parseNixHash "sha256:!!invalid!!")
    ]

-- ---------------------------------------------------------------------------
-- StorePath tests
-- ---------------------------------------------------------------------------

testStorePath :: IO Bool
testStorePath =
  runGroup
    "StorePath"
    [ test "parse/render roundtrip" $
        let storeDir = StorePath.defaultStoreDir
            input = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello-1.0"
         in case StorePath.parseStorePath storeDir input of
              Left err -> do
                putStrLn ("  parse failed: " ++ err)
                pure False
              Right sp ->
                assertEqual "roundtrip" input (StorePath.renderStorePath storeDir sp),
      test "parse basename only" $
        let storeDir = StorePath.defaultStoreDir
            basename = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello-1.0"
         in case StorePath.parseStorePath storeDir basename of
              Left err -> do
                putStrLn ("  parse failed: " ++ err)
                pure False
              Right sp ->
                assertEqual "basename" basename (StorePath.storePathBaseName sp),
      test "parse extracts hash" $
        let storeDir = StorePath.defaultStoreDir
            input = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-test"
         in case StorePath.parseStorePath storeDir input of
              Left _ -> pure False
              Right sp ->
                assertEqual "hash" "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" (StorePath.storePathHashString sp),
      test "reject too short" $
        let storeDir = StorePath.defaultStoreDir
         in assertLeft "too short" (StorePath.parseStorePath storeDir "abc-def"),
      test "reject empty name" $
        let storeDir = StorePath.defaultStoreDir
         in assertLeft "empty name" (StorePath.parseStorePath storeDir "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-"),
      test "reject invalid name chars" $
        let storeDir = StorePath.defaultStoreDir
            input = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello world"
         in assertLeft "invalid chars" (StorePath.parseStorePath storeDir input),
      -- Upstream's dot rule: the first dash-separated component may not
      -- be "." or ".."; other dot-leading names stay valid.
      test "reject dot-segment names" $
        let hash = T.replicate 32 "a"
            rejected name = assertLeft (T.unpack name) (StorePath.parseStorePathBaseName (hash <> "-" <> name))
         in do
              ok1 <- rejected "."
              ok2 <- rejected ".."
              ok3 <- rejected ".-x"
              ok4 <- rejected "..-y"
              pure (ok1 && ok2 && ok3 && ok4),
      test "dotfile-style names stay valid" $
        let hash = T.replicate 32 "a"
         in do
              ok1 <- assertTrue "dotfile" (either (const False) (const True) (StorePath.parseStorePathBaseName (hash <> "-.config-1.0")))
              ok2 <- assertTrue "interior dots" (either (const False) (const True) (StorePath.parseStorePathBaseName (hash <> "-x.y.z")))
              pure (ok1 && ok2)
    ]

-- ---------------------------------------------------------------------------
-- NAR tests
-- ---------------------------------------------------------------------------

testNAR :: IO Bool
testNAR =
  runGroup
    "NAR"
    [ test "serialise/deserialise roundtrip (regular file)" $
        let entry = NAR.NarRegular False (BS.pack [72, 101, 108, 108, 111])
            serialised = NAR.serialise entry
         in assertRight "roundtrip regular" entry (NAR.deserialise serialised),
      test "serialise/deserialise roundtrip (empty file)" $
        let entry = NAR.NarRegular False BS.empty
            serialised = NAR.serialise entry
         in assertRight "roundtrip empty" entry (NAR.deserialise serialised),
      test "serialise/deserialise roundtrip (executable)" $
        let entry = NAR.NarRegular True (BS.pack [0x7F, 0x45, 0x4C, 0x46])
            serialised = NAR.serialise entry
         in assertRight "roundtrip exec" entry (NAR.deserialise serialised),
      test "serialise/deserialise roundtrip (symlink)" $
        let entry = NAR.NarSymlink "/usr/bin/hello"
            serialised = NAR.serialise entry
         in assertRight "roundtrip symlink" entry (NAR.deserialise serialised),
      test "serialise/deserialise roundtrip (directory)" $
        let entry =
              NAR.NarDirectory
                [ ("bar", NAR.NarRegular False (BS.pack [2])),
                  ("foo", NAR.NarRegular False (BS.pack [1]))
                ]
            serialised = NAR.serialise entry
         in assertRight "roundtrip dir" entry (NAR.deserialise serialised),
      test "serialise/deserialise roundtrip (nested directory)" $
        let entry =
              NAR.NarDirectory
                [ ("bin", NAR.NarDirectory [("hello", NAR.NarRegular True (BS.pack [42]))]),
                  ("lib", NAR.NarSymlink "../lib64")
                ]
            serialised = NAR.serialise entry
         in assertRight "roundtrip nested" entry (NAR.deserialise serialised),
      test "directory entries sorted" $
        let entry =
              NAR.NarDirectory
                [ ("zebra", NAR.NarRegular False BS.empty),
                  ("alpha", NAR.NarRegular False BS.empty)
                ]
            serialised = NAR.serialise entry
         in case NAR.deserialise serialised of
              Left err -> do
                putStrLn ("  deserialise failed: " ++ err)
                pure False
              Right (NAR.NarDirectory entries) ->
                assertEqual "sorted" ["alpha", "zebra"] (map fst entries)
              Right other -> do
                putStrLn ("  expected directory, got: " ++ show other)
                pure False,
      test "narHash deterministic" $
        let entry = NAR.NarRegular False (BS.pack [1, 2, 3])
            h1 = NAR.narHash entry
            h2 = NAR.narHash entry
         in assertEqual "deterministic hash" h1 h2,
      test "narHash differs for different content" $
        let h1 = NAR.narHash (NAR.NarRegular False (BS.pack [1]))
            h2 = NAR.narHash (NAR.NarRegular False (BS.pack [2]))
         in assertTrue "different hashes" (h1 /= h2),
      test "deserialise garbage fails" $
        assertLeft "garbage" (NAR.deserialise (BS.pack [0, 0, 0, 0, 0, 0, 0, 0])),
      test "roundtrip edge: empty directory" $
        let entry = NAR.NarDirectory []
         in assertRight "empty dir" entry (NAR.deserialise (NAR.serialise entry)),
      test "roundtrip edge: contents a multiple of 8 (zero padding)" $
        let entry = NAR.NarRegular False (BS.replicate 8 0x41)
         in assertRight "8-byte contents" entry (NAR.deserialise (NAR.serialise entry)),
      test "roundtrip edge: executable empty file" $
        let entry = NAR.NarRegular True BS.empty
         in assertRight "exec empty" entry (NAR.deserialise (NAR.serialise entry)),
      -- Cache-served archives are untrusted input: every name that could
      -- traverse out of an extraction root must fail the parse.
      test "unsafe directory entry names rejected" $
        let evil name = NAR.serialise (NAR.NarDirectory [(name, NAR.NarRegular False "x")])
            names = ["..", ".", "", "a/b", "a\\b", "a\0b"]
            rejected bytes = either (const True) (const False) (NAR.deserialise bytes)
         in assertTrue "all unsafe names rejected" (all (rejected . evil) names),
      test "duplicate directory entries rejected" $
        let dup =
              NAR.serialise
                ( NAR.NarDirectory
                    [ ("same", NAR.NarRegular False "1"),
                      ("same", NAR.NarRegular False "2")
                    ]
                )
         in assertLeft "duplicate entries" (NAR.deserialise dup),
      test "out-of-order directory entries rejected" $
        assertLeft "unsorted entries" (NAR.deserialise outOfOrderDirNar),
      test "trailing bytes after the root node rejected" $
        let valid = NAR.serialise (NAR.NarRegular False "x")
         in assertLeft "trailing bytes" (NAR.deserialise (valid <> "junk1234")),
      test "nonzero string padding rejected" $
        assertLeft "nonzero padding" (NAR.deserialise badPaddingNar),
      -- The format fixes the executable marker's value as empty; upstream
      -- rejects a nonempty value, and NAR.serialise cannot produce one.
      test "nonempty executable marker rejected" $
        let marked =
              BS.concat
                ( map
                    (narWireStr 0)
                    ["nix-archive-1", "(", "type", "regular", "executable", "X", "contents", "hi", ")"]
                )
         in assertLeft "nonempty marker" (NAR.deserialise marked),
      -- Windows resolves these names to something other than a file of
      -- this spelling (drive/stream colon, device, NTFS dot/space strip).
      test "Windows-hazard entry names rejected" $
        let evil name = NAR.serialise (NAR.NarDirectory [(name, NAR.NarRegular False "x")])
            -- The last three: COM0/LPT0 are reserved alongside COM1-9,
            -- the device stem is compared with trailing spaces trimmed
            -- ("NUL .txt" still opens the device), and the superscript
            -- digits (here U+00B9 as UTF-8) count as device digits.
            names =
              [ "C:evil",
                "a:b",
                "nul",
                "NUL",
                "com1",
                "nul.txt",
                "foo.",
                "foo ",
                "com0",
                "lpt0",
                "nul .txt",
                "CON .x",
                "com" <> BS.pack [0xC2, 0xB9]
              ]
            rejected bytes = either (const True) (const False) (NAR.deserialise bytes)
         in assertTrue "all hazard names rejected" (all (rejected . evil) names),
      test "near-miss names still parse" $
        let plain name = NAR.serialise (NAR.NarDirectory [(name, NAR.NarRegular False "x")])
            -- "com" followed by a non-digit non-superscript byte (here
            -- U+00B4, acute accent) is an ordinary name; so are stems
            -- one character too long.
            names = ["nul2", "com10", "conx", "foo.bar", "a.b.c", "lpt00", "com" <> BS.pack [0xC2, 0xB4]]
            accepted bytes = either (const False) (const True) (NAR.deserialise bytes)
         in assertTrue "all near-miss names accepted" (all (accepted . plain) names),
      -- Upstream carries names and targets as raw bytes: entries that
      -- do not decode as UTF-8 parse and round-trip.
      test "non-UTF-8 entry name round-trips" $
        let entry = NAR.NarDirectory [(BS.pack [0x66, 0xFF], NAR.NarRegular False "x")]
         in assertRight "raw-byte name" entry (NAR.deserialise (NAR.serialise entry)),
      test "non-UTF-8 symlink target round-trips" $
        let entry = NAR.NarSymlink (BS.pack [0x2F, 0x74, 0x6D, 0x70, 0x2F, 0xFF])
         in assertRight "raw-byte target" entry (NAR.deserialise (NAR.serialise entry)),
      test "entries sort bytewise, non-UTF-8 names included" $
        let entry =
              NAR.NarDirectory
                [ (BS.pack [0xFF], NAR.NarRegular False "hi"),
                  ("b", NAR.NarRegular False "lo")
                ]
         in case NAR.deserialise (NAR.serialise entry) of
              Left err -> do
                putStrLn ("  deserialise failed: " ++ err)
                pure False
              Right (NAR.NarDirectory entries) ->
                assertEqual "byte order" ["b", BS.pack [0xFF]] (map fst entries)
              Right other -> do
                putStrLn ("  expected directory, got: " ++ show other)
                pure False,
      -- The hazard checks are ASCII-structural, so they fire inside
      -- names that do not decode as text.
      test "hazards inside non-UTF-8 names still rejected" $
        let evil name = NAR.serialise (NAR.NarDirectory [(name, NAR.NarRegular False "x")])
            names = ["nul." <> BS.pack [0xFF], BS.pack [0xFF, 0x2E], BS.pack [0xFF] <> ":x"]
            rejected bytes = either (const True) (const False) (NAR.deserialise bytes)
         in assertTrue "all hazard bytes rejected" (all (rejected . evil) names),
      -- The case-hack strip: a tree materialized with upstream's
      -- collision suffix serialises back under its NAR names.
      test "serialiseFromPathWith strips the case-hack suffix" $ do
        dir <- caseHackFixture "nova-cache-test-casehack"
        BS.writeFile (dir <> "/Foo") "upper"
        BS.writeFile (dir <> "/foo~nix~case~hack~1") "lower"
        entry <- NAR.serialiseFromPathWith NAR.CaseHackEnabled dir
        removeDirectoryRecursive dir
        let expected =
              NAR.NarDirectory
                [ ("Foo", NAR.NarRegular False "upper"),
                  ("foo", NAR.NarRegular False "lower")
                ]
        roundTrip <- assertRight "stripped tree reparses" expected (NAR.deserialise (NAR.serialise entry))
        pure (entry == expected && roundTrip),
      test "serialiseFromPathWith keeps the suffix verbatim when disabled" $ do
        dir <- caseHackFixture "nova-cache-test-casehack-off"
        BS.writeFile (dir <> "/foo~nix~case~hack~1") "kept"
        entry <- NAR.serialiseFromPathWith NAR.CaseHackDisabled dir
        removeDirectoryRecursive dir
        assertEqual
          "verbatim name"
          (NAR.NarDirectory [("foo~nix~case~hack~1", NAR.NarRegular False "kept")])
          entry,
      test "serialiseFromPathWith fails loudly on an unhack collision" $ do
        dir <- caseHackFixture "nova-cache-test-casehack-clash"
        BS.writeFile (dir <> "/foo") "plain"
        BS.writeFile (dir <> "/foo~nix~case~hack~1") "hacked"
        outcome <- try (NAR.serialiseFromPathWith NAR.CaseHackEnabled dir)
        removeDirectoryRecursive dir
        pure $ case (outcome :: Either SomeException NAR.NarEntry) of
          Left _ -> True
          Right _ -> False,
      -- The walk's boundary encoding: a Unicode disk name enters the
      -- archive as its UTF-8 bytes on every platform.
      test "serialiseFromPath encodes a Unicode disk name as UTF-8" $ do
        dir <- caseHackFixture "nova-cache-test-uniname"
        BS.writeFile (dir <> "/caf\233") "au lait"
        entry <- NAR.serialiseFromPathWith NAR.CaseHackDisabled dir
        removeDirectoryRecursive dir
        assertEqual
          "utf8 name"
          (NAR.NarDirectory [(BS.pack [0x63, 0x61, 0x66, 0xC3, 0xA9], NAR.NarRegular False "au lait")])
          entry,
      -- POSIX names are bytes; one that is not valid UTF-8 must archive
      -- verbatim (it used to be silently rewritten with replacement
      -- characters).  Linux-gated: NTFS and APFS names are Unicode, so
      -- the fixture cannot exist there.  "\56575" is the lone surrogate
      -- GHC's filesystem encoding round-trips to byte 0xFF.
      test "serialiseFromPath carries a non-UTF-8 disk name verbatim" $
        if System.Info.os /= "linux"
          then pure True
          else do
            dir <- caseHackFixture "nova-cache-test-rawname"
            BS.writeFile (dir <> "/f\56575") "raw"
            entry <- NAR.serialiseFromPathWith NAR.CaseHackDisabled dir
            removeDirectoryRecursive dir
            assertEqual
              "raw byte name"
              (NAR.NarDirectory [(BS.pack [0x66, 0xFF], NAR.NarRegular False "raw")])
              entry
    ]

-- | A fresh, empty fixture directory under the system temp dir.
caseHackFixture :: String -> IO FilePath
caseHackFixture name = do
  tmpBase <- getTemporaryDirectory
  let dir = tmpBase <> "/" <> name
  _ <- try (removeDirectoryRecursive dir) :: IO (Either SomeException ())
  createDirectory dir
  pure dir

-- | Encode one NAR wire string with a chosen padding byte.  The spec
-- demands zero padding, so a nonzero byte builds archives the parser
-- must reject - and 'NAR.serialise' (rightly) cannot produce them.
narWireStr :: Word8 -> ByteString -> ByteString
narWireStr padByte str = lenLE <> str <> BS.replicate padLen padByte
  where
    n = BS.length str
    lenLE = BS.pack [fromIntegral ((n `shiftR` (8 * i)) .&. 0xff) | i <- [0 .. 7]]
    padLen = (8 - n `mod` 8) `mod` 8

-- | A directory NAR whose entries arrive out of sorted order - again not
-- producible via 'NAR.serialise', which sorts on write.
outOfOrderDirNar :: ByteString
outOfOrderDirNar =
  BS.concat
    ( map
        (narWireStr 0)
        ( ["nix-archive-1", "(", "type", "directory"]
            ++ entryFor "b"
            ++ entryFor "a"
            ++ [")"]
        )
    )
  where
    entryFor name = ["entry", "(", "name", name, "node", "(", "type", "regular", "contents", "", ")", ")"]

-- | A regular-file NAR whose contents padding is nonzero.
badPaddingNar :: ByteString
badPaddingNar =
  BS.concat
    [ BS.concat (map (narWireStr 0) ["nix-archive-1", "(", "type", "regular", "contents"]),
      narWireStr 1 "abc",
      narWireStr 0 ")"
    ]

-- ---------------------------------------------------------------------------
-- NAR.Stream tests
-- ---------------------------------------------------------------------------

-- | Drive the streaming parser over the given chunks (all non-empty),
-- then signal end of input, collecting events.
runStream :: [ByteString] -> Either String [Stream.NarEvent]
runStream chunks = go Stream.narStream chunks []
  where
    go step pending acc = case step of
      Stream.NarFail err -> Left err
      Stream.NarDone -> Right (reverse acc)
      Stream.NarYield event continue -> go continue pending (event : acc)
      Stream.NarAwait continue -> case pending of
        [] -> go (continue BS.empty) [] acc
        (chunk : rest) -> go (continue chunk) rest acc

-- | Entry shapes the chunking-independence test sweeps: every node
-- kind, empty and aligned contents, nesting, and a non-UTF-8 name.
streamCorpus :: [NAR.NarEntry]
streamCorpus =
  [ NAR.NarRegular False "hello",
    NAR.NarRegular True BS.empty,
    NAR.NarRegular False (BS.replicate 8 0x41),
    NAR.NarSymlink "/usr/bin/hello",
    NAR.NarDirectory [],
    NAR.NarDirectory
      [ ("bin", NAR.NarDirectory [("hello", NAR.NarRegular True (BS.pack [42]))]),
        ("lib", NAR.NarSymlink "../lib64"),
        (BS.pack [0x66, 0xFF], NAR.NarRegular False "raw")
      ]
  ]

-- | Merge consecutive contents slices.  Slice granularity deliberately
-- follows the fed chunks, so parses of different chunkings compare by
-- structure and content, not by how the input happened to arrive.
coalesceChunks :: [Stream.NarEvent] -> [Stream.NarEvent]
coalesceChunks (Stream.EventRegularChunk a : Stream.EventRegularChunk b : rest) =
  coalesceChunks (Stream.EventRegularChunk (a <> b) : rest)
coalesceChunks (event : rest) = event : coalesceChunks rest
coalesceChunks [] = []

-- | Split a byte string into fixed-size pieces.
chunksOf :: Int -> ByteString -> [ByteString]
chunksOf n bs
  | BS.null bs = []
  | otherwise = case BS.splitAt n bs of
      (piece, rest) -> piece : chunksOf n rest

-- | Pull a source dry, collecting its chunks (the terminating empty
-- chunk excluded).
collectChunks :: IO ByteString -> IO [ByteString]
collectChunks pull = go []
  where
    go acc = do
      chunk <- pull
      if BS.null chunk then pure (reverse acc) else go (chunk : acc)

-- | Pull a source dry into one byte string.
drainSource :: IO ByteString -> IO ByteString
drainSource pull = BS.concat <$> collectChunks pull

-- | Hash a source chunk by chunk as it is pulled.
hashPull :: Hash.HashContext -> IO ByteString -> IO Hash.NixHash
hashPull ctx pull = do
  chunk <- pull
  if BS.null chunk
    then pure (Hash.hashFinalize ctx)
    else hashPull (Hash.hashUpdate ctx chunk) pull

testStream :: IO Bool
testStream =
  runGroup
    "NAR.Stream"
    [ test "events for a regular file" $
        assertEqual
          "event sequence"
          ( Right
              [ Stream.EventRegularBegin True 2,
                Stream.EventRegularChunk "hi",
                Stream.EventRegularEnd
              ]
          )
          (runStream [NAR.serialise (NAR.NarRegular True "hi")]),
      test "events for a directory arrive entry by entry" $
        let entry = NAR.NarDirectory [("a", NAR.NarSymlink "t"), ("b", NAR.NarRegular False "")]
            expected =
              [ Stream.EventDirectoryBegin,
                Stream.EventEntryBegin "a",
                Stream.EventSymlink "t",
                Stream.EventEntryEnd,
                Stream.EventEntryBegin "b",
                Stream.EventRegularBegin False 0,
                Stream.EventRegularEnd,
                Stream.EventEntryEnd,
                Stream.EventDirectoryEnd
              ]
         in assertEqual "event sequence" (Right expected) (runStream [NAR.serialise entry]),
      test "byte-at-a-time chunking equals whole-input parsing" $
        let normalize = fmap coalesceChunks
            agrees entry =
              let bytes = NAR.serialise entry
               in normalize (runStream [bytes]) == normalize (runStream (map BS.singleton (BS.unpack bytes)))
         in assertTrue "chunking-independent" (all agrees streamCorpus),
      test "contents slices reassemble across misaligned chunks" $
        -- 7-byte chunks sit deliberately askew of the 8-byte wire
        -- alignment, so every length prefix and padding run straddles
        -- a chunk boundary somewhere.
        let payload = BS.pack (concat (replicate 40 [0 .. 7]))
            bytes = NAR.serialise (NAR.NarRegular False payload)
         in case runStream (chunksOf 7 bytes) of
              Left err -> do
                putStrLn ("  streaming parse failed: " ++ err)
                pure False
              Right events ->
                assertEqual
                  "reassembled contents"
                  payload
                  (BS.concat [c | Stream.EventRegularChunk c <- events]),
      test "streaming agrees with deserialise on the malformed corpus" $
        let evil name = NAR.serialise (NAR.NarDirectory [(name, NAR.NarRegular False "x")])
            malformed =
              [ outOfOrderDirNar,
                badPaddingNar,
                NAR.serialise (NAR.NarRegular False "x") <> "junk1234",
                evil "..",
                evil "a/b",
                evil "nul"
              ]
            bothReject bytes = isLeft (runStream [bytes]) && isLeft (NAR.deserialise bytes)
         in assertTrue "all rejected by both parsers" (all bothReject malformed),
      test "the structural bound applies to streaming, not deserialise" $
        -- deserialise instantiates the machine with its input's length
        -- as the bound, so a name this size stays accepted there; the
        -- streaming default caps structural strings at 64 KiB.
        let longName = BS.replicate 70000 0x61
            bytes = NAR.serialise (NAR.NarDirectory [(longName, NAR.NarRegular False "x")])
         in do
              ok1 <- assertTrue "deserialise accepts" (either (const False) (const True) (NAR.deserialise bytes))
              ok2 <- assertTrue "streaming rejects" (isLeft (runStream [bytes]))
              pure (ok1 && ok2),
      test "a truncated archive fails" $
        let bytes = NAR.serialise (NAR.NarRegular False "some contents here")
         in assertLeft "eof" (runStream [BS.take (BS.length bytes - 9) bytes]),
      test "the declared contents size arrives before the bytes" $
        case runStream [NAR.serialise (NAR.NarRegular False (BS.replicate 24 0x2A))] of
          Right (Stream.EventRegularBegin False declared : _) ->
            assertEqual "declared size" 24 declared
          other -> do
            putStrLn ("    expected EventRegularBegin first, got: " ++ show other)
            pure False,
      test "withNarSource streams byte-identically to serialise" $ do
        dir <- caseHackFixture "nova-cache-test-narsource"
        createDirectory (dir <> "/sub")
        -- Larger than two pull chunks, so mid-file continuation runs.
        BS.writeFile (dir <> "/big.bin") (BS.replicate 300000 0x41)
        BS.writeFile (dir <> "/sub/small") "tiny"
        BS.writeFile (dir <> "/zero") ""
        entry <- NAR.serialiseFromPathWith NAR.CaseHackDisabled dir
        streamed <- NAR.withNarSource NAR.CaseHackDisabled dir drainSource
        removeDirectoryRecursive dir
        assertTrue "bytes equal" (NAR.serialise entry == streamed),
      test "withNarSource under the case-hack matches the strict walk" $ do
        dir <- caseHackFixture "nova-cache-test-narsource-hack"
        BS.writeFile (dir <> "/Foo") "upper"
        BS.writeFile (dir <> "/foo~nix~case~hack~1") "lower"
        entry <- NAR.serialiseFromPathWith NAR.CaseHackEnabled dir
        streamed <- NAR.withNarSource NAR.CaseHackEnabled dir drainSource
        removeDirectoryRecursive dir
        assertTrue "bytes equal" (NAR.serialise entry == streamed),
      test "withNarSource keeps returning empty after the end" $ do
        dir <- caseHackFixture "nova-cache-test-narsource-end"
        BS.writeFile (dir <> "/f") "x"
        ends <- NAR.withNarSource NAR.CaseHackDisabled dir $ \pull -> do
          _ <- collectChunks pull
          endA <- pull
          endB <- pull
          pure (endA, endB)
        removeDirectoryRecursive dir
        assertEqual "stable end" ("", "") ends,
      test "pulled chunks parse back to the walked tree" $ do
        dir <- caseHackFixture "nova-cache-test-narsource-loop"
        BS.writeFile (dir <> "/data.bin") (BS.replicate 200000 0x5A)
        entry <- NAR.serialiseFromPathWith NAR.CaseHackDisabled dir
        chunks <- NAR.withNarSource NAR.CaseHackDisabled dir collectChunks
        removeDirectoryRecursive dir
        ok1 <- assertRight "strict parse of the stream" entry (NAR.deserialise (BS.concat chunks))
        ok2 <- assertTrue "streaming parse of the chunk list" (either (const False) (const True) (runStream chunks))
        pure (ok1 && ok2),
      test "incremental hashing equals whole-input hashing" $
        let payload = BS.pack [0 .. 255]
            pieces = [BS.take 100 payload, BS.take 55 (BS.drop 100 payload), BS.drop 155 payload]
            incremental = Hash.hashFinalize (foldl' Hash.hashUpdate Hash.hashInit pieces)
         in do
              ok1 <- assertEqual "split arbitrarily" (Hash.hashBytes payload) incremental
              ok2 <- assertEqual "empty input" (Hash.hashBytes BS.empty) (Hash.hashFinalize Hash.hashInit)
              pure (ok1 && ok2),
      test "hashing a pulled source equals narHash of the walk" $ do
        dir <- caseHackFixture "nova-cache-test-streamhash"
        BS.writeFile (dir <> "/blob") (BS.replicate 150000 0x07)
        entry <- NAR.serialiseFromPathWith NAR.CaseHackDisabled dir
        digest <- NAR.withNarSource NAR.CaseHackDisabled dir (hashPull Hash.hashInit)
        removeDirectoryRecursive dir
        assertEqual "hash matches" (NAR.narHash entry) digest
    ]

-- ---------------------------------------------------------------------------
-- NarInfo tests
-- ---------------------------------------------------------------------------

sampleNarInfoText :: Text
sampleNarInfoText =
  T.unlines
    [ "StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello-1.0",
      "URL: nar/1234abcd.nar.xz",
      "Compression: xz",
      "FileHash: sha256:abcdef1234567890",
      "FileSize: 12345",
      "NarHash: sha256:fedcba0987654321",
      "NarSize: 67890",
      "References: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello-1.0 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-glibc-2.38",
      "Deriver: cccccccccccccccccccccccccccccccc-hello-1.0.drv",
      "Sig: cache.example.com:c2lnbmF0dXJl",
      "Sig: backup.example.com:YW5vdGhlcnNpZw=="
    ]

testNarInfo :: IO Bool
testNarInfo =
  runGroup
    "NarInfo"
    [ test "parse sample narinfo" $
        case NarInfo.parseNarInfo sampleNarInfoText of
          Left err -> do
            putStrLn ("  parse failed: " ++ err)
            pure False
          Right ni -> do
            ok1 <- assertEqual "storePath" "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello-1.0" (NarInfo.niStorePath ni)
            ok2 <- assertEqual "url" "nar/1234abcd.nar.xz" (NarInfo.niUrl ni)
            ok3 <- assertEqual "compression" "xz" (NarInfo.niCompression ni)
            ok4 <- assertEqual "fileSize" (Just 12345) (NarInfo.niFileSize ni)
            ok5 <- assertEqual "narSize" 67890 (NarInfo.niNarSize ni)
            ok6 <- assertEqual "refs count" 2 (length (NarInfo.niReferences ni))
            ok7 <- assertEqual "deriver" (Just "cccccccccccccccccccccccccccccccc-hello-1.0.drv") (NarInfo.niDeriver ni)
            ok8 <- assertEqual "sigs count" 2 (length (NarInfo.niSigs ni))
            pure (ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7 && ok8),
      test "parse/render roundtrip" $
        case NarInfo.parseNarInfo sampleNarInfoText of
          Left err -> do
            putStrLn ("  parse failed: " ++ err)
            pure False
          Right ni ->
            let rendered = NarInfo.renderNarInfo ni
             in case NarInfo.parseNarInfo rendered of
                  Left err -> do
                    putStrLn ("  re-parse failed: " ++ err)
                    pure False
                  Right reparsed ->
                    assertEqual "roundtrip" ni reparsed,
      test "parse minimal narinfo (no optional fields)" $
        let minimal =
              T.unlines
                [ "StorePath: /nix/store/aaaa-test",
                  "URL: nar/test.nar.xz",
                  "Compression: xz",
                  "FileHash: sha256:abc",
                  "FileSize: 100",
                  "NarHash: sha256:def",
                  "NarSize: 200",
                  "References: "
                ]
         in case NarInfo.parseNarInfo minimal of
              Left err -> do
                putStrLn ("  parse failed: " ++ err)
                pure False
              Right ni -> do
                ok1 <- assertEqual "deriver" Nothing (NarInfo.niDeriver ni)
                ok2 <- assertEqual "sigs" [] (NarInfo.niSigs ni)
                ok3 <- assertEqual "ca" Nothing (NarInfo.niCA ni)
                ok4 <- assertEqual "refs" [] (NarInfo.niReferences ni)
                pure (ok1 && ok2 && ok3 && ok4),
      test "CRLF-terminated narinfo parses identically" $
        assertEqual
          "crlf tolerated"
          (NarInfo.parseNarInfo sampleNarInfoText)
          (NarInfo.parseNarInfo (T.replace "\n" "\r\n" sampleNarInfoText)),
      test "upstream-optional fields default as upstream" $
        -- Only StorePath, URL, NarHash, NarSize are mandatory upstream;
        -- Compression defaults to bzip2 and FileHash/FileSize stay absent.
        let bare =
              T.unlines
                [ "StorePath: /nix/store/aaaa-test",
                  "URL: nar/test.nar.xz",
                  "NarHash: sha256:def",
                  "NarSize: 200"
                ]
         in case NarInfo.parseNarInfo bare of
              Left err -> do
                putStrLn ("  parse failed: " ++ err)
                pure False
              Right ni -> do
                ok1 <- assertEqual "compression default" "bzip2" (NarInfo.niCompression ni)
                ok2 <- assertEqual "fileHash absent" Nothing (NarInfo.niFileHash ni)
                ok3 <- assertEqual "fileSize absent" Nothing (NarInfo.niFileSize ni)
                pure (ok1 && ok2 && ok3),
      test "CA field parse/render roundtrip" $
        let withCA = sampleNarInfoText <> "CA: fixed:r:sha256:0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73\n"
         in case NarInfo.parseNarInfo withCA of
              Left err -> do
                putStrLn ("  parse failed: " ++ err)
                pure False
              Right ni -> do
                ok1 <-
                  assertEqual
                    "ca parsed"
                    (Just "fixed:r:sha256:0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73")
                    (NarInfo.niCA ni)
                ok2 <- assertRight "ca survives render" ni (NarInfo.parseNarInfo (NarInfo.renderNarInfo ni))
                pure (ok1 && ok2),
      test "parse missing required key fails" $
        let incomplete = T.unlines ["StorePath: /nix/store/aaaa-test", "URL: nar/test.nar.xz"]
         in assertLeft "missing key" (NarInfo.parseNarInfo incomplete),
      test "parse bad integer fails" $
        let bad =
              T.unlines
                [ "StorePath: /nix/store/aaaa-test",
                  "URL: nar/test.nar.xz",
                  "Compression: xz",
                  "FileHash: sha256:abc",
                  "FileSize: not-a-number",
                  "NarHash: sha256:def",
                  "NarSize: 200",
                  "References: "
                ]
         in assertLeft "bad integer" (NarInfo.parseNarInfo bad),
      -- Sizes are uint64 on the wire: at most 20 digits.  A longer field
      -- rejects before the quadratic bignum accumulation.
      test "parse rejects an overlong size field" $
        let long =
              T.unlines
                [ "StorePath: /nix/store/aaaa-test",
                  "URL: nar/test.nar.xz",
                  "NarHash: sha256:def",
                  "NarSize: 123456789012345678901"
                ]
         in assertLeft "overlong size" (NarInfo.parseNarInfo long),
      test "a 20-digit size field still parses" $
        let capped =
              T.unlines
                [ "StorePath: /nix/store/aaaa-test",
                  "URL: nar/test.nar.xz",
                  "NarHash: sha256:def",
                  "NarSize: 18446744073709551615"
                ]
         in case NarInfo.parseNarInfo capped of
              Left err -> do
                putStrLn ("  parse failed: " ++ err)
                pure False
              Right ni -> assertEqual "uint64 max" 18446744073709551615 (NarInfo.niNarSize ni),
      -- Twenty digits still fit values past 2^64 - 1; upstream's
      -- string2Int<uint64_t> refuses them, so signing one here would
      -- produce a narinfo every real client rejects as corrupt.
      test "a 20-digit size above the uint64 maximum rejects" $
        let overCap =
              T.unlines
                [ "StorePath: /nix/store/aaaa-test",
                  "URL: nar/test.nar.xz",
                  "NarHash: sha256:def",
                  "NarSize: 18446744073709551616"
                ]
         in assertLeft "size above uint64" (NarInfo.parseNarInfo overCap),
      -- Upstream assigns fields as it reads, so a duplicated scalar key
      -- resolves to the LAST value (Sig stays the repeatable exception).
      test "duplicate scalar keys resolve last-wins" $
        let dup =
              T.unlines
                [ "StorePath: /nix/store/aaaa-test",
                  "URL: nar/first.nar",
                  "URL: nar/last.nar",
                  "Compression: xz",
                  "Compression: zstd",
                  "NarHash: sha256:def",
                  "NarSize: 200"
                ]
         in case NarInfo.parseNarInfo dup of
              Left err -> do
                putStrLn ("  parse failed: " ++ err)
                pure False
              Right ni -> do
                ok1 <- assertEqual "url last" "nar/last.nar" (NarInfo.niUrl ni)
                ok2 <- assertEqual "compression last" "zstd" (NarInfo.niCompression ni)
                pure (ok1 && ok2)
    ]

-- ---------------------------------------------------------------------------
-- Signing tests
-- ---------------------------------------------------------------------------

testSigning :: IO Bool
testSigning =
  runGroup
    "Signing"
    [ test "fingerprint format" $
        let ni = mkTestNarInfo
            fp = Signing.fingerprint ni
         in do
              ok1 <- assertTrue "starts with 1;" (T.isPrefixOf "1;" fp)
              ok2 <- assertTrue "contains storePath" (T.isInfixOf "/nix/store/" fp)
              pure (ok1 && ok2),
      test "fingerprint renders references as full store paths" $
        let ni = mkTestNarInfo {NarInfo.niReferences = ["00000000000000000000000000000000-glibc-2.40"]}
            fp = Signing.fingerprint ni
         in assertTrue
              "reference is a full /nix/store path in the fingerprint"
              (T.isInfixOf "/nix/store/00000000000000000000000000000000-glibc-2.40" fp),
      test "fingerprint sorts and dedupes references" $
        let ni =
              mkTestNarInfo
                { NarInfo.niReferences =
                    [ "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-zlib-1.3",
                      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-glibc-2.40",
                      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-zlib-1.3"
                    ]
                }
            fp = Signing.fingerprint ni
         in assertTrue
              "references sorted by basename and deduplicated (C++ Nix parity)"
              -- The leading field separator pins the WHOLE references
              -- field: without it, the pre-fix "zlib,glibc,zlib"
              -- rendering also ends in "...glibc...,...zlib..." and the
              -- assertion cannot fail on a regression to unsorted output.
              ( T.isSuffixOf
                  ";/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-glibc-2.40,/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-zlib-1.3"
                  fp
              ),
      test "SecretKey Show redacts the key bytes" $
        let sk = Signing.SecretKey {Signing.skName = "test-key", Signing.skBytes = BS.pack ([1 .. 32] ++ [33 .. 64])}
         in assertEqual "redacted" "SecretKey \"test-key\" <redacted>" (show sk),
      test "SecretKey equality compares name and bytes" $
        let bytesA = BS.pack ([1 .. 32] ++ [33 .. 64])
            skA = Signing.SecretKey "k" bytesA
            skB = Signing.SecretKey "k" bytesA
            skC = Signing.SecretKey "k" (BS.pack (0 : [2 .. 64]))
         in do
              ok1 <- assertTrue "equal keys" (skA == skB)
              ok2 <- assertTrue "different bytes differ" (skA /= skC)
              pure (ok1 && ok2),
      test "parseSecretKey valid" $
        let keyBytes = BS.pack ([1 .. 32] ++ [33 .. 64])
            keyB64 = TE.decodeUtf8 (B64.encode keyBytes)
            keyStr = "test-key:" <> keyB64
         in case Signing.parseSecretKey keyStr of
              Left err -> do
                putStrLn ("  parse failed: " ++ err)
                pure False
              Right sk ->
                assertEqual "key name" "test-key" (Signing.skName sk),
      test "parsePublicKey valid" $
        let keyBytes = BS.pack [1 .. 32]
            keyB64 = TE.decodeUtf8 (B64.encode keyBytes)
            keyStr = "test-key:" <> keyB64
         in case Signing.parsePublicKey keyStr of
              Left err -> do
                putStrLn ("  parse failed: " ++ err)
                pure False
              Right pk ->
                assertEqual "key name" "test-key" (Signing.pkName pk),
      test "parseSecretKey no colon fails" $
        assertLeft "no colon" (Signing.parseSecretKey "nokeyname"),
      test "empty key name rejected" $
        -- An empty-named key would emit :sig lines no named trust anchor
        -- matches; the misconfiguration must fail at load time.
        let material = TE.decodeUtf8 (B64.encode (BS.pack [1 .. 64]))
         in assertLeft "empty name" (Signing.parseSecretKey (":" <> material)),
      test "empty key material rejected" $
        assertLeft "empty material" (Signing.parsePublicKey "test-key:"),
      test "signature from a different keypair rejected" $ do
        signingKey <- generateTestSecretKey
        otherKey <- generateTestSecretKey
        let verifier = deriveTestPublicKey otherKey
        case Signing.sign signingKey mkTestNarInfo of
          Left err -> do
            putStrLn ("  sign failed: " ++ err)
            pure False
          Right signed ->
            assertTrue "cross-key rejected" (not (Signing.verify verifier mkTestNarInfo signed)),
      test "valid signature under a renamed trust anchor rejected" $ do
        signingKey <- generateTestSecretKey
        let renamed = (deriveTestPublicKey signingKey) {Signing.pkName = "some-other-cache"}
        case Signing.sign signingKey mkTestNarInfo of
          Left err -> do
            putStrLn ("  sign failed: " ++ err)
            pure False
          Right signed ->
            assertTrue "name mismatch rejected" (not (Signing.verify renamed mkTestNarInfo signed)),
      test "malformed signature lines rejected" $ do
        signingKey <- generateTestSecretKey
        let verifier = deriveTestPublicKey signingKey
            wrongSize = "test-key:" <> TE.decodeUtf8 (B64.encode (BS.pack [1 .. 16]))
            badLines = ["test-key:!!!not-base64!!!", wrongSize, "test-key:", "no-colon-at-all"]
        assertTrue
          "all malformed rejected"
          (not (any (Signing.verify verifier mkTestNarInfo) badLines)),
      test "parsePublicKey wrong size fails" $
        let keyStr = "test-key:" <> TE.decodeUtf8 (B64.encode (BS.pack [1 .. 16]))
         in assertLeft "wrong size" (Signing.parsePublicKey keyStr),
      test "sign/verify roundtrip" $ do
        sk <- generateTestSecretKey
        let pk = deriveTestPublicKey sk
            ni = mkTestNarInfo
        case Signing.sign sk ni of
          Left err -> do
            putStrLn ("  sign failed: " ++ err)
            pure False
          Right sig ->
            assertTrue "verify passes" (Signing.verify pk ni sig),
      test "verify rejects tampered narinfo" $ do
        sk <- generateTestSecretKey
        let pk = deriveTestPublicKey sk
            ni = mkTestNarInfo
        case Signing.sign sk ni of
          Left err -> do
            putStrLn ("  sign failed: " ++ err)
            pure False
          Right sig ->
            let tampered = ni {NarInfo.niNarSize = 999999}
             in assertFalse "verify rejects tampered" (Signing.verify pk tampered sig),
      test "toPublicKey derives the verifying key" $ do
        sk <- generateTestSecretKey
        case Signing.toPublicKey sk of
          Left err -> do
            putStrLn ("  toPublicKey failed: " ++ err)
            pure False
          Right pk -> do
            okName <- assertEqual "key name carried over" (Signing.skName sk) (Signing.pkName pk)
            okBytes <- assertEqual "matches the stored public half" (BS.drop 32 (Signing.skBytes sk)) (Signing.pkBytes pk)
            case Signing.sign sk mkTestNarInfo of
              Left err -> do
                putStrLn ("  sign failed: " ++ err)
                pure False
              Right sig -> do
                okVerify <- assertTrue "derived key verifies a signature" (Signing.verify pk mkTestNarInfo sig)
                pure (okName && okBytes && okVerify),
      test "renderPublicKey round-trips through parsePublicKey" $ do
        sk <- generateTestSecretKey
        case Signing.toPublicKey sk of
          Left err -> do
            putStrLn ("  toPublicKey failed: " ++ err)
            pure False
          Right pk -> case Signing.parsePublicKey (Signing.renderPublicKey pk) of
            Left err -> do
              putStrLn ("  parse failed: " ++ err)
              pure False
            Right reparsed -> assertEqual "round-trip" pk reparsed,
      test "normalizeKeyText strips BOM and whitespace" $ do
        ok1 <- assertEqual "BOM stripped" "test-key:abc" (Signing.normalizeKeyText ("\xFEFF" <> "test-key:abc"))
        ok2 <- assertEqual "CRLF stripped" "test-key:abc" (Signing.normalizeKeyText "test-key:abc\r\n")
        ok3 <- assertEqual "spaces stripped" "test-key:abc" (Signing.normalizeKeyText "  test-key:abc  ")
        ok4 <- assertEqual "clean text unchanged" "test-key:abc" (Signing.normalizeKeyText "test-key:abc")
        pure (ok1 && ok2 && ok3 && ok4)
    ]

-- | Create a test NarInfo for signing tests.
mkTestNarInfo :: NarInfo.NarInfo
mkTestNarInfo =
  NarInfo.NarInfo
    { NarInfo.niStorePath = "/nix/store/aaaa-hello-1.0",
      NarInfo.niUrl = "nar/test.nar.xz",
      NarInfo.niCompression = "xz",
      NarInfo.niFileHash = Just "sha256:abc",
      NarInfo.niFileSize = Just 100,
      NarInfo.niNarHash = "sha256:def",
      NarInfo.niNarSize = 200,
      NarInfo.niReferences = ["aaaa-hello-1.0"],
      NarInfo.niDeriver = Nothing,
      NarInfo.niSigs = [],
      NarInfo.niCA = Nothing
    }

-- ---------------------------------------------------------------------------
-- FileStore tests
-- ---------------------------------------------------------------------------

testFileStore :: IO Bool
testFileStore =
  runGroup
    "FileStore"
    [ test "narinfo write/read roundtrip" $ do
        tmpDir <- createTestDir
        store <- Store.newFileStore tmpDir
        let hashKey = "testhash123"
            content = TE.encodeUtf8 ("StorePath: /nix/store/test\n" :: Text)
        wOk <- Store.writeNarInfo store hashKey content
        result <- Store.readNarInfo store hashKey
        removeDirectoryRecursive tmpDir
        ok1 <- assertTrue "write succeeded" wOk
        ok2 <- assertEqual "narinfo roundtrip" (Just content) result
        pure (ok1 && ok2),
      test "nar write/read roundtrip" $ do
        tmpDir <- createTestDir
        store <- Store.newFileStore tmpDir
        let fileName = "test.nar.xz"
            content = BS.pack [1, 2, 3, 4, 5]
        wOk <- Store.writeNar store fileName content
        result <- Store.readNar store fileName
        removeDirectoryRecursive tmpDir
        ok1 <- assertTrue "write succeeded" wOk
        ok2 <- assertEqual "nar roundtrip" (Just content) result
        pure (ok1 && ok2),
      test "read nonexistent returns Nothing" $ do
        tmpDir <- createTestDir
        store <- Store.newFileStore tmpDir
        result <- Store.readNarInfo store "nonexistent"
        removeDirectoryRecursive tmpDir
        assertEqual "not found" Nothing result,
      test "cacheInfo defaults" $ do
        tmpDir <- createTestDir
        store <- Store.newFileStore tmpDir
        let info = Store.getCacheInfo store
        removeDirectoryRecursive tmpDir
        ok1 <- assertEqual "storeDir" "/nix/store" (Store.ciStoreDir info)
        ok2 <- assertTrue "wantMassQuery" (Store.ciWantMassQuery info)
        ok3 <- assertEqual "priority" 50 (Store.ciPriority info)
        pure (ok1 && ok2 && ok3),
      test "sanitizePath rejects traversal" $
        assertEqual "dotdot" Nothing (Store.sanitizePath ".."),
      test "sanitizePath rejects slash" $
        assertEqual "slash" Nothing (Store.sanitizePath "../../etc/passwd"),
      test "sanitizePath rejects backslash" $
        assertEqual "backslash" Nothing (Store.sanitizePath "..\\..\\etc\\passwd"),
      test "sanitizePath rejects empty" $
        assertEqual "empty" Nothing (Store.sanitizePath ""),
      test "sanitizePath accepts valid hash" $
        assertEqual "valid" (Just "abc123def456") (Store.sanitizePath "abc123def456"),
      test "sanitizePath rejects windows device name" $
        assertEqual "device nul" Nothing (Store.sanitizePath "nul"),
      test "sanitizePath rejects the zero-numbered devices" $ do
        ok1 <- assertEqual "com0" Nothing (Store.sanitizePath "com0")
        ok2 <- assertEqual "lpt0" Nothing (Store.sanitizePath "lpt0")
        ok3 <- assertEqual "com10 stays valid" (Just "com10") (Store.sanitizePath "com10")
        pure (ok1 && ok2 && ok3),
      test "sanitizePath rejects dotfile" $
        assertEqual "dotfile" Nothing (Store.sanitizePath ".hidden"),
      test "sanitizePath rejects a trailing dot" $
        assertEqual "trailing dot" Nothing (Store.sanitizePath "foo."),
      test "sanitizePath keeps interior dots valid" $
        assertEqual "interior dots" (Just "foo.nar.xz") (Store.sanitizePath "foo.nar.xz"),
      test "read rejects traversal" $ do
        tmpDir <- createTestDir
        store <- Store.newFileStore tmpDir
        result <- Store.readNarInfo store "../../etc/passwd"
        removeDirectoryRecursive tmpDir
        assertEqual "blocked" Nothing result,
      test "writeNarInfo rejects traversal" $ do
        tmpDir <- createTestDir
        store <- Store.newFileStore tmpDir
        ok <- Store.writeNarInfo store "../../etc/passwd" "bad"
        removeDirectoryRecursive tmpDir
        assertFalse "write rejected" ok,
      test "writeNar rejects traversal" $ do
        tmpDir <- createTestDir
        store <- Store.newFileStore tmpDir
        ok <- Store.writeNar store "../escape.nar" "bad"
        removeDirectoryRecursive tmpDir
        assertFalse "write rejected" ok,
      test "listNarInfoHashes returns stored hashes" $ do
        tmpDir <- createTestDir
        store <- Store.newFileStore tmpDir
        _ <- Store.writeNarInfo store "hash1" "content1"
        _ <- Store.writeNarInfo store "hash2" "content2"
        hashes <- Store.listNarInfoHashes store
        removeDirectoryRecursive tmpDir
        let sorted = sort hashes
        assertEqual "listed hashes" ["hash1", "hash2"] sorted,
      test "listNarInfoHashes empty store" $ do
        tmpDir <- createTestDir
        store <- Store.newFileStore tmpDir
        hashes <- Store.listNarInfoHashes store
        removeDirectoryRecursive tmpDir
        assertEqual "empty" [] hashes
    ]

-- ---------------------------------------------------------------------------
-- Validate tests
-- ---------------------------------------------------------------------------

-- | Bytes whose SHA-256 is used as the NarHash in 'mkValidNarInfo'.
validNarBytes :: ByteString
validNarBytes = BS.pack [1, 2, 3, 4, 5]

-- | Bytes whose SHA-256 is used as the FileHash in 'mkValidNarInfo'.
validFileBytes :: ByteString
validFileBytes = BS.pack [10, 20, 30, 40, 50]

-- | A narinfo that passes all field validation.
mkValidNarInfo :: NarInfo.NarInfo
mkValidNarInfo =
  NarInfo.NarInfo
    { NarInfo.niStorePath = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello-1.0",
      NarInfo.niUrl = "nar/test.nar.xz",
      NarInfo.niCompression = "xz",
      NarInfo.niFileHash = Just (Hash.formatNixHash (Hash.hashBytes validFileBytes)),
      NarInfo.niFileSize = Just 5,
      NarInfo.niNarHash = Hash.formatNixHash (Hash.hashBytes validNarBytes),
      NarInfo.niNarSize = 5,
      NarInfo.niReferences = ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello-1.0"],
      NarInfo.niDeriver = Nothing,
      NarInfo.niSigs = [],
      NarInfo.niCA = Nothing
    }

testValidate :: IO Bool
testValidate =
  runGroup
    "Validate"
    [ test "validateNarInfo valid" $
        assertEqual
          "valid narinfo"
          (Right mkValidNarInfo)
          (Validate.validateNarInfo mkValidNarInfo),
      test "validateNarInfo negative FileSize" $
        let ni = mkValidNarInfo {NarInfo.niFileSize = Just (-1)}
         in assertEqual
              "negative filesize"
              (Left [Validate.NegativeFileSize (-1)])
              (Validate.validateNarInfo ni),
      test "validateNarInfo negative NarSize" $
        let ni = mkValidNarInfo {NarInfo.niNarSize = -1}
         in assertEqual
              "negative narsize"
              (Left [Validate.NegativeNarSize (-1)])
              (Validate.validateNarInfo ni),
      test "validateNarInfo derivation StorePath rejected" $
        let drvPath = "/nix/store/abc12345678901234567890123456789-foo.drv"
            ni = mkValidNarInfo {NarInfo.niStorePath = drvPath}
         in case Validate.validateNarInfo ni of
              Left [Validate.DerivationStorePath raw] ->
                assertEqual "raw value" drvPath raw
              other -> do
                putStrLn ("    expected Left [DerivationStorePath ..], got: " ++ show other)
                pure False,
      test "validateNarInfo bad StorePath" $
        let ni = mkValidNarInfo {NarInfo.niStorePath = "not-a-store-path"}
         in case Validate.validateNarInfo ni of
              Left [Validate.InvalidStorePath raw _] ->
                assertEqual "raw value" "not-a-store-path" raw
              other -> do
                putStrLn ("    expected Left [InvalidStorePath ..], got: " ++ show other)
                pure False,
      test "validateNarInfo bad FileHash" $
        let ni = mkValidNarInfo {NarInfo.niFileHash = Just "md5:bogus"}
         in case Validate.validateNarInfo ni of
              Left [Validate.InvalidFileHash raw _] ->
                assertEqual "raw value" "md5:bogus" raw
              other -> do
                putStrLn ("    expected Left [InvalidFileHash ..], got: " ++ show other)
                pure False,
      test "validateNarInfo bad NarHash" $
        let ni = mkValidNarInfo {NarInfo.niNarHash = "md5:bogus"}
         in case Validate.validateNarInfo ni of
              Left [Validate.InvalidNarHash raw _] ->
                assertEqual "raw value" "md5:bogus" raw
              other -> do
                putStrLn ("    expected Left [InvalidNarHash ..], got: " ++ show other)
                pure False,
      test "validateNarInfo bad reference" $
        let ni = mkValidNarInfo {NarInfo.niReferences = ["bad"]}
         in case Validate.validateNarInfo ni of
              Left [Validate.InvalidReference raw _] ->
                assertEqual "raw value" "bad" raw
              other -> do
                putStrLn ("    expected Left [InvalidReference ..], got: " ++ show other)
                pure False,
      test "validateNarInfo multiple errors collected" $
        let ni =
              mkValidNarInfo
                { NarInfo.niFileSize = Just (-1),
                  NarInfo.niNarSize = -1,
                  NarInfo.niStorePath = "bad"
                }
         in case Validate.validateNarInfo ni of
              Left errs -> assertTrue "at least 3 errors" (length errs >= 3)
              Right _ -> do
                putStrLn "    expected Left, got Right"
                pure False,
      test "validateNarHash correct" $
        assertEqual
          "correct nar hash"
          (Right ())
          (Validate.validateNarHash mkValidNarInfo validNarBytes),
      test "validateNarHash wrong" $
        case Validate.validateNarHash mkValidNarInfo (BS.pack [99]) of
          Left (Validate.NarHashMismatch _ _) -> pure True
          other -> do
            putStrLn ("    expected Left NarHashMismatch, got: " ++ show other)
            pure False,
      test "validateFileHash correct" $
        assertEqual
          "correct file hash"
          (Right ())
          (Validate.validateFileHash mkValidNarInfo validFileBytes),
      test "validateFileHash wrong" $
        case Validate.validateFileHash mkValidNarInfo (BS.pack [99]) of
          Left (Validate.FileHashMismatch _ _) -> pure True
          other -> do
            putStrLn ("    expected Left FileHashMismatch, got: " ++ show other)
            pure False,
      test "validateSignature valid" $ do
        sk <- generateTestSecretKey
        let pk = deriveTestPublicKey sk
            ni = mkValidNarInfo
        case Signing.sign sk ni of
          Left err -> do
            putStrLn ("  sign failed: " ++ err)
            pure False
          Right sig ->
            let niSigned = ni {NarInfo.niSigs = [sig]}
             in assertEqual "valid sig" (Right ()) (Validate.validateSignature pk niSigned),
      test "validateSignature invalid" $ do
        sk <- generateTestSecretKey
        let pk = deriveTestPublicKey sk
            bogusSig = "bogus-key:aW52YWxpZA=="
            ni = mkValidNarInfo {NarInfo.niSigs = [bogusSig]}
        assertEqual
          "invalid sig"
          (Left [Validate.SignatureInvalid bogusSig])
          (Validate.validateSignature pk ni),
      test "validateSignature no sigs" $ do
        sk <- generateTestSecretKey
        let pk = deriveTestPublicKey sk
        assertEqual
          "no sigs"
          (Left [Validate.NoSignatures])
          (Validate.validateSignature pk mkValidNarInfo),
      test "validateFull all good" $ do
        sk <- generateTestSecretKey
        let pk = deriveTestPublicKey sk
            ni = mkValidNarInfo
        case Signing.sign sk ni of
          Left err -> do
            putStrLn ("  sign failed: " ++ err)
            pure False
          Right sig ->
            let niSigned = ni {NarInfo.niSigs = [sig]}
             in assertEqual
                  "full valid"
                  (Right ())
                  (Validate.validateFull pk niSigned validNarBytes validFileBytes),
      test "validateFull multiple failures" $ do
        sk <- generateTestSecretKey
        let pk = deriveTestPublicKey sk
            ni = mkValidNarInfo {NarInfo.niFileSize = Just (-1), NarInfo.niNarSize = -1}
        case Validate.validateFull pk ni (BS.pack [99]) (BS.pack [99]) of
          Left errs -> assertTrue "at least 4 errors" (length errs >= 4)
          Right _ -> do
            putStrLn "    expected Left, got Right"
            pure False
    ]

-- ---------------------------------------------------------------------------
-- Server (WAI) tests
-- ---------------------------------------------------------------------------

-- | The write key the authenticated-server tests configure.
serverTestApiKey :: ByteString
serverTestApiKey = "test-api-key"

-- | The Authorization header 'serverTestApiKey' expects.
serverAuthHeader :: HTTP.Header
serverAuthHeader = (HTTP.hAuthorization, "Bearer " <> serverTestApiKey)

-- | Store-path hash of 'validServerNarInfo' (32 nix-base32 zeros).
validNarInfoHashKey :: Text
validNarInfoHashKey = T.replicate 32 "0"

-- | A canonical all-zero sha256 in nix-base32: 52 digits, and the 4
-- spare bits of the 260-bit encoding are zero, so it parses.
zeroNarHash :: Text
zeroNarHash = "sha256:" <> T.replicate 52 "0"

-- | A narinfo that passes 'Validate.validateNarInfo' end to end, keyed
-- under 'validNarInfoHashKey'.
validServerNarInfo :: NarInfo.NarInfo
validServerNarInfo =
  NarInfo.NarInfo
    { NarInfo.niStorePath = "/nix/store/" <> validNarInfoHashKey <> "-hello-1.0",
      NarInfo.niUrl = "nar/test.nar",
      NarInfo.niCompression = "none",
      NarInfo.niFileHash = Nothing,
      NarInfo.niFileSize = Nothing,
      NarInfo.niNarHash = zeroNarHash,
      NarInfo.niNarSize = 200,
      NarInfo.niReferences = [validNarInfoHashKey <> "-hello-1.0"],
      NarInfo.niDeriver = Nothing,
      NarInfo.niSigs = [],
      NarInfo.niCA = Nothing
    }

-- | Rendered wire form of 'validServerNarInfo'.
validServerNarInfoBytes :: BL.ByteString
validServerNarInfoBytes =
  BL.fromStrict (TE.encodeUtf8 (NarInfo.renderNarInfo validServerNarInfo))

-- | Run one test against a fresh server (configurable write key and
-- signing key), removing the store directory afterwards.
withServer :: Maybe ByteString -> Maybe Signing.SecretKey -> (Server.ServerConfig -> IO Bool) -> IO Bool
withServer apiKey sigKey body = do
  tmpDir <- createTestDir
  store <- Store.newFileStore tmpDir
  passed <-
    body
      Server.ServerConfig
        { Server.scStore = store,
          Server.scApiKey = apiKey,
          Server.scSigningKey = sigKey,
          Server.scRootResponse = Server.defaultRootResponse
        }
  removeDirectoryRecursive tmpDir
  pure passed

-- | 'withServer' with write auth armed and no signing - the common case.
withAuthedServer :: (Server.ServerConfig -> IO Bool) -> IO Bool
withAuthedServer = withServer (Just serverTestApiKey) Nothing

-- | Execute a single request against the server.
serverRequest :: Server.ServerConfig -> BS.ByteString -> [Text] -> [HTTP.Header] -> BL.ByteString -> IO WT.SResponse
serverRequest cfg method segments headers body =
  WT.runSession (WT.srequest (WT.SRequest req body)) (Server.cacheApp cfg)
  where
    req =
      defaultRequest
        { requestMethod = method,
          pathInfo = segments,
          requestHeaders = headers
        }

-- | Like 'serverRequest', with a declared Content-Length - for the
-- reject-before-reading limit checks.
serverRequestSized :: Server.ServerConfig -> BS.ByteString -> [Text] -> [HTTP.Header] -> Word -> IO WT.SResponse
serverRequestSized cfg method segments headers declared =
  WT.runSession (WT.srequest (WT.SRequest req "")) (Server.cacheApp cfg)
  where
    req =
      defaultRequest
        { requestMethod = method,
          pathInfo = segments,
          requestHeaders = headers,
          requestBodyLength = KnownLength (fromIntegral declared)
        }

-- | A chunk source yielding the given chunks, then empty (end of input).
chunkSource :: [ByteString] -> IO (IO ByteString)
chunkSource chunks = do
  remaining <- newIORef chunks
  pure $
    atomicModifyIORef' remaining $ \case
      [] -> ([], BS.empty)
      (c : cs) -> (cs, c)

-- | Body bytes as strict ByteString, for infix assertions.
strictBody :: WT.SResponse -> ByteString
strictBody = BL.toStrict . WT.simpleBody

testServer :: IO Bool
testServer =
  runGroup
    "Server"
    [ test "GET / serves the default root response" $
        withServer Nothing Nothing $ \cfg -> do
          resp <- serverRequest cfg "GET" [] [] ""
          ok1 <- assertEqual "status" HTTP.status200 (WT.simpleStatus resp)
          ok2 <- assertEqual "body" "nova-cache: a Nix binary cache\n" (WT.simpleBody resp)
          pure (ok1 && ok2),
      -- newTTLCache: within the TTL the action runs once; a zero TTL
      -- never satisfies the freshness check, so every call re-runs.
      test "newTTLCache memoizes within the TTL and re-runs past it" $ do
        counter <- newIORef (0 :: Int)
        let bump = atomicModifyIORef' counter (\n -> (n + 1, n + 1))
        cachedHour <- Server.newTTLCache 3600 bump
        firstRead <- cachedHour
        secondRead <- cachedHour
        cachedNever <- Server.newTTLCache 0 bump
        thirdRead <- cachedNever
        fourthRead <- cachedNever
        ok1 <- assertEqual "memoized" (1, 1) (firstRead, secondRead)
        ok2 <- assertEqual "re-run each call" (2, 3) (thirdRead, fourthRead)
        pure (ok1 && ok2),
      test "GET /nix-cache-info renders cache metadata" $
        withServer Nothing Nothing $ \cfg -> do
          resp <- serverRequest cfg "GET" ["nix-cache-info"] [] ""
          ok1 <- assertEqual "status" HTTP.status200 (WT.simpleStatus resp)
          ok2 <- assertTrue "StoreDir line" (BS.isInfixOf "StoreDir: /nix/store" (strictBody resp))
          pure (ok1 && ok2),
      test "unknown route is 404" $
        withServer Nothing Nothing $ \cfg -> do
          resp <- serverRequest cfg "GET" ["no", "such", "route"] [] ""
          assertEqual "status" HTTP.status404 (WT.simpleStatus resp),
      -- HEAD is routed exactly like GET (upstream clients probe narinfo
      -- existence with HEAD; it used to fall through to 404).
      test "HEAD is served wherever GET is" $
        withServer Nothing Nothing $ \cfg -> do
          okResp <- serverRequest cfg "HEAD" ["nix-cache-info"] [] ""
          missingResp <- serverRequest cfg "HEAD" [validNarInfoHashKey <> ".narinfo"] [] ""
          ok1 <- assertEqual "present" HTTP.status200 (WT.simpleStatus okResp)
          ok2 <- assertEqual "absent" HTTP.status404 (WT.simpleStatus missingResp)
          pure (ok1 && ok2),
      -- Write authentication
      test "PUT narinfo without auth is 401" $
        withAuthedServer $ \cfg -> do
          resp <- serverRequest cfg "PUT" [validNarInfoHashKey <> ".narinfo"] [] validServerNarInfoBytes
          assertEqual "status" HTTP.status401 (WT.simpleStatus resp),
      test "PUT narinfo with the wrong key is 401" $
        withAuthedServer $ \cfg -> do
          let wrongAuth = (HTTP.hAuthorization, "Bearer not-the-key")
          resp <- serverRequest cfg "PUT" [validNarInfoHashKey <> ".narinfo"] [wrongAuth] validServerNarInfoBytes
          assertEqual "status" HTTP.status401 (WT.simpleStatus resp),
      test "PUT then GET narinfo roundtrip" $
        withAuthedServer $ \cfg -> do
          putResp <- serverRequest cfg "PUT" [validNarInfoHashKey <> ".narinfo"] [serverAuthHeader] validServerNarInfoBytes
          getResp <- serverRequest cfg "GET" [validNarInfoHashKey <> ".narinfo"] [] ""
          ok1 <- assertEqual "PUT status" HTTP.status200 (WT.simpleStatus putResp)
          ok2 <- assertEqual "GET status" HTTP.status200 (WT.simpleStatus getResp)
          ok3 <- assertTrue "StorePath present" (BS.isInfixOf (TE.encodeUtf8 validNarInfoHashKey) (strictBody getResp))
          ok4 <-
            assertEqual
              "revalidatable, never immutable"
              (Just "public, max-age=3600, must-revalidate")
              (lookup HTTP.hCacheControl (WT.simpleHeaders getResp))
          pure (ok1 && ok2 && ok3 && ok4),
      test "PUT narinfo signs when a key is configured" $ do
        sigKey <- generateTestSecretKey
        withServer (Just serverTestApiKey) (Just sigKey) $ \cfg -> do
          putResp <- serverRequest cfg "PUT" [validNarInfoHashKey <> ".narinfo"] [serverAuthHeader] validServerNarInfoBytes
          getResp <- serverRequest cfg "GET" [validNarInfoHashKey <> ".narinfo"] [] ""
          ok1 <- assertEqual "PUT status" HTTP.status200 (WT.simpleStatus putResp)
          ok2 <- assertTrue "Sig line present" (BS.isInfixOf "Sig: test-key:" (strictBody getResp))
          pure (ok1 && ok2),
      -- The confused-deputy gate: a narinfo describing path X cannot be
      -- stored under path Y's key.
      test "PUT narinfo under a mismatched hash is 400" $
        withAuthedServer $ \cfg -> do
          let otherKey = T.replicate 32 "1" <> ".narinfo"
          resp <- serverRequest cfg "PUT" [otherKey] [serverAuthHeader] validServerNarInfoBytes
          assertEqual "status" HTTP.status400 (WT.simpleStatus resp),
      test "PUT malformed narinfo is 400" $
        withAuthedServer $ \cfg -> do
          resp <- serverRequest cfg "PUT" [validNarInfoHashKey <> ".narinfo"] [serverAuthHeader] "not a narinfo"
          assertEqual "status" HTTP.status400 (WT.simpleStatus resp),
      test "PUT narinfo with an oversized declared length is 413" $
        withAuthedServer $ \cfg -> do
          resp <-
            serverRequestSized
              cfg
              "PUT"
              [validNarInfoHashKey <> ".narinfo"]
              [serverAuthHeader]
              (fromIntegral Server.maxNarInfoBodySize + 1)
          assertEqual "status" HTTP.status413 (WT.simpleStatus resp),
      -- The hash listing is push-tool plumbing: authenticated, uncacheable.
      test "GET /narinfo-hashes without auth is 401" $
        withAuthedServer $ \cfg -> do
          resp <- serverRequest cfg "GET" ["narinfo-hashes"] [] ""
          assertEqual "status" HTTP.status401 (WT.simpleStatus resp),
      test "GET /narinfo-hashes with auth lists hashes, uncacheable" $
        withAuthedServer $ \cfg -> do
          putResp <- serverRequest cfg "PUT" [validNarInfoHashKey <> ".narinfo"] [serverAuthHeader] validServerNarInfoBytes
          resp <- serverRequest cfg "GET" ["narinfo-hashes"] [serverAuthHeader] ""
          ok1 <- assertEqual "PUT status" HTTP.status200 (WT.simpleStatus putResp)
          ok2 <- assertEqual "status" HTTP.status200 (WT.simpleStatus resp)
          ok3 <- assertTrue "uploaded hash listed" (BS.isInfixOf (TE.encodeUtf8 validNarInfoHashKey) (strictBody resp))
          ok4 <- assertEqual "no-store" (Just "no-store") (lookup HTTP.hCacheControl (WT.simpleHeaders resp))
          pure (ok1 && ok2 && ok3 && ok4),
      test "GET /narinfo-hashes in open mode needs no auth" $
        withServer Nothing Nothing $ \cfg -> do
          resp <- serverRequest cfg "GET" ["narinfo-hashes"] [] ""
          assertEqual "status" HTTP.status200 (WT.simpleStatus resp),
      -- NAR transfer
      test "PUT then GET and HEAD a NAR" $
        withAuthedServer $ \cfg -> do
          putResp <- serverRequest cfg "PUT" ["nar", "test.nar"] [serverAuthHeader] "nar-payload-bytes"
          getResp <- serverRequest cfg "GET" ["nar", "test.nar"] [] ""
          headResp <- serverRequest cfg "HEAD" ["nar", "test.nar"] [] ""
          ok1 <- assertEqual "PUT status" HTTP.status200 (WT.simpleStatus putResp)
          ok2 <- assertEqual "GET status" HTTP.status200 (WT.simpleStatus getResp)
          ok3 <- assertEqual "GET body" "nar-payload-bytes" (WT.simpleBody getResp)
          ok4 <-
            assertEqual
              "immutable content address"
              (Just "public, max-age=31536000, immutable")
              (lookup HTTP.hCacheControl (WT.simpleHeaders getResp))
          ok5 <- assertEqual "HEAD status" HTTP.status200 (WT.simpleStatus headResp)
          pure (ok1 && ok2 && ok3 && ok4 && ok5),
      test "PUT NAR without auth is 401" $
        withAuthedServer $ \cfg -> do
          resp <- serverRequest cfg "PUT" ["nar", "test.nar"] [] "nar-payload-bytes"
          assertEqual "status" HTTP.status401 (WT.simpleStatus resp),
      test "PUT NAR with a traversal name is 400" $
        withAuthedServer $ \cfg -> do
          resp <- serverRequest cfg "PUT" ["nar", ".."] [serverAuthHeader] "escape"
          assertEqual "status" HTTP.status400 (WT.simpleStatus resp),
      test "PUT NAR with an oversized declared length is 413" $
        withAuthedServer $ \cfg -> do
          resp <-
            serverRequestSized
              cfg
              "PUT"
              ["nar", "test.nar"]
              [serverAuthHeader]
              (fromIntegral Server.maxNarBodySize + 1)
          assertEqual "status" HTTP.status413 (WT.simpleStatus resp),
      test "GET absent NAR is 404" $
        withServer Nothing Nothing $ \cfg -> do
          resp <- serverRequest cfg "GET" ["nar", "absent.nar"] [] ""
          assertEqual "status" HTTP.status404 (WT.simpleStatus resp),
      -- Streaming write, at the store layer
      test "writeNarStreaming writes chunks and lands atomically" $ do
        tmpDir <- createTestDir
        store <- Store.newFileStore tmpDir
        source <- chunkSource ["ab", "cd", "ef"]
        result <- Store.writeNarStreaming store "streamed.nar" 16 source
        stored <- Store.readNar store "streamed.nar"
        located <- Store.narFilePath store "streamed.nar"
        removeDirectoryRecursive tmpDir
        ok1 <- assertEqual "result" Store.NarWriteOk result
        ok2 <- assertEqual "content" (Just "abcdef") stored
        ok3 <- assertTrue "narFilePath resolves" (isJust located)
        pure (ok1 && ok2 && ok3),
      test "writeNarStreaming over the cap deletes the partial file" $ do
        tmpDir <- createTestDir
        store <- Store.newFileStore tmpDir
        source <- chunkSource ["four", "more", "over"]
        result <- Store.writeNarStreaming store "big.nar" 8 source
        leftovers <- listDirectory (tmpDir ++ "/nar")
        removeDirectoryRecursive tmpDir
        ok1 <- assertEqual "result" Store.NarWriteTooLarge result
        ok2 <- assertEqual "no partial files" [] leftovers
        pure (ok1 && ok2),
      test "writeNarStreaming rejects a traversal name" $ do
        tmpDir <- createTestDir
        store <- Store.newFileStore tmpDir
        source <- chunkSource ["x"]
        result <- Store.writeNarStreaming store "../escape" 8 source
        removeDirectoryRecursive tmpDir
        assertEqual "result" Store.NarWriteBadPath result,
      test "narFilePath rejects a traversal name" $ do
        tmpDir <- createTestDir
        store <- Store.newFileStore tmpDir
        located <- Store.narFilePath store "../escape"
        removeDirectoryRecursive tmpDir
        assertEqual "path" Nothing located
    ]

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

-- | A fresh, unique directory under the system temp dir.  A fixed
-- machine-global path poisons later runs whenever cleanup is skipped and
-- races concurrent checkouts; probing numbered names until createDirectory
-- succeeds gives uniqueness against both.
createTestDir :: IO FilePath
createTestDir = do
  base <- getTemporaryDirectory
  probe base (0 :: Int)
  where
    probe base n = do
      let dir = base ++ "/nova-cache-test-" ++ show n
      made <- try (createDirectory dir) :: IO (Either SomeException ())
      case made of
        Right () -> pure dir
        Left _ -> probe base (n + 1)

-- | Generate a test Ed25519 secret key using crypton.
generateTestSecretKey :: IO Signing.SecretKey
generateTestSecretKey = do
  sk <- Ed25519.generateSecretKey
  let pk = Ed25519.toPublic sk
      skBytes = convert sk <> (convert pk :: ByteString)
  pure
    Signing.SecretKey
      { Signing.skName = "test-key",
        Signing.skBytes = skBytes
      }

-- | Derive the public key from a test secret key.
deriveTestPublicKey :: Signing.SecretKey -> Signing.PublicKey
deriveTestPublicKey sk =
  Signing.PublicKey
    { Signing.pkName = Signing.skName sk,
      Signing.pkBytes = BS.drop 32 (Signing.skBytes sk)
    }
