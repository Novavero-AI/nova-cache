module Main (main) where

import qualified Crypto.PubKey.Ed25519 as Ed25519
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import Data.List (sort)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified NovaCache.Base32 as Base32
import qualified NovaCache.Hash as Hash
import qualified NovaCache.NAR as NAR
import qualified NovaCache.NarInfo as NarInfo
import qualified NovaCache.Signing as Signing
import qualified NovaCache.Store as Store
import qualified NovaCache.StorePath as StorePath
import qualified NovaCache.Validate as Validate
import System.Directory (createDirectoryIfMissing, removeDirectoryRecursive)
import System.Exit (exitFailure, exitSuccess)
import System.IO (hFlush, stdout)

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
      testNarInfo,
      testSigning,
      testFileStore,
      testValidate
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
        -- 32 bytes -> ceil(32*8/5) = ceil(51.2) = 52 chars
        let bs = BS.replicate 32 0x42
            encoded = Base32.encode bs
         in assertEqual "encoded length" 52 (T.length encoded),
      test "nix known vector" $
        -- SHA-256 of empty string in nix-base32 should be 52 chars
        let Hash.NixHash raw = Hash.hashBytes BS.empty
            encoded = Base32.encode raw
         in assertEqual "sha256 of empty in base32 length" 52 (T.length encoded)
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
         in assertLeft "invalid chars" (StorePath.parseStorePath storeDir input)
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
        assertLeft "garbage" (NAR.deserialise (BS.pack [0, 0, 0, 0, 0, 0, 0, 0]))
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
            ok4 <- assertEqual "fileSize" 12345 (NarInfo.niFileSize ni)
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
         in assertLeft "bad integer" (NarInfo.parseNarInfo bad)
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
             in assertFalse "verify rejects tampered" (Signing.verify pk tampered sig)
    ]

-- | Create a test NarInfo for signing tests.
mkTestNarInfo :: NarInfo.NarInfo
mkTestNarInfo =
  NarInfo.NarInfo
    { NarInfo.niStorePath = "/nix/store/aaaa-hello-1.0",
      NarInfo.niUrl = "nar/test.nar.xz",
      NarInfo.niCompression = "xz",
      NarInfo.niFileHash = "sha256:abc",
      NarInfo.niFileSize = 100,
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
      test "sanitizePath rejects dotfile" $
        assertEqual "dotfile" Nothing (Store.sanitizePath ".hidden"),
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
      NarInfo.niFileHash = Hash.formatNixHash (Hash.hashBytes validFileBytes),
      NarInfo.niFileSize = 5,
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
        let ni = mkValidNarInfo {NarInfo.niFileSize = -1}
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
        let ni = mkValidNarInfo {NarInfo.niFileHash = "md5:bogus"}
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
                { NarInfo.niFileSize = -1,
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
            ni = mkValidNarInfo {NarInfo.niFileSize = -1, NarInfo.niNarSize = -1}
        case Validate.validateFull pk ni (BS.pack [99]) (BS.pack [99]) of
          Left errs -> assertTrue "at least 4 errors" (length errs >= 4)
          Right _ -> do
            putStrLn "    expected Left, got Right"
            pure False
    ]

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

-- | Create a temporary test directory.
createTestDir :: IO FilePath
createTestDir = do
  let dir = "/tmp/nova-cache-test"
  createDirectoryIfMissing True dir
  pure dir

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
