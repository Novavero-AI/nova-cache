{-# LANGUAGE CPP #-}
{-# LANGUAGE LambdaCase #-}

module Main (main) where

import Control.Concurrent (MVar, ThreadId, forkFinally, killThread, myThreadId, newEmptyMVar, putMVar, takeMVar, yield)
import Control.Exception (AsyncException (ThreadKilled, UserInterrupt), Exception, IOException, SomeException, bracket_, displayException, finally, fromException, throwTo, try)
import Control.Monad (guard, replicateM, void, zipWithM)
import qualified Crypto.PubKey.Ed25519 as Ed25519
import Data.Bits (shiftR, (.&.))
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Builder as Builder
import qualified Data.ByteString.Lazy as BL
import Data.Either (isLeft, isRight)
import Data.Foldable (toList, traverse_)
import Data.IORef (atomicModifyIORef', newIORef, readIORef, writeIORef)
import Data.List (isSuffixOf, sort)
import Data.Maybe (isJust)
import Data.Set (Set)
import qualified Data.Set as Set
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time.Calendar (fromGregorian)
import Data.Time.Clock (NominalDiffTime, UTCTime (..), addUTCTime, diffUTCTime, getCurrentTime, nominalDay)
import Data.Traversable (for)
import Data.Word (Word64, Word8)
import GHC.Conc (BlockReason (..), ThreadStatus (..), threadStatus)
import qualified Network.HTTP.Types as HTTP
import Network.Wai (RequestBodyLength (..), defaultRequest, pathInfo, queryString, requestBodyLength, requestHeaders, requestMethod)
import qualified Network.Wai.Test as WT
import qualified NovaCache.Base32 as Base32
import qualified NovaCache.Hash as Hash
import qualified NovaCache.NAR as NAR
import qualified NovaCache.NAR.Stream as Stream
import qualified NovaCache.NarInfo as NarInfo
import qualified NovaCache.Reclaim as Reclaim
import qualified NovaCache.Server as Server
import qualified NovaCache.Signing as Signing
import qualified NovaCache.Store as Store
import qualified NovaCache.StorePath as StorePath
import qualified NovaCache.Validate as Validate
import System.Directory (Permissions, createDirectory, createDirectoryLink, createFileLink, doesDirectoryExist, emptyPermissions, getPermissions, getTemporaryDirectory, listDirectory, readable, removeDirectoryRecursive, removeFile, searchable, setModificationTime, setOwnerExecutable, setOwnerReadable, setOwnerSearchable, setPermissions)
import System.Exit (exitFailure, exitSuccess)
import System.IO (hFlush, stdout)
import System.IO.Error (ioeGetErrorString, isPermissionError, isUserError, mkIOError, permissionErrorType)
import qualified System.Info
import Test.QuickCheck (Args (chatty), Gen, Result (Failure, GaveUp, NoExpectedFailure, Success, output), Testable, arbitrary, choose, elements, forAll, frequency, ioProperty, listOf, listOf1, oneof, property, quickCheckWithResult, stdArgs, sublistOf, suchThat, suchThatMap, vectorOf, (.&&.), (===))
#if defined(darwin_HOST_OS)
import Foreign.C.Error (throwErrnoPathIfMinus1_)
import Foreign.C.String (CString)
import Foreign.C.Types (CInt (..))
import System.Directory (getSymbolicLinkTarget)
import System.Posix.Internals (withFilePath)
import System.Posix.Types (CMode (..))
#endif
#if !defined(mingw32_HOST_OS)
import qualified Network.Socket as Socket
import qualified System.Posix.Files as Posix
#endif

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
      testWalkFailures,
      testNarInfo,
      testSigning,
      testFileStore,
      testReclaim,
      testValidate,
      testServer,
      testStoredNarCheck,
      testMultipartUpload,
      testRemoval
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
      -- traverse out of a POSIX extraction root must fail the parse.
      test "unsafe directory entry names rejected" $
        let evil name = NAR.serialise (NAR.NarDirectory [(name, NAR.NarRegular False "x")])
            names = ["..", ".", "", "a/b", "a\0b"]
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
      -- Upstream's restore accepts these on Unix, and real
      -- cache.nixos.org archives carry them (perl man pages named
      -- ExtUtils::MakeMaker.3, kernel trees carrying aux.c): the
      -- parser must too, or substitution fails where upstream
      -- succeeds.  Rejecting them is the store writer's call, via
      -- NAR.isWindowsHazardName, where the target filesystem needs it.
      test "Windows-hazard names parse, as upstream accepts" $
        let entryFor name = NAR.NarDirectory [(name, NAR.NarRegular False "x")]
            names = ["ExtUtils::MakeMaker.3", "aux.c", "a:b", "a\\b", "nul", "foo.", "foo "]
            roundTrips name = NAR.deserialise (NAR.serialise (entryFor name)) == Right (entryFor name)
         in assertTrue "all parse and round-trip" (all roundTrips names),
      -- Windows resolves these names to something other than a file of
      -- this spelling (drive/stream colon, separator backslash, device,
      -- NTFS dot/space strip).
      test "isWindowsHazardName flags the hazard categories" $
        -- Among the devices: COM0/LPT0 are reserved alongside COM1-9,
        -- the device stem is compared with trailing spaces trimmed
        -- ("NUL .txt" still opens the device), and the superscript
        -- digits (here U+00B9 as UTF-8) count as device digits.
        let names =
              [ "C:evil",
                "a:b",
                "a\\b",
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
         in assertTrue "all hazard names flagged" (all NAR.isWindowsHazardName names),
      test "near-miss names parse and pass the hazard predicate" $
        let plain name = NAR.serialise (NAR.NarDirectory [(name, NAR.NarRegular False "x")])
            -- "com" followed by a non-digit non-superscript byte (here
            -- U+00B4, acute accent) is an ordinary name; so are stems
            -- one character too long.
            names = ["nul2", "com10", "conx", "foo.bar", "a.b.c", "lpt00", "com" <> BS.pack [0xC2, 0xB4]]
            accepted bytes = either (const False) (const True) (NAR.deserialise bytes)
            clean name = accepted (plain name) && not (NAR.isWindowsHazardName name)
         in assertTrue "all near-miss names accepted" (all clean names),
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
      test "hazards inside non-UTF-8 names still flagged" $
        let names = ["nul." <> BS.pack [0xFF], BS.pack [0xFF, 0x2E], BS.pack [0xFF] <> ":x"]
         in assertTrue "all hazard bytes flagged" (all NAR.isWindowsHazardName names),
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
      -- The resolver is the executable-bit source: its answer lands
      -- verbatim, independent of permissions or extension.
      test "serialiseFromPathOpts takes the exec bit from the resolver" $ do
        dir <- caseHackFixture "nova-cache-test-execresolver"
        BS.writeFile (dir <> "/plain") "p"
        let opts =
              NAR.defaultSerialiseOptions
                { NAR.soCaseHack = NAR.CaseHackDisabled,
                  NAR.soExecBit = \_ -> pure True
                }
        entry <- NAR.serialiseFromPathOpts opts dir
        removeDirectoryRecursive dir
        assertEqual
          "resolver answer"
          (NAR.NarDirectory [("plain", NAR.NarRegular True "p")])
          entry,
      -- A real on-disk exec bit round-trips through the default
      -- resolver; no earlier fixture ever set one.  POSIX-gated:
      -- Windows has no mode bit for the default to read.
      test "a real owner-exec bit round-trips from disk" $
        if System.Info.os == "mingw32"
          then pure True
          else do
            dir <- caseHackFixture "nova-cache-test-realexec"
            BS.writeFile (dir <> "/doc") "txt"
            BS.writeFile (dir <> "/tool") "bin"
            perms <- getPermissions (dir <> "/tool")
            setPermissions (dir <> "/tool") (setOwnerExecutable True perms)
            entry <- NAR.serialiseFromPathWith NAR.CaseHackDisabled dir
            removeDirectoryRecursive dir
            assertEqual
              "owner bit from the file mode"
              ( NAR.NarDirectory
                  [ ("doc", NAR.NarRegular False "txt"),
                    ("tool", NAR.NarRegular True "bin")
                  ]
              )
              entry,
      -- The resolver contract, pinned as an exact call set for both
      -- producers: once per regular file, never for the directory,
      -- and always the on-disk spelling - under the case hack, the
      -- suffixed name the walk reads, not the stripped entry name.
      test "the resolver sees the on-disk case-hacked spelling" $ do
        dir <- caseHackFixture "nova-cache-test-execdisk"
        BS.writeFile (dir <> "/Foo") "upper"
        BS.writeFile (dir <> "/foo~nix~case~hack~1") "lower"
        seenWalk <- newIORef []
        seenPlan <- newIORef []
        let recordingOpts ref =
              NAR.defaultSerialiseOptions
                { NAR.soCaseHack = NAR.CaseHackEnabled,
                  NAR.soExecBit = \path ->
                    atomicModifyIORef' ref (\paths -> (path : paths, ())) >> pure False
                }
            baseName = reverse . takeWhile (\c -> c /= '/' && c /= '\\') . reverse
        _ <- NAR.serialiseFromPathOpts (recordingOpts seenWalk) dir
        _ <- NAR.withNarSourceOpts (recordingOpts seenPlan) dir drainSource
        removeDirectoryRecursive dir
        walked <- readIORef seenWalk
        planned <- readIORef seenPlan
        let expected = ["Foo", "foo~nix~case~hack~1"]
        walkOk <-
          assertEqual
            "eager walk call set"
            expected
            (sort (map baseName walked))
        planOk <-
          assertEqual
            "streaming plan call set"
            expected
            (sort (map baseName planned))
        pure (walkOk && planOk),
      -- A symlink target with a separator serialises to the POSIX
      -- spelling on every platform: Windows stores a
      -- reparse point with backslashes, so a target written bin/tool
      -- reads back bin\tool, and an unpack-then-recheck round-trip
      -- diverges from the archive unless the NAR boundary normalises
      -- it.  Both producers must agree with the forward-slash form.
      -- Guarded on symlink privilege, which a Windows runner without
      -- developer mode lacks.
      test "a separator-bearing symlink target serialises with forward slashes" $ do
        dir <- caseHackFixture "nova-cache-test-symlinksep"
        created <- try (createFileLink "bin/tool" (dir <> "/link")) :: IO (Either SomeException ())
        case created of
          Left _ -> removeDirectoryRecursive dir >> pure True
          Right () -> do
            let expectedEntry = NAR.NarDirectory [("link", NAR.NarSymlink "bin/tool")]
            eager <- NAR.serialiseFromPathWith NAR.CaseHackDisabled dir
            streamed <- NAR.withNarSource NAR.CaseHackDisabled dir drainSource
            removeDirectoryRecursive dir
            eagerOk <- assertEqual "eager target spelling" expectedEntry eager
            streamOk <- assertEqual "streamed target spelling" (NAR.serialise expectedEntry) streamed
            pure (eagerOk && streamOk),
      -- The type the walk reads decides the archive's bytes: a symlink
      -- to a directory archives as the symlink, not the directory it
      -- leads to, a symlink walked as the root likewise, and an empty
      -- directory as a directory.  Guarded on symlink privilege, as
      -- above.
      test "a symlink to a directory, a symlink root and an empty directory archive as their own types" $
        withWalkTree $ \root -> do
          createDirectory (root ++ "/empty")
          createDirectory (root ++ "/real")
          BS.writeFile (root ++ "/real/file") "x"
          linked <- try (createDirectoryLink "real" (root ++ "/link")) :: IO (Either IOException ())
          case linked of
            Left _ -> pure True
            Right () -> do
              treeOk <-
                expectArchive
                  ( NAR.NarDirectory
                      [ ("empty", NAR.NarDirectory []),
                        ("link", NAR.NarSymlink "real"),
                        ("real", NAR.NarDirectory [("file", NAR.NarRegular False "x")])
                      ]
                  )
                  root
              rootOk <- expectArchive (NAR.NarSymlink "real") (root ++ "/link")
              pure (treeOk && rootOk),
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
      -- verbatim, never rewritten with replacement characters.  Linux-gated:
      -- NTFS and APFS names are Unicode, so the fixture cannot exist
      -- there.  "\56575" is the lone surrogate
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
runStream = runStreamFrom Stream.narStream

-- | 'runStream' from an explicitly constructed machine, for tests that
-- need a bound other than the default.
runStreamFrom :: Stream.NarStep -> [ByteString] -> Either String [Stream.NarEvent]
runStreamFrom start chunks = go start chunks []
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
                evil ""
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
      -- Regression: under a huge caller bound, a declared length near
      -- maxBound Int once wrapped the padded Int demand negative, so
      -- the machine "read" the string instantly as empty at an unmoved
      -- position and this archive parsed as a complete empty symlink.
      -- The parse must fail, as upstream would at end of input.
      test "a near-maxBound declared length fails under a huge bound" $
        let declared = fromIntegral (maxBound :: Int) :: Word64
            lenPrefix = BS.pack [fromIntegral ((declared `shiftR` (8 * i)) .&. 0xff) | i <- [0 .. 7]]
            bytes =
              BS.concat (map (narWireStr 0) ["nix-archive-1", "(", "type", "symlink", "target"])
                <> lenPrefix
                <> narWireStr 0 ")"
         in assertLeft
              "overflowing padded demand"
              (runStreamFrom (Stream.narStreamBounded (maxBound :: Word64)) [bytes]),
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
      -- The streaming planner asks the same resolver the eager walk
      -- does, so a custom executable-bit source streams byte-equal.
      test "withNarSourceOpts streams the resolver's flags byte-identically" $ do
        dir <- caseHackFixture "nova-cache-test-narsource-exec"
        BS.writeFile (dir <> "/doc") "txt"
        BS.writeFile (dir <> "/tool") "bin"
        let opts =
              NAR.defaultSerialiseOptions
                { NAR.soCaseHack = NAR.CaseHackDisabled,
                  NAR.soExecBit = \path -> pure ("tool" `isSuffixOf` path)
                }
        entry <- NAR.serialiseFromPathOpts opts dir
        streamed <- NAR.withNarSourceOpts opts dir drainSource
        removeDirectoryRecursive dir
        flagsOk <-
          assertEqual
            "eager flags"
            ( NAR.NarDirectory
                [ ("doc", NAR.NarRegular False "txt"),
                  ("tool", NAR.NarRegular True "bin")
                ]
            )
            entry
        bytesOk <- assertTrue "stream equals serialise" (NAR.serialise entry == streamed)
        pure (flagsOk && bytesOk),
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
      -- The pull that opens a file reads its size, so a file cut to
      -- nothing after that pull leaves the next read short, and the
      -- empty chunk after that failure would read as the clean end of
      -- a torn archive.  Writing the file afterwards shows the failure
      -- closed it: GHC refuses a writer while the process holds a
      -- reader open.
      test "every pull after a shrink failure rethrows it" $
        withWalkTree $ \root -> do
          let file = root ++ "/file"
              shrank = Left (userError ("withNarSource: " ++ file ++ " shrank while streaming"))
          BS.writeFile file "contents"
          NAR.withNarSourceOpts walkOptions file $ \pull -> do
            _ <- pull
            _ <- pull
            withTruncated file $ do
              failed <- try pull
              later <- replicateM 2 (try pull)
              closed <- isRight <$> (try (BS.writeFile file "") :: IO (Either IOException ()))
              assertEqual
                "the pull after the cut, the pulls after it, the file closed"
                (shrank, [shrank, shrank], True)
                (failed, later, closed),
      -- The latch holds any failure, not only a shrink: a file that
      -- could not be opened stays failed once it is readable again,
      -- rather than resuming an archive its consumer saw fail.
      test "every pull after a failed open rethrows it" $
        withWalkTree $ \root -> do
          let file = root ++ "/file"
          BS.writeFile file "contents"
          NAR.withNarSourceOpts walkOptions file $ \pull -> do
            _ <- pull
            withoutPermission readable setOwnerReadable file $ do
              refused <- try pull
              getPermissions file >>= setPermissions file . setOwnerReadable True
              later <- try pull
              assertEqual
                "a failed open, then the pull once the file is readable again"
                (True, refused)
                (isLeft refused, later :: Either NAR.NarWalkError ByteString),
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
-- NAR walk failure tests
-- ---------------------------------------------------------------------------

-- | Each failed access, and each type a NAR cannot hold, is provoked on
-- an entry and walked through both entry points.
testWalkFailures :: IO Bool
testWalkFailures =
  runGroup
    "NAR walk failures"
    [ test "an unreadable file fails the walk as a file read" $
        withWalkTree $ \root -> do
          let locked = root ++ "/sub/locked"
          createDirectory (root ++ "/sub")
          BS.writeFile locked "secret"
          withoutPermission readable setOwnerReadable locked $
            expectWalkFailure NAR.WalkReadFile locked root,
      test "an unlistable directory fails the walk as a directory listing" $
        withWalkTree $ \root -> do
          let sub = root ++ "/sub"
          createDirectory sub
          BS.writeFile (sub ++ "/file") "x"
          withoutPermission readable setOwnerReadable sub $
            expectWalkFailure NAR.WalkListDirectory sub root,
      -- A directory with read but not search permission lists its
      -- entries' names and refuses an lstat of any of them.
      test "an entry of an unsearchable directory fails the walk as a status read" $
        withWalkTree $ \root -> do
          let sub = root ++ "/sub"
          createDirectory sub
          BS.writeFile (sub ++ "/file") "x"
          withoutPermission searchable setOwnerSearchable sub $
            expectWalkFailure NAR.WalkStatus (sub ++ "/file") root,
      test "a symlink whose target cannot be read fails the walk as a readlink" $
        withWalkTree $ \root -> do
          let link = root ++ "/sub/link"
          createDirectory (root ++ "/sub")
          withUnreadableLink link $
            expectWalkFailure NAR.WalkReadLink link root,
      test "a FIFO in a tree is refused as an unsupported type" $
        withWalkTree $ \root -> do
          let pipe = root ++ "/sub/pipe"
          createDirectory (root ++ "/sub")
          withFifo pipe $
            expectUnsupportedType pipe root,
      test "a Unix socket in a tree is refused as an unsupported type" $
        withWalkTree $ \root -> do
          let socketPath = root ++ "/sub/socket"
          createDirectory (root ++ "/sub")
          withUnixSocket socketPath $
            expectUnsupportedType socketPath root,
      -- Making a device takes privilege, and /dev/null is one every
      -- POSIX system has; as the root it goes through the same
      -- classification as an entry below.  Windows has no /dev/null.
      test "a device walked as the root is refused as an unsupported type" $
        if System.Info.os == "mingw32"
          then pure True
          else expectUnsupportedType "/dev/null" "/dev/null",
      -- The resolver is the one place a test can raise an interrupt
      -- mid-walk: no access blocks long enough to be interrupted on
      -- cue.  The handler around each access catches 'IOException' by
      -- its type alone.
      test "an interrupt raised by the resolver mid-walk reaches the caller as itself" $
        withWalkTree $ \root -> do
          BS.writeFile (root ++ "/file") "x"
          let interrupt = myThreadId >>= (`throwTo` UserInterrupt) >> pure False
          outcomes <- walkOutcomes walkOptions {NAR.soExecBit = const interrupt} root
          and
            <$> traverse
              (\(entryPoint, outcome) -> assertEqual (entryPoint ++ " raised") (Just UserInterrupt) (either fromException (const Nothing) outcome))
              outcomes,
      test "a walk failure renders as its IOException, the access as location" $
        let cause = mkIOError permissionErrorType "openBinaryFile" Nothing (Just "/d/tree/sub/locked")
         in assertEqual
              "rendering"
              "/d/tree/sub/locked: reading file: permission denied"
              (displayException (NAR.NarWalkError NAR.WalkReadFile "/d/tree/sub/locked" cause))
    ]

-- | The options every walk-failure test walks with.
walkOptions :: NAR.SerialiseOptions
walkOptions = NAR.defaultSerialiseOptions {NAR.soCaseHack = NAR.CaseHackDisabled}

-- | A fresh tree for one test, removed however the test ends.
withWalkTree :: (FilePath -> IO Bool) -> IO Bool
withWalkTree body = do
  root <- createTestDir
  body root `finally` removeDirectoryRecursive root

-- | What each entry point raised walking a tree, by name.
walkOutcomes :: NAR.SerialiseOptions -> FilePath -> IO [(String, Either SomeException ())]
walkOutcomes opts root = do
  eager <- try (void (NAR.serialiseFromPathOpts opts root))
  streamed <- try (void (NAR.withNarSourceOpts opts root drainSource))
  pure [("serialiseFromPathOpts", eager), ("withNarSourceOpts", streamed)]

-- | Assert that both entry points fail to walk a tree with a
-- 'NAR.NarWalkError' naming the access and the entry, over the
-- permission error the test caused.
expectWalkFailure :: NAR.WalkAccess -> FilePath -> FilePath -> IO Bool
expectWalkFailure access path =
  expectWalkRefusal
    "NarWalkError"
    (\failure -> (NAR.nweAccess failure, NAR.nwePath failure, isPermissionError (NAR.nweCause failure)))
    (access, path, True)

-- | Assert that both entry points refuse a tree with upstream's
-- unsupported-type error, naming the entry.
expectUnsupportedType :: FilePath -> FilePath -> IO Bool
expectUnsupportedType path =
  expectWalkRefusal
    "IOException"
    (\refusal -> (isUserError refusal, ioeGetErrorString refusal))
    (True, "file '" ++ path ++ "' has an unsupported type")

-- | Assert that both entry points archive a path as an entry: the walk
-- builds the entry itself, and the stream pulls its serialised bytes.
expectArchive :: NAR.NarEntry -> FilePath -> IO Bool
expectArchive expected path = do
  walked <- NAR.serialiseFromPathOpts walkOptions path
  streamed <- NAR.withNarSourceOpts walkOptions path drainSource
  walkedOk <- assertEqual (path ++ " walked") expected walked
  streamedOk <- assertEqual (path ++ " streamed") (NAR.serialise expected) streamed
  pure (walkedOk && streamedOk)

-- | Assert that both entry points fail to walk a tree with an exception
-- of the type named, and that what the test reads off it is expected.
expectWalkRefusal :: (Exception e, Eq a, Show a) => String -> (e -> a) -> a -> FilePath -> IO Bool
expectWalkRefusal typeName observe expected root = do
  outcomes <- walkOutcomes walkOptions root
  and <$> traverse check outcomes
  where
    check (entryPoint, outcome) = case outcome of
      Left raised
        | Just refusal <- fromException raised ->
            assertEqual (entryPoint ++ " refusal") expected (observe refusal)
      Left raised -> do
        putStrLn ""
        putStrLn ("    " ++ entryPoint ++ ": expected " ++ typeName ++ ", got: " ++ displayException raised)
        pure False
      Right () -> do
        putStrLn ""
        putStrLn ("    " ++ entryPoint ++ ": expected " ++ typeName ++ ", the walk succeeded")
        pure False

-- | Take one of the owner's permissions from a path and run a check
-- while it is gone, then give it back.  Windows has no mode bit to
-- take, and root's access ignores the mode, so on either there is no
-- refusal to cause and the check is skipped, as 'makeUnreadable''s
-- callers skip theirs.
withoutPermission :: (Permissions -> Bool) -> (Bool -> Permissions -> Permissions) -> FilePath -> IO Bool -> IO Bool
withoutPermission held setHeld path check
  | System.Info.os == "mingw32" = pure True
  | otherwise = do
      original <- getPermissions path
      bracket_ (setPermissions path (setHeld False original)) (setPermissions path original) $ do
        refused <- not . held <$> getPermissions path
        if refused then check else pure True

-- | Create a symlink with no permissions of its own and run a check if
-- that leaves its target unreadable.  macOS checks a symlink's own
-- mode on readlink (root exempt); Linux ignores the mode and Windows
-- has none, so on both no permission refuses a readlink that the lstat
-- before it was allowed, and the check is skipped.
withUnreadableLink :: FilePath -> IO Bool -> IO Bool
#if defined(darwin_HOST_OS)
withUnreadableLink link check = do
  createFileLink "target" link
  withFilePath link (throwErrnoPathIfMinus1_ "lchmod" link . (`c_lchmod` 0))
  refused <- isLeft <$> (try (getSymbolicLinkTarget link) :: IO (Either IOException FilePath))
  if refused then check else pure True

foreign import ccall unsafe "lchmod"
  c_lchmod :: CString -> CMode -> IO CInt
#else
withUnreadableLink _ _ = pure True
#endif

-- | Make a FIFO at a path and run a check.  Windows has no FIFO a
-- directory holds and no file mode the walk reads, so the check is
-- skipped there.
withFifo :: FilePath -> IO Bool -> IO Bool
#if defined(mingw32_HOST_OS)
withFifo _ _ = pure True
#else
withFifo path check = do
  Posix.createNamedPipe path (Posix.unionFileModes Posix.ownerReadMode Posix.ownerWriteMode)
  check
#endif

-- | Bind a Unix socket at a path and run a check on the file the bind
-- leaves, which outlives the socket.  The walk on Windows reads no
-- file mode, so the check is skipped there.
withUnixSocket :: FilePath -> IO Bool -> IO Bool
#if defined(mingw32_HOST_OS)
withUnixSocket _ _ = pure True
#else
withUnixSocket path check = do
  bound <- Socket.socket Socket.AF_UNIX Socket.Stream Socket.defaultProtocol
  Socket.bind bound (Socket.SockAddrUnix path) `finally` Socket.close bound
  check
#endif

-- | Cut a file to nothing and run a check.  A stream holding the file
-- open for reading keeps GHC from giving the same process a handle
-- that writes it, so the cut is truncate(2), which Windows lacks; the
-- check is skipped there.
withTruncated :: FilePath -> IO Bool -> IO Bool
#if defined(mingw32_HOST_OS)
withTruncated _ _ = pure True
#else
withTruncated path check = do
  Posix.setFileSize path 0
  check
#endif

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
        assertEqual "empty" [] hashes,
      test "removeNarInfo removes a narinfo, reports one that is absent, and refuses a traversal name" $ do
        tmpDir <- createTestDir
        store <- Store.newFileStore tmpDir
        _ <- Store.writeNarInfo store "hash1" "content1"
        _ <- Store.writeNarInfo store "hash2" "content2"
        outcomes <- traverse (Store.removeNarInfo store) ["hash1", "hash1", "../hash2"]
        hashes <- Store.listNarInfoHashes store
        removeDirectoryRecursive tmpDir
        ok1 <- assertEqual "outcomes" [Store.NarInfoRemoved, Store.NarInfoAbsent, Store.NarInfoRemoveBadPath] outcomes
        ok2 <- assertEqual "remaining" ["hash2"] hashes
        pure (ok1 && ok2)
    ]

-- ---------------------------------------------------------------------------
-- Reclaim tests
-- ---------------------------------------------------------------------------

testReclaim :: IO Bool
testReclaim =
  runGroup
    "Reclaim"
    [ test "a nar/<file> URL names that file, compression suffix included" $
        assertEqual
          "target"
          (Reclaim.NamesNar "1w1fff338fvdw53sqgamddn1b2xgds473pv6y13gizdbqjv4i5p3.nar.zst")
          (narInfoBytesTarget (mkValidNarInfo {NarInfo.niUrl = "nar/1w1fff338fvdw53sqgamddn1b2xgds473pv6y13gizdbqjv4i5p3.nar.zst"})),
      test "a URL in any other spelling is unresolvable" $
        let spellings =
              [ "https://cache.example/nar/x.nar",
                "./nar/x.nar",
                "nar/../x.nar",
                "nar/a/x.nar",
                "nar/x.nar?v=1",
                "nar/x%2Enar",
                "nar/.nova1.tmp",
                "nar/",
                "x.nar"
              ]
            resolved = [url | url <- spellings, not (isUnresolvable (narInfoBytesTarget (mkValidNarInfo {NarInfo.niUrl = url})))]
         in assertEqual "spellings that resolved" [] resolved,
      test "an unreadable, undecodable or unparseable narinfo is unresolvable" $ do
        let unreadable = Reclaim.narInfoTarget (Left (userError "permission denied"))
            undecodable = Reclaim.narInfoTarget (Right (BS.pack [0x55, 0x52, 0x4c, 0x3a, 0xff]))
            unparseable = Reclaim.narInfoTarget (Right "StorePath: /nix/store/x\nNarSize: 5\n")
        assertTrue "all unresolvable" (all isUnresolvable [unreadable, undecodable, unparseable]),
      test "property: a nar/<name> URL resolves to the name through the parser" $
        checkProperty $
          forAll genSafeNarName $ \name ->
            narInfoBytesTarget (mkValidNarInfo {NarInfo.niUrl = "nar/" <> name}) === Reclaim.NamesNar name,
      test "property: a referenced NAR is never selected" $
        checkProperty $
          forAll genSelection $ \(minimumAge, references, nars) ->
            let selected = selectAll minimumAge references nars
             in all ((`Set.notMember` references) . Store.nfName) selected,
      test "property: the selection is a subset of the NARs present" $
        checkProperty $
          forAll genSelection $ \(minimumAge, references, nars) ->
            all (`elem` nars) (selectAll minimumAge references nars),
      test "property: every unreferenced NAR is either eligible or kept, never both" $
        checkProperty $
          forAll genSelection $ \(minimumAge, references, nars) ->
            sort (map Store.nfName (selectAll minimumAge references nars))
              === sort [Store.nfName nar | nar <- nars, Set.notMember (Store.nfName nar) references],
      test "property: eligible NARs are at least the minimum age, kept ones younger" $
        checkProperty $
          forAll genSelection $ \(minimumAge, references, nars) ->
            let plan = Reclaim.selectUnreferenced minimumAge referenceTime references nars
             in all ((>= minimumAge) . ageOf) (Reclaim.rpEligible plan)
                  && all ((< minimumAge) . ageOf) (Reclaim.rpTooYoung plan),
      test "property: adding a narinfo never grows the eligible set" $
        checkProperty $
          forAll genSelection $ \(minimumAge, references, nars) ->
            forAll genNarName $ \added ->
              let eligible refs = Reclaim.rpEligible (Reclaim.selectUnreferenced minimumAge referenceTime refs nars)
               in all (`elem` eligible references) (eligible (Set.insert added references)),
      test "property: raising the minimum age never grows the eligible set" $
        checkProperty $
          forAll genSelection $ \(minimumAge, references, nars) ->
            forAll genMinimumAge $ \raise ->
              let eligible age = Reclaim.rpEligible (Reclaim.selectUnreferenced age referenceTime references nars)
               in all (`elem` eligible minimumAge) (eligible (minimumAge + raise)),
      test "property: any unresolvable narinfo blocks the run, and all are reported" $
        checkProperty $
          forAll genSelection $ \(minimumAge, _, nars) ->
            forAll (listOf genTarget) $ \targets ->
              let narInfos = zip [show i | i <- [0 :: Int ..]] targets
                  scan = scanOf narInfos nars
                  blocking = [path | (path, Reclaim.Unresolvable _) <- narInfos]
               in case Reclaim.planReclaim minimumAge scan of
                    Left (Reclaim.UnresolvedNarInfos unresolved) -> map Reclaim.unresolvedPath (toList unresolved) === blocking
                    Left Reclaim.NoNarInfos -> property (null targets && not (null nars))
                    Right _ -> blocking === [],
      test "property: a store with NARs and no narinfo blocks the run, and an empty store plans nothing" $
        checkProperty $
          forAll genSelection $ \(minimumAge, _, nars) ->
            let scan = scanOf [] nars
                expected = case nars of
                  [] -> Right Reclaim.ReclaimPlan {Reclaim.rpEligible = [], Reclaim.rpTooYoung = []}
                  _ -> Left Reclaim.NoNarInfos
             in Reclaim.planReclaim minimumAge scan === expected,
      test "property: a run plans its uploads as selectAbandoned splits them, and a blocked run plans nothing" $
        checkProperty $
          forAll genSelection $ \(minimumAge, _, nars) ->
            forAll (listOf genTarget) $ \targets ->
              forAll (listOf genStagedUpload) $ \uploads ->
                let scan = (scanOf (zip [show i | i <- [0 :: Int ..]] targets) nars) {Reclaim.scanStagedUploads = uploads}
                 in Reclaim.planStore minimumAge scan
                      === ( (\narPlan -> Reclaim.StorePlan narPlan (Reclaim.selectAbandoned minimumAge referenceTime uploads))
                              <$> Reclaim.planReclaim minimumAge scan
                          ),
      test "a NAR exactly the minimum age old is eligible" $
        let nar = narAged "edge.nar" Reclaim.defaultMinimumAge
            plan = Reclaim.selectUnreferenced Reclaim.defaultMinimumAge referenceTime Set.empty [nar]
         in assertEqual "eligible" [nar] (Reclaim.rpEligible plan),
      test "a scan of a store: blocked by a broken narinfo, then reclaimed" $ do
        tmpDir <- createTestDir
        store <- Store.newFileStore tmpDir
        now <- getCurrentTime
        let monthAgo = addUTCTime (negate (30 * nominalDay)) now
            narPath name = tmpDir ++ "/nar/" ++ name
            putNar name modified = do
              _ <- Store.writeNar store (T.pack name) "nar bytes"
              setModificationTime (narPath name) modified
        _ <- Store.writeNarInfo store "referencing" (TE.encodeUtf8 (NarInfo.renderNarInfo (mkValidNarInfo {NarInfo.niUrl = "nar/ref.nar.zst"})))
        _ <- Store.writeNarInfo store "broken" "not a narinfo\n"
        putNar "ref.nar.zst" monthAgo
        putNar "old.nar.zst" monthAgo
        putNar "young.nar.zst" now
        -- An upload in progress: the temp name a streaming write uses.
        BS.writeFile (narPath ".nova123-4.tmp") "partial"
        setModificationTime (narPath ".nova123-4.tmp") monthAgo
        blocked <- Reclaim.planReclaim Reclaim.defaultMinimumAge <$> Reclaim.scanStore store getCurrentTime
        removeFile (tmpDir ++ "/narinfo/broken")
        reclaimable <- Reclaim.planReclaim Reclaim.defaultMinimumAge <$> Reclaim.scanStore store getCurrentTime
        let blockedBy = case blocked of
              Left (Reclaim.UnresolvedNarInfos unresolved) -> map Reclaim.unresolvedPath (toList unresolved)
              _ -> []
            eligible = either (const []) (map Store.nfName . Reclaim.rpEligible) reclaimable
            tooYoung = either (const []) (map Store.nfName . Reclaim.rpTooYoung) reclaimable
        removals <- traverse (Store.removeNar store) eligible
        remaining <- sort <$> listDirectory (tmpDir ++ "/nar")
        removeDirectoryRecursive tmpDir
        ok1 <- assertTrue "blocked by the broken narinfo alone" (case blockedBy of [path] -> "broken" `isSuffixOf` path; _ -> False)
        ok2 <- assertEqual "eligible" ["old.nar.zst"] eligible
        ok3 <- assertEqual "kept" ["young.nar.zst"] tooYoung
        ok4 <- assertEqual "removals" [Store.NarRemoved] removals
        ok5 <- assertEqual "remaining" [".nova123-4.tmp", "ref.nar.zst", "young.nar.zst"] remaining
        pure (ok1 && ok2 && ok3 && ok4 && ok5),
      test "a store whose narinfo directory the server recreated blocks the run" $ do
        tmpDir <- createTestDir
        store <- Store.newFileStore tmpDir
        now <- getCurrentTime
        _ <- Store.writeNar store "old.nar.zst" "nar bytes"
        setModificationTime (tmpDir ++ "/nar/old.nar.zst") (addUTCTime (negate (30 * nominalDay)) now)
        removeDirectoryRecursive (tmpDir ++ "/narinfo")
        restarted <- Store.newFileStore tmpDir
        plan <- Reclaim.planReclaim Reclaim.defaultMinimumAge <$> Reclaim.scanStore restarted getCurrentTime
        removeDirectoryRecursive tmpDir
        assertEqual "blocked" (Left Reclaim.NoNarInfos) plan,
      test "a scan of a store that lost its narinfo directory fails and creates nothing" $ do
        tmpDir <- createTestDir
        store <- Store.newFileStore tmpDir
        removeDirectoryRecursive (tmpDir ++ "/narinfo")
        result <- tryIO (Reclaim.scanStore store getCurrentTime)
        created <- doesDirectoryExist (tmpDir ++ "/narinfo")
        removeDirectoryRecursive tmpDir
        ok1 <- assertTrue "scan failed" (isLeft result)
        ok2 <- assertFalse "narinfo directory created" created
        pure (ok1 && ok2),
      test "removeNar reports a missing file and refuses a traversal name" $ do
        tmpDir <- createTestDir
        store <- Store.newFileStore tmpDir
        missing <- Store.removeNar store "absent.nar"
        traversal <- Store.removeNar store "../escape.nar"
        removeDirectoryRecursive tmpDir
        ok1 <- assertTrue "missing file fails" (case missing of Store.NarRemoveFailed _ -> True; _ -> False)
        ok2 <- assertEqual "traversal" Store.NarRemoveBadPath traversal
        pure (ok1 && ok2),
      -- Abandoned multipart uploads
      test "property: a staged upload is eligible exactly when idle for the minimum age" $
        checkProperty $
          forAll genMinimumAge $ \minimumAge ->
            forAll (listOf genStagedUpload) $ \uploads ->
              let plan = Reclaim.selectAbandoned minimumAge referenceTime uploads
               in (sort (map Store.suPath (Reclaim.upEligible plan ++ Reclaim.upTooYoung plan)) === sort (map Store.suPath uploads))
                    .&&. all ((>= minimumAge) . uploadAge) (Reclaim.upEligible plan)
                    .&&. all ((< minimumAge) . uploadAge) (Reclaim.upTooYoung plan),
      test "a reclaim of staged uploads: an idle one is removed, an active one and a stray directory are kept" $ do
        tmpDir <- createTestDir
        store <- Store.newFileStore tmpDir
        monthAgo <- addUTCTime (negate (30 * nominalDay)) <$> getCurrentTime
        idle <- stageUpload store "idle.nar" ["idle", " bytes"]
        active <- stageUpload store "active.nar" ["active"]
        createDirectory (tmpDir ++ "/uploads/stray")
        setModificationTime (tmpDir ++ "/uploads/stray") monthAgo
        traverse_ (backdateUpload monthAgo) . filter ((== "idle.nar") . Store.suFileName) =<< Store.listStagedUploads store
        reclaimed <- Reclaim.reclaim store Reclaim.defaultMinimumAge getCurrentTime
        remaining <- map Store.suFileName <$> Store.listStagedUploads store
        strayKept <- doesDirectoryExist (tmpDir ++ "/uploads/stray")
        removeDirectoryRecursive tmpDir
        let removals = either (const []) Reclaim.rdUploads reclaimed
            kept = either (const []) (Reclaim.upTooYoung . Reclaim.spUploads . Reclaim.rdPlan) reclaimed
        ok1 <- assertTrue "uploads staged" (isJust idle && isJust active)
        ok2 <- assertEqual "removed" [("idle.nar", 10, Store.UploadRemoved)] [(Store.suFileName u, Store.suSize u, outcome) | (u, outcome) <- removals]
        ok3 <- assertEqual "kept" ["active.nar"] (map Store.suFileName kept)
        ok4 <- assertEqual "remaining" ["active.nar"] remaining
        ok5 <- assertTrue "stray directory kept" strayKept
        pure (ok1 && ok2 && ok3 && ok4 && ok5),
      test "a part, or a part in progress, written to an idle upload makes it active again" $ do
        tmpDir <- createTestDir
        store <- Store.newFileStore tmpDir
        monthAgo <- addUTCTime (negate (30 * nominalDay)) <$> getCurrentTime
        staged <- stageUpload store "resumed.nar" ["first"]
        let ageNow = do
              scan <- Reclaim.scanStore store getCurrentTime
              let plan = Reclaim.selectAbandoned Reclaim.defaultMinimumAge (Reclaim.scanTime scan) (Reclaim.scanStagedUploads scan)
              pure (length (Reclaim.upEligible plan), length (Reclaim.upTooYoung plan))
            backdateAll = traverse_ (backdateUpload monthAgo) =<< Store.listStagedUploads store
        backdateAll
        idle <- ageNow
        written <- traverse (\uid -> writeStorePart store "resumed.nar" uid 2 ["second"] Server.maxNarBodySize) staged
        afterPart <- ageNow
        backdateAll
        -- A part in progress is a temp file in the upload's directory.
        uploads <- Store.listStagedUploads store
        traverse_ (\upload -> BS.writeFile (Store.suPath upload ++ "/.nova123-4.tmp") "partial" >> setModificationTime (Store.suPath upload) monthAgo) uploads
        afterTemp <- ageNow
        removeDirectoryRecursive tmpDir
        ok1 <- assertEqual "idle (eligible, kept)" (1, 0) idle
        ok2 <- assertEqual "part written" (Just (Just Store.PartWritten)) written
        ok3 <- assertEqual "after a part (eligible, kept)" (0, 1) afterPart
        ok4 <- assertEqual "after a part in progress (eligible, kept)" (0, 1) afterTemp
        pure (ok1 && ok2 && ok3 && ok4),
      test "a store with no uploads directory has no staged uploads" $ do
        tmpDir <- createTestDir
        store <- Store.newFileStore tmpDir
        removeDirectoryRecursive (tmpDir ++ "/uploads")
        uploads <- Store.listStagedUploads store
        removeDirectoryRecursive tmpDir
        assertEqual "uploads" [] uploads,
      test "removeUpload refuses a traversal name" $ do
        tmpDir <- createTestDir
        store <- Store.newFileStore tmpDir
        staged <- stageUpload store "kept.nar" ["kept"]
        outcomes <- traverse (Store.removeUpload store "../kept.nar") staged
        remaining <- map Store.suFileName <$> Store.listStagedUploads store
        removeDirectoryRecursive tmpDir
        ok1 <- assertEqual "outcome" (Just Store.UploadRemoveBadPath) outcomes
        ok2 <- assertEqual "remaining" ["kept.nar"] remaining
        pure (ok1 && ok2)
    ]

-- | Run a QuickCheck property quietly, printing its report on failure.
checkProperty :: (Testable prop) => prop -> IO Bool
checkProperty prop = do
  result <- quickCheckWithResult stdArgs {chatty = False} prop
  case result of
    Success {} -> pure True
    Failure {output = report} -> failWith report
    GaveUp {output = report} -> failWith report
    NoExpectedFailure {output = report} -> failWith report
  where
    failWith report = do
      putStrLn ""
      putStr report
      pure False

-- | The target of a narinfo rendered and read back as the store holds it.
narInfoBytesTarget :: NarInfo.NarInfo -> Reclaim.NarInfoTarget
narInfoBytesTarget = Reclaim.narInfoTarget . Right . TE.encodeUtf8 . NarInfo.renderNarInfo

isUnresolvable :: Reclaim.NarInfoTarget -> Bool
isUnresolvable (Reclaim.Unresolvable _) = True
isUnresolvable (Reclaim.NamesNar _) = False

-- | Everything a selection names, eligible or kept.
selectAll :: NominalDiffTime -> Set Text -> [Store.NarFile] -> [Store.NarFile]
selectAll minimumAge references nars =
  let plan = Reclaim.selectUnreferenced minimumAge referenceTime references nars
   in Reclaim.rpEligible plan ++ Reclaim.rpTooYoung plan

-- | A scan at 'referenceTime' of narinfos and NARs, with no staged
-- upload.
scanOf :: [(FilePath, Reclaim.NarInfoTarget)] -> [Store.NarFile] -> Reclaim.StoreScan
scanOf narInfos nars =
  Reclaim.StoreScan
    { Reclaim.scanNarInfos = narInfos,
      Reclaim.scanNars = nars,
      Reclaim.scanStagedUploads = [],
      Reclaim.scanTime = referenceTime
    }

-- | The fixed "now" of the pure selection tests.
referenceTime :: UTCTime
referenceTime = UTCTime (fromGregorian 2026 10 9) 0

ageOf :: Store.NarFile -> NominalDiffTime
ageOf nar = diffUTCTime referenceTime (Store.nfModified nar)

narAged :: Text -> NominalDiffTime -> Store.NarFile
narAged name age =
  Store.NarFile
    { Store.nfName = name,
      Store.nfPath = "nar/" ++ T.unpack name,
      Store.nfSize = 0,
      Store.nfModified = addUTCTime (negate age) referenceTime
    }

-- | NAR names from a small pool, so references and listings overlap
-- often.
narNamePool :: [Text]
narNamePool = [T.pack ("n" ++ show i ++ ".nar.zst") | i <- [0 .. 11 :: Int]]

genNarName :: Gen Text
genNarName = elements narNamePool

-- | Whole hours, so ages land on the minimum age exactly now and then;
-- the negative end is a modification time in the future (a clock that
-- stepped back).
genAge :: Gen NominalDiffTime
genAge = (* 3600) . fromInteger <$> choose (-2, 24 * 30)

genMinimumAge :: Gen NominalDiffTime
genMinimumAge = (* 3600) . fromInteger <$> choose (0, 24 * 21)

-- | A listing has distinct names, as a directory does.
genListing :: Gen [Store.NarFile]
genListing = traverse (\name -> narAged name <$> genAge) =<< sublistOf narNamePool

genSelection :: Gen (NominalDiffTime, Set Text, [Store.NarFile])
genSelection = (,,) <$> genMinimumAge <*> (Set.fromList <$> sublistOf narNamePool) <*> genListing

genTarget :: Gen Reclaim.NarInfoTarget
genTarget =
  frequency
    [ (4, Reclaim.NamesNar <$> genNarName),
      (1, pure (Reclaim.Unresolvable "unparseable"))
    ]

-- | An upload staged in a directory of its own, idle for a generated age.
genStagedUpload :: Gen Store.StagedUpload
genStagedUpload = do
  uid <- genUploadId
  age <- genAge
  pure
    Store.StagedUpload
      { Store.suFileName = "n.nar",
        Store.suUploadId = uid,
        Store.suPath = "uploads/" ++ T.unpack (Store.renderUploadId uid) ++ "-n.nar",
        Store.suSize = 0,
        Store.suModified = addUTCTime (negate age) referenceTime
      }

uploadAge :: Store.StagedUpload -> NominalDiffTime
uploadAge upload = diffUTCTime referenceTime (Store.suModified upload)

genUploadId :: Gen Store.UploadId
genUploadId = (T.pack <$> vectorOf 32 (elements lowerHexDigits)) `suchThatMap` Store.parseUploadId

lowerHexDigits :: String
lowerHexDigits = "0123456789abcdef"

-- | Begin an upload of a NAR in a store and write its parts in order:
-- the upload, when every step succeeded.
stageUpload :: Store.FileStore -> Text -> [ByteString] -> IO (Maybe Store.UploadId)
stageUpload store name parts = do
  begun <- Store.beginUpload store name
  case begun of
    Nothing -> pure Nothing
    Just uid -> do
      written <- zipWithM (\n bytes -> writeStorePart store name uid n [bytes] Server.maxNarBodySize) [1 ..] parts
      pure (if all (== Just Store.PartWritten) written then Just uid else Nothing)

-- | Write part @n@ of an upload from chunks, under a cap; 'Nothing' when
-- @n@ is not a part number.
writeStorePart :: Store.FileStore -> Text -> Store.UploadId -> Int -> [ByteString] -> Int -> IO (Maybe Store.PartWriteResult)
writeStorePart store name uid n chunks limit = case Store.parsePartNumber (T.pack (show n)) of
  Nothing -> pure Nothing
  Just part -> Just <$> (Store.writeUploadPart store name uid part limit =<< chunkSource chunks)

-- | Set the modification time of an upload's files, then of its
-- directory, which setting a file's time leaves alone.
backdateUpload :: UTCTime -> Store.StagedUpload -> IO ()
backdateUpload time upload = do
  files <- listDirectory (Store.suPath upload)
  traverse_ (\file -> setModificationTime (Store.suPath upload ++ "/" ++ file) time) files
  setModificationTime (Store.suPath upload) time

-- | Names 'Store.sanitizePath' admits.
genSafeNarName :: Gen Text
genSafeNarName =
  (T.pack <$> listOf1 (elements safeNameChars)) `suchThat` (isJust . Store.sanitizePath)
  where
    safeNameChars = ['a' .. 'z'] ++ ['A' .. 'Z'] ++ ['0' .. '9'] ++ "._+-"

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

-- | The file 'validServerNarInfo' names under @nar\/@.
serverNarName :: Text
serverNarName = "test.nar"

-- | The bytes 'validServerNarInfo' declares for its NAR.
serverNarBytes :: ByteString
serverNarBytes = "nar-payload-bytes"

-- | A narinfo that passes 'Validate.validateNarInfo' end to end, keyed
-- under 'validNarInfoHashKey', describing 'serverNarBytes' stored as
-- 'serverNarName'.
validServerNarInfo :: NarInfo.NarInfo
validServerNarInfo =
  NarInfo.NarInfo
    { NarInfo.niStorePath = "/nix/store/" <> validNarInfoHashKey <> "-hello-1.0",
      NarInfo.niUrl = "nar/" <> serverNarName,
      NarInfo.niCompression = "none",
      NarInfo.niFileHash = Just (Hash.formatNixHash (Hash.hashBytes serverNarBytes)),
      NarInfo.niFileSize = Just (fromIntegral (BS.length serverNarBytes)),
      NarInfo.niNarHash = zeroNarHash,
      NarInfo.niNarSize = 200,
      NarInfo.niReferences = [validNarInfoHashKey <> "-hello-1.0"],
      NarInfo.niDeriver = Nothing,
      NarInfo.niSigs = [],
      NarInfo.niCA = Nothing
    }

-- | Rendered wire form of 'validServerNarInfo'.
validServerNarInfoBytes :: BL.ByteString
validServerNarInfoBytes = renderNarInfoBody validServerNarInfo

-- | A narinfo's wire form as a request body.
renderNarInfoBody :: NarInfo.NarInfo -> BL.ByteString
renderNarInfoBody = BL.fromStrict . TE.encodeUtf8 . NarInfo.renderNarInfo

-- | Upload bytes as 'serverNarName', authenticated.
putServerNar :: Server.ServerConfig -> ByteString -> IO WT.SResponse
putServerNar cfg bytes = serverRequest cfg "PUT" ["nar", serverNarName] [serverAuthHeader] (BL.fromStrict bytes)

-- | Upload a narinfo under 'validNarInfoHashKey', authenticated.
putServerNarInfo :: Server.ServerConfig -> NarInfo.NarInfo -> IO WT.SResponse
putServerNarInfo cfg ni = serverRequest cfg "PUT" [validNarInfoHashKey <> ".narinfo"] [serverAuthHeader] (renderNarInfoBody ni)

-- | Upload a NAR, then a narinfo for it; the narinfo's response, and the
-- status a GET of that narinfo answers afterwards.
putNarThenNarInfo :: Server.ServerConfig -> ByteString -> NarInfo.NarInfo -> IO (WT.SResponse, HTTP.Status)
putNarThenNarInfo cfg bytes ni = do
  _ <- putServerNar cfg bytes
  putResp <- putServerNarInfo cfg ni
  getResp <- serverRequest cfg "GET" [validNarInfoHashKey <> ".narinfo"] [] ""
  pure (putResp, WT.simpleStatus getResp)

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

-- | Take every permission from a file, and say whether that left it
-- unreadable.  Windows has no mode bit that stops a read (and a
-- read-only file would then resist the test's cleanup), and root reads
-- a file whatever its mode, so on either there is no read failure to
-- cause.
makeUnreadable :: FilePath -> IO Bool
makeUnreadable path
  | System.Info.os == "mingw32" = pure False
  | otherwise = do
      setPermissions path emptyPermissions
      not . readable <$> getPermissions path

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
      test "GET / serves a deployment's root page as HTML" $
        withServer Nothing Nothing $ \cfg -> do
          let page = "<!DOCTYPE html><title>cache</title>"
          resp <- serverRequest cfg {Server.scRootResponse = Server.htmlRootResponse page} "GET" [] [] ""
          ok1 <- assertEqual "status" HTTP.status200 (WT.simpleStatus resp)
          ok2 <- assertEqual "content type" (Just "text/html; charset=utf-8") (lookup HTTP.hContentType (WT.simpleHeaders resp))
          ok3 <- assertEqual "body" page (strictBody resp)
          pure (ok1 && ok2 && ok3),
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
      -- existence with HEAD).
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
          _ <- putServerNar cfg serverNarBytes
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
          _ <- putServerNar cfg serverNarBytes
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
      -- A narinfo is signed and stored only over the NAR it describes,
      -- so an upload that went wrong fails here and the next push sends
      -- both again.
      test "PUT narinfo with no NAR stored is 400 and stores nothing" $
        withAuthedServer $ \cfg -> do
          putResp <- putServerNarInfo cfg validServerNarInfo
          getResp <- serverRequest cfg "GET" [validNarInfoHashKey <> ".narinfo"] [] ""
          ok1 <- assertEqual "PUT status" HTTP.status400 (WT.simpleStatus putResp)
          ok2 <- assertEqual "body" "NAR nar/test.nar is not stored; upload it before its narinfo" (strictBody putResp)
          ok3 <- assertEqual "GET status" HTTP.status404 (WT.simpleStatus getResp)
          pure (ok1 && ok2 && ok3),
      test "PUT narinfo over a short NAR is 400 and stores nothing" $
        withAuthedServer $ \cfg -> do
          (putResp, getStatus) <- putNarThenNarInfo cfg (BS.take 10 serverNarBytes) validServerNarInfo
          ok1 <- assertEqual "PUT status" HTTP.status400 (WT.simpleStatus putResp)
          ok2 <- assertEqual "body" "NAR nar/test.nar is 10 bytes, narinfo FileSize is 17" (strictBody putResp)
          ok3 <- assertEqual "GET status" HTTP.status404 getStatus
          pure (ok1 && ok2 && ok3),
      test "PUT narinfo over a same-size NAR of other content is 400 and stores nothing" $
        withAuthedServer $ \cfg -> do
          let other = BS.map (+ 1) serverNarBytes
          (putResp, getStatus) <- putNarThenNarInfo cfg other validServerNarInfo
          let expected =
                "NAR nar/test.nar hashes to "
                  <> TE.encodeUtf8 (Hash.formatNixHash (Hash.hashBytes other))
                  <> ", narinfo FileHash is "
                  <> TE.encodeUtf8 (Hash.formatNixHash (Hash.hashBytes serverNarBytes))
          ok1 <- assertEqual "PUT status" HTTP.status400 (WT.simpleStatus putResp)
          ok2 <- assertEqual "body" expected (strictBody putResp)
          ok3 <- assertEqual "GET status" HTTP.status404 getStatus
          pure (ok1 && ok2 && ok3),
      test "PUT narinfo over its NAR is 200 and stores it" $
        withAuthedServer $ \cfg -> do
          (putResp, getStatus) <- putNarThenNarInfo cfg serverNarBytes validServerNarInfo
          ok1 <- assertEqual "PUT status" HTTP.status200 (WT.simpleStatus putResp)
          ok2 <- assertEqual "GET status" HTTP.status200 getStatus
          pure (ok1 && ok2),
      test "a refused narinfo is accepted once the right NAR is uploaded again" $
        withAuthedServer $ \cfg -> do
          (refused, _) <- putNarThenNarInfo cfg (BS.take 10 serverNarBytes) validServerNarInfo
          (accepted, getStatus) <- putNarThenNarInfo cfg serverNarBytes validServerNarInfo
          ok1 <- assertEqual "first PUT status" HTTP.status400 (WT.simpleStatus refused)
          ok2 <- assertEqual "second PUT status" HTTP.status200 (WT.simpleStatus accepted)
          ok3 <- assertEqual "GET status" HTTP.status200 getStatus
          pure (ok1 && ok2 && ok3),
      test "PUT narinfo whose URL is not under nar/ is 400" $
        withAuthedServer $ \cfg -> do
          let elsewhere = validServerNarInfo {NarInfo.niUrl = "https://cache.example/nar/" <> serverNarName}
          (putResp, getStatus) <- putNarThenNarInfo cfg serverNarBytes elsewhere
          ok1 <- assertEqual "PUT status" HTTP.status400 (WT.simpleStatus putResp)
          ok2 <- assertEqual "body" "narinfo URL https://cache.example/nar/test.nar does not name a file under nar/" (strictBody putResp)
          ok3 <- assertEqual "GET status" HTTP.status404 getStatus
          pure (ok1 && ok2 && ok3),
      test "PUT narinfo without FileSize or FileHash is 400" $
        withAuthedServer $ \cfg -> do
          (noSize, _) <- putNarThenNarInfo cfg serverNarBytes validServerNarInfo {NarInfo.niFileSize = Nothing}
          (noHash, getStatus) <- putNarThenNarInfo cfg serverNarBytes validServerNarInfo {NarInfo.niFileHash = Nothing}
          ok1 <- assertEqual "no FileSize" (HTTP.status400, "narinfo declares no FileSize to check its NAR against") (WT.simpleStatus noSize, strictBody noSize)
          ok2 <- assertEqual "no FileHash" (HTTP.status400, "narinfo declares no FileHash to check its NAR against") (WT.simpleStatus noHash, strictBody noHash)
          ok3 <- assertEqual "GET status" HTTP.status404 getStatus
          pure (ok1 && ok2 && ok3),
      test "PUT narinfo over an unreadable NAR is 500 and stores nothing" $
        withAuthedServer $ \cfg -> do
          _ <- putServerNar cfg serverNarBytes
          unreadable <- makeUnreadable (Store.fsRoot (Server.scStore cfg) ++ "/nar/" ++ T.unpack serverNarName)
          if not unreadable
            then pure True
            else do
              putResp <- putServerNarInfo cfg validServerNarInfo
              getResp <- serverRequest cfg "GET" [validNarInfoHashKey <> ".narinfo"] [] ""
              ok1 <- assertEqual "PUT status" HTTP.status500 (WT.simpleStatus putResp)
              ok2 <- assertEqual "body" "NAR nar/test.nar could not be read" (strictBody putResp)
              ok3 <- assertEqual "GET status" HTTP.status404 (WT.simpleStatus getResp)
              pure (ok1 && ok2 && ok3),
      -- The hash listing is push-tool plumbing: authenticated, uncacheable.
      test "GET /narinfo-hashes without auth is 401" $
        withAuthedServer $ \cfg -> do
          resp <- serverRequest cfg "GET" ["narinfo-hashes"] [] ""
          assertEqual "status" HTTP.status401 (WT.simpleStatus resp),
      test "GET /narinfo-hashes with auth lists hashes, uncacheable" $
        withAuthedServer $ \cfg -> do
          _ <- putServerNar cfg serverNarBytes
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
-- Stored NAR check (pure)
-- ---------------------------------------------------------------------------

testStoredNarCheck :: IO Bool
testStoredNarCheck =
  runGroup
    "Stored NAR check"
    [ test "a narinfo URL resolves to the file its GET is routed to" $
        let cases =
              [ ("nar/1w1fff338fvdw53sqgamddn1b2xgds473pv6y13gizdbqjv4i5p3.nar.zst", Just "1w1fff338fvdw53sqgamddn1b2xgds473pv6y13gizdbqjv4i5p3.nar.zst"),
                ("nar/a%2Bb.nar", Just "a+b.nar"),
                ("nar/x.nar?v=1", Just "x.nar"),
                ("/nar/x.nar", Nothing),
                ("https://cache.example/nar/x.nar", Nothing),
                ("nar/../x.nar", Nothing),
                ("nar/a/x.nar", Nothing),
                ("x.nar", Nothing)
              ]
         in assertEqual
              "mismatches"
              []
              [(url, expected, actual) | (url, expected) <- cases, let actual = Server.narUrlFileName url, actual /= expected],
      test "property: a NAR's request path, as a narinfo URL, resolves to its name" $
        checkProperty $
          forAll (T.pack <$> arbitrary) $ \name ->
            Server.narUrlFileName (relativeRequestPath ["nar", name]) === Just name,
      test "property: a nar/<name> URL claims that name, FileSize and FileHash" $
        checkProperty $
          forAll genClaim $ \claim ->
            Server.narClaim (claimingNarInfo claim) === Right claim,
      test "a narinfo with no FileSize, no usable FileHash or no served URL claims nothing" $ do
        let refusal ni = either Just (const Nothing) (Server.narClaim ni)
            withUrl url = validServerNarInfo {NarInfo.niUrl = url}
        ok1 <- assertEqual "no FileSize" (Just Server.NarFileSizeUndeclared) (refusal validServerNarInfo {NarInfo.niFileSize = Nothing})
        ok2 <- assertEqual "no FileHash" (Just Server.NarFileHashUndeclared) (refusal validServerNarInfo {NarInfo.niFileHash = Nothing})
        ok3 <-
          assertTrue
            "unparseable FileHash"
            ( case refusal validServerNarInfo {NarInfo.niFileHash = Just "sha256:abc"} of
                Just (Server.NarFileHashInvalid "sha256:abc" _) -> True
                _ -> False
            )
        ok4 <-
          assertEqual
            "names no store could hold"
            [Just (Server.NarUrlNotServed url) | url <- unservedUrls]
            (map (refusal . withUrl) unservedUrls)
        pure (ok1 && ok2 && ok3 && ok4),
      test "property: a stored NAR is accepted exactly when it is the declared file" $
        checkProperty $
          forAll genClaim $ \claim ->
            forAll (genStoredNear claim) $ \stored ->
              isRight (Server.judgeStoredNar claim (Just stored))
                === (stored == Server.StoredNar (Server.ncFileSize claim) (Server.ncFileHash claim)),
      test "property: a NAR of another size is refused on its size" $
        checkProperty $
          forAll genClaim $ \claim ->
            forAll (genFileSize `suchThat` (/= Server.ncFileSize claim)) $ \size ->
              forAll genNixHash $ \digest ->
                Server.judgeStoredNar claim (Just (Server.StoredNar size digest))
                  === Left (Server.NarSizeMismatch (Server.ncFileName claim) (Server.ncFileSize claim) size),
      test "property: a same-size NAR of other content is refused on its hash" $
        checkProperty $
          forAll genClaim $ \claim ->
            forAll (genNixHash `suchThat` (/= Server.ncFileHash claim)) $ \digest ->
              Server.judgeStoredNar claim (Just (Server.StoredNar (Server.ncFileSize claim) digest))
                === Left (Server.NarHashMismatch (Server.ncFileName claim) (Server.ncFileHash claim) digest),
      test "property: an absent NAR is refused as not stored" $
        checkProperty $
          forAll genClaim $ \claim ->
            Server.judgeStoredNar claim Nothing === Left (Server.NarNotStored (Server.ncFileName claim))
    ]

-- | URLs that name nothing under @nar\/@ a store could hold: an empty
-- name, an upload's temp-file name, and a Windows device.
unservedUrls :: [Text]
unservedUrls = ["nar/", "nar/.nova123-4.tmp", "nar/nul"]

-- | The request path a client forms for segments, relative to the cache
-- root and percent-encoded as http-types encodes a path.
relativeRequestPath :: [Text] -> Text
relativeRequestPath =
  TE.decodeLatin1 . BL.toStrict . Builder.toLazyByteString . HTTP.encodePathSegmentsRelative

-- | 'validServerNarInfo' declaring a claim's name, FileSize and FileHash.
claimingNarInfo :: Server.NarClaim -> NarInfo.NarInfo
claimingNarInfo claim =
  validServerNarInfo
    { NarInfo.niUrl = "nar/" <> Server.ncFileName claim,
      NarInfo.niFileSize = Just (Server.ncFileSize claim),
      NarInfo.niFileHash = Just (Hash.formatNixHash (Server.ncFileHash claim))
    }

-- | A FileSize the narinfo parser admits: up to the uint64 maximum.
genFileSize :: Gen Integer
genFileSize = choose (0, 18446744073709551615)

genNixHash :: Gen Hash.NixHash
genNixHash = Hash.NixHash . BS.pack <$> vectorOf 32 arbitrary

genClaim :: Gen Server.NarClaim
genClaim = Server.NarClaim <$> genSafeNarName <*> genFileSize <*> genNixHash

-- | A stored NAR that keeps or replaces each of the claim's size and
-- hash independently, so the exact file turns up about a quarter of
-- the time.
genStoredNear :: Server.NarClaim -> Gen Server.StoredNar
genStoredNear claim =
  Server.StoredNar
    <$> oneof [pure (Server.ncFileSize claim), genFileSize]
    <*> oneof [pure (Server.ncFileHash claim), genNixHash]

-- ---------------------------------------------------------------------------
-- Multipart upload tests
-- ---------------------------------------------------------------------------

-- | Begin an upload of a NAR, authenticated: the response, and the id
-- its body carries.
beginServerUpload :: Server.ServerConfig -> Text -> IO (WT.SResponse, Text)
beginServerUpload cfg name = do
  resp <- serverRequest cfg "POST" ["nar", name, "uploads"] [serverAuthHeader] ""
  pure (resp, T.strip (TE.decodeLatin1 (strictBody resp)))

-- | Send a part of an upload, authenticated, by the part number as the
-- path spells it.
putServerPart :: Server.ServerConfig -> Text -> Text -> Text -> ByteString -> IO WT.SResponse
putServerPart cfg name uploadId part bytes =
  serverRequest cfg "PUT" ["nar", name, "uploads", uploadId, part] [serverAuthHeader] (BL.fromStrict bytes)

-- | Complete an upload with a body, authenticated.
completeServerUpload :: Server.ServerConfig -> Text -> Text -> ByteString -> IO WT.SResponse
completeServerUpload cfg name uploadId body =
  serverRequest cfg "POST" ["nar", name, "uploads", uploadId] [serverAuthHeader] (BL.fromStrict body)

-- | A completion body, spelled out as the protocol defines it rather
-- than rendered, so a change to the wire format fails here.
totalsBody :: Int -> Int -> ByteString
totalsBody parts size = TE.encodeUtf8 (T.pack ("Parts: " ++ show parts ++ "\nFileSize: " ++ show size ++ "\n"))

-- | Upload bytes as a NAR, one request per part: the statuses of the
-- begin, of each part and of the completion, in order.
uploadInParts :: Server.ServerConfig -> Text -> [ByteString] -> IO [HTTP.Status]
uploadInParts cfg name parts = do
  (begun, uploadId) <- beginServerUpload cfg name
  sent <- zipWithM (putServerPart cfg name uploadId . T.pack . show) [1 :: Int ..] parts
  completed <- completeServerUpload cfg name uploadId (totalsBody (length parts) (sum (map BS.length parts)))
  pure (map WT.simpleStatus (begun : sent ++ [completed]))

-- | The entries of a store subdirectory, sorted.
storeEntries :: Server.ServerConfig -> FilePath -> IO [FilePath]
storeEntries cfg subdir = sort <$> listDirectory (Store.fsRoot (Server.scStore cfg) ++ "/" ++ subdir)

-- | The files each staged upload's directory holds.
stagedFiles :: Server.ServerConfig -> IO [[FilePath]]
stagedFiles cfg = traverse (fmap sort . listDirectory . Store.suPath) =<< Store.listStagedUploads (Server.scStore cfg)

-- | A response's status and body.
statusAndBody :: WT.SResponse -> (HTTP.Status, ByteString)
statusAndBody resp = (WT.simpleStatus resp, strictBody resp)

-- | Split bytes at each length in turn, the remainder last, so there is
-- always one part more than lengths.
splitAtLengths :: [Int] -> ByteString -> [ByteString]
splitAtLengths [] rest = [rest]
splitAtLengths (len : lens) bytes = case BS.splitAt len bytes of
  (piece, rest) -> piece : splitAtLengths lens rest

testMultipartUpload :: IO Bool
testMultipartUpload =
  runGroup
    "Multipart upload"
    [ test "a NAR uploaded in parts is served back byte for byte, and its narinfo is accepted" $
        withAuthedServer $ \cfg -> do
          statuses <- uploadInParts cfg serverNarName ["nar-pay", "load-by", "tes"]
          getResp <- serverRequest cfg "GET" ["nar", serverNarName] [] ""
          narInfoResp <- putServerNarInfo cfg validServerNarInfo
          staged <- storeEntries cfg "uploads"
          ok1 <- assertEqual "statuses" (HTTP.status201 : replicate 4 HTTP.status200) statuses
          ok2 <- assertEqual "GET" (HTTP.status200, serverNarBytes) (statusAndBody getResp)
          ok3 <- assertEqual "narinfo status" HTTP.status200 (WT.simpleStatus narInfoResp)
          ok4 <- assertEqual "uploads left staged" [] staged
          pure (ok1 && ok2 && ok3 && ok4),
      test "beginning an upload answers 201, its id, and its path relative to the request's" $
        withAuthedServer $ \cfg -> do
          (begun, uploadId) <- beginServerUpload cfg serverNarName
          (_, otherId) <- beginServerUpload cfg serverNarName
          ok1 <- assertEqual "status" HTTP.status201 (WT.simpleStatus begun)
          ok2 <- assertTrue "id is 32 lowercase hex digits" (T.length uploadId == 32 && T.all (`elem` lowerHexDigits) uploadId)
          ok3 <- assertEqual "body" (TE.encodeUtf8 uploadId <> "\n") (strictBody begun)
          ok4 <- assertEqual "Location" (Just ("uploads/" <> TE.encodeUtf8 uploadId)) (lookup HTTP.hLocation (WT.simpleHeaders begun))
          ok5 <- assertTrue "each upload has its own id" (uploadId /= otherId)
          pure (ok1 && ok2 && ok3 && ok4 && ok5),
      test "an upload in progress leaves nothing under nar/" $
        withAuthedServer $ \cfg -> do
          (_, uploadId) <- beginServerUpload cfg serverNarName
          _ <- putServerPart cfg serverNarName uploadId "1" "nar-payload"
          _ <- putServerPart cfg serverNarName uploadId "2" "-bytes"
          refused <- completeServerUpload cfg serverNarName uploadId (totalsBody 3 17)
          nars <- storeEntries cfg "nar"
          getResp <- serverRequest cfg "GET" ["nar", serverNarName] [] ""
          narInfoResp <- putServerNarInfo cfg validServerNarInfo
          ok1 <- assertEqual "completion" HTTP.status409 (WT.simpleStatus refused)
          ok2 <- assertEqual "nar/" [] nars
          ok3 <- assertEqual "GET status" HTTP.status404 (WT.simpleStatus getResp)
          ok4 <- assertEqual "narinfo" (HTTP.status400, "NAR nar/test.nar is not stored; upload it before its narinfo") (statusAndBody narInfoResp)
          pure (ok1 && ok2 && ok3 && ok4),
      test "every upload request needs the write key" $
        withAuthedServer $ \cfg -> do
          (_, uploadId) <- beginServerUpload cfg serverNarName
          let requests headers =
                [ serverRequest cfg "POST" ["nar", serverNarName, "uploads"] headers "",
                  serverRequest cfg "PUT" ["nar", serverNarName, "uploads", uploadId, "1"] headers (BL.fromStrict serverNarBytes),
                  serverRequest cfg "POST" ["nar", serverNarName, "uploads", uploadId] headers (BL.fromStrict (totalsBody 1 17))
                ]
          missing <- traverse (fmap WT.simpleStatus) (requests [])
          wrong <- traverse (fmap WT.simpleStatus) (requests [(HTTP.hAuthorization, "Bearer not-the-key")])
          staged <- stagedFiles cfg
          nars <- storeEntries cfg "nar"
          ok1 <- assertEqual "without a key" (replicate 3 HTTP.status401) missing
          ok2 <- assertEqual "with the wrong key" (replicate 3 HTTP.status401) wrong
          ok3 <- assertEqual "staged: the one authenticated upload, holding no part" [[]] staged
          ok4 <- assertEqual "nar/" [] nars
          pure (ok1 && ok2 && ok3 && ok4),
      test "a part that would leave a gap is 409, and the upload still completes" $
        withAuthedServer $ \cfg -> do
          (_, uploadId) <- beginServerUpload cfg serverNarName
          early <- putServerPart cfg serverNarName uploadId "2" "load-by"
          firstPart <- putServerPart cfg serverNarName uploadId "1" "nar-pay"
          skipped <- putServerPart cfg serverNarName uploadId "3" "tes"
          staged <- stagedFiles cfg
          _ <- putServerPart cfg serverNarName uploadId "2" "load-by"
          _ <- putServerPart cfg serverNarName uploadId "3" "tes"
          completed <- completeServerUpload cfg serverNarName uploadId (totalsBody 3 17)
          getResp <- serverRequest cfg "GET" ["nar", serverNarName] [] ""
          ok1 <- assertEqual "part 2 first" (HTTP.status409, "upload of nar/test.nar holds 0 parts, so the next is part 1, not part 2") (statusAndBody early)
          ok2 <- assertEqual "part 1" HTTP.status200 (WT.simpleStatus firstPart)
          ok3 <- assertEqual "part 3 after part 1" (HTTP.status409, "upload of nar/test.nar holds 1 part, so the next is part 2, not part 3") (statusAndBody skipped)
          ok4 <- assertEqual "parts held after the refusals" [["1"]] staged
          ok5 <- assertEqual "completion" HTTP.status200 (WT.simpleStatus completed)
          ok6 <- assertEqual "GET body" serverNarBytes (strictBody getResp)
          pure (ok1 && ok2 && ok3 && ok4 && ok5 && ok6),
      test "a part sent again replaces the one held" $
        withAuthedServer $ \cfg -> do
          (_, uploadId) <- beginServerUpload cfg serverNarName
          _ <- putServerPart cfg serverNarName uploadId "1" "a first attempt"
          _ <- putServerPart cfg serverNarName uploadId "2" "-bytes"
          resent <- putServerPart cfg serverNarName uploadId "1" "nar-payload"
          completed <- completeServerUpload cfg serverNarName uploadId (totalsBody 2 17)
          getResp <- serverRequest cfg "GET" ["nar", serverNarName] [] ""
          ok1 <- assertEqual "part 1 again" HTTP.status200 (WT.simpleStatus resent)
          ok2 <- assertEqual "completion" HTTP.status200 (WT.simpleStatus completed)
          ok3 <- assertEqual "GET body" serverNarBytes (strictBody getResp)
          pure (ok1 && ok2 && ok3),
      test "a part number other than 1 to 10000 in canonical decimal is 400" $
        withAuthedServer $ \cfg -> do
          (_, uploadId) <- beginServerUpload cfg serverNarName
          let spellings = ["0", "01", "10001", "-1", "+1", "1.0", "one", ""]
          responses <- traverse (\part -> putServerPart cfg serverNarName uploadId part "x") spellings
          staged <- stagedFiles cfg
          ok1 <- assertEqual "statuses" (map (const HTTP.status400) spellings) (map WT.simpleStatus responses)
          ok2 <- assertEqual "body" "part number must be a whole number from 1 to 10000" (foldMap strictBody (take 1 responses))
          ok3 <- assertEqual "parts held" [[]] staged
          pure (ok1 && ok2 && ok3),
      test "a part declaring more than the NAR cap is 413 before it is read" $
        withAuthedServer $ \cfg -> do
          (_, uploadId) <- beginServerUpload cfg serverNarName
          resp <-
            serverRequestSized
              cfg
              "PUT"
              ["nar", serverNarName, "uploads", uploadId, "1"]
              [serverAuthHeader]
              (fromIntegral Server.maxNarBodySize + 1)
          staged <- stagedFiles cfg
          ok1 <- assertEqual "status" HTTP.status413 (WT.simpleStatus resp)
          ok2 <- assertEqual "parts held" [[]] staged
          pure (ok1 && ok2),
      test "an upload's parts are held to the cap together, and a part over it changes nothing" $ do
        tmpDir <- createTestDir
        store <- Store.newFileStore tmpDir
        staged <- stageUpload store "capped.nar" ["abc"]
        let write n chunks = maybe (pure Nothing) (\uid -> writeStorePart store "capped.nar" uid n chunks 8) staged
        over <- write 2 ["fgh", "ijk"]
        heldAfterOver <- traverse (fmap sort . listDirectory . Store.suPath) =<< Store.listStagedUploads store
        fits <- write 2 ["defgh"]
        regrown <- write 1 ["abcd"]
        completed <- traverse (\uid -> traverse (Store.completeUpload store "capped.nar" uid 8) (totalsOf 2 8)) staged
        stored <- Store.readNar store "capped.nar"
        removeDirectoryRecursive tmpDir
        ok1 <- assertEqual "part 2 over the cap" (Just Store.PartTooLarge) over
        ok2 <- assertEqual "files held after it" [["1"]] heldAfterOver
        ok3 <- assertEqual "part 2 within the cap" (Just Store.PartWritten) fits
        ok4 <- assertEqual "part 1 again, past the cap with part 2" (Just Store.PartTooLarge) regrown
        ok5 <- assertEqual "completion" (Just (Just Store.UploadCompleted)) completed
        ok6 <- assertEqual "stored" (Just "abcdefgh") stored
        pure (ok1 && ok2 && ok3 && ok4 && ok5 && ok6),
      test "two part writes at once can pass the cap together, and completion refuses what they join to" $ do
        tmpDir <- createTestDir
        store <- Store.newFileStore tmpDir
        staged <- stageUpload store "raced.nar" ["a", "b"]
        -- Part 2 is written while part 1 streams, so each finds the other
        -- at one byte and is allowed seven under a cap of eight.
        raced <- for staged $ \uid -> do
          secondWrite <- newIORef Nothing
          rest <- chunkSource ["1111111"]
          let source = do
                pending <- readIORef secondWrite
                case pending of
                  Nothing -> writeIORef secondWrite . Just =<< writeStorePart store "raced.nar" uid 2 ["2222222"] 8
                  Just _ -> pure ()
                rest
          first <- traverse (\part -> Store.writeUploadPart store "raced.nar" uid part 8 source) (Store.parsePartNumber "1")
          second <- readIORef secondWrite
          completed <- traverse (Store.completeUpload store "raced.nar" uid 8) (totalsOf 2 14)
          pure (first, second, completed)
        nars <- listDirectory (tmpDir ++ "/nar")
        removeDirectoryRecursive tmpDir
        ok1 <- assertEqual "both parts written" (Just (Just Store.PartWritten, Just (Just Store.PartWritten))) (fmap (\(first, second, _) -> (first, second)) raced)
        ok2 <- assertEqual "completion" (Just (Just (Store.CompletionTooLarge 14))) (fmap (\(_, _, completed) -> completed) raced)
        ok3 <- assertEqual "nar/" [] nars
        pure (ok1 && ok2 && ok3),
      test "a join that cannot be renamed into nar/ leaves no copy behind" $ do
        tmpDir <- createTestDir
        store <- Store.newFileStore tmpDir
        staged <- stageUpload store "blocked.nar" ["nar", "-bytes"]
        createDirectory (tmpDir ++ "/nar/blocked.nar")
        completed <- for staged $ \uid -> traverse (tryIO . Store.completeUpload store "blocked.nar" uid Server.maxNarBodySize) (totalsOf 2 9)
        held <- traverse (fmap sort . listDirectory . Store.suPath) =<< Store.listStagedUploads store
        removeDirectoryRecursive tmpDir
        ok1 <- assertTrue "completion failed" (case completed of Just (Just (Left _)) -> True; _ -> False)
        ok2 <- assertEqual "files held" [["1", "2"]] held
        pure (ok1 && ok2),
      test "a temp file left in an upload is neither joined nor left behind" $ do
        tmpDir <- createTestDir
        store <- Store.newFileStore tmpDir
        staged <- stageUpload store "tidy.nar" ["abc"]
        traverse_ (\upload -> BS.writeFile (Store.suPath upload ++ "/.nova123-4.tmp") "leftover") =<< Store.listStagedUploads store
        completed <- for staged $ \uid -> traverse (Store.completeUpload store "tidy.nar" uid 8) (totalsOf 1 3)
        stored <- Store.readNar store "tidy.nar"
        remaining <- listDirectory (tmpDir ++ "/uploads")
        removeDirectoryRecursive tmpDir
        ok1 <- assertEqual "completion" (Just (Just Store.UploadCompleted)) completed
        ok2 <- assertEqual "stored" (Just "abc") stored
        ok3 <- assertEqual "uploads/" [] remaining
        pure (ok1 && ok2 && ok3),
      test "a completion declaring a FileSize over the NAR cap is 413" $
        withAuthedServer $ \cfg -> do
          (_, uploadId) <- beginServerUpload cfg serverNarName
          _ <- putServerPart cfg serverNarName uploadId "1" serverNarBytes
          resp <- completeServerUpload cfg serverNarName uploadId (totalsBody 1 (Server.maxNarBodySize + 1))
          nars <- storeEntries cfg "nar"
          ok1 <- assertEqual "refusal" (HTTP.status413, "FileSize 4294967297 is over the 4294967296 bytes a NAR may hold") (statusAndBody resp)
          ok2 <- assertEqual "nar/" [] nars
          pure (ok1 && ok2),
      test "a NAR name too long to stage is 400" $
        withAuthedServer $ \cfg -> do
          -- The staging directory is named by the 32-digit id, a dash and
          -- the NAR's name, 256 long here, past the 255 a file name holds.
          resp <- serverRequest cfg "POST" ["nar", T.replicate 219 "a" <> ".nar", "uploads"] [serverAuthHeader] ""
          staged <- storeEntries cfg "uploads"
          ok1 <- assertEqual "refusal" (HTTP.status400, "invalid path") (statusAndBody resp)
          ok2 <- assertEqual "uploads begun" [] staged
          pure (ok1 && ok2),
      test "a request for an upload that is not staged is 404" $
        withAuthedServer $ \cfg -> do
          (_, otherId) <- beginServerUpload cfg "other.nar"
          (_, uploadId) <- beginServerUpload cfg serverNarName
          _ <- putServerPart cfg serverNarName uploadId "1" serverNarBytes
          _ <- completeServerUpload cfg serverNarName uploadId (totalsBody 1 17)
          let neverIssued = T.replicate 32 "0"
          responses <-
            sequence
              [ completeServerUpload cfg serverNarName neverIssued (totalsBody 1 17),
                putServerPart cfg serverNarName neverIssued "1" "x",
                completeServerUpload cfg serverNarName "not-an-id" (totalsBody 1 17),
                completeServerUpload cfg serverNarName otherId (totalsBody 1 17),
                completeServerUpload cfg serverNarName uploadId (totalsBody 1 17),
                putServerPart cfg serverNarName uploadId "2" "x"
              ]
          ok1 <- assertEqual "statuses" (map (const HTTP.status404) responses) (map WT.simpleStatus responses)
          ok2 <- assertEqual "body" ("no upload " <> TE.encodeUtf8 neverIssued <> " of nar/test.nar") (foldMap strictBody (take 1 responses))
          pure (ok1 && ok2),
      test "a NAR name the store cannot hold is 400 on every upload request" $
        withAuthedServer $ \cfg -> do
          let uploadId = T.replicate 32 "0"
          responses <-
            sequence
              [ serverRequest cfg "POST" ["nar", "..", "uploads"] [serverAuthHeader] "",
                serverRequest cfg "POST" ["nar", ".nova.tmp1", "uploads"] [serverAuthHeader] "",
                putServerPart cfg "nul" uploadId "1" "x",
                completeServerUpload cfg "a/b" uploadId (totalsBody 1 1)
              ]
          staged <- storeEntries cfg "uploads"
          ok1 <- assertEqual "statuses" (map (const HTTP.status400) responses) (map WT.simpleStatus responses)
          ok2 <- assertEqual "uploads begun" [] staged
          pure (ok1 && ok2),
      test "a completion declaring other parts or another size is 409, and the upload stays" $
        withAuthedServer $ \cfg -> do
          (_, uploadId) <- beginServerUpload cfg serverNarName
          _ <- putServerPart cfg serverNarName uploadId "1" "nar-payload"
          _ <- putServerPart cfg serverNarName uploadId "2" "-bytes"
          refusals <- traverse (completeServerUpload cfg serverNarName uploadId) [totalsBody 3 17, totalsBody 1 17, totalsBody 2 18, totalsBody 2 16]
          nars <- storeEntries cfg "nar"
          staged <- stagedFiles cfg
          completed <- completeServerUpload cfg serverNarName uploadId (totalsBody 2 17)
          getResp <- serverRequest cfg "GET" ["nar", serverNarName] [] ""
          ok1 <-
            assertEqual
              "refusals"
              [ (HTTP.status409, "upload of nar/test.nar holds 2 parts, Parts is 3"),
                (HTTP.status409, "upload of nar/test.nar holds 2 parts, Parts is 1"),
                (HTTP.status409, "upload of nar/test.nar joins to 17 bytes, FileSize is 18"),
                (HTTP.status409, "upload of nar/test.nar joins to 17 bytes, FileSize is 16")
              ]
              (map statusAndBody refusals)
          ok2 <- assertEqual "nar/" [] nars
          ok3 <- assertEqual "files held, no join left behind" [["1", "2"]] staged
          ok4 <- assertEqual "completion" HTTP.status200 (WT.simpleStatus completed)
          ok5 <- assertEqual "GET body" serverNarBytes (strictBody getResp)
          pure (ok1 && ok2 && ok3 && ok4 && ok5),
      test "a completion body other than one Parts line and one FileSize line is refused" $ do
        let refused =
              [ "",
                "Parts: 1\n",
                "FileSize: 3\n",
                "Parts: 1\nFileSize: 3\nFileHash: sha256:00\n",
                "Parts: 1\nParts: 1\nFileSize: 3\n",
                "Parts: 01\nFileSize: 3\n",
                "Parts: 1\nFileSize: 03\n",
                "Parts: 1\nFileSize: -3\n",
                "Parts: 1\nFileSize: 3 \n",
                "Parts: 0\nFileSize: 0\n",
                "Parts: 10001\nFileSize: 3\n",
                "Parts 1\nFileSize: 3\n",
                "Parts: 1\n\nFileSize: 3\n",
                "Parts: 1\r\nFileSize: 3\r\n",
                "Parts: 1\nFileSize: 123456789012345678901\n",
                BS.pack [0x50, 0xff]
              ]
            accepted = ["FileSize: 3\nParts: 1\n", "Parts: 1\nFileSize: 3"]
            expected = map (const (totalsOf 1 3)) accepted
        ok1 <- assertEqual "refused bodies accepted" [] [body | body <- refused, isRight (Server.parseUploadTotals body)]
        ok2 <- assertEqual "accepted" expected (map (either (const Nothing) Just . Server.parseUploadTotals) accepted)
        pure (ok1 && ok2),
      test "a malformed completion body is 400, and one over its cap is 413" $
        withAuthedServer $ \cfg -> do
          (_, uploadId) <- beginServerUpload cfg serverNarName
          _ <- putServerPart cfg serverNarName uploadId "1" serverNarBytes
          malformed <- completeServerUpload cfg serverNarName uploadId "Parts: 1\n"
          oversized <- completeServerUpload cfg serverNarName uploadId (BS.replicate (Server.maxUploadTotalsBodySize + 1) 0x20)
          nars <- storeEntries cfg "nar"
          ok1 <- assertEqual "malformed" (HTTP.status400, "completion body has no FileSize line") (statusAndBody malformed)
          ok2 <- assertEqual "oversized" HTTP.status413 (WT.simpleStatus oversized)
          ok3 <- assertEqual "nar/" [] nars
          pure (ok1 && ok2 && ok3),
      test "two uploads of one NAR stage apart" $
        withAuthedServer $ \cfg -> do
          (_, firstId) <- beginServerUpload cfg serverNarName
          (_, secondId) <- beginServerUpload cfg serverNarName
          _ <- putServerPart cfg serverNarName firstId "1" "first"
          _ <- putServerPart cfg serverNarName secondId "1" "second"
          _ <- completeServerUpload cfg serverNarName firstId (totalsBody 1 5)
          afterFirst <- serverRequest cfg "GET" ["nar", serverNarName] [] ""
          _ <- completeServerUpload cfg serverNarName secondId (totalsBody 1 6)
          afterSecond <- serverRequest cfg "GET" ["nar", serverNarName] [] ""
          ok1 <- assertEqual "after the first" "first" (strictBody afterFirst)
          ok2 <- assertEqual "after the second" "second" (strictBody afterSecond)
          pure (ok1 && ok2),
      test "property: a NAR uploaded in parts of any sizes is served back byte for byte" $
        withAuthedServer $ \cfg ->
          checkProperty $
            forAll genSplitBytes $ \(bytes, lengths) ->
              ioProperty $ do
                let parts = splitAtLengths lengths bytes
                statuses <- uploadInParts cfg serverNarName parts
                served <- serverRequest cfg "GET" ["nar", serverNarName] [] ""
                pure ((statuses === HTTP.status201 : replicate (length parts + 1) HTTP.status200) .&&. (strictBody served === bytes)),
      test "property: completion totals render and parse back" $
        checkProperty $
          forAll genUploadTotals $ \totals ->
            Server.parseUploadTotals (Server.renderUploadTotals totals) === Right totals,
      test "property: a part number reads back exactly when it is 1 to 10000 in canonical decimal" $
        checkProperty $
          forAll (choose (-3, Store.maxUploadParts + 3)) $ \n ->
            let spelled = T.pack (show n)
                inRange = n >= 1 && n <= Store.maxUploadParts
             in ((Store.renderPartNumber <$> Store.parsePartNumber spelled) === (spelled <$ guard inRange))
                  .&&. (Store.parsePartNumber ("0" <> spelled) === Nothing),
      test "property: an upload id reads back exactly when it is 32 lowercase hex digits" $
        checkProperty $
          forAll genUploadIdText $ \txt ->
            let wellFormed = T.length txt == 32 && T.all (`elem` lowerHexDigits) txt
             in (Store.renderUploadId <$> Store.parseUploadId txt) === (txt <$ guard wellFormed)
    ]

-- | Bytes, and the lengths of the parts to split them into before the
-- last; a length may run past the bytes, which leaves empty parts.
genSplitBytes :: Gen (ByteString, [Int])
genSplitBytes = do
  bytes <- BS.pack <$> listOf arbitrary
  lengths <- listOf (choose (0, 24))
  pure (bytes, lengths)

-- | 'try' at 'IOException'.
tryIO :: IO a -> IO (Either IOException a)
tryIO = try

-- | Totals over every part count and any size up to the uint64 maximum.
genUploadTotals :: Gen Store.UploadTotals
genUploadTotals =
  Store.UploadTotals
    <$> (T.pack . show <$> choose (1, Store.maxUploadParts)) `suchThatMap` Store.parsePartNumber
    <*> genFileSize

-- | Mostly upload ids, and near misses: a digit short or over, or an
-- uppercase digit.
genUploadIdText :: Gen Text
genUploadIdText =
  oneof
    [ T.pack <$> vectorOf 32 (elements lowerHexDigits),
      T.pack <$> vectorOf 31 (elements lowerHexDigits),
      T.pack <$> vectorOf 33 (elements lowerHexDigits),
      T.pack <$> vectorOf 32 (elements (lowerHexDigits ++ "ABCDEF"))
    ]

-- | 'Store.UploadTotals' of a part count and size; 'Nothing' when the
-- count is not a part number.
totalsOf :: Int -> Integer -> Maybe Store.UploadTotals
totalsOf parts size = (`Store.UploadTotals` size) <$> Store.parsePartNumber (T.pack (show parts))

-- ---------------------------------------------------------------------------
-- Removal tests
-- ---------------------------------------------------------------------------

-- | The hash of a second store path, for an entry a test keeps.
otherHashKey :: Text
otherHashKey = T.replicate 32 "1"

-- | 'validServerNarInfo' for the store path of a hash, describing bytes
-- stored under a NAR's name.
entryNarInfo :: Text -> Text -> ByteString -> NarInfo.NarInfo
entryNarInfo hashKey narName bytes =
  validServerNarInfo
    { NarInfo.niStorePath = "/nix/store/" <> hashKey <> "-entry-1.0",
      NarInfo.niUrl = "nar/" <> narName,
      NarInfo.niFileHash = Just (Hash.formatNixHash (Hash.hashBytes bytes)),
      NarInfo.niFileSize = Just (fromIntegral (BS.length bytes)),
      NarInfo.niReferences = []
    }

-- | Upload a NAR, then a narinfo naming it, authenticated: the status
-- the narinfo is answered with.
putEntry :: Server.ServerConfig -> NarInfo.NarInfo -> Text -> ByteString -> IO HTTP.Status
putEntry cfg ni narName bytes = do
  _ <- serverRequest cfg "PUT" ["nar", narName] [serverAuthHeader] (BL.fromStrict bytes)
  WT.simpleStatus <$> putEntryNarInfo cfg ni

-- | Upload a narinfo under its own store path's hash, authenticated.
putEntryNarInfo :: Server.ServerConfig -> NarInfo.NarInfo -> IO WT.SResponse
putEntryNarInfo cfg ni =
  serverRequest cfg "PUT" [T.take 32 (T.drop (T.length "/nix/store/") (NarInfo.niStorePath ni)) <> ".narinfo"] [serverAuthHeader] (renderNarInfoBody ni)

-- | Store an entry the tests keep, so a store holds a narinfo besides
-- the ones a test removes and a reclaim is not blocked for want of one.
putKeptEntry :: Server.ServerConfig -> IO HTTP.Status
putKeptEntry cfg = putEntry cfg (entryNarInfo otherHashKey "kept.nar" "kept-bytes") "kept.nar" "kept-bytes"

-- | Set a stored NAR's modification time a month back, past the default
-- minimum age.
ageNar :: Server.ServerConfig -> Text -> IO ()
ageNar cfg name = do
  monthAgo <- addUTCTime (negate (30 * nominalDay)) <$> getCurrentTime
  setModificationTime (Store.fsRoot (Server.scStore cfg) ++ "/nar/" ++ T.unpack name) monthAgo

-- | A GET's status and body.
getResource :: Server.ServerConfig -> [Text] -> IO (HTTP.Status, ByteString)
getResource cfg segments = statusAndBody <$> serverRequest cfg "GET" segments [] ""

-- | A reclaim request with a query, authenticated.
reclaimQuery :: Server.ServerConfig -> BS.ByteString -> HTTP.Query -> IO WT.SResponse
reclaimQuery cfg method query =
  WT.runSession (WT.srequest (WT.SRequest req "")) (Server.cacheApp cfg)
  where
    req =
      defaultRequest
        { requestMethod = method,
          pathInfo = ["reclaim"],
          requestHeaders = [serverAuthHeader],
          queryString = query
        }

-- | The report a reclaim at the default minimum age answers with,
-- spelled out, so a change to its form fails here.
reclaimReport :: [ByteString] -> ByteString
reclaimReport body = BS.concat (map (<> "\n") ("minimum age: 336 hours" : body))

-- | How a thread stands once it has run as far as it can.
data Settled
  = -- | Waiting in STM, which in these tests is a store's gate.
    AtGate
  | Finished
  | -- | Waiting on an MVar, which nothing in these tests releases.
    BlockedElsewhere
  deriving (Eq, Show)

-- | Yield to a thread until it finishes or waits, and say which.  This
-- suite runs on the single-threaded runtime, where a thread that has
-- neither finished nor blocked is runnable and runs while this one
-- yields, so the loop waits on the thread's own progress and no clock.
settle :: ThreadId -> IO Settled
settle thread = do
  status <- threadStatus thread
  case status of
    ThreadFinished -> pure Finished
    ThreadDied -> pure Finished
    ThreadBlocked BlockedOnSTM -> pure AtGate
    ThreadBlocked BlockedOnMVar -> pure BlockedElsewhere
    ThreadBlocked _ -> yield >> settle thread
    ThreadRunning -> yield >> settle thread

-- | Run an action in a thread of its own: the thread, and where its
-- outcome arrives.
spawn :: IO a -> IO (ThreadId, MVar (Either SomeException a))
spawn action = do
  done <- newEmptyMVar
  thread <- forkFinally action (putMVar done)
  pure (thread, done)

-- | An outcome with its exception, if any, as text.
described :: Either SomeException a -> Either String a
described = either (Left . displayException) Right

-- | Run a reclaim of a server's store at the default minimum age and
-- stop it once it has listed the store, then run @during@ in a thread of
-- its own, and let the reclaim go on once @during@ has run as far as it
-- can: how @during@ stood then, and both outcomes.  The reclaim reads
-- its clock after every listing and before any removal, inside its hold
-- on the gate, so the clock is where it stops: between the listing and
-- the removals, the window no narinfo and no NAR may enter.
duringReclaim :: Server.ServerConfig -> IO a -> IO (Settled, Either String (Either Reclaim.ReclaimBlocked Reclaim.Reclaimed), Either String a)
duringReclaim cfg during = do
  now <- getCurrentTime
  listed <- newEmptyMVar
  resume <- newEmptyMVar
  let clock = putMVar listed () >> takeMVar resume >> pure now
  (_, reclaimed) <- spawn (Reclaim.reclaim (Server.scStore cfg) Reclaim.defaultMinimumAge clock)
  takeMVar listed
  (thread, outcome) <- spawn during
  standing <- settle thread
  putMVar resume ()
  reclaimOutcome <- described <$> takeMVar reclaimed
  duringOutcome <- described <$> takeMVar outcome
  pure (standing, reclaimOutcome, duringOutcome)

-- | The NARs a reclaim removed, by name, with each outcome.
removedNars :: Either String (Either Reclaim.ReclaimBlocked Reclaim.Reclaimed) -> Either String (Either Reclaim.ReclaimBlocked [(Text, Store.NarRemoveResult)])
removedNars = fmap (fmap (\done -> [(Store.nfName nar, outcome) | (nar, outcome) <- Reclaim.rdNars done]))

testRemoval :: IO Bool
testRemoval =
  runGroup
    "Removal"
    [ test "DELETE of a narinfo needs the write key, removes it, and leaves its NAR served" $
        withAuthedServer $ \cfg -> do
          stored <- putEntry cfg validServerNarInfo serverNarName serverNarBytes
          let narInfoPath = [validNarInfoHashKey <> ".narinfo"]
          unauthorized <- serverRequest cfg "DELETE" narInfoPath [] ""
          kept <- fst <$> getResource cfg narInfoPath
          deleted <- serverRequest cfg "DELETE" narInfoPath [serverAuthHeader] ""
          gone <- fst <$> getResource cfg narInfoPath
          again <- serverRequest cfg "DELETE" narInfoPath [serverAuthHeader] ""
          traversal <- serverRequest cfg "DELETE" ["...narinfo"] [serverAuthHeader] ""
          nar <- getResource cfg ["nar", serverNarName]
          ok1 <- assertEqual "stored" HTTP.status200 stored
          ok2 <- assertEqual "without the key" (HTTP.status401, HTTP.status200) (WT.simpleStatus unauthorized, kept)
          ok3 <- assertEqual "deleted" (HTTP.status200, HTTP.status404) (WT.simpleStatus deleted, gone)
          ok4 <- assertEqual "deleted again" HTTP.status404 (WT.simpleStatus again)
          ok5 <- assertEqual "traversal" HTTP.status400 (WT.simpleStatus traversal)
          ok6 <- assertEqual "NAR" (HTTP.status200, serverNarBytes) nar
          pure (ok1 && ok2 && ok3 && ok4 && ok5 && ok6),
      test "an entry deleted, GET /reclaim lists its NAR, and POST /reclaim removes it" $
        withAuthedServer $ \cfg -> do
          _ <- putKeptEntry cfg
          stored <- putEntry cfg validServerNarInfo serverNarName serverNarBytes
          ageNar cfg serverNarName
          ageNar cfg "kept.nar"
          _ <- serverRequest cfg "DELETE" [validNarInfoHashKey <> ".narinfo"] [serverAuthHeader] ""
          listed <- reclaimQuery cfg "GET" []
          afterListing <- fst <$> getResource cfg ["nar", serverNarName]
          removed <- reclaimQuery cfg "POST" []
          afterRemoval <- fst <$> getResource cfg ["nar", serverNarName]
          kept <- fst <$> getResource cfg ["nar", "kept.nar"]
          ok1 <- assertEqual "stored" HTTP.status200 stored
          ok2 <-
            assertEqual
              "listed"
              ( HTTP.status200,
                reclaimReport
                  [ "unreferenced: nar/test.nar (17 bytes)",
                    "eligible: 1 NAR, 17 bytes; 0 abandoned uploads, 0 bytes",
                    "kept, younger than the minimum age: 0 NARs, 0 uploads"
                  ]
              )
              (statusAndBody listed)
          ok3 <- assertEqual "served after the listing" HTTP.status200 afterListing
          ok4 <-
            assertEqual
              "removed"
              ( HTTP.status200,
                reclaimReport
                  [ "removed: nar/test.nar (17 bytes)",
                    "reclaimed: 1 NAR, 17 bytes; 0 abandoned uploads, 0 bytes",
                    "kept, younger than the minimum age: 0 NARs, 0 uploads"
                  ]
              )
              (statusAndBody removed)
          ok5 <- assertEqual "after the removal" (HTTP.status404, HTTP.status200) (afterRemoval, kept)
          ok6 <- assertEqual "uncacheable" [Just "no-store", Just "no-store"] (map (lookup HTTP.hCacheControl . WT.simpleHeaders) [listed, removed])
          pure (ok1 && ok2 && ok3 && ok4 && ok5 && ok6),
      test "GET and POST /reclaim need the write key" $
        withAuthedServer $ \cfg -> do
          _ <- putKeptEntry cfg
          _ <- putServerNar cfg serverNarBytes
          ageNar cfg serverNarName
          responses <- traverse (\method -> serverRequest cfg method ["reclaim"] [] "") ["GET", "POST"]
          nar <- fst <$> getResource cfg ["nar", serverNarName]
          ok1 <- assertEqual "statuses" [HTTP.status401, HTTP.status401] (map WT.simpleStatus responses)
          ok2 <- assertEqual "NAR" HTTP.status200 nar
          pure (ok1 && ok2),
      test "min-age-hours sets a reclaim's minimum age, and any other query is 400" $
        withAuthedServer $ \cfg -> do
          _ <- putKeptEntry cfg
          _ <- putServerNar cfg serverNarBytes
          byDefault <- statusAndBody <$> reclaimQuery cfg "POST" []
          refusals <-
            traverse
              (fmap WT.simpleStatus . reclaimQuery cfg "POST")
              [ [("min-age-hours", Just "01")],
                [("min-age-hours", Just "-1")],
                [("min-age-hours", Just "1.5")],
                [("min-age-hours", Nothing)],
                [("min-age", Just "0")],
                [("min-age-hours", Just "0"), ("min-age-hours", Just "0")],
                [("min-age-hours", Just "0"), ("delete", Nothing)]
              ]
          survived <- fst <$> getResource cfg ["nar", serverNarName]
          atZero <- statusAndBody <$> reclaimQuery cfg "POST" [("min-age-hours", Just "0")]
          gone <- fst <$> getResource cfg ["nar", serverNarName]
          ok1 <-
            assertEqual
              "at the default age"
              ( HTTP.status200,
                reclaimReport
                  [ "reclaimed: 0 NARs, 0 bytes; 0 abandoned uploads, 0 bytes",
                    "kept, younger than the minimum age: 1 NAR, 0 uploads"
                  ]
              )
              byDefault
          ok2 <- assertEqual "refusals" (map (const HTTP.status400) refusals) refusals
          ok3 <- assertEqual "kept through the refusals" HTTP.status200 survived
          ok4 <-
            assertEqual
              "at zero"
              ( HTTP.status200,
                "minimum age: 0 hours\nremoved: nar/test.nar (17 bytes)\nreclaimed: 1 NAR, 17 bytes; 0 abandoned uploads, 0 bytes\nkept, younger than the minimum age: 0 NARs, 0 uploads\n"
              )
              atZero
          ok5 <- assertEqual "removed at zero" HTTP.status404 gone
          pure (ok1 && ok2 && ok3 && ok4 && ok5),
      test "property: min-age-hours reads back as that many hours" $
        checkProperty $
          forAll (choose (0, 1000000 :: Integer)) $ \hours ->
            Server.parseMinimumAge [("min-age-hours", Just (TE.encodeUtf8 (T.pack (show hours))))]
              === Right (fromInteger hours * 3600)
              .&&. Server.parseMinimumAge [] === Right Reclaim.defaultMinimumAge,
      test "a narinfo that cannot be resolved blocks a reclaim with 409, which removes nothing" $
        withAuthedServer $ \cfg -> do
          _ <- putKeptEntry cfg
          _ <- putServerNar cfg serverNarBytes
          ageNar cfg serverNarName
          _ <- Store.writeNarInfo (Server.scStore cfg) "broken" "not a narinfo\n"
          responses <- traverse (\method -> reclaimQuery cfg method []) ["GET", "POST"]
          nar <- fst <$> getResource cfg ["nar", serverNarName]
          ok1 <- assertEqual "statuses" [HTTP.status409, HTTP.status409] (map WT.simpleStatus responses)
          ok2 <- assertTrue "names the narinfo" (all (BS.isPrefixOf "unresolved: broken.narinfo: " . strictBody) responses)
          ok3 <- assertEqual "NAR" HTTP.status200 nar
          pure (ok1 && ok2 && ok3),
      test "POST /reclaim removes an upload idle for the minimum age, named by its request path" $
        withAuthedServer $ \cfg -> do
          (_, uploadId) <- beginServerUpload cfg serverNarName
          _ <- putServerPart cfg serverNarName uploadId "1" "abandoned"
          monthAgo <- addUTCTime (negate (30 * nominalDay)) <$> getCurrentTime
          traverse_ (backdateUpload monthAgo) =<< Store.listStagedUploads (Server.scStore cfg)
          removed <- reclaimQuery cfg "POST" []
          staged <- storeEntries cfg "uploads"
          completion <- completeServerUpload cfg serverNarName uploadId (totalsBody 1 9)
          ok1 <-
            assertEqual
              "removed"
              ( HTTP.status200,
                reclaimReport
                  [ "removed: nar/test.nar/uploads/" <> TE.encodeUtf8 uploadId <> " (9 bytes)",
                    "reclaimed: 0 NARs, 0 bytes; 1 abandoned upload, 9 bytes",
                    "kept, younger than the minimum age: 0 NARs, 0 uploads"
                  ]
              )
              (statusAndBody removed)
          ok2 <- assertEqual "uploads/" [] staged
          ok3 <- assertEqual "completion" HTTP.status404 (WT.simpleStatus completion)
          pure (ok1 && ok2 && ok3),
      -- The server checks a narinfo's file fields against the file it
      -- names, never the encoding, so the bytes stand in for a zstd
      -- frame.
      test "a narinfo over an entry replaces its NAR with a smaller encoding, and a reclaim removes the old one alone" $
        withAuthedServer $ \cfg -> do
          let uncompressed = BS.replicate 64 0x61
              compressed = "zstd-frame"
              replacement = (entryNarInfo validNarInfoHashKey "small.nar.zst" compressed) {NarInfo.niCompression = "zstd"}
          stored <- putEntry cfg (entryNarInfo validNarInfoHashKey "big.nar" uncompressed) "big.nar" uncompressed
          ageNar cfg "big.nar"
          replaced <- putEntry cfg replacement "small.nar.zst" compressed
          narInfo <- getResource cfg [validNarInfoHashKey <> ".narinfo"]
          oldBefore <- fst <$> getResource cfg ["nar", "big.nar"]
          removed <- reclaimQuery cfg "POST" []
          oldAfter <- fst <$> getResource cfg ["nar", "big.nar"]
          newAfter <- getResource cfg ["nar", "small.nar.zst"]
          ok1 <- assertEqual "stored, then replaced" (HTTP.status200, HTTP.status200) (stored, replaced)
          ok2 <- assertTrue "narinfo names the smaller NAR" (all (`BS.isInfixOf` snd narInfo) ["URL: nar/small.nar.zst\n", "Compression: zstd\n", "FileSize: 10\n"])
          ok3 <- assertEqual "old NAR served until the reclaim" HTTP.status200 oldBefore
          ok4 <-
            assertEqual
              "removed"
              ( HTTP.status200,
                reclaimReport
                  [ "removed: nar/big.nar (64 bytes)",
                    "reclaimed: 1 NAR, 64 bytes; 0 abandoned uploads, 0 bytes",
                    "kept, younger than the minimum age: 0 NARs, 0 uploads"
                  ]
              )
              (statusAndBody removed)
          ok5 <- assertEqual "after the reclaim" (HTTP.status404, (HTTP.status200, compressed)) (oldAfter, newAfter)
          pure (ok1 && ok2 && ok3 && ok4 && ok5),
      -- A narinfo and a reclaim at once
      test "a narinfo stored before a reclaim keeps its NAR, however old" $
        withAuthedServer $ \cfg -> do
          stored <- putEntry cfg validServerNarInfo serverNarName serverNarBytes
          ageNar cfg serverNarName
          reclaimed <- Reclaim.reclaim (Server.scStore cfg) Reclaim.defaultMinimumAge getCurrentTime
          nar <- fst <$> getResource cfg ["nar", serverNarName]
          ok1 <- assertEqual "stored" HTTP.status200 stored
          ok2 <- assertEqual "removed" (Right (Right [])) (removedNars (Right reclaimed))
          ok3 <- assertEqual "NAR" HTTP.status200 nar
          pure (ok1 && ok2 && ok3),
      test "a narinfo sent during a reclaim waits for it, and is refused once its NAR is gone" $
        withAuthedServer $ \cfg -> do
          _ <- putKeptEntry cfg
          _ <- putServerNar cfg serverNarBytes
          ageNar cfg serverNarName
          (standing, reclaimed, put) <- duringReclaim cfg (putServerNarInfo cfg validServerNarInfo)
          narInfo <- fst <$> getResource cfg [validNarInfoHashKey <> ".narinfo"]
          ok1 <- assertEqual "the narinfo, during the reclaim" AtGate standing
          ok2 <- assertEqual "removed" (Right (Right [(serverNarName, Store.NarRemoved)])) (removedNars reclaimed)
          ok3 <- assertEqual "narinfo" (Right (HTTP.status400, "NAR nar/test.nar is not stored; upload it before its narinfo")) (statusAndBody <$> put)
          ok4 <- assertEqual "narinfo stored" HTTP.status404 narInfo
          pure (ok1 && ok2 && ok3 && ok4),
      -- The signer runs after the narinfo upload has checked its NAR and
      -- before it writes the narinfo, so this one stops there.
      test "a reclaim started between a narinfo upload's check and its write waits, and keeps the NAR" $
        withAuthedServer $ \cfg -> case Server.narClaim validServerNarInfo of
          Left refusal -> assertEqual "claim" Nothing (Just refusal)
          Right claim -> do
            let store = Server.scStore cfg
            _ <- putKeptEntry cfg
            _ <- putServerNar cfg serverNarBytes
            ageNar cfg serverNarName
            checked <- newEmptyMVar
            resume <- newEmptyMVar
            let signer ni = putMVar checked () >> takeMVar resume >> Server.signNarInfo Nothing ni
            (_, written) <- spawn (Server.storeNarInfo store signer validNarInfoHashKey validServerNarInfo claim)
            takeMVar checked
            (reclaiming, reclaimed) <- spawn (Reclaim.reclaim store Reclaim.defaultMinimumAge getCurrentTime)
            standing <- settle reclaiming
            putMVar resume ()
            writeOutcome <- described <$> takeMVar written
            reclaimOutcome <- described <$> takeMVar reclaimed
            nar <- fst <$> getResource cfg ["nar", serverNarName]
            narInfo <- fst <$> getResource cfg [validNarInfoHashKey <> ".narinfo"]
            ok1 <- assertEqual "the reclaim, during the upload" AtGate standing
            ok2 <- assertEqual "upload" (Right Server.NarInfoWritten) writeOutcome
            ok3 <- assertEqual "removed" (Right (Right [])) (removedNars reclaimOutcome)
            ok4 <- assertEqual "NAR and narinfo" (HTTP.status200, HTTP.status200) (nar, narInfo)
            pure (ok1 && ok2 && ok3 && ok4),
      -- A NAR and a reclaim at once
      test "a NAR uploaded during a reclaim lands after it, so the reclaim never removes it" $
        withAuthedServer $ \cfg -> do
          _ <- putKeptEntry cfg
          _ <- putServerNar cfg "an earlier upload"
          ageNar cfg serverNarName
          (standing, reclaimed, put) <- duringReclaim cfg (putServerNar cfg serverNarBytes)
          nar <- getResource cfg ["nar", serverNarName]
          narInfo <- WT.simpleStatus <$> putServerNarInfo cfg validServerNarInfo
          ok1 <- assertEqual "the upload, during the reclaim" AtGate standing
          ok2 <- assertEqual "removed: the earlier upload" (Right (Right [(serverNarName, Store.NarRemoved)])) (removedNars reclaimed)
          ok3 <- assertEqual "upload" (Right HTTP.status200) (WT.simpleStatus <$> put)
          ok4 <- assertEqual "NAR" (HTTP.status200, serverNarBytes) nar
          ok5 <- assertEqual "narinfo" HTTP.status200 narInfo
          pure (ok1 && ok2 && ok3 && ok4 && ok5),
      test "a multipart upload completed during a reclaim lands after it" $
        withAuthedServer $ \cfg -> do
          _ <- putKeptEntry cfg
          _ <- putServerNar cfg "an earlier upload"
          ageNar cfg serverNarName
          (_, uploadId) <- beginServerUpload cfg serverNarName
          _ <- putServerPart cfg serverNarName uploadId "1" "nar-payload"
          _ <- putServerPart cfg serverNarName uploadId "2" "-bytes"
          (standing, reclaimed, completed) <- duringReclaim cfg (completeServerUpload cfg serverNarName uploadId (totalsBody 2 17))
          nar <- getResource cfg ["nar", serverNarName]
          ok1 <- assertEqual "the completion, during the reclaim" AtGate standing
          ok2 <- assertEqual "removed: the earlier upload" (Right (Right [(serverNarName, Store.NarRemoved)])) (removedNars reclaimed)
          ok3 <- assertEqual "completion" (Right HTTP.status200) (WT.simpleStatus <$> completed)
          ok4 <- assertEqual "NAR" (HTTP.status200, serverNarBytes) nar
          pure (ok1 && ok2 && ok3 && ok4),
      -- The gate itself
      test "a removal waits for the gate's holders, and holds new ones off until it is done" $ do
        tmpDir <- createTestDir
        store <- Store.newFileStore tmpDir
        events <- newIORef []
        let record event = atomicModifyIORef' events (\done -> (done ++ [event], ()))
        (removalStanding, removalDone, holderStanding, holderDone) <- Store.withoutRemoval store $ do
          (removal, removalDone) <- spawn (Store.withRemoval store (record "removal"))
          removalStanding <- settle removal
          (holder, holderDone) <- spawn (Store.withoutRemoval store (record "new holder"))
          holderStanding <- settle holder
          record "first holder"
          pure (removalStanding, removalDone, holderStanding, holderDone)
        outcomes <- traverse (fmap described . takeMVar) [removalDone, holderDone]
        order <- readIORef events
        removeDirectoryRecursive tmpDir
        ok1 <- assertEqual "standing, while the first holder holds" (AtGate, AtGate) (removalStanding, holderStanding)
        ok2 <- assertEqual "outcomes" [Right (), Right ()] outcomes
        ok3 <- assertEqual "order" ["first holder", "removal", "new holder" :: String] order
        pure (ok1 && ok2 && ok3),
      test "a removal interrupted while it waits withdraws, and new holders go ahead" $ do
        tmpDir <- createTestDir
        store <- Store.newFileStore tmpDir
        (removalStanding, interrupted, holderStanding) <- Store.withoutRemoval store $ do
          (removal, removalDone) <- spawn (Store.withRemoval store (pure ()))
          removalStanding <- settle removal
          killThread removal
          outcome <- takeMVar removalDone
          (holder, _) <- spawn (Store.withoutRemoval store (pure ()))
          holderStanding <- settle holder
          pure (removalStanding, either fromException (const Nothing) outcome, holderStanding)
        removeDirectoryRecursive tmpDir
        ok1 <- assertEqual "removal, waiting" AtGate removalStanding
        ok2 <- assertEqual "removal, interrupted" (Just ThreadKilled) interrupted
        ok3 <- assertEqual "new holder" Finished holderStanding
        pure (ok1 && ok2 && ok3)
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
