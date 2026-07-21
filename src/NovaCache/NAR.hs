{-# LANGUAGE CPP #-}

-- | NAR (Nix ARchive) binary format serialization and deserialization.
--
-- NAR is a deterministic archive format used by Nix. All strings are
-- length-prefixed and padded to 8-byte alignment. The grammar is:
--
-- @
-- archive   ::= "nix-archive-1" node
-- node      ::= "(" "type" ("regular" regular | "symlink" symlink | "directory" directory) ")"
-- regular   ::= ["executable" ""] "contents" STRING
-- symlink   ::= "target" STRING
-- directory ::= (entry)*
-- entry     ::= "entry" "(" "name" STRING "node" node ")"
-- @
--
-- Entry names and symlink targets are raw byte strings: the format
-- imposes no text encoding on them, and upstream carries them verbatim.
module NovaCache.NAR
  ( NarEntry (..),
    serialise,
    deserialise,
    narHash,
    serialiseFromPath,
    serialiseFromPathWith,
    CaseHack (..),
    defaultCaseHack,
    caseHackSuffix,
  )
where

import Data.Bits (shiftL, (.&.), (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as B
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString.Lazy as BL
import Data.List (sort, sortBy)
import Data.Ord (comparing)
import Data.Word (Word64)
import qualified NovaCache.Hash as Hash
import NovaCache.SafeName (hasTrailingDotOrSpace, isReservedDeviceName)
import System.Directory.OsPath
  ( doesDirectoryExist,
    doesFileExist,
    executable,
    getPermissions,
    getSymbolicLinkTarget,
    listDirectory,
    pathIsSymbolicLink,
  )
import qualified System.Info
import System.OsPath (OsPath, decodeFS, encodeFS, (</>))
import qualified System.OsPath as OP
#ifdef mingw32_HOST_OS
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
#else
import System.IO (latin1)
#endif

-- ---------------------------------------------------------------------------
-- Types
-- ---------------------------------------------------------------------------

-- | A node in the NAR tree.
data NarEntry
  = -- | Regular file: executable flag and contents.
    NarRegular !Bool !ByteString
  | -- | Symbolic link: target path, as the raw bytes the archive
    -- carries.
    NarSymlink !ByteString
  | -- | Directory: list of (name, entry) pairs.  Names are the raw
    -- bytes the archive carries; they must be unique, the serializer
    -- sorts them bytewise, and 'deserialise' rejects duplicate or
    -- out-of-order names.
    NarDirectory ![(ByteString, NarEntry)]
  deriving (Eq, Show)

-- ---------------------------------------------------------------------------
-- Wire tokens (named constants, no magic strings)
-- ---------------------------------------------------------------------------

tokMagic, tokLParen, tokRParen, tokType :: ByteString
tokMagic = "nix-archive-1"
tokLParen = "("
tokRParen = ")"
tokType = "type"

tokRegular, tokDirectory, tokSymlink :: ByteString
tokRegular = "regular"
tokDirectory = "directory"
tokSymlink = "symlink"

tokContents, tokTarget, tokExecutable :: ByteString
tokContents = "contents"
tokTarget = "target"
tokExecutable = "executable"

tokEntry, tokName, tokNode :: ByteString
tokEntry = "entry"
tokName = "name"
tokNode = "node"

-- | Alignment boundary for NAR wire strings.
narAlignment :: Int
narAlignment = 8

-- ---------------------------------------------------------------------------
-- Serialization (pure Builder pipeline)
-- ---------------------------------------------------------------------------

-- | Serialise a 'NarEntry' to NAR binary format.
serialise :: NarEntry -> ByteString
serialise = BL.toStrict . B.toLazyByteString . buildArchive

-- | Build the full NAR archive: magic header followed by the root node.
buildArchive :: NarEntry -> B.Builder
buildArchive entry = narStr tokMagic <> buildNode entry

-- | Build a NAR node.
buildNode :: NarEntry -> B.Builder
buildNode (NarRegular isExec contents) =
  narStr tokLParen
    <> narStr tokType
    <> narStr tokRegular
    <> execFlag isExec
    <> narStr tokContents
    <> narStr contents
    <> narStr tokRParen
buildNode (NarSymlink target) =
  narStr tokLParen
    <> narStr tokType
    <> narStr tokSymlink
    <> narStr tokTarget
    <> narStr target
    <> narStr tokRParen
buildNode (NarDirectory entries) =
  narStr tokLParen
    <> narStr tokType
    <> narStr tokDirectory
    <> foldMap buildDirEntry (sortBy (comparing fst) entries)
    <> narStr tokRParen

-- | Emit the executable flag tokens if the file is executable.
execFlag :: Bool -> B.Builder
execFlag True = narStr tokExecutable <> narStr BS.empty
execFlag False = mempty

-- | Build a single directory entry: @"entry" "(" "name" \<n\> "node" \<node\> ")"@.
buildDirEntry :: (ByteString, NarEntry) -> B.Builder
buildDirEntry (entryName, entry) =
  narStr tokEntry
    <> narStr tokLParen
    <> narStr tokName
    <> narStr entryName
    <> narStr tokNode
    <> buildNode entry
    <> narStr tokRParen

-- | Write a length-prefixed, 8-byte-padded bytestring to the Builder.
narStr :: ByteString -> B.Builder
narStr bs =
  B.word64LE (fromIntegral len)
    <> B.byteString bs
    <> B.byteString (BS.replicate padLen 0)
  where
    len = BS.length bs
    padLen = narPad len

-- | Compute padding to reach the next 8-byte boundary.
narPad :: Int -> Int
narPad len =
  let remainder = len .&. (narAlignment - 1)
   in if remainder == 0 then 0 else narAlignment - remainder

-- ---------------------------------------------------------------------------
-- Deserialization (pure, cursor-passing parser)
-- ---------------------------------------------------------------------------

-- | Parser state: remaining bytes after consuming a token.
type NarParser a = ByteString -> Either String (a, ByteString)

-- | Deserialise NAR binary format to a 'NarEntry'.
deserialise :: ByteString -> Either String NarEntry
deserialise bs = do
  (magic, rest) <- readStr bs
  expect tokMagic magic
  (entry, rest2) <- parseNode rest
  if BS.null rest2
    then Right entry
    else Left "trailing bytes after NAR root node"

-- | Parse a single NAR node.
parseNode :: NarParser NarEntry
parseNode bs = do
  (lp, rest) <- readStr bs
  expect tokLParen lp
  (ty, afterTy) <- readStr rest
  expect tokType ty
  (kind, afterKind) <- readStr afterTy
  dispatch kind afterKind
  where
    dispatch kind rest
      | kind == tokRegular = parseRegular rest
      | kind == tokSymlink = parseSymlink rest
      | kind == tokDirectory = parseDirectory rest
      | otherwise = Left ("unknown NAR entry type: " ++ show kind)

-- | Parse a regular file node (optional executable flag + contents).
parseRegular :: NarParser NarEntry
parseRegular bs = do
  (tok, afterTok) <- readStr bs
  regular tok afterTok
  where
    regular tok rest
      | tok == tokExecutable = do
          (marker, afterEmpty) <- readStr rest
          -- The format fixes the executable marker's value as the empty
          -- string; upstream rejects a nonempty value.
          if BS.null marker
            then Right ()
            else Left ("executable marker must be empty, got: " ++ show marker)
          (cTok, afterCTok) <- readStr afterEmpty
          expect tokContents cTok
          (contents, afterContents) <- readStr afterCTok
          (rp, final) <- readStr afterContents
          expect tokRParen rp
          pure (NarRegular True contents, final)
      | tok == tokContents = do
          (contents, afterContents) <- readStr rest
          (rp, final) <- readStr afterContents
          expect tokRParen rp
          pure (NarRegular False contents, final)
      | otherwise =
          -- 'contents' is mandatory (even an empty file serialises with it), so
          -- a regular node without it is malformed - reject, matching Nix.
          Left ("expected 'executable' or 'contents' in regular, got: " ++ show tok)

-- | Parse a symlink node.  The target is carried verbatim: upstream
-- imposes no text encoding on it.
parseSymlink :: NarParser NarEntry
parseSymlink bs = do
  (tgt, afterTgt) <- readStr bs
  expect tokTarget tgt
  (targetPath, afterPath) <- readStr afterTgt
  (rp, final) <- readStr afterPath
  expect tokRParen rp
  pure (NarSymlink targetPath, final)

-- | Parse a directory node (zero or more child entries).
parseDirectory :: NarParser NarEntry
parseDirectory = go Nothing []
  where
    go !prev !acc bs = do
      (tok, afterTok) <- readStr bs
      if tok == tokRParen
        then pure (NarDirectory (reverse acc), afterTok)
        else do
          expect tokEntry tok
          (lp, afterLp) <- readStr afterTok
          expect tokLParen lp
          (nTok, afterNTok) <- readStr afterLp
          expect tokName nTok
          (entryName, afterName) <- readStr afterNTok
          (nodeTok, afterNodeTok) <- readStr afterName
          expect tokNode nodeTok
          (entry, afterEntry) <- parseNode afterNodeTok
          (rp, afterRp) <- readStr afterEntry
          expect tokRParen rp
          _ <- checkName prev entryName
          go (Just entryName) ((entryName, entry) : acc) afterRp
    -- NAR directory entries must have safe names in strictly increasing
    -- (sorted, unique) byte order.  Enforcing this rejects malformed or
    -- hostile archives, keeps @serialise . deserialise@ an identity, and
    -- forecloses the path-traversal surface for any future NAR-extraction
    -- consumer.  Names are arbitrary bytes; every check here is
    -- ASCII-structural, so it stays exact whether or not the name
    -- decodes as text (see "NovaCache.SafeName").
    checkName prev name
      | BS.null name = Left "empty NAR directory entry name"
      -- Backslash is a directory separator on Windows - this library's
      -- primary consumer - so a name like "..\out.exe" is as much a
      -- traversal vector as one with '/'.  A colon is a drive prefix
      -- ("C:evil") or an NTFS alternate data stream ("a:b"), either of
      -- which resolves the write somewhere other than a file of this name.
      | name == "." || name == ".." || BS8.any (\c -> c == '/' || c == '\\' || c == '\0' || c == ':') name =
          Left ("unsafe NAR directory entry name: " ++ show name)
      -- Windows-unsafe categories, shared with the store-key allowlist
      -- (NovaCache.SafeName): a device name resolves to the device, and
      -- NTFS strips a trailing dot or space so the on-disk name would
      -- silently diverge from the NAR name.
      | isReservedDeviceName name =
          Left ("Windows reserved device name as NAR directory entry: " ++ show name)
      | hasTrailingDotOrSpace name =
          Left ("NAR directory entry name ends with a dot or space: " ++ show name)
      | Just p <- prev,
        name <= p =
          Left ("NAR directory entries not strictly increasing: " ++ show name)
      | otherwise = Right ()

-- ---------------------------------------------------------------------------
-- Wire primitives
-- ---------------------------------------------------------------------------

-- | Read a length-prefixed, 8-byte-padded string from the buffer.
readStr :: NarParser ByteString
readStr bs
  | BS.length bs < wordSize =
      Left "unexpected end of NAR: need 8 bytes for string length"
  -- Compare the Word64 length to the remaining bytes BEFORE narrowing it to
  -- Int: a hostile length above maxBound::Int would otherwise wrap negative
  -- and slip past the totalLen check below.
  | len > fromIntegral (BS.length payload) =
      Left
        ( "unexpected end of NAR: string length "
            ++ show len
            ++ " exceeds remaining "
            ++ show (BS.length payload)
        )
  | totalLen > BS.length payload =
      Left
        ( "unexpected end of NAR: padded string length "
            ++ show totalLen
            ++ " exceeds remaining "
            ++ show (BS.length payload)
        )
  -- Nix's reader rejects nonzero padding; accepting it would let archives
  -- that upstream tooling refuses round-trip through this library.
  | BS.any (/= 0) padding =
      Left "nonzero padding bytes in NAR string"
  | otherwise =
      Right (BS.take (fromIntegral len) payload, BS.drop totalLen payload)
  where
    len = readWord64LE bs
    payload = BS.drop wordSize bs
    totalLen = fromIntegral len + narPad (fromIntegral len)
    padding = BS.take (totalLen - fromIntegral len) (BS.drop (fromIntegral len) payload)

-- | Read a little-endian 'Word64' from the first 8 bytes.
readWord64LE :: ByteString -> Word64
readWord64LE bs =
  byte 0
    .|. (byte 1 `shiftL` 8)
    .|. (byte 2 `shiftL` 16)
    .|. (byte 3 `shiftL` 24)
    .|. (byte 4 `shiftL` 32)
    .|. (byte 5 `shiftL` 40)
    .|. (byte 6 `shiftL` 48)
    .|. (byte 7 `shiftL` 56)
  where
    byte i = fromIntegral (BS.index bs i)

-- | Size of a Word64 in bytes.
wordSize :: Int
wordSize = 8

-- | Assert that a token matches the expected value.
expect :: ByteString -> ByteString -> Either String ()
expect expected got
  | got == expected = Right ()
  | otherwise = Left ("expected " ++ show expected ++ ", got " ++ show got)

-- ---------------------------------------------------------------------------
-- Hashing
-- ---------------------------------------------------------------------------

-- | SHA-256 hash of the NAR serialization. Pure composition.
narHash :: NarEntry -> Hash.NixHash
narHash = Hash.hashBytes . serialise

-- ---------------------------------------------------------------------------
-- Filesystem to NarEntry (IO boundary)
-- ---------------------------------------------------------------------------

-- | Whether the serialiser strips upstream's case-hack suffix from
-- on-disk names.  A case-folding store filesystem cannot hold two
-- sibling names differing only by case, so an extractor there
-- materializes the second with a reversible suffix; serialisation must
-- strip it for the tree to reproduce its original NAR bytes.
data CaseHack = CaseHackEnabled | CaseHackDisabled
  deriving (Eq, Show)

-- | The platform default 'serialiseFromPath' uses: enabled where the
-- store filesystem folds case (Windows NTFS, default macOS APFS),
-- disabled elsewhere - a Linux file legitimately named with the suffix
-- must serialise verbatim.  Matches upstream's use-case-hack defaults.
defaultCaseHack :: CaseHack
defaultCaseHack = case System.Info.os of
  "mingw32" -> CaseHackEnabled
  "darwin" -> CaseHackEnabled
  _ -> CaseHackDisabled

-- | Upstream's reversible collision suffix (its @caseHackSuffix@): an
-- extractor appends @~nix~case~hack~<N>@ to a sibling whose name
-- case-folds onto an earlier one, and serialisation strips from the
-- suffix onward to recover the NAR name.  Bytes, matching the entry
-- names it marks.
caseHackSuffix :: ByteString
caseHackSuffix = "~nix~case~hack~"

-- | Walk a filesystem path and build a 'NarEntry' under
-- 'defaultCaseHack'.
--
-- This is the module's IO boundary. It classifies each path as symlink,
-- directory, or regular file, then delegates to pure constructors.
serialiseFromPath :: FilePath -> IO NarEntry
serialiseFromPath = serialiseFromPathWith defaultCaseHack

-- | 'serialiseFromPath' with the case-hack mode explicit, for callers
-- and tests that need behavior independent of the host platform.
serialiseFromPathWith :: CaseHack -> FilePath -> IO NarEntry
serialiseFromPathWith mode path = walkPath mode =<< encodeFS path

-- | Walk one platform-native path.  The walk runs on 'OsPath' so child
-- names reach the archive byte-true ('osPathBytes'); only the root
-- enters as 'FilePath', and the root's own name never appears in a
-- NAR.
walkPath :: CaseHack -> OsPath -> IO NarEntry
walkPath mode path = do
  isSym <- pathIsSymbolicLink path
  if isSym
    then NarSymlink <$> (osPathBytes =<< getSymbolicLinkTarget path)
    else do
      isDir <- doesDirectoryExist path
      if isDir
        then buildDirectory mode path
        else buildRegularFile path

-- | Build a directory entry by recursively walking children.  Under
-- 'CaseHackEnabled', each on-disk name is stripped of the case-hack
-- suffix and entries are ordered by the STRIPPED name (the NAR name);
-- two on-disk names stripping to the same entry name fail loudly, as
-- upstream's serialiser does - continuing would emit an archive with
-- duplicate entries no parser accepts.
buildDirectory :: CaseHack -> OsPath -> IO NarEntry
buildDirectory mode path = do
  names <- sort <$> listDirectory path
  named <- traverse withNameBytes names
  case unhackedDirNames mode named of
    Left (first, second) -> do
      firstPath <- decodeFS (path </> first)
      secondPath <- decodeFS (path </> second)
      fail
        ( "serialiseFromPath: file name collision between '"
            ++ firstPath
            ++ "' and '"
            ++ secondPath
            ++ "' after case-hack stripping"
        )
    Right resolved -> NarDirectory <$> traverse walkChild resolved
  where
    withNameBytes diskName = do
      nameBytes <- osPathBytes diskName
      pure (nameBytes, diskName)
    walkChild (entryName, diskName) = do
      entry <- walkPath mode (path </> diskName)
      pure (entryName, entry)

-- | Resolve (NAR name, on-disk name) pairs for a directory's children.
-- Under 'CaseHackDisabled' pairs pass through verbatim (serialisation
-- sorts at emit).  Under 'CaseHackEnabled' the case-hack suffix is
-- stripped from each NAR name and pairs are re-sorted by the stripped
-- bytes; @Left@ carries the first pair of disk names whose stripped
-- entry names coincide.
unhackedDirNames :: CaseHack -> [(ByteString, OsPath)] -> Either (OsPath, OsPath) [(ByteString, OsPath)]
unhackedDirNames CaseHackDisabled named = Right named
unhackedDirNames CaseHackEnabled named =
  detectCollision (sortBy (comparing fst) (map resolve named))
  where
    resolve (nameBytes, diskName) =
      let (unhacked, rest) = BS.breakSubstring caseHackSuffix nameBytes
       in if BS.null rest
            then (nameBytes, diskName)
            else (unhacked, diskName)
    detectCollision resolved =
      case [ (diskA, diskB)
           | ((entryA, diskA), (entryB, diskB)) <- zip resolved (drop 1 resolved),
             entryA == entryB
           ] of
        ((diskA, diskB) : _) -> Left (diskA, diskB)
        [] -> Right resolved

-- | Build a regular file entry, checking the executable bit.
buildRegularFile :: OsPath -> IO NarEntry
buildRegularFile path = do
  isFile <- doesFileExist path
  if isFile
    then do
      contents <- readFileBytes path
      isExec <- checkExecutable path
      pure (NarRegular isExec contents)
    else do
      -- Not a symlink, directory, or regular file: a special file (FIFO,
      -- socket, device) or a path that vanished mid-walk.  Fail loudly rather
      -- than fabricating an empty regular (which would silently change the NAR
      -- and its hash) - matching Nix, which aborts on unsupported types.
      shownPath <- decodeFS path
      fail ("serialiseFromPath: not a regular file (special or vanished): " ++ shownPath)

-- | Check whether a file has the executable permission set.
-- Uses 'System.Directory.OsPath.getPermissions' which is cross-platform:
-- checks the user-execute bit on Unix, file extension on Windows.
checkExecutable :: OsPath -> IO Bool
checkExecutable path = executable <$> getPermissions path

-- | Read a file's contents by platform-native path.  The byte-string
-- file API still takes 'FilePath', so the path bridges through
-- 'decodeFS' - interop with unmigrated APIs is that function's
-- documented purpose, and its contract is the exact round-trip: the
-- reopened path names the same file even when the name has no text
-- decoding.
readFileBytes :: OsPath -> IO ByteString
readFileBytes path = BS.readFile =<< decodeFS path

-- | The NAR name for one platform-native path component: on POSIX the
-- raw bytes the filesystem reports, on Windows the UTF-8 encoding of
-- the UTF-16 name - each platform's spelling of the upstream rule that
-- a NAR carries names as byte strings.  Symlink targets take the same
-- path.  The one refusal is a Windows name holding an unpaired
-- surrogate: it has no UTF-8 form and upstream defines no byte
-- spelling for it, so failing loudly beats inventing a name (the same
-- policy 'buildRegularFile' applies to special files).
#ifdef mingw32_HOST_OS
osPathBytes :: OsPath -> IO ByteString
osPathBytes path = case OP.decodeUtf path of
  Just decoded -> pure (TE.encodeUtf8 (T.pack decoded))
  Nothing ->
    fail ("serialiseFromPath: name has no UTF-8 form (unpaired surrogate): " ++ show path)
#else
osPathBytes :: OsPath -> IO ByteString
osPathBytes path = case OP.decodeWith latin1 latin1 path of
  Right decoded -> pure (BS8.pack decoded)
  Left err ->
    -- Unreachable: latin1 decoding is total - byte N reads as code
    -- point N, and Char8 re-truncation above inverts it exactly - but
    -- surfacing the impossible beats hiding it.
    fail ("serialiseFromPath: undecodable name: " ++ show err)
#endif
