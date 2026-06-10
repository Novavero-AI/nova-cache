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
module NovaCache.NAR
  ( NarEntry (..),
    serialise,
    deserialise,
    narHash,
    serialiseFromPath,
  )
where

import Data.Bits (shiftL, (.&.), (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as B
import qualified Data.ByteString.Lazy as BL
import Data.List (sort, sortBy)
import Data.Ord (comparing)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Word (Word64)
import qualified NovaCache.Hash as Hash
import System.Directory
  ( doesDirectoryExist,
    doesFileExist,
    executable,
    getPermissions,
    getSymbolicLinkTarget,
    listDirectory,
    pathIsSymbolicLink,
  )
import System.FilePath ((</>))

-- ---------------------------------------------------------------------------
-- Types
-- ---------------------------------------------------------------------------

-- | A node in the NAR tree.
data NarEntry
  = -- | Regular file: executable flag and contents.
    NarRegular !Bool !ByteString
  | -- | Symbolic link: target path.
    NarSymlink !Text
  | -- | Directory: sorted list of (name, entry) pairs.
    NarDirectory ![(Text, NarEntry)]
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
    <> narStr (TE.encodeUtf8 target)
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
buildDirEntry :: (Text, NarEntry) -> B.Builder
buildDirEntry (entryName, entry) =
  narStr tokEntry
    <> narStr tokLParen
    <> narStr tokName
    <> narStr (TE.encodeUtf8 entryName)
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
          (_, afterEmpty) <- readStr rest
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
          -- a regular node without it is malformed — reject, matching Nix.
          Left ("expected 'executable' or 'contents' in regular, got: " ++ show tok)

-- | Parse a symlink node.
parseSymlink :: NarParser NarEntry
parseSymlink bs = do
  (tgt, afterTgt) <- readStr bs
  expect tokTarget tgt
  (targetPath, afterPath) <- readStr afterTgt
  (rp, final) <- readStr afterPath
  expect tokRParen rp
  symTarget <- decodeUtf8Safe targetPath
  pure (NarSymlink symTarget, final)

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
          decodedName <- decodeUtf8Safe entryName
          _ <- checkName prev decodedName
          go (Just decodedName) ((decodedName, entry) : acc) afterRp
    -- NAR directory entries must have safe names in strictly increasing
    -- (sorted, unique) order.  Enforcing this rejects malformed or hostile
    -- archives, keeps @serialise . deserialise@ an identity, and forecloses the
    -- path-traversal surface for any future NAR-extraction consumer.
    checkName prev name
      | T.null name = Left "empty NAR directory entry name"
      | name == "." || name == ".." || T.any (\c -> c == '/' || c == '\0') name =
          Left ("unsafe NAR directory entry name: " ++ T.unpack name)
      | Just p <- prev,
        name <= p =
          Left ("NAR directory entries not strictly increasing: " ++ T.unpack name)
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
  | otherwise =
      Right (BS.take (fromIntegral len) payload, BS.drop totalLen payload)
  where
    len = readWord64LE bs
    payload = BS.drop wordSize bs
    totalLen = fromIntegral len + narPad (fromIntegral len)

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

-- | Decode a UTF-8 bytestring, converting decode failures to parse errors.
decodeUtf8Safe :: ByteString -> Either String Text
decodeUtf8Safe bs = case TE.decodeUtf8' bs of
  Right txt -> Right txt
  Left err -> Left ("invalid UTF-8 in NAR: " ++ show err)

-- ---------------------------------------------------------------------------
-- Hashing
-- ---------------------------------------------------------------------------

-- | SHA-256 hash of the NAR serialization. Pure composition.
narHash :: NarEntry -> Hash.NixHash
narHash = Hash.hashBytes . serialise

-- ---------------------------------------------------------------------------
-- Filesystem to NarEntry (IO boundary)
-- ---------------------------------------------------------------------------

-- | Walk a filesystem path and build a 'NarEntry'.
--
-- This is the sole IO function in the module. It classifies each path
-- as symlink, directory, or regular file, then delegates to pure
-- constructors.
serialiseFromPath :: FilePath -> IO NarEntry
serialiseFromPath path = do
  isSym <- pathIsSymbolicLink path
  if isSym
    then NarSymlink . T.pack <$> getSymbolicLinkTarget path
    else do
      isDir <- doesDirectoryExist path
      if isDir
        then buildDirectory path
        else buildRegularFile path

-- | Build a directory entry by recursively walking children.
buildDirectory :: FilePath -> IO NarEntry
buildDirectory path = do
  names <- sort <$> listDirectory path
  entries <- traverse walkChild names
  pure (NarDirectory entries)
  where
    walkChild name = do
      entry <- serialiseFromPath (path </> name)
      pure (T.pack name, entry)

-- | Build a regular file entry, checking the executable bit.
buildRegularFile :: FilePath -> IO NarEntry
buildRegularFile path = do
  isFile <- doesFileExist path
  if isFile
    then do
      contents <- BS.readFile path
      isExec <- checkExecutable path
      pure (NarRegular isExec contents)
    else pure (NarRegular False BS.empty)

-- | Check whether a file has the executable permission set.
-- Uses 'System.Directory.getPermissions' which is cross-platform:
-- checks the user-execute bit on Unix, file extension on Windows.
checkExecutable :: FilePath -> IO Bool
checkExecutable path = executable <$> getPermissions path
