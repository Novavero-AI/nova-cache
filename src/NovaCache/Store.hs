-- | Filesystem storage backend for a Nix binary cache.
--
-- Stores narinfo and NAR files in a directory tree:
--
-- @
-- \<root\>\/narinfo\/\<hash\>   -- narinfo files by store path hash
-- \<root\>\/nar\/\<filename\>   -- compressed NAR files
-- @
module NovaCache.Store
  ( FileStore (..),
    newFileStore,
    readNarInfo,
    writeNarInfo,
    readNar,
    writeNar,
    listNarInfoHashes,
    getCacheInfo,
    sanitizePath,
  )
where

import Control.Exception (SomeException, catch, onException)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Text (Text)
import qualified Data.Text as T
import System.Directory
  ( createDirectoryIfMissing,
    doesFileExist,
    listDirectory,
    removeFile,
    renameFile,
  )
import System.FilePath (takeDirectory, (</>))
import System.IO (hClose, openBinaryTempFile)

-- ---------------------------------------------------------------------------
-- Types
-- ---------------------------------------------------------------------------

-- | Filesystem-backed cache store configuration.
data FileStore = FileStore
  { fsRoot :: !FilePath,
    fsStoreDir :: !Text,
    fsPriority :: !Int
  }
  deriving (Show)

-- ---------------------------------------------------------------------------
-- Constants
-- ---------------------------------------------------------------------------

-- | Subdirectory for narinfo files.
narinfoSubdir :: String
narinfoSubdir = "narinfo"

-- | Subdirectory for NAR files.
narSubdir :: String
narSubdir = "nar"

-- | Default cache priority (lower = preferred by Nix).
-- Community caches should use a higher number than cache.nixos.org (40)
-- so the official cache is preferred and we serve as a fallback.
defaultPriority :: Int
defaultPriority = 50

-- | Default Nix store directory.
defaultStoreDir :: Text
defaultStoreDir = "/nix/store"

-- | Prefix for temporary files used during atomic writes.
tempFilePrefix :: String
tempFilePrefix = ".nova.tmp"

-- ---------------------------------------------------------------------------
-- Initialization
-- ---------------------------------------------------------------------------

-- | Create a 'FileStore' rooted at the given directory.
--
-- Ensures the @narinfo@ and @nar@ subdirectories exist.
newFileStore :: FilePath -> IO FileStore
newFileStore root = do
  createDirectoryIfMissing True (root </> narinfoSubdir)
  createDirectoryIfMissing True (root </> narSubdir)
  pure
    FileStore
      { fsRoot = root,
        fsStoreDir = defaultStoreDir,
        fsPriority = defaultPriority
      }

-- ---------------------------------------------------------------------------
-- NarInfo operations
-- ---------------------------------------------------------------------------

-- | Read a narinfo by its store path hash. Returns 'Nothing' if absent.
--
-- Returns 'Nothing' for path components containing traversal sequences.
readNarInfo :: FileStore -> Text -> IO (Maybe ByteString)
readNarInfo fs hashKey = case sanitizePath hashKey of
  Nothing -> pure Nothing
  Just safe -> readIfExists (fsRoot fs </> narinfoSubdir </> safe)

-- | Write a narinfo by its store path hash.
--
-- Uses atomic write-to-temp-then-rename so concurrent readers never
-- see partial content.
-- Returns 'False' for path components containing traversal sequences.
writeNarInfo :: FileStore -> Text -> ByteString -> IO Bool
writeNarInfo fs hashKey body = case sanitizePath hashKey of
  Nothing -> pure False
  Just safe -> atomicWriteFile (fsRoot fs </> narinfoSubdir </> safe) body >> pure True

-- ---------------------------------------------------------------------------
-- NAR operations
-- ---------------------------------------------------------------------------

-- | Read a NAR file by its filename. Returns 'Nothing' if absent.
--
-- Returns 'Nothing' for path components containing traversal sequences.
readNar :: FileStore -> Text -> IO (Maybe ByteString)
readNar fs fileName = case sanitizePath fileName of
  Nothing -> pure Nothing
  Just safe -> readIfExists (fsRoot fs </> narSubdir </> safe)

-- | Write a NAR file by its filename.
--
-- Uses atomic write-to-temp-then-rename so concurrent readers never
-- see partial content.
-- Returns 'False' for path components containing traversal sequences.
writeNar :: FileStore -> Text -> ByteString -> IO Bool
writeNar fs fileName body = case sanitizePath fileName of
  Nothing -> pure False
  Just safe -> atomicWriteFile (fsRoot fs </> narSubdir </> safe) body >> pure True

-- ---------------------------------------------------------------------------
-- Listing
-- ---------------------------------------------------------------------------

-- | List all narinfo hashes currently stored.
--
-- Returns the filenames in the @narinfo/@ subdirectory as 'Text' values.
-- Filters out temporary files from in-progress atomic writes.
listNarInfoHashes :: FileStore -> IO [Text]
listNarInfoHashes fs =
  filter (not . T.isPrefixOf ".") . map T.pack
    <$> listDirectory (fsRoot fs </> narinfoSubdir)

-- ---------------------------------------------------------------------------
-- Cache metadata
-- ---------------------------------------------------------------------------

-- | Cache metadata: (storeDir, wantMassQuery, priority).
getCacheInfo :: FileStore -> (Text, Bool, Int)
getCacheInfo fs = (fsStoreDir fs, True, fsPriority fs)

-- ---------------------------------------------------------------------------
-- Path sanitization
-- ---------------------------------------------------------------------------

-- | Validate a path component for safe filesystem use.
--
-- Rejects components containing directory separators (@\/@, @\\@),
-- traversal sequences (@..@), or empty strings. Returns 'Just' the
-- sanitized 'FilePath' on success, 'Nothing' on rejection.
sanitizePath :: Text -> Maybe FilePath
sanitizePath txt
  | T.null txt = Nothing
  | T.any isPathSeparator txt = Nothing
  | txt == ".." = Nothing
  | otherwise = Just (T.unpack txt)
  where
    isPathSeparator c = c == '/' || c == '\\'

-- ---------------------------------------------------------------------------
-- Internal
-- ---------------------------------------------------------------------------

-- | Write a file atomically via write-to-temp-then-rename.
--
-- Writes to a temporary file in the same directory, then renames to
-- the target path. On POSIX, @rename@ is atomic — readers see either
-- the old content or the new content, never a partial write.
-- Cleans up the temporary file on failure.
atomicWriteFile :: FilePath -> ByteString -> IO ()
atomicWriteFile target content = do
  let dir = takeDirectory target
  (tmpPath, h) <- openBinaryTempFile dir tempFilePrefix
  let cleanup = do
        ignoringExceptions (hClose h)
        ignoringExceptions (removeFile tmpPath)
  ( do
      BS.hPut h content
      hClose h
      renameFile tmpPath target
    )
    `onException` cleanup

-- | Swallow all exceptions from a cleanup action.
ignoringExceptions :: IO () -> IO ()
ignoringExceptions action = action `catch` silenceException
  where
    silenceException :: SomeException -> IO ()
    silenceException _ = pure ()

-- | Read a file if it exists, returning 'Nothing' otherwise.
readIfExists :: FilePath -> IO (Maybe ByteString)
readIfExists path = do
  exists <- doesFileExist path
  if exists
    then Just <$> BS.readFile path
    else pure Nothing
