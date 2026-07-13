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
    NarWriteResult (..),
    writeNarStreaming,
    narFilePath,
    listNarInfoHashes,
    CacheInfo (..),
    getCacheInfo,
    sanitizePath,
  )
where

import Control.Exception (IOException, SomeException, catch, onException)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Char (isAsciiLower, isAsciiUpper, isDigit)
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

-- | Outcome of a streaming NAR write.
data NarWriteResult
  = -- | Fully written and atomically renamed into place.
    NarWriteOk
  | -- | The chunk stream exceeded the size cap; the partial temp file
    -- was deleted and nothing changed in the store.
    NarWriteTooLarge
  | -- | The filename failed 'sanitizePath'; nothing was written.
    NarWriteBadPath
  deriving (Eq, Show)

-- | Stream a NAR to disk from a chunk source (an empty chunk means end of
-- input), enforcing a total-size cap as bytes arrive so the body is never
-- held in memory.  Same atomic temp-then-rename discipline as 'writeNar':
-- readers see the old file or the complete new one, never a partial write.
writeNarStreaming :: FileStore -> Text -> Int -> IO ByteString -> IO NarWriteResult
writeNarStreaming fs fileName limit nextChunk = case sanitizePath fileName of
  Nothing -> pure NarWriteBadPath
  Just safe -> do
    let target = fsRoot fs </> narSubdir </> safe
    (tmpPath, handle) <- openBinaryTempFile (takeDirectory target) tempFilePrefix
    let cleanup = do
          ignoringExceptions (hClose handle)
          ignoringExceptions (removeFile tmpPath)
        consume !total = do
          chunk <- nextChunk
          if BS.null chunk
            then do
              hClose handle
              renameFile tmpPath target
              pure NarWriteOk
            else
              let grown = total + BS.length chunk
               in if grown > limit
                    then cleanup >> pure NarWriteTooLarge
                    else BS.hPut handle chunk >> consume grown
    consume 0 `onException` cleanup

-- | The on-disk path of a stored NAR, if present.  Lets a server hand the
-- file to its transport layer (e.g. WAI's @responseFile@, which streams
-- from disk) instead of buffering the bytes; the name passes the same
-- 'sanitizePath' contract as 'readNar'.
narFilePath :: FileStore -> Text -> IO (Maybe FilePath)
narFilePath fs fileName = case sanitizePath fileName of
  Nothing -> pure Nothing
  Just safe -> do
    let path = fsRoot fs </> narSubdir </> safe
    exists <- doesFileExist path
    pure (if exists then Just path else Nothing)

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

-- | Cache metadata for the @nix-cache-info@ response.
data CacheInfo = CacheInfo
  { ciStoreDir :: !Text,
    ciWantMassQuery :: !Bool,
    ciPriority :: !Int
  }
  deriving (Eq, Show)

-- | This file-backed cache answers mass-query (path-existence) requests.
defaultWantMassQuery :: Bool
defaultWantMassQuery = True

-- | Read the cache's metadata.
getCacheInfo :: FileStore -> CacheInfo
getCacheInfo fs =
  CacheInfo
    { ciStoreDir = fsStoreDir fs,
      ciWantMassQuery = defaultWantMassQuery,
      ciPriority = fsPriority fs
    }

-- ---------------------------------------------------------------------------
-- Path sanitization
-- ---------------------------------------------------------------------------

-- | Validate a path component for safe filesystem use via a positive allowlist.
--
-- Accepts only non-empty names of @[A-Za-z0-9._+-]@ that do not start with a
-- dot and are not a Windows reserved device name. This rejects directory
-- separators, @.@\/@..@ traversal, dotfiles (including the temp-write prefix),
-- NUL bytes, alternate-data-stream (@name:stream@) syntax, and device names
-- like @nul@ - so a client-supplied hash or NAR filename can never escape the
-- store directory or resolve to a device, on any platform.
sanitizePath :: Text -> Maybe FilePath
sanitizePath txt
  | T.null txt = Nothing
  | T.isPrefixOf "." txt = Nothing
  | T.any (not . isSafeChar) txt = Nothing
  | isReservedName txt = Nothing
  | otherwise = Just (T.unpack txt)
  where
    isSafeChar c =
      isAsciiLower c || isAsciiUpper c || isDigit c || c `elem` ("._-+" :: [Char])

-- | Is the name a Windows reserved device (@con@, @prn@, @aux@, @nul@,
-- @com1@-@com9@, @lpt1@-@lpt9@)? Matched case-insensitively on the portion
-- before the first dot, since @nul.txt@ also opens the device. Enforced on
-- every platform so a Windows-hosted cache is safe too.
isReservedName :: Text -> Bool
isReservedName txt = T.toLower (T.takeWhile (/= '.') txt) `elem` reservedNames
  where
    reservedNames =
      ["con", "prn", "aux", "nul"]
        ++ ["com" <> n | n <- digits]
        ++ ["lpt" <> n | n <- digits]
    digits = [T.pack (show n) | n <- [1 .. 9 :: Int]]

-- ---------------------------------------------------------------------------
-- Internal
-- ---------------------------------------------------------------------------

-- | Write a file atomically via write-to-temp-then-rename.
--
-- Writes to a temporary file in the same directory, then renames to
-- the target path. On POSIX, @rename@ is atomic - readers see either
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
--
-- Any I/O error (bad permissions, a race with deletion, a name that slips
-- through validation) is treated as absence rather than propagating and
-- crashing the request handler.
readIfExists :: FilePath -> IO (Maybe ByteString)
readIfExists path = readExisting `catch` ignoreIOError
  where
    readExisting = do
      exists <- doesFileExist path
      if exists
        then Just <$> BS.readFile path
        else pure Nothing
    ignoreIOError :: IOException -> IO (Maybe ByteString)
    ignoreIOError _ = pure Nothing
