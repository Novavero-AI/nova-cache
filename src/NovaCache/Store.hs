-- | Filesystem storage backend for a Nix binary cache.
--
-- Stores narinfo and NAR files in a directory tree:
--
-- @
-- \<root\>\/narinfo\/\<hash\>              -- narinfo files by store path hash
-- \<root\>\/nar\/\<filename\>              -- compressed NAR files
-- \<root\>\/uploads\/\<id\>-\<filename\>\/\<n\>  -- parts of a multipart upload in progress
-- @
--
-- A multipart upload is completed by a rename from its directory under
-- @uploads\/@ into @nar\/@, so the two share a filesystem, as they do
-- under one store root unless one of them is mounted apart.
module NovaCache.Store
  ( FileStore (..),
    newFileStore,
    fileStoreAt,
    readNarInfo,
    writeNarInfo,
    readNar,
    writeNar,
    NarWriteResult (..),
    writeNarStreaming,
    narFilePath,
    NarRemoveResult (..),
    removeNar,
    listNarInfoHashes,
    listNarInfoFiles,
    NarFile (..),
    listNarFiles,

    -- * Multipart uploads
    UploadId,
    parseUploadId,
    renderUploadId,
    PartNumber,
    maxUploadParts,
    parsePartNumber,
    renderPartNumber,
    beginUpload,
    PartWriteResult (..),
    writeUploadPart,
    UploadTotals (..),
    CompletionResult (..),
    completeUpload,
    StagedUpload (..),
    listStagedUploads,
    UploadRemoveResult (..),
    removeUpload,

    -- * Metadata and names
    CacheInfo (..),
    getCacheInfo,
    sanitizePath,
  )
where

import Control.Exception (IOException, catch, onException, try, tryJust)
import Control.Monad (foldM, guard, join)
import Crypto.Random (getRandomBytes)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as Builder
import qualified Data.ByteString.Lazy as BL
import Data.Char (isAsciiLower, isAsciiUpper, isDigit)
import Data.List (isPrefixOf)
import Data.Maybe (catMaybes, fromMaybe)
import qualified Data.Set as Set
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Text.Read as TR
import Data.Time.Clock (UTCTime)
import NovaCache.SafeName (hasTrailingDotOrSpace, isReservedDeviceName)
import System.Directory
  ( createDirectory,
    createDirectoryIfMissing,
    doesDirectoryExist,
    doesFileExist,
    getFileSize,
    getModificationTime,
    listDirectory,
    removeDirectoryRecursive,
    removeFile,
    renameFile,
  )
import System.FilePath (takeDirectory, (</>))
import System.IO (Handle, IOMode (ReadMode), hClose, openBinaryTempFile, withBinaryFile)
import System.IO.Error (isDoesNotExistError)

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

-- | Subdirectory for multipart uploads in progress.
uploadsSubdir :: String
uploadsSubdir = "uploads"

-- | Prefix for temporary files used during atomic writes.
tempFilePrefix :: String
tempFilePrefix = ".nova.tmp"

-- | Bytes read per step while joining an upload's parts.
joinReadBytes :: Int
joinReadBytes = 128 * 1024

-- | The longest file name ext4, APFS and NTFS admit: 255 bytes,
-- characters or UTF-16 units by filesystem, which agree for the ASCII
-- names a store holds.
maxFileNameLength :: Int
maxFileNameLength = 255

-- ---------------------------------------------------------------------------
-- Initialization
-- ---------------------------------------------------------------------------

-- | Create a 't:FileStore' rooted at the given directory.
--
-- Ensures the @narinfo@, @nar@ and @uploads@ subdirectories exist.
newFileStore :: FilePath -> IO FileStore
newFileStore root = do
  createDirectoryIfMissing True (root </> narinfoSubdir)
  createDirectoryIfMissing True (root </> narSubdir)
  createDirectoryIfMissing True (root </> uploadsSubdir)
  pure (fileStoreAt root)

-- | A 't:FileStore' over a directory tree as it stands, creating
-- nothing.  For a host tool that reads the store and acts on what it
-- finds: a mistyped root, or a store missing its @narinfo@ directory,
-- must fail the listing, not be scanned as an empty store whose every
-- NAR looks unreferenced.
fileStoreAt :: FilePath -> FileStore
fileStoreAt root =
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
    streamed <- streamIntoPlace (takeDirectory target) limit nextChunk (`renameFile` target)
    pure $ case streamed of
      StreamWritten -> NarWriteOk
      StreamOverLimit -> NarWriteTooLarge

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

-- | Outcome of removing a stored NAR.
data NarRemoveResult
  = -- | The file is gone.
    NarRemoved
  | -- | The filesystem refused; nothing was removed.
    NarRemoveFailed !IOException
  | -- | The filename failed 'sanitizePath'; nothing was touched.
    NarRemoveBadPath
  deriving (Eq, Show)

-- | Remove a stored NAR by its filename.  Nothing in the HTTP protocol
-- calls this: deletion is for a tool the host operator runs against
-- the store directory.
removeNar :: FileStore -> Text -> IO NarRemoveResult
removeNar fs fileName = case sanitizePath fileName of
  Nothing -> pure NarRemoveBadPath
  Just safe ->
    either NarRemoveFailed (const NarRemoved)
      <$> tryIO (removeFile (fsRoot fs </> narSubdir </> safe))

-- ---------------------------------------------------------------------------
-- Listing
-- ---------------------------------------------------------------------------

-- | List all narinfo hashes currently stored.
--
-- Returns the filenames in the @narinfo/@ subdirectory as 'Text' values.
-- Filters out temporary files from in-progress atomic writes.
listNarInfoHashes :: FileStore -> IO [Text]
listNarInfoHashes fs =
  map T.pack . filter (not . isHiddenEntry)
    <$> listDirectory (fsRoot fs </> narinfoSubdir)

-- | The path of every stored narinfo: the files 'listNarInfoHashes'
-- names.
listNarInfoFiles :: FileStore -> IO [FilePath]
listNarInfoFiles fs =
  map (dir </>) . filter (not . isHiddenEntry) <$> listDirectory dir
  where
    dir = fsRoot fs </> narinfoSubdir

-- | A stored NAR as listed.
data NarFile = NarFile
  { -- | The filename under @nar\/@, as @PUT \/nar\/\<file\>@ named it.
    nfName :: !Text,
    nfPath :: !FilePath,
    nfSize :: !Integer,
    nfModified :: !UTCTime
  }
  deriving (Eq, Show)

-- | Every stored NAR: the regular files under @nar\/@ whose names
-- 'sanitizePath' admits, which are exactly the names an upload can
-- create.  An upload is written to a dotfile and renamed into place
-- only once complete, and 'sanitizePath' admits no dotfile, so a
-- partial write is never listed.  The rename keeps the temp file's
-- modification time, so 'nfModified' is when the upload's last bytes
-- were written.
listNarFiles :: FileStore -> IO [NarFile]
listNarFiles fs = catMaybes <$> (traverse describe =<< listDirectory dir)
  where
    dir = fsRoot fs </> narSubdir
    describe entry = case sanitizePath (T.pack entry) of
      Nothing -> pure Nothing
      Just safe -> do
        let path = dir </> safe
        isFile <- doesFileExist path
        if isFile
          then do
            size <- getFileSize path
            modified <- getModificationTime path
            pure
              ( Just
                  NarFile
                    { nfName = T.pack safe,
                      nfPath = path,
                      nfSize = size,
                      nfModified = modified
                    }
              )
          else pure Nothing

-- ---------------------------------------------------------------------------
-- Multipart uploads
-- ---------------------------------------------------------------------------

-- | Names one multipart upload: 16 random bytes, as 32 lowercase hex
-- digits.  The constructor is not exported, so every value is
-- one 'beginUpload' drew or 'parseUploadId' accepted, and its text is
-- safe in a file name.
newtype UploadId = UploadId Text
  deriving (Eq, Ord, Show)

-- | Random bytes in an upload id.  At 128 bits, ids drawn independently
-- do not collide in practice, so two pushes uploading the same NAR at
-- once stage their parts apart, with no record kept of the ids issued.
uploadIdBytes :: Int
uploadIdBytes = 16

-- | Hex digits in an upload id.
uploadIdDigits :: Int
uploadIdDigits = 2 * uploadIdBytes

-- | An upload id as a request names it: exactly 32 lowercase hex
-- digits.
parseUploadId :: Text -> Maybe UploadId
parseUploadId txt
  | T.length txt == uploadIdDigits && T.all isLowerHexDigit txt = Just (UploadId txt)
  | otherwise = Nothing
  where
    isLowerHexDigit c = isDigit c || (c >= 'a' && c <= 'f')

-- | An upload id as the server issues it and a request names it.
renderUploadId :: UploadId -> Text
renderUploadId (UploadId txt) = txt

-- | Draw a fresh upload id from the system's random source.
newUploadId :: IO UploadId
newUploadId = do
  bytes <- getRandomBytes uploadIdBytes
  pure (UploadId (TE.decodeLatin1 (BL.toStrict (Builder.toLazyByteString (Builder.byteStringHex bytes)))))

-- | A part's place in its upload, from 1 to 'maxUploadParts'.  The
-- constructor is not exported: every value is one 'parsePartNumber'
-- accepted.
newtype PartNumber = PartNumber Int
  deriving (Eq, Ord, Show)

-- | The most parts one upload holds, S3's limit.  Each part is a file in
-- the upload's staging directory, so this bounds the files one upload
-- creates.
maxUploadParts :: Int
maxUploadParts = 10000

-- | A part number in canonical decimal, from 1 to 'maxUploadParts':
-- digits only, with no sign and no leading zero, so each part has one
-- spelling in a request path and in its staging directory.  The length
-- is bounded before the parse, so an overlong number cannot wrap 'Int'
-- into range.
parsePartNumber :: Text -> Maybe PartNumber
parsePartNumber txt
  | T.length txt > T.length (renderInt maxUploadParts) = Nothing
  | otherwise = case TR.decimal txt of
      Right (n, _)
        | renderInt n == txt && n >= 1 && n <= maxUploadParts -> Just (PartNumber n)
      _ -> Nothing

-- | A part number in the canonical decimal 'parsePartNumber' reads.
renderPartNumber :: PartNumber -> Text
renderPartNumber (PartNumber n) = renderInt n

renderInt :: Int -> Text
renderInt = T.pack . show

-- | Joins an upload's id to its NAR's name in the name of its staging
-- directory.
stagingSeparator :: Char
stagingSeparator = '-'

-- | The staging directory of an upload of a NAR, by the name
-- 'sanitizePath' admitted: @uploads\/\<id\>-\<name\>@.  The NAR's name is
-- part of the directory's, so an upload is bound to the NAR it was
-- begun for, and a request naming another NAR finds no upload.
stagingDir :: FileStore -> FilePath -> UploadId -> FilePath
stagingDir fs safe (UploadId uid) =
  fsRoot fs </> uploadsSubdir </> (T.unpack uid ++ stagingSeparator : safe)

-- | The upload a directory under @uploads\/@ stages, by the directory's
-- name: its id and its NAR's name, or 'Nothing' for a name 'stagingDir'
-- never makes.
parseStagingName :: FilePath -> Maybe (UploadId, Text)
parseStagingName entry = case splitAt uploadIdDigits entry of
  (idDigits, separator : name)
    | separator == stagingSeparator,
      Just uid <- parseUploadId (T.pack idDigits),
      Just _ <- sanitizePath (T.pack name) ->
        Just (uid, T.pack name)
  _ -> Nothing

-- | A part's file in its upload's staging directory, named by its number.
partPath :: FilePath -> Int -> FilePath
partPath dir n = dir </> T.unpack (renderInt n)

-- | The parts an upload holds, in order: the files named 1, 2, and so on,
-- up to the first number missing.  Temp files are dotfiles, never part
-- numbers.  'Nothing' when the upload's directory does not exist.
listStagedParts :: FilePath -> IO (Maybe [(Int, FilePath)])
listStagedParts dir = fmap inOrder <$> ifPresent (listDirectory dir)
  where
    inOrder entries =
      let held = Set.fromList [n | Just (PartNumber n) <- map (parsePartNumber . T.pack) entries]
       in [(n, partPath dir n) | n <- takeWhile (`Set.member` held) [1 ..]]

-- | Begin a multipart upload of a NAR: an empty staging directory under
-- @uploads\/@, outside @nar\/@, so nothing an upload holds is served
-- before 'completeUpload' joins it.  'Nothing' when the name fails
-- 'sanitizePath', or is too long to stage: the directory's name is the
-- NAR's with the id before it.  'createDirectory' fails on a directory
-- that exists, so a drawn id never joins another upload.
beginUpload :: FileStore -> Text -> IO (Maybe UploadId)
beginUpload fs fileName = traverse begin (sanitizePath fileName >>= stageable)
  where
    stageable safe = safe <$ guard (uploadIdDigits + 1 + length safe <= maxFileNameLength)
    begin safe = do
      uid <- newUploadId
      createDirectory (stagingDir fs safe uid)
      pure uid

-- | Outcome of writing one part of an upload.
data PartWriteResult
  = -- | Written whole, in place of any earlier part of the same number.
    PartWritten
  | -- | The name failed 'sanitizePath'; nothing was written.
    PartBadPath
  | -- | No upload of that id is staged for that name: never begun,
    -- completed, or removed.
    PartUploadUnknown
  | -- | The part would leave a gap: the upload holds this many parts, so
    -- the next is one more.  Nothing was written.
    PartOutOfOrder !Int
  | -- | The upload's parts would hold more than the cap; the partial part
    -- was deleted and the parts held are unchanged.
    PartTooLarge
  deriving (Eq, Show)

-- | Stream one part of an upload into its staging directory, as
-- 'writeNarStreaming' streams a whole NAR: in constant memory, to a temp
-- file renamed into place only once complete, so a part is held whole
-- or not at all.  Parts arrive in order: part @n@ is accepted when the
-- upload holds parts 1 to @n - 1@, and a part it already holds is
-- replaced, so a client that lost a response can send the part again.
-- The cap bounds the part with the parts the upload holds when it
-- begins; parts written at once can pass it together, and
-- 'completeUpload' holds the joined NAR to it.
writeUploadPart :: FileStore -> Text -> UploadId -> PartNumber -> Int -> IO ByteString -> IO PartWriteResult
writeUploadPart fs fileName uid part@(PartNumber n) limit nextChunk = case sanitizePath fileName of
  Nothing -> pure PartBadPath
  Just safe -> do
    let dir = stagingDir fs safe uid
    staged <- listStagedParts dir
    maybe (pure PartUploadUnknown) (writePart dir) staged
  where
    writePart dir parts
      | n > length parts + 1 = pure (PartOutOfOrder (length parts))
      | otherwise = do
          others <- sum <$> traverse getFileSize [path | (number, path) <- parts, number /= n]
          let allowance = toInteger limit - others
              target = dir </> T.unpack (renderPartNumber part)
          streamed <-
            if allowance < 0
              then pure StreamOverLimit
              else streamIntoPlace dir (fromInteger allowance) nextChunk (`renameFile` target)
          pure $ case streamed of
            StreamWritten -> PartWritten
            StreamOverLimit -> PartTooLarge

-- | What a client declares when it completes an upload: how many parts
-- it sent, which is the number of its last part, and how many bytes
-- they hold together.
data UploadTotals = UploadTotals
  { utParts :: !PartNumber,
    utFileSize :: !Integer
  }
  deriving (Eq, Show)

-- | Outcome of completing an upload.
data CompletionResult
  = -- | The parts are joined into @nar\/\<file\>@ and the upload is gone.
    UploadCompleted
  | -- | The parts are joined into @nar\/\<file\>@, but the upload's
    -- directory could not be removed, so 'listStagedUploads' still
    -- lists it.
    UploadCompletedStagingKept !IOException
  | -- | The name failed 'sanitizePath'; nothing changed.
    CompletionBadPath
  | -- | No upload of that id is staged for that name; nothing changed.
    CompletionUploadUnknown
  | -- | The upload holds another number of parts than declared; nothing
    -- changed. (declared, held)
    CompletionPartsMismatch !Int !Int
  | -- | The parts join to another size than declared; nothing changed
    -- under @nar\/@ and the parts are kept. (declared, joined)
    CompletionSizeMismatch !Integer !Integer
  | -- | The declared size is over the cap; nothing changed and the parts
    -- are kept. (declared)
    CompletionTooLarge !Integer
  deriving (Eq, Show)

-- | Complete an upload: check that it holds the declared number of
-- parts and that the declared size is within the cap, join the parts in
-- order into a temp file in its directory, check the bytes joined
-- against the declared size, and only then rename the file to
-- @nar\/\<file\>@.  A NAR appears there whole or not at all, and a
-- missing part or a short one fails here rather than at the narinfo.
-- Each part write holds the parts to the cap as it finds them, which two
-- writes at once can each pass, so the cap is checked again here: the
-- joined size must equal the declared one, so no NAR over the cap is
-- renamed into place.  The join reads each part once, in constant
-- memory.
completeUpload :: FileStore -> Text -> UploadId -> Int -> UploadTotals -> IO CompletionResult
completeUpload fs fileName uid limit (UploadTotals (PartNumber declaredParts) declaredSize) =
  case sanitizePath fileName of
    Nothing -> pure CompletionBadPath
    Just safe -> do
      let dir = stagingDir fs safe uid
      staged <- listStagedParts dir
      maybe (pure CompletionUploadUnknown) (complete safe dir . map snd) staged
  where
    complete safe dir parts
      | declaredSize > toInteger limit = pure (CompletionTooLarge declaredSize)
      | length parts /= declaredParts = pure (CompletionPartsMismatch declaredParts (length parts))
      | otherwise = do
          joined <- joinThen dir parts (placeJoined safe)
          case joined of
            UploadCompleted ->
              either UploadCompletedStagingKept (const UploadCompleted)
                <$> tryIO (removeDirectoryRecursive dir)
            refused -> pure refused
    placeJoined safe joinedPath size
      | size /= declaredSize = CompletionSizeMismatch declaredSize size <$ removeFile joinedPath
      | otherwise = UploadCompleted <$ renameFile joinedPath (fsRoot fs </> narSubdir </> safe)

-- | Concatenate files, in order, into a new temp file in a directory, in
-- constant memory, then hand the closed file and the bytes it holds to
-- @finish@, which moves it into place or removes it.  If the join or
-- @finish@ fails, the temp file is removed, so a failed rename leaves no
-- copy behind.
joinThen :: FilePath -> [FilePath] -> (FilePath -> Integer -> IO a) -> IO a
joinThen dir paths finish = do
  (tmpPath, handle) <- openBinaryTempFile dir tempFilePrefix
  ( do
      size <- foldM (appendFileTo handle) 0 paths
      hClose handle
      finish tmpPath size
    )
    `onException` discardTemp tmpPath handle

-- | Append a file's bytes to a handle in constant memory, adding their
-- count to a running total.
appendFileTo :: Handle -> Integer -> FilePath -> IO Integer
appendFileTo out total path = withBinaryFile path ReadMode (copy total)
  where
    copy !count input = do
      chunk <- BS.hGetSome input joinReadBytes
      if BS.null chunk
        then pure count
        else BS.hPut out chunk >> copy (count + toInteger (BS.length chunk)) input

-- | A multipart upload as staged: begun, and neither completed nor
-- removed.
data StagedUpload = StagedUpload
  { -- | The NAR it was begun for, as @POST \/nar\/\<file\>\/uploads@ named it.
    suFileName :: !Text,
    suUploadId :: !UploadId,
    -- | Its staging directory.
    suPath :: !FilePath,
    -- | Bytes its files hold: its parts, and any part or join in progress.
    suSize :: !Integer,
    -- | Its last activity: the latest modification time of its directory
    -- and of the files in it.
    suModified :: !UTCTime
  }
  deriving (Eq, Show)

-- | Every staged upload: the directories under @uploads\/@ named
-- @\<id\>-\<file\>@ for an upload id and a NAR's name.  A store with no
-- @uploads\/@ directory, as a server older than multipart uploads leaves
-- one, holds none.  An upload in progress renames its temp files and a
-- completion removes its directory, so a file or directory that
-- vanishes while it is read is activity, skipped rather than failing
-- the listing.
listStagedUploads :: FileStore -> IO [StagedUpload]
listStagedUploads fs = do
  entries <- fromMaybe [] <$> ifPresent (listDirectory dir)
  catMaybes <$> traverse describe entries
  where
    dir = fsRoot fs </> uploadsSubdir
    describe entry = case parseStagingName entry of
      Nothing -> pure Nothing
      Just (uid, name) -> do
        let path = dir </> entry
        isDir <- doesDirectoryExist path
        if isDir
          then fmap (staged uid name path) <$> measureStaging path
          else pure Nothing
    staged uid name path (size, modified) =
      StagedUpload
        { suFileName = name,
          suUploadId = uid,
          suPath = path,
          suSize = size,
          suModified = modified
        }

-- | The bytes an upload's directory holds and its last activity, or
-- 'Nothing' when the directory is gone.  The directory's own time is
-- read after its files, so a part renamed into place while they are
-- read still counts as activity.
measureStaging :: FilePath -> IO (Maybe (Integer, UTCTime))
measureStaging path = do
  listed <- ifPresent (listDirectory path)
  join <$> traverse measure listed
  where
    measure names = do
      files <- catMaybes <$> traverse (ifPresent . sizeAndTime . (path </>)) names
      dirTime <- ifPresent (getModificationTime path)
      pure (fmap (\time -> (sum (map fst files), foldl' max time (map snd files))) dirTime)
    sizeAndTime file = (,) <$> getFileSize file <*> getModificationTime file

-- | Outcome of removing a staged upload.
data UploadRemoveResult
  = -- | The upload and every part it held are gone.
    UploadRemoved
  | -- | The filesystem refused; what remains is still listed.
    UploadRemoveFailed !IOException
  | -- | The name failed 'sanitizePath'; nothing was touched.
    UploadRemoveBadPath
  deriving (Eq, Show)

-- | Remove a staged upload and every part it holds.  Nothing in the HTTP
-- protocol calls this: like 'removeNar', it is for a tool the host
-- operator runs against the store directory.
removeUpload :: FileStore -> Text -> UploadId -> IO UploadRemoveResult
removeUpload fs fileName uid = case sanitizePath fileName of
  Nothing -> pure UploadRemoveBadPath
  Just safe ->
    either UploadRemoveFailed (const UploadRemoved)
      <$> tryIO (removeDirectoryRecursive (stagingDir fs safe uid))

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
-- dot, do not end with a dot (NTFS strips it, silently renaming the file),
-- and are not a Windows reserved device name. This rejects directory
-- separators, @.@\/@..@ traversal, dotfiles (including the temp-write prefix),
-- NUL bytes, alternate-data-stream (@name:stream@) syntax, and device names
-- like @nul@ - so a client-supplied hash or NAR filename can never escape the
-- store directory, resolve to a device, or land under a different name, on
-- any platform.  The Windows-specific categories are shared with the NAR
-- entry-name guard via "NovaCache.SafeName".
sanitizePath :: Text -> Maybe FilePath
sanitizePath txt
  | T.null txt = Nothing
  | T.isPrefixOf "." txt = Nothing
  | T.any (not . isSafeChar) txt = Nothing
  | isReservedDeviceName keyBytes = Nothing
  | hasTrailingDotOrSpace keyBytes = Nothing
  | otherwise = Just (T.unpack txt)
  where
    -- The shared hazard predicates take the byte form NAR entry names
    -- have; a store key is ASCII by the allowlist above, so its UTF-8
    -- encoding is the same spelling.
    keyBytes = TE.encodeUtf8 txt
    isSafeChar c =
      isAsciiLower c || isAsciiUpper c || isDigit c || c `elem` ("._-+" :: [Char])

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
  ( do
      BS.hPut h content
      hClose h
      renameFile tmpPath target
    )
    `onException` discardTemp tmpPath h

-- | Whether a stream fit under its cap.
data Streamed = StreamWritten | StreamOverLimit

-- | Stream chunks (an empty chunk ends the input) into a new temp file in
-- a directory under a size cap, never holding the body in memory, then
-- hand the closed file to @commit@, which renames it into place.  Past
-- the cap, or on an exception, the temp file is removed and nothing is
-- committed.
streamIntoPlace :: FilePath -> Int -> IO ByteString -> (FilePath -> IO ()) -> IO Streamed
streamIntoPlace dir limit nextChunk commit = do
  (tmpPath, handle) <- openBinaryTempFile dir tempFilePrefix
  let consume !total = do
        chunk <- nextChunk
        if BS.null chunk
          then do
            hClose handle
            commit tmpPath
            pure StreamWritten
          else
            let grown = total + BS.length chunk
             in if grown > limit
                  then discardTemp tmpPath handle >> pure StreamOverLimit
                  else BS.hPut handle chunk >> consume grown
  consume 0 `onException` discardTemp tmpPath handle

-- | Close and remove a temp file a write abandons, past its cap or while
-- its own failure propagates.  Errors here are dropped, so they never
-- replace that failure.
discardTemp :: FilePath -> Handle -> IO ()
discardTemp tmpPath handle = do
  ignoringExceptions (hClose handle)
  ignoringExceptions (removeFile tmpPath)

-- | Run a filesystem read, or 'Nothing' when what it reads does not
-- exist; any other failure propagates.
ifPresent :: IO a -> IO (Maybe a)
ifPresent action = either (const Nothing) Just <$> tryJust (guard . isDoesNotExistError) action

-- | A dotfile: every temp file the atomic writes create (the
-- template's leading dot survives 'openBinaryTempFile'), and never a
-- key 'sanitizePath' admits.
isHiddenEntry :: FilePath -> Bool
isHiddenEntry = isPrefixOf "."

-- | 'try' at 'IOException', the failure a filesystem call is expected
-- to raise; anything else (an interrupt among them) propagates.
tryIO :: IO a -> IO (Either IOException a)
tryIO = try

-- | Drop the 'IOException' a cleanup action raises; anything else, an
-- interrupt among them, propagates.
ignoringExceptions :: IO () -> IO ()
ignoringExceptions action = action `catch` silenceException
  where
    silenceException :: IOException -> IO ()
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
