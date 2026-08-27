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
--
-- Parsing is the whole-input instantiation of the incremental machine
-- in "NovaCache.NAR.Stream", and serialisation draws on that module's
-- wire vocabulary - the grammar exists once.  To serialise a tree
-- without holding file contents in memory, see 'withNarSource'.
module NovaCache.NAR
  ( NarEntry (..),
    serialise,
    deserialise,
    isWindowsHazardName,
    narHash,
    serialiseFromPath,
    serialiseFromPathWith,
    serialiseFromPathOpts,
    withNarSource,
    withNarSourceOpts,
    SerialiseOptions (..),
    defaultSerialiseOptions,
    ExecBitResolver,
    defaultExecBitResolver,
    CaseHack (..),
    defaultCaseHack,
    caseHackSuffix,
  )
where

import Control.Exception (bracketOnError, finally)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as B
import qualified Data.ByteString.Lazy as BL
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import Data.List (sort, sortBy)
import Data.Ord (comparing)
import Data.Word (Word64)
import qualified NovaCache.Hash as Hash
import NovaCache.NAR.Stream
  ( NarEvent (..),
    NarStep (..),
    isWindowsHazardName,
    narPad,
    narPadOf,
    narStreamBounded,
    tokContents,
    tokDirectory,
    tokEntry,
    tokExecutable,
    tokLParen,
    tokMagic,
    tokName,
    tokNode,
    tokRParen,
    tokRegular,
    tokSymlink,
    tokTarget,
    tokType,
  )
import System.Directory.OsPath
  ( doesDirectoryExist,
    doesFileExist,
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
import System.Directory.OsPath (executable, getPermissions)
import System.IO (Handle, IOMode (ReadMode), hClose, hFileSize, openBinaryFile)
#else
import qualified Data.ByteString.Char8 as BS8
import System.IO (Handle, IOMode (ReadMode), hClose, hFileSize, latin1, openBinaryFile)
import qualified System.Posix.Files as Posix
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

-- ---------------------------------------------------------------------------
-- Deserialization (the streaming machine, driven over the whole input)
-- ---------------------------------------------------------------------------

-- | Deserialise NAR binary format to a 'NarEntry'.
--
-- Drives "NovaCache.NAR.Stream" over the whole input, folding its
-- events back into a tree.  The structural-string bound is the input's
-- own length - a wire string cannot outgrow its container - so this
-- accepts exactly what the dedicated whole-input parser accepted,
-- with no extra ceiling.  Contents events are slices of the input, so
-- single-chunk files rebuild by sharing, not copying.
deserialise :: ByteString -> Either String NarEntry
deserialise input = drive True (narStreamBounded (fromIntegral (BS.length input))) [] Nothing
  where
    drive !firstFeed step !stack !root = case step of
      NarFail err -> Left err
      NarDone -> case (stack, root) of
        ([], Just entry) -> Right entry
        _ -> Left malformedEventStream
      NarYield event continue -> do
        (stackNext, rootNext) <- applyEvent event stack root
        drive firstFeed continue stackNext rootNext
      NarAwait continue
        | firstFeed -> drive False (continue input) stack root
        | otherwise -> drive False (continue BS.empty) stack root

-- | One frame of the event fold in 'deserialise': the construct
-- enclosing the node currently being built.
data BuildFrame
  = -- | A regular file: executable flag and reversed contents slices.
    FrameRegular !Bool ![ByteString]
  | -- | A directory: completed children, reversed.
    FrameDirectory ![(ByteString, NarEntry)]
  | -- | A directory entry: its name, then its node once complete.
    FrameEntry !ByteString !(Maybe NarEntry)

-- | Apply one event to the frame stack.  The machine already validated
-- the grammar, so the mismatch arms are unreachable through
-- 'narStreamBounded'; they fail closed rather than building partially.
applyEvent :: NarEvent -> [BuildFrame] -> Maybe NarEntry -> Either String ([BuildFrame], Maybe NarEntry)
applyEvent event stack root = case (event, stack) of
  (EventRegularBegin isExec _declaredSize, _) ->
    Right (FrameRegular isExec [] : stack, root)
  (EventRegularChunk slice, FrameRegular isExec chunks : rest) ->
    Right (FrameRegular isExec (slice : chunks) : rest, root)
  (EventRegularEnd, FrameRegular isExec chunks : rest) ->
    complete (NarRegular isExec (BS.concat (reverse chunks))) rest
  (EventSymlink target, _) ->
    complete (NarSymlink target) stack
  (EventDirectoryBegin, _) ->
    Right (FrameDirectory [] : stack, root)
  (EventEntryBegin entryName, _) ->
    Right (FrameEntry entryName Nothing : stack, root)
  (EventEntryEnd, FrameEntry entryName (Just entry) : FrameDirectory entriesRev : rest) ->
    Right (FrameDirectory ((entryName, entry) : entriesRev) : rest, root)
  (EventDirectoryEnd, FrameDirectory entriesRev : rest) ->
    complete (NarDirectory (reverse entriesRev)) rest
  _ -> Left malformedEventStream
  where
    complete entry remaining = case remaining of
      [] -> case root of
        Nothing -> Right ([], Just entry)
        Just _ -> Left malformedEventStream
      FrameEntry entryName Nothing : rest ->
        Right (FrameEntry entryName (Just entry) : rest, root)
      _ -> Left malformedEventStream

malformedEventStream :: String
malformedEventStream = "malformed NAR event stream"

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

-- | Answers "is this file executable" for one regular file during a
-- walk.  Called with the platform-native ON-DISK path - under
-- 'CaseHackEnabled' that is the suffixed spelling the walk is
-- reading, not the stripped NAR entry name - and the answer lands
-- verbatim in the entry's (or stream's) executable flag.  Lets a
-- store that models the bit outside POSIX permissions (an NTFS
-- alternate data stream, a sidecar, a database) serialise correct
-- NAR bytes in the same walk, streaming included.
--
-- The path is the walk's own 'decodeFS' rendering: pass it to any
-- 'FilePath'-taking API as-is; 'encodeFS' it first to compare raw
-- bytes, since a non-UTF-8 name arrives with surrogate escapes.
type ExecBitResolver = FilePath -> IO Bool

#ifdef mingw32_HOST_OS

-- | The stock resolver on Windows: 'getPermissions', which answers
-- from the file extension - the platform has no mode bit to read.
defaultExecBitResolver :: ExecBitResolver
defaultExecBitResolver path = executable <$> (getPermissions =<< encodeFS path)

#else

-- | The stock resolver on POSIX: the owner-execute bit of the file's
-- own mode, as upstream's dump reads it (@st_mode & S_IXUSR@).  Not
-- 'System.Directory.OsPath.getPermissions', which answers from
-- @access(2)@ - what the CALLING PROCESS may do - and so diverges for
-- root (any execute bit reads as executable), ACLs, and files the
-- caller does not own; the flag lands in NAR bytes, so that
-- divergence moves a hash (#65).
defaultExecBitResolver :: ExecBitResolver
defaultExecBitResolver path = do
  status <- Posix.getSymbolicLinkStatus path
  pure (Posix.intersectFileModes (Posix.fileMode status) Posix.ownerExecuteMode /= Posix.nullFileMode)

#endif

-- | How a tree is read for serialisation: the case-hack mode and the
-- executable-bit source.
data SerialiseOptions = SerialiseOptions
  { -- | Directory-name case-hack resolution (see 'CaseHack').
    soCaseHack :: !CaseHack,
    -- | Where a regular file's executable flag comes from.
    soExecBit :: !ExecBitResolver
  }

-- | 'defaultCaseHack' and 'defaultExecBitResolver': with these,
-- 'serialiseFromPathOpts' is exactly 'serialiseFromPath'.
defaultSerialiseOptions :: SerialiseOptions
defaultSerialiseOptions =
  SerialiseOptions
    { soCaseHack = defaultCaseHack,
      soExecBit = defaultExecBitResolver
    }

-- | Walk a filesystem path and build a 'NarEntry' under
-- 'defaultCaseHack'.
--
-- This is the module's IO boundary: the platform-native walk
-- classifies each path as symlink, directory, or regular file and
-- delegates to pure constructors.
serialiseFromPath :: FilePath -> IO NarEntry
serialiseFromPath = serialiseFromPathOpts defaultSerialiseOptions

-- | 'serialiseFromPath' with the case-hack mode explicit, for callers
-- and tests that need behavior independent of the host platform.
serialiseFromPathWith :: CaseHack -> FilePath -> IO NarEntry
serialiseFromPathWith mode = serialiseFromPathOpts defaultSerialiseOptions {soCaseHack = mode}

-- | 'serialiseFromPath' with every knob explicit.
serialiseFromPathOpts :: SerialiseOptions -> FilePath -> IO NarEntry
serialiseFromPathOpts opts path = walkPath opts =<< encodeFS path

-- | Walk one platform-native path.  The walk runs on 'OsPath' so child
-- names reach the archive byte-true ('osPathBytes'); only the root
-- enters as 'FilePath', and the root's own name never appears in a
-- NAR.
walkPath :: SerialiseOptions -> OsPath -> IO NarEntry
walkPath opts path = do
  isSym <- pathIsSymbolicLink path
  if isSym
    then NarSymlink <$> (symlinkTargetBytes =<< getSymbolicLinkTarget path)
    else do
      isDir <- doesDirectoryExist path
      if isDir
        then buildDirectory opts path
        else buildRegularFile (soExecBit opts) path

-- | Build a directory entry by recursively walking children.
buildDirectory :: SerialiseOptions -> OsPath -> IO NarEntry
buildDirectory opts path = do
  resolved <- resolvedDirEntries (soCaseHack opts) path
  NarDirectory <$> traverse walkChild resolved
  where
    walkChild (entryName, diskName) = do
      entry <- walkPath opts (path </> diskName)
      pure (entryName, entry)

-- | A directory's children as (NAR name, on-disk name) pairs under the
-- case-hack mode.  Under 'CaseHackEnabled', each on-disk name is
-- stripped of the case-hack suffix and entries are ordered by the
-- STRIPPED name (the NAR name); two on-disk names stripping to the
-- same entry name fail loudly, as upstream's serialiser does -
-- continuing would emit an archive with duplicate entries no parser
-- accepts.
resolvedDirEntries :: CaseHack -> OsPath -> IO [(ByteString, OsPath)]
resolvedDirEntries mode path = do
  names <- sort <$> listDirectory path
  named <- traverse withNameBytes names
  case unhackedDirNames mode named of
    Left (collidedA, collidedB) -> do
      pathA <- decodeFS (path </> collidedA)
      pathB <- decodeFS (path </> collidedB)
      fail
        ( "serialiseFromPath: file name collision between '"
            ++ pathA
            ++ "' and '"
            ++ pathB
            ++ "' after case-hack stripping"
        )
    Right resolved -> pure resolved
  where
    withNameBytes diskName = do
      nameBytes <- osPathBytes diskName
      pure (nameBytes, diskName)

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
buildRegularFile :: ExecBitResolver -> OsPath -> IO NarEntry
buildRegularFile resolver path = do
  isFile <- doesFileExist path
  if isFile
    then do
      contents <- readFileBytes path
      isExec <- resolveExecBit resolver path
      pure (NarRegular isExec contents)
    else specialFileFailure path

-- | The shared refusal for a path that is not a symlink, directory, or
-- regular file: a special file (FIFO, socket, device) or a path that
-- vanished mid-walk.  Fail loudly rather than fabricating an empty
-- regular (which would silently change the NAR and its hash) -
-- matching Nix, which aborts on unsupported types.
specialFileFailure :: OsPath -> IO a
specialFileFailure path = do
  shownPath <- decodeFS path
  fail ("serialiseFromPath: not a regular file (special or vanished): " ++ shownPath)

-- | Run the resolver on a platform-native path.  The resolver contract
-- is 'FilePath', so the path bridges through 'decodeFS' - the same
-- interop seam as 'readFileBytes'.
resolveExecBit :: ExecBitResolver -> OsPath -> IO Bool
resolveExecBit resolver path = resolver =<< decodeFS path

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

-- | A symlink target's NAR bytes.  Identical to 'osPathBytes' for a name,
-- except that on Windows the separator is normalised to @\/@: Windows
-- stores a reparse point with backslashes, so a target written @bin\/tool@
-- reads back @bin\\tool@, and a NAR target is the POSIX spelling on every
-- platform so the archive stays host-independent.  A backslash is only
-- ever a separator on Windows, never a filename byte, and it encodes as
-- the single byte @0x5C@ that no multi-byte UTF-8 sequence contains, so
-- the byte-level replacement is exact.  On POSIX a backslash is a
-- legitimate filename byte and is left untouched.
symlinkTargetBytes :: OsPath -> IO ByteString
#ifdef mingw32_HOST_OS
symlinkTargetBytes path = BS.map normalizeSeparator <$> osPathBytes path
  where
    normalizeSeparator b = if b == backslashByte then forwardSlashByte else b
    backslashByte = 0x5C
    forwardSlashByte = 0x2F
#else
symlinkTargetBytes = osPathBytes
#endif

-- ---------------------------------------------------------------------------
-- Streaming filesystem serialisation (IO boundary)
-- ---------------------------------------------------------------------------

-- | Chunk size for streaming file contents: large enough to amortize
-- per-chunk handling in consumers, small enough that one pull's memory
-- and latency stay flat.
narSourceChunkBytes :: Int
narSourceChunkBytes = 131072

-- | One planned piece of the archive: structural bytes rendered up
-- front, or a regular file whose length prefix, contents, and padding
-- stream at pull time.
data NarSegment
  = SegmentBytes !ByteString
  | SegmentFile !OsPath

-- | What the puller is doing between calls.  The 'IORef' holding this
-- is the module's one piece of mutable state - the same deliberate,
-- documented boundary as the streaming write in "NovaCache.Store".
data SourceState
  = SourceSegments ![NarSegment]
  | -- | Mid-file: the open handle, its decoded path for error text,
    -- the bytes still owed, the padding after them, and the remaining
    -- segments.
    SourceFile !Handle !FilePath !Word64 !Int ![NarSegment]
  | SourceDrained

-- | Serialise a filesystem tree as a pull source of NAR chunks,
-- without ever holding a file's contents in memory: the tree's
-- structure is planned up front (names, kinds, symlink targets,
-- executable flags - never contents), so the resolver's IO runs
-- before the first pull; then each pull returns the next chunk, reading
-- regular files 128 KiB at a time.  The empty chunk
-- means end of input and repeats on further pulls - the convention
-- 'NovaCache.Store.writeNarStreaming' consumes, so the two ends
-- compose directly.  Pair with "NovaCache.Hash"'s incremental hashing
-- to compute the NAR hash in the same pass.
--
-- The walk applies the same case-hack resolution and loud failures as
-- 'serialiseFromPathWith', and emits entries in the same bytewise
-- order, so the pulled bytes equal @'serialise' \<tree\>@ exactly.  A
-- file's size is read when its streaming starts and exactly that many
-- bytes are emitted, as upstream's dump does; a file that shrinks
-- mid-stream fails loudly rather than emitting a torn archive.  Any
-- file handle still open when the continuation exits is closed.
withNarSource :: CaseHack -> FilePath -> (IO ByteString -> IO a) -> IO a
withNarSource mode = withNarSourceOpts defaultSerialiseOptions {soCaseHack = mode}

-- | 'withNarSource' with every knob explicit.
withNarSourceOpts :: SerialiseOptions -> FilePath -> (IO ByteString -> IO a) -> IO a
withNarSourceOpts opts root consume = do
  rootPath <- encodeFS root
  segments <- planSegments opts rootPath
  stateRef <- newIORef (SourceSegments segments)
  consume (pullChunk stateRef) `finally` closeCurrent stateRef
  where
    closeCurrent stateRef = do
      state <- readIORef stateRef
      case state of
        SourceFile handle _ _ _ _ -> hClose handle
        _ -> pure ()

-- | Produce the next chunk of the planned archive.
pullChunk :: IORef SourceState -> IO ByteString
pullChunk stateRef = advance =<< readIORef stateRef
  where
    advance (SourceSegments []) = do
      writeIORef stateRef SourceDrained
      pure BS.empty
    advance (SourceSegments (SegmentBytes bytes : rest)) = do
      writeIORef stateRef (SourceSegments rest)
      pure bytes
    advance (SourceSegments (SegmentFile path : rest)) = do
      shownPath <- decodeFS path
      -- hFileSize can throw after a successful open (the path swapped
      -- for a FIFO between plan and pull); until the state ref records
      -- the handle, closeCurrent cannot see it, so ownership transfers
      -- under bracketOnError - the same discipline as the shrink path
      -- below.
      bracketOnError (openBinaryFile shownPath ReadMode) hClose $ \handle -> do
        size <- hFileSize handle
        let owed = fromIntegral size :: Word64
        writeIORef stateRef (SourceFile handle shownPath owed (narPadOf owed) rest)
        pure (BL.toStrict (B.toLazyByteString (B.word64LE owed)))
    advance (SourceFile handle _ 0 padLen rest) = do
      hClose handle
      writeIORef stateRef (SourceSegments rest)
      if padLen == 0
        then pullChunk stateRef
        else pure (BS.replicate padLen 0)
    advance (SourceFile handle shownPath owed padLen rest) = do
      chunk <- BS.hGet handle (fromIntegral (min owed (fromIntegral narSourceChunkBytes)))
      if BS.null chunk
        then do
          hClose handle
          writeIORef stateRef SourceDrained
          ioError (userError ("withNarSource: " ++ shownPath ++ " shrank while streaming"))
        else do
          writeIORef
            stateRef
            (SourceFile handle shownPath (owed - fromIntegral (BS.length chunk)) padLen rest)
          pure chunk
    advance SourceDrained = pure BS.empty

-- | Plan the archive: every structural byte rendered, file contents
-- deferred as 'SegmentFile's.  Holds structure only - O(entries),
-- never contents.
planSegments :: SerialiseOptions -> OsPath -> IO [NarSegment]
planSegments opts path = do
  pieces <- planNode opts path
  pure (coalesce (PieceBytes (narStr tokMagic) : pieces))

-- | Plan pieces before coalescing: structural builders, or a deferred
-- regular file.
data PlanPiece
  = PieceBytes !B.Builder
  | PieceFile !OsPath

-- | Merge adjacent structural runs and render each strict, so a pull
-- returns a directory's worth of tokens in one chunk instead of one
-- token at a time.
coalesce :: [PlanPiece] -> [NarSegment]
coalesce = go mempty
  where
    go !pending [] = flushOnto pending []
    go !pending (PieceBytes builder : rest) = go (pending <> builder) rest
    go !pending (PieceFile path : rest) =
      flushOnto pending (SegmentFile path : go mempty rest)
    flushOnto pending segments =
      let bytes = BL.toStrict (B.toLazyByteString pending)
       in if BS.null bytes then segments else SegmentBytes bytes : segments

-- | Plan one node, mirroring 'walkPath'.
planNode :: SerialiseOptions -> OsPath -> IO [PlanPiece]
planNode opts path = do
  isSym <- pathIsSymbolicLink path
  if isSym
    then do
      target <- symlinkTargetBytes =<< getSymbolicLinkTarget path
      pure [PieceBytes (buildNode (NarSymlink target))]
    else do
      isDir <- doesDirectoryExist path
      if isDir
        then planDirectory opts path
        else planRegular (soExecBit opts) path

-- | Plan a directory.  Children are ordered by their NAR-name bytes -
-- the same order 'buildNode' emits - not by on-disk order, which can
-- differ on Windows where 'OsPath' sorts by UTF-16 units.
planDirectory :: SerialiseOptions -> OsPath -> IO [PlanPiece]
planDirectory opts path = do
  resolved <- resolvedDirEntries (soCaseHack opts) path
  children <- traverse planChild (sortBy (comparing fst) resolved)
  pure
    ( PieceBytes (narStr tokLParen <> narStr tokType <> narStr tokDirectory)
        : concat children
        ++ [PieceBytes (narStr tokRParen)]
    )
  where
    planChild (entryName, diskName) = do
      node <- planNode opts (path </> diskName)
      pure
        ( PieceBytes
            ( narStr tokEntry
                <> narStr tokLParen
                <> narStr tokName
                <> narStr entryName
                <> narStr tokNode
            )
            : node
            ++ [PieceBytes (narStr tokRParen)]
        )

-- | Plan a regular file: the node's structure now, its contents at
-- pull time.  The pieces mirror 'buildNode' on 'NarRegular' exactly,
-- with the contents wire string (length, bytes, padding) deferred.
planRegular :: ExecBitResolver -> OsPath -> IO [PlanPiece]
planRegular resolver path = do
  isFile <- doesFileExist path
  if isFile
    then do
      isExec <- resolveExecBit resolver path
      pure
        [ PieceBytes
            ( narStr tokLParen
                <> narStr tokType
                <> narStr tokRegular
                <> execFlag isExec
                <> narStr tokContents
            ),
          PieceFile path,
          PieceBytes (narStr tokRParen)
        ]
    else specialFileFailure path
