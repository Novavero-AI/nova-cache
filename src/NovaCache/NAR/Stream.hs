-- | Incremental NAR parsing: a pure, chunk-fed event machine.
--
-- "NovaCache.NAR" parses a NAR held whole in memory; consumers realize
-- entire archives to walk them, and nova-nix's substituter documents
-- the resident-set spike that costs on large paths.  This module parses
-- the same grammar incrementally: feed chunks as they arrive - from a
-- download, a decompressor - and act on events as they complete.
-- Regular-file contents pass through as slices of the fed chunks, so
-- memory is bounded by the largest structural wire string
-- ('maxWireStringBytes'), never by archive or file size.
--
-- The grammar lives here once: 'NovaCache.NAR.deserialise' is the
-- whole-input instantiation of this machine, and the serialiser draws
-- its wire vocabulary from the exports below, so the two directions
-- cannot drift apart.
module NovaCache.NAR.Stream
  ( -- * Events
    NarEvent (..),

    -- * The machine
    NarStep (..),
    narStream,
    narStreamBounded,
    maxWireStringBytes,

    -- * Entry-name safety
    checkEntryName,

    -- * Wire vocabulary (shared with the serialiser in "NovaCache.NAR")
    tokMagic,
    tokLParen,
    tokRParen,
    tokType,
    tokRegular,
    tokDirectory,
    tokSymlink,
    tokContents,
    tokTarget,
    tokExecutable,
    tokEntry,
    tokName,
    tokNode,
    narAlignment,
    narPad,
    narPadOf,
  )
where

import Data.Bits (shiftL, (.&.), (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Data.Word (Word64)
import NovaCache.SafeName (hasTrailingDotOrSpace, isReservedDeviceName)

-- ---------------------------------------------------------------------------
-- Wire vocabulary
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

-- | Compute padding to reach the next 8-byte boundary.
narPad :: Int -> Int
narPad len =
  let remainder = len .&. (narAlignment - 1)
   in if remainder == 0 then 0 else narAlignment - remainder

-- | 'narPad' over the wire's own length type, for sizes that may not
-- fit 'Int'.  The result is a padding count, so it always does.
narPadOf :: Word64 -> Int
narPadOf len =
  let remainder = len .&. fromIntegral (narAlignment - 1)
   in if remainder == 0 then 0 else narAlignment - fromIntegral remainder

-- | Size of the length prefix preceding every wire string.
lengthPrefixBytes :: Int
lengthPrefixBytes = 8

-- ---------------------------------------------------------------------------
-- Events
-- ---------------------------------------------------------------------------

-- | One structural step of an archive.  A node unfolds as either
--
-- @'EventRegularBegin' ('EventRegularChunk'*) 'EventRegularEnd'@,
-- an 'EventSymlink', or
-- @'EventDirectoryBegin' entry* 'EventDirectoryEnd'@ where each entry
-- is @'EventEntryBegin' node 'EventEntryEnd'@.
data NarEvent
  = -- | A regular file opens: executable flag and its declared
    -- contents size, known up front from the wire length prefix.
    EventRegularBegin !Bool !Word64
  | -- | One slice of regular-file contents, in order.  Slices are
    -- substrings of the fed chunks (no copying); their lengths sum to
    -- the declared size.
    EventRegularChunk !ByteString
  | -- | The regular file's contents and padding are fully consumed and
    -- its node is closed.
    EventRegularEnd
  | -- | A complete symlink node: the target, as the raw bytes the
    -- archive carries.
    EventSymlink !ByteString
  | EventDirectoryBegin
  | -- | An entry opens under the innermost open directory.  The name
    -- has already passed 'checkEntryName', order included.
    EventEntryBegin !ByteString
  | EventEntryEnd
  | EventDirectoryEnd
  deriving (Eq, Show)

-- | The machine's outward face.  Drive it by pattern matching: hand
-- 'NarAwait' the next chunk (the empty string means end of input, the
-- same convention as 'NovaCache.Store.writeNarStreaming' consumes), and
-- read events off 'NarYield' as they complete.  'NarDone' confirms the
-- archive ended exactly at the root node's close; anything else that
-- can go wrong is a 'NarFail'.
data NarStep
  = NarAwait !(ByteString -> NarStep)
  | NarYield !NarEvent NarStep
  | NarDone
  | NarFail !String

-- | The bound 'narStream' places on structural wire strings - tokens,
-- entry names, symlink targets; never file contents, which stream
-- through unaccumulated.  Real names fit a filesystem's 255-byte
-- component limit and targets its path limit, so 64 KiB is generous;
-- without some bound a hostile length prefix could demand an
-- arbitrary-size allocation from one 8-byte read.
maxWireStringBytes :: Word64
maxWireStringBytes = 65536

-- | The parser, positioned at the start of an archive, holding
-- 'maxWireStringBytes' over structural strings.
narStream :: NarStep
narStream = narStreamBounded maxWireStringBytes

-- ---------------------------------------------------------------------------
-- Parser
-- ---------------------------------------------------------------------------

-- | A parse state waiting for its share of the input: apply it to the
-- unconsumed bytes to proceed.
type Continue = ByteString -> NarStep

-- | 'narStream' with the structural-string bound explicit.
-- 'NovaCache.NAR.deserialise' passes its whole input's length - a
-- string cannot outgrow its container, so the strict parser accepts
-- exactly what it always accepted - while streaming callers keep the
-- documented default.
narStreamBounded :: Word64 -> NarStep
narStreamBounded bound =
  expectWire limited "archive magic" tokMagic (parseNode limited archiveEnd) BS.empty
  where
    -- Declared lengths are compared in Word64 and narrowed only below
    -- the bound, so the bound itself must fit Int for the narrowing to
    -- be exact.
    limited = min bound (fromIntegral (maxBound :: Int))
    archiveEnd leftover
      | BS.null leftover = NarAwait confirm
      | otherwise = NarFail trailingBytes
    confirm chunk
      | BS.null chunk = NarDone
      | otherwise = NarFail trailingBytes
    trailingBytes = "trailing bytes after NAR root node"

-- | Parse one node and continue.
parseNode :: Word64 -> Continue -> Continue
parseNode bound k =
  expectWire bound "node opening" tokLParen
    $ expectWire bound "type keyword" tokType
    $ wireString bound "node type" dispatch
  where
    dispatch kind
      | kind == tokRegular = parseRegular bound k
      | kind == tokSymlink = parseSymlink bound k
      | kind == tokDirectory = parseDirectory bound k
      | otherwise = failWith ("unknown NAR entry type: " ++ show kind)

-- | Parse a regular file node: optional executable flag, then contents
-- streamed through as chunk events.
parseRegular :: Word64 -> Continue -> Continue
parseRegular bound k = wireString bound "regular-node keyword" body
  where
    body tok
      | tok == tokExecutable =
          -- The format fixes the executable marker's value as the
          -- empty string; upstream rejects a nonempty value.
          wireString bound "executable marker" $ \marker ->
            if BS.null marker
              then expectWire bound "contents keyword" tokContents (contentsOf True)
              else failWith ("executable marker must be empty, got: " ++ show marker)
      | tok == tokContents = contentsOf False
      | otherwise =
          failWith ("expected 'executable' or 'contents' in regular, got: " ++ show tok)
    contentsOf isExec = exactly lengthPrefixBytes "length of file contents" (withSize isExec)
    withSize isExec lenBytes leftover =
      let size = word64LE lenBytes
       in NarYield
            (EventRegularBegin isExec size)
            (streamContents size (afterContents size) leftover)
    afterContents size =
      exactly (narPadOf size) "file contents padding" $ \padding ->
        if BS.any (/= 0) padding
          then failWith nonzeroPadding
          else expectWire bound "node closing" tokRParen $ \leftover ->
            NarYield EventRegularEnd (k leftover)

-- | Yield contents slices until the declared size is consumed.  Slices
-- are substrings of the fed chunks; nothing accumulates.
streamContents :: Word64 -> Continue -> Continue
streamContents remaining k leftover
  | remaining == 0 = k leftover
  | BS.null leftover = NarAwait feed
  | otherwise =
      let sliceLen = fromIntegral (min remaining (fromIntegral (BS.length leftover)))
          (slice, rest) = BS.splitAt sliceLen leftover
       in NarYield
            (EventRegularChunk slice)
            (streamContents (remaining - fromIntegral sliceLen) k rest)
  where
    feed chunk
      | BS.null chunk = NarFail "unexpected end of NAR: file contents"
      | otherwise = streamContents remaining k chunk

-- | Parse a symlink node.  The target is carried verbatim: upstream
-- imposes no text encoding on it.
parseSymlink :: Word64 -> Continue -> Continue
parseSymlink bound k =
  expectWire bound "target keyword" tokTarget $
    wireString bound "symlink target" $ \target ->
      expectWire bound "node closing" tokRParen $ \leftover ->
        NarYield (EventSymlink target) (k leftover)

-- | Parse a directory node: entries validated name by name as they
-- open, so a consumer can act on each entry before the next arrives.
parseDirectory :: Word64 -> Continue -> Continue
parseDirectory bound k leftover =
  NarYield EventDirectoryBegin (entries Nothing leftover)
  where
    entries prev = wireString bound "directory token" (branch prev)
    branch prev tok
      | tok == tokRParen = NarYield EventDirectoryEnd . k
      | tok == tokEntry =
          expectWire bound "entry opening" tokLParen
            $ expectWire bound "name keyword" tokName
            $ wireString bound "entry name" (named prev)
      | otherwise = failWith ("expected 'entry' or ')' in directory, got: " ++ show tok)
    named prev entryName = case checkEntryName prev entryName of
      Left err -> failWith err
      Right () ->
        NarYield (EventEntryBegin entryName)
          . expectWire bound "node keyword" tokNode (parseNode bound (closeEntry entryName))
    closeEntry entryName =
      expectWire bound "entry closing" tokRParen $ \leftover2 ->
        NarYield EventEntryEnd (entries (Just entryName) leftover2)

-- ---------------------------------------------------------------------------
-- Entry-name safety
-- ---------------------------------------------------------------------------

-- | Reject a NAR directory entry name that is unsafe or out of order
-- against its predecessor.  Entries must have safe names in strictly
-- increasing (sorted, unique) byte order: enforcing this rejects
-- malformed or hostile archives, keeps @serialise . deserialise@ an
-- identity, and forecloses the path-traversal surface for any
-- NAR-extraction consumer.  Names are arbitrary bytes; every check
-- here is ASCII-structural, so it stays exact whether or not the name
-- decodes as text (see "NovaCache.SafeName").
checkEntryName :: Maybe ByteString -> ByteString -> Either String ()
checkEntryName prev name
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
-- Chunk-fed primitives
-- ---------------------------------------------------------------------------

-- | Read one whole wire string - length prefix, payload, zero padding -
-- refusing a declared length over the bound before allocating for it.
-- For structural strings only; file contents go through
-- 'streamContents'.
wireString :: Word64 -> String -> (ByteString -> Continue) -> Continue
wireString bound what k = exactly lengthPrefixBytes ("length of " ++ what) withLength
  where
    withLength lenBytes =
      let declared = word64LE lenBytes
       in if declared > bound
            then
              failWith
                ( what
                    ++ ": declared length "
                    ++ show declared
                    ++ " exceeds the "
                    ++ show bound
                    ++ "-byte wire-string bound"
                )
            else
              -- Safe narrowing: declared <= bound, and narStreamBounded
              -- clamps every bound to Int's range.
              let len = fromIntegral declared
               in exactly (len + narPad len) what $ \whole ->
                    case BS.splitAt len whole of
                      (payload, padding)
                        -- Nix's reader rejects nonzero padding; accepting it
                        -- would let archives that upstream tooling refuses
                        -- round-trip through this library.
                        | BS.any (/= 0) padding -> failWith nonzeroPadding
                        | otherwise -> k payload

-- | Read a wire string and require an exact token.
expectWire :: Word64 -> String -> ByteString -> Continue -> Continue
expectWire bound what expected k = wireString bound what check
  where
    check got
      | got == expected = k
      | otherwise = failWith ("expected " ++ show expected ++ ", got " ++ show got)

-- | Demand exactly @n@ bytes, awaiting more chunks as needed, then
-- continue with them and the leftover.  Held chunks concatenate once,
-- so pathological chunking costs linear work, not quadratic.
exactly :: Int -> String -> (ByteString -> Continue) -> Continue
exactly n what k leftover = go [leftover] (BS.length leftover)
  where
    go !heldRev !heldLen
      | heldLen >= n =
          case BS.splitAt n (BS.concat (reverse heldRev)) of
            (taken, rest) -> k taken rest
      | otherwise = NarAwait $ \chunk ->
          if BS.null chunk
            then NarFail ("unexpected end of NAR: " ++ what)
            else go (chunk : heldRev) (heldLen + BS.length chunk)

-- | Fail from any position that still owes the machine a continuation.
failWith :: String -> Continue
failWith err _ = NarFail err

nonzeroPadding :: String
nonzeroPadding = "nonzero padding bytes in NAR string"

-- | Read a little-endian 'Word64' from an 8-byte string.
word64LE :: ByteString -> Word64
word64LE = BS.foldr accumulate 0
  where
    accumulate byte acc = (acc `shiftL` bitsPerByte) .|. fromIntegral byte

-- | Bits per byte, for the length-prefix fold.
bitsPerByte :: Int
bitsPerByte = 8
