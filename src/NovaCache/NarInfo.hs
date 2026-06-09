-- | NarInfo text format parsing and rendering.
--
-- A @.narinfo@ file is a simple @Key: Value@ text format describing a
-- store path in a binary cache. The format supports multiple @Sig@ lines
-- and optional fields for @Deriver@ and @CA@.
module NovaCache.NarInfo
  ( NarInfo (..),
    parseNarInfo,
    renderNarInfo,
  )
where

import Data.List (find)
import Data.Maybe (fromMaybe, mapMaybe)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Read as TR

-- ---------------------------------------------------------------------------
-- Types
-- ---------------------------------------------------------------------------

-- | A parsed @.narinfo@ record. All fields are strict.
data NarInfo = NarInfo
  { niStorePath :: !Text,
    niUrl :: !Text,
    niCompression :: !Text,
    niFileHash :: !Text,
    niFileSize :: !Integer,
    niNarHash :: !Text,
    niNarSize :: !Integer,
    niReferences :: ![Text],
    niDeriver :: !(Maybe Text),
    niSigs :: ![Text],
    niCA :: !(Maybe Text)
  }
  deriving (Eq, Show)

-- ---------------------------------------------------------------------------
-- Key constants (no magic strings in logic)
-- ---------------------------------------------------------------------------

keyStorePath, keyUrl, keyCompression, keyFileHash :: Text
keyStorePath = "StorePath"
keyUrl = "URL"
keyCompression = "Compression"
keyFileHash = "FileHash"

keyFileSize, keyNarHash, keyNarSize, keyReferences :: Text
keyFileSize = "FileSize"
keyNarHash = "NarHash"
keyNarSize = "NarSize"
keyReferences = "References"

keyDeriver, keySig, keyCA :: Text
keyDeriver = "Deriver"
keySig = "Sig"
keyCA = "CA"

-- | Key-value separator used when rendering narinfo lines.
kvSeparator :: Text
kvSeparator = ": "

-- | Field delimiter used when parsing (Nix splits on the first colon).
fieldColon :: Text
fieldColon = ":"

-- ---------------------------------------------------------------------------
-- Parsing
-- ---------------------------------------------------------------------------

-- | Parse a narinfo text body into a 'NarInfo'.
parseNarInfo :: Text -> Either String NarInfo
parseNarInfo txt = do
  let kvs = mapMaybe parseLine (T.lines txt)
  storePath <- require keyStorePath kvs
  url <- require keyUrl kvs
  compression <- require keyCompression kvs
  fileHash <- require keyFileHash kvs
  fileSize <- require keyFileSize kvs >>= parseInteger keyFileSize
  narHashVal <- require keyNarHash kvs
  narSize <- require keyNarSize kvs >>= parseInteger keyNarSize
  pure
    NarInfo
      { niStorePath = storePath,
        niUrl = url,
        niCompression = compression,
        niFileHash = fileHash,
        niFileSize = fileSize,
        niNarHash = narHashVal,
        niNarSize = narSize,
        niReferences = parseRefs (lookupFirst keyReferences kvs),
        niDeriver = lookupFirst keyDeriver kvs,
        niSigs = lookupAll keySig kvs,
        niCA = lookupFirst keyCA kvs
      }

-- | Parse a space-separated references field.
parseRefs :: Maybe Text -> [Text]
parseRefs Nothing = []
parseRefs (Just r)
  | T.null (T.strip r) = []
  | otherwise = T.words r

-- ---------------------------------------------------------------------------
-- Rendering
-- ---------------------------------------------------------------------------

-- | Render a 'NarInfo' to its text representation.
renderNarInfo :: NarInfo -> Text
renderNarInfo ni =
  T.unlines $
    [ kv keyStorePath (niStorePath ni),
      kv keyUrl (niUrl ni),
      kv keyCompression (niCompression ni),
      kv keyFileHash (niFileHash ni),
      kv keyFileSize (showT (niFileSize ni)),
      kv keyNarHash (niNarHash ni),
      kv keyNarSize (showT (niNarSize ni)),
      kv keyReferences (T.unwords (niReferences ni))
    ]
      ++ optionalKV keyDeriver (niDeriver ni)
      ++ map (kv keySig) (niSigs ni)
      ++ optionalKV keyCA (niCA ni)

-- ---------------------------------------------------------------------------
-- Key-value primitives
-- ---------------------------------------------------------------------------

-- | Parse a single @Key: Value@ line.
--
-- Splits on the first colon (matching Nix), strips a single leading space
-- from the value, and tolerates a trailing carriage return so CRLF-terminated
-- narinfo from other tools parses correctly.
parseLine :: Text -> Maybe (Text, Text)
parseLine rawLine = case T.breakOn fieldColon line of
  (_, rest)
    | T.null rest -> Nothing
  (key, rest) -> Just (key, dropLeadingSpace (T.drop 1 rest))
  where
    line = T.dropWhileEnd (== '\r') rawLine
    dropLeadingSpace value = fromMaybe value (T.stripPrefix " " value)

-- | Render a key-value pair.
kv :: Text -> Text -> Text
kv key val = key <> kvSeparator <> val

-- | Render an optional key-value pair.
optionalKV :: Text -> Maybe Text -> [Text]
optionalKV _ Nothing = []
optionalKV key (Just val) = [kv key val]

-- | Look up the first occurrence of a key.
lookupFirst :: Text -> [(Text, Text)] -> Maybe Text
lookupFirst key kvs = snd <$> find ((== key) . fst) kvs

-- | Look up all occurrences of a key.
lookupAll :: Text -> [(Text, Text)] -> [Text]
lookupAll key = map snd . filter ((== key) . fst)

-- | Require a key to be present.
require :: Text -> [(Text, Text)] -> Either String Text
require key kvs = case lookupFirst key kvs of
  Nothing -> Left ("missing required key: " ++ T.unpack key)
  Just val -> Right val

-- | Parse a non-negative base-10 integer, matching C++ Nix's narinfo parser.
-- Uses 'TR.decimal' (not 'reads', which also accepts hex/octal/leading space)
-- and requires the whole field to be consumed, so a non-canonical value cannot
-- slip through and then be re-signed under the cache's key.
parseInteger :: Text -> Text -> Either String Integer
parseInteger key txt = case TR.decimal txt of
  Right (n, rest) | T.null rest -> Right n
  _ -> Left ("invalid integer for " ++ T.unpack key ++ ": " ++ T.unpack txt)

-- | Show a value as 'Text'.
showT :: (Show a) => a -> Text
showT = T.pack . show
