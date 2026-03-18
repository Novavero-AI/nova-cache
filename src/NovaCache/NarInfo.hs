-- | NarInfo text format parsing and rendering.
--
-- A @.narinfo@ file is a simple @Key: Value@ text format describing a
-- store path in a binary cache. The format supports multiple @Sig@ lines
-- and optional fields for @Deriver@, @System@, and @CA@.
module NovaCache.NarInfo
  ( NarInfo (..),
    parseNarInfo,
    renderNarInfo,
  )
where

import Data.List (find)
import Data.Maybe (mapMaybe)
import Data.Text (Text)
import qualified Data.Text as T

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
    niSystem :: !(Maybe Text),
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

keyDeriver, keySystem, keySig, keyCA :: Text
keyDeriver = "Deriver"
keySystem = "System"
keySig = "Sig"
keyCA = "CA"

-- | Key-value separator in narinfo format.
kvSeparator :: Text
kvSeparator = ": "

-- | Length of the key-value separator.
kvSeparatorLen :: Int
kvSeparatorLen = 2

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
        niSystem = lookupFirst keySystem kvs,
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
      ++ optionalKV keySystem (niSystem ni)
      ++ map (kv keySig) (niSigs ni)
      ++ optionalKV keyCA (niCA ni)

-- ---------------------------------------------------------------------------
-- Key-value primitives
-- ---------------------------------------------------------------------------

-- | Parse a single @Key: Value@ line.
parseLine :: Text -> Maybe (Text, Text)
parseLine line = case T.breakOn kvSeparator line of
  (_, rest)
    | T.null rest -> Nothing
  (key, rest) -> Just (key, T.drop kvSeparatorLen rest)

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

-- | Parse an integer value from text.
parseInteger :: Text -> Text -> Either String Integer
parseInteger key txt = case reads (T.unpack txt) of
  [(n, "")] -> Right n
  _ -> Left ("invalid integer for " ++ T.unpack key ++ ": " ++ T.unpack txt)

-- | Show a value as 'Text'.
showT :: (Show a) => a -> Text
showT = T.pack . show
