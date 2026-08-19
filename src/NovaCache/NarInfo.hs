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

import Data.Maybe (fromMaybe, mapMaybe)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Read as TR

-- ---------------------------------------------------------------------------
-- Types
-- ---------------------------------------------------------------------------

-- | A parsed @.narinfo@ record. All fields are strict.
--
-- Field optionality mirrors upstream Nix's parser: only StorePath, URL,
-- NarHash, and NarSize are mandatory; Compression defaults to bzip2 when
-- absent, and FileHash\/FileSize describe the compressed blob only when
-- the cache provides them.
data NarInfo = NarInfo
  { niStorePath :: !Text,
    niUrl :: !Text,
    niCompression :: !Text,
    niFileHash :: !(Maybe Text),
    niFileSize :: !(Maybe Integer),
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

-- | Compression assumed when the narinfo omits the field, as upstream's
-- parser does.
defaultCompression :: Text
defaultCompression = "bzip2"

-- | Parse a narinfo text body into a 'NarInfo'.  Only StorePath, URL,
-- NarHash, and NarSize are required, matching upstream Nix; a valid
-- narinfo from a foreign cache must not be rejected over an absent
-- optional field.
parseNarInfo :: Text -> Either String NarInfo
parseNarInfo txt = do
  let kvs = mapMaybe parseLine (T.lines txt)
  storePath <- require keyStorePath kvs
  url <- require keyUrl kvs
  fileSize <- traverse (parseInteger keyFileSize) (lookupLast keyFileSize kvs)
  narHashVal <- require keyNarHash kvs
  narSize <- require keyNarSize kvs >>= parseInteger keyNarSize
  pure
    NarInfo
      { niStorePath = storePath,
        niUrl = url,
        niCompression = fromMaybe defaultCompression (lookupLast keyCompression kvs),
        niFileHash = lookupLast keyFileHash kvs,
        niFileSize = fileSize,
        niNarHash = narHashVal,
        niNarSize = narSize,
        niReferences = parseRefs (lookupLast keyReferences kvs),
        niDeriver = lookupLast keyDeriver kvs,
        niSigs = lookupAll keySig kvs,
        niCA = lookupLast keyCA kvs
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
      kv keyCompression (niCompression ni)
    ]
      ++ optionalKV keyFileHash (niFileHash ni)
      ++ optionalKV keyFileSize (showT <$> niFileSize ni)
      ++ [ kv keyNarHash (niNarHash ni),
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
-- | Look up the LAST occurrence of a scalar key: upstream's parser
-- assigns each field as it reads, so a duplicated key resolves to the
-- final value.  (@Sig@ is the one intentionally repeatable key -
-- 'lookupAll'.)
lookupLast :: Text -> [(Text, Text)] -> Maybe Text
lookupLast key = foldl' pick Nothing
  where
    pick acc (k, v) = if k == key then Just v else acc

-- | Look up all occurrences of a key.
lookupAll :: Text -> [(Text, Text)] -> [Text]
lookupAll key = map snd . filter ((== key) . fst)

-- | Require a key to be present.
require :: Text -> [(Text, Text)] -> Either String Text
require key kvs = case lookupLast key kvs of
  Nothing -> Left ("missing required key: " ++ T.unpack key)
  Just val -> Right val

-- | Sizes on the wire are uint64 in Nix: at most 20 digits.  A longer
-- field is rejected before the bignum parse, because 'TR.decimal'
-- accumulates digit by digit - quadratic in the field length - so an
-- unbounded field costs quadratic CPU and a proportional allocation
-- before any consumer looks at the value.
maxSizeFieldDigits :: Int
maxSizeFieldDigits = 20

-- | Parse a non-negative base-10 integer, matching C++ Nix's narinfo parser.
-- Uses 'TR.decimal' (not 'reads', which also accepts hex/octal/leading space)
-- and requires the whole field to be consumed, so a non-canonical value cannot
-- slip through and then be re-signed under the cache's key.  The length is
-- bounded first ('maxSizeFieldDigits'), so the parse cost is constant.
parseInteger :: Text -> Text -> Either String Integer
parseInteger key txt
  | T.length txt > maxSizeFieldDigits =
      Left ("integer field for " ++ T.unpack key ++ " is " ++ show (T.length txt) ++ " characters, above the " ++ show maxSizeFieldDigits ++ " maximum")
  | otherwise = case TR.decimal txt of
      Right (n, rest) | T.null rest -> Right n
      _ -> Left ("invalid integer for " ++ T.unpack key ++ ": " ++ T.unpack txt)

-- | Show a value as 'Text'.
showT :: (Show a) => a -> Text
showT = T.pack . show
