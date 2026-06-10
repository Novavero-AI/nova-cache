-- | Nix store path parsing, rendering, and validation.
--
-- A store path has the form @\/nix\/store\/\<hash\>-\<name\>@ where the hash
-- is a 32-character nix-base32 string and the name contains only characters
-- from a restricted set: alphanumeric plus @-._+?=@.
module NovaCache.StorePath
  ( StoreDir (..),
    StorePath (..),
    StorePathHash (..),
    StorePathName (..),
    parseStorePath,
    renderStorePath,
    storePathHashString,
    storePathBaseName,
    defaultStoreDir,
  )
where

import Data.Char (isAlphaNum)
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import qualified Data.Text as T
import NovaCache.Base32 (isBase32Char)

-- ---------------------------------------------------------------------------
-- Types
-- ---------------------------------------------------------------------------

-- | Root directory of the Nix store.
newtype StoreDir = StoreDir FilePath
  deriving (Eq, Ord, Show)

-- | A parsed store path: hash prefix and validated name.
data StorePath = StorePath
  { spHash :: !StorePathHash,
    spName :: !StorePathName
  }
  deriving (Eq, Ord, Show)

-- | The 32-character nix-base32 hash prefix of a store path.
newtype StorePathHash = StorePathHash Text
  deriving (Eq, Ord, Show)

-- | The validated name component of a store path.
newtype StorePathName = StorePathName Text
  deriving (Eq, Ord, Show)

-- ---------------------------------------------------------------------------
-- Constants
-- ---------------------------------------------------------------------------

-- | The standard Nix store directory.
defaultStoreDir :: StoreDir
defaultStoreDir = StoreDir defaultStoreDirPath

-- | Default store directory path.
defaultStoreDirPath :: FilePath
defaultStoreDirPath = "/nix/store"

-- | Length of the nix-base32 hash in a store path.
storePathHashLen :: Int
storePathHashLen = 32

-- | Minimum basename length: hash + separator.
minBaseNameLen :: Int
minBaseNameLen = storePathHashLen + 1

-- | The separator between hash and name in a store path.
hashNameSeparator :: Char
hashNameSeparator = '-'

-- ---------------------------------------------------------------------------
-- Validation
-- ---------------------------------------------------------------------------

-- | Characters allowed in the name component of a store path.
--
-- Alphanumeric plus @-._+?=@, matching the Nix specification.
validNameChar :: Char -> Bool
validNameChar c =
  isAlphaNum c
    || c == '-'
    || c == '_'
    || c == '.'
    || c == '+'
    || c == '?'
    || c == '='

-- ---------------------------------------------------------------------------
-- Parsing
-- ---------------------------------------------------------------------------

-- | Parse a store path from a full path or bare basename.
--
-- Accepts @\/nix\/store\/\<hash\>-\<name\>@ or just @\<hash\>-\<name\>@.
parseStorePath :: StoreDir -> Text -> Either String StorePath
parseStorePath (StoreDir dir) txt =
  parseBaseName (stripDirPrefix dir txt)

-- | Strip the store directory prefix if present.
stripDirPrefix :: FilePath -> Text -> Text
stripDirPrefix dir txt =
  fromMaybe txt (T.stripPrefix (T.pack dir <> "/") txt)

-- | Parse a @\<hash\>-\<name\>@ basename into a 'StorePath'.
parseBaseName :: Text -> Either String StorePath
parseBaseName basename
  | T.length basename < minBaseNameLen =
      Left ("store path too short: " ++ T.unpack basename)
  -- Safe: minBaseNameLen = storePathHashLen + 1, so the length guard above
  -- guarantees index storePathHashLen is in bounds.
  | T.index basename storePathHashLen /= hashNameSeparator =
      Left ("expected '-' after hash in store path: " ++ T.unpack basename)
  | not (T.all isBase32Char hashPart) =
      Left ("invalid nix-base32 hash in store path: " ++ T.unpack hashPart)
  | T.null name =
      Left ("empty name in store path: " ++ T.unpack basename)
  | not (T.all validNameChar name) =
      Left ("invalid characters in store path name: " ++ T.unpack name)
  | otherwise =
      Right StorePath {spHash = StorePathHash hashPart, spName = StorePathName name}
  where
    hashPart = T.take storePathHashLen basename
    name = T.drop minBaseNameLen basename

-- ---------------------------------------------------------------------------
-- Rendering
-- ---------------------------------------------------------------------------

-- | Render a store path as a full path under the given store directory.
renderStorePath :: StoreDir -> StorePath -> Text
renderStorePath (StoreDir dir) sp =
  T.pack dir <> "/" <> storePathBaseName sp

-- | Extract the 32-character nix-base32 hash string.
storePathHashString :: StorePath -> Text
storePathHashString (StorePath (StorePathHash h) _) = h

-- | Render the @\<hash\>-\<name\>@ basename.
storePathBaseName :: StorePath -> Text
storePathBaseName (StorePath (StorePathHash h) (StorePathName n)) =
  h <> T.singleton hashNameSeparator <> n
