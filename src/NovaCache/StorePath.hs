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
    parseStorePathBaseName,
    parseAbsoluteStorePath,
    renderStorePath,
    storePathHashString,
    storePathBaseName,
    defaultStoreDir,
  )
where

import Data.Char (isAlphaNum, isAscii)
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

-- | Maximum length of a store path name, as enforced by Nix.
maxNameLen :: Int
maxNameLen = 211

-- ---------------------------------------------------------------------------
-- Validation
-- ---------------------------------------------------------------------------

-- | Characters allowed in the name component of a store path.
--
-- ASCII alphanumeric plus @-._+?=@, matching the Nix specification.  The
-- ASCII restriction matters: Nix rejects non-ASCII letters and digits, so
-- accepting them here would sign and store paths no Nix client can parse.
validNameChar :: Char -> Bool
validNameChar c =
  (isAscii c && isAlphaNum c)
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
-- Wire-format fields have a REQUIRED spelling; use 'parseStorePathBaseName'
-- (narinfo References, Deriver) or 'parseAbsoluteStorePath' (narinfo
-- StorePath) to enforce it.
parseStorePath :: StoreDir -> Text -> Either String StorePath
parseStorePath (StoreDir dir) txt =
  parseBaseName (stripDirPrefix dir txt)

-- | Parse a bare @\<hash\>-\<name\>@ basename, rejecting any path separator.
-- Narinfo References and Deriver are basenames on the wire; upstream Nix
-- rejects tokens containing @\/@ outright.
parseStorePathBaseName :: Text -> Either String StorePath
parseStorePathBaseName txt
  | T.any (== '/') txt =
      Left ("expected a store path basename, got a path: " ++ T.unpack txt)
  | otherwise = parseBaseName txt

-- | Parse a full @\<store-dir\>\/\<hash\>-\<name\>@ path, rejecting a bare
-- basename.  The narinfo StorePath field is absolute on the wire.
parseAbsoluteStorePath :: StoreDir -> Text -> Either String StorePath
parseAbsoluteStorePath (StoreDir dir) txt =
  case T.stripPrefix (T.pack dir <> "/") txt of
    Just basename -> parseBaseName basename
    Nothing ->
      Left ("expected an absolute store path under " ++ dir ++ ": " ++ T.unpack txt)

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
  | T.length name > maxNameLen =
      Left ("store path name longer than " ++ show maxNameLen ++ " characters: " ++ T.unpack name)
  -- Upstream's checkName dot rule: the FIRST dash-separated component may
  -- not be "." or "..", rejecting the traversal names and their ".-x" /
  -- "..-y" prefixed forms alike, while other dot-leading names
  -- (".config-1.0") stay valid.  Same rule nova-nix enforces at its
  -- construction and parse boundaries; a dot name accepted here would be
  -- stored and signed although no Nix client parses it.
  | firstDashComponent == "." || firstDashComponent == ".." =
      Left ("store path name may not begin with a dot segment: " ++ T.unpack name)
  | not (T.all validNameChar name) =
      Left ("invalid characters in store path name: " ++ T.unpack name)
  | otherwise =
      Right StorePath {spHash = StorePathHash hashPart, spName = StorePathName name}
  where
    hashPart = T.take storePathHashLen basename
    name = T.drop minBaseNameLen basename
    firstDashComponent = T.takeWhile (/= '-') name

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
