-- | Ed25519 signing and verification for Nix binary cache.
--
-- Nix signs narinfo fingerprints with Ed25519. Keys are stored as
-- @name:base64@ pairs. The fingerprint is a semicolon-delimited string:
--
-- @1;\<StorePath\>;\<NarHash\>;\<NarSize\>;\<comma-separated-refs\>@
module NovaCache.Signing
  ( SecretKey (..),
    PublicKey (..),
    parseSecretKey,
    parsePublicKey,
    fingerprint,
    sign,
    verify,
  )
where

import Crypto.Error (CryptoFailable (..))
import qualified Crypto.PubKey.Ed25519 as Ed25519
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import NovaCache.NarInfo (NarInfo (..))

-- ---------------------------------------------------------------------------
-- Types
-- ---------------------------------------------------------------------------

-- | An Ed25519 secret key with its key name.
data SecretKey = SecretKey
  { skName :: !Text,
    skBytes :: !ByteString
  }
  deriving (Eq, Show)

-- | An Ed25519 public key with its key name.
data PublicKey = PublicKey
  { pkName :: !Text,
    pkBytes :: !ByteString
  }
  deriving (Eq, Show)

-- ---------------------------------------------------------------------------
-- Constants
-- ---------------------------------------------------------------------------

-- | Size of an Ed25519 secret key: 32-byte seed + 32-byte public half.
ed25519SecretKeySize :: Int
ed25519SecretKeySize = 64

-- | Size of an Ed25519 public key.
ed25519PublicKeySize :: Int
ed25519PublicKeySize = 32

-- | Size of the Ed25519 seed (first half of the secret key).
ed25519SeedSize :: Int
ed25519SeedSize = 32

-- | Key separator in @name:base64@ format.
keySeparator :: Text
keySeparator = ":"

-- | Fingerprint version tag.
fingerprintVersion :: Text
fingerprintVersion = "1"

-- | Fingerprint field separator.
fingerprintSep :: Text
fingerprintSep = ";"

-- | Reference separator within a fingerprint.
referenceSep :: Text
referenceSep = ","

-- ---------------------------------------------------------------------------
-- Key parsing
-- ---------------------------------------------------------------------------

-- | Parse a @name:base64@ secret key string.
parseSecretKey :: Text -> Either String SecretKey
parseSecretKey txt = do
  (keyName, decoded) <- splitAndDecode txt "secret key"
  expectSize ed25519SecretKeySize "secret key" decoded
  pure SecretKey {skName = keyName, skBytes = decoded}

-- | Parse a @name:base64@ public key string.
parsePublicKey :: Text -> Either String PublicKey
parsePublicKey txt = do
  (keyName, decoded) <- splitAndDecode txt "public key"
  expectSize ed25519PublicKeySize "public key" decoded
  pure PublicKey {pkName = keyName, pkBytes = decoded}

-- | Split a @name:base64@ string and decode the base64 payload.
splitAndDecode :: Text -> String -> Either String (Text, ByteString)
splitAndDecode txt label = case T.breakOn keySeparator txt of
  (_, rest)
    | T.null rest -> Left (label ++ " missing ':' separator")
    | otherwise -> do
        let encoded = T.drop 1 rest
            keyName = fst (T.breakOn keySeparator txt)
        decoded <- decodeBase64 encoded
        pure (keyName, decoded)

-- | Assert that decoded bytes have the expected size.
expectSize :: Int -> String -> ByteString -> Either String ()
expectSize expected label bs
  | BS.length bs == expected = Right ()
  | otherwise =
      Left
        ( "expected "
            ++ show expected
            ++ "-byte "
            ++ label
            ++ ", got "
            ++ show (BS.length bs)
        )

-- ---------------------------------------------------------------------------
-- Fingerprint
-- ---------------------------------------------------------------------------

-- | Construct the fingerprint string for a narinfo.
--
-- Format: @1;\<StorePath\>;\<NarHash\>;\<NarSize\>;\<ref1,ref2,...\>@
fingerprint :: NarInfo -> Text
fingerprint ni =
  T.intercalate
    fingerprintSep
    [ fingerprintVersion,
      niStorePath ni,
      niNarHash ni,
      T.pack (show (niNarSize ni)),
      T.intercalate referenceSep (map (storeDir <>) (niReferences ni))
    ]
  where
    -- References in a narinfo are basenames, but the fingerprint signs them as
    -- full store paths (/nix/store/<hash>-<name>), matching C++ Nix.  The store
    -- directory is the leading path of the (already absolute) niStorePath.
    storeDir = T.dropWhileEnd (/= '/') (niStorePath ni)

-- ---------------------------------------------------------------------------
-- Signing and verification
-- ---------------------------------------------------------------------------

-- | Sign a narinfo, producing a @keyname:base64sig@ string.
sign :: SecretKey -> NarInfo -> Either String Text
sign (SecretKey keyName secretBytes) ni = do
  sk <- cryptoSecretKey (BS.take ed25519SeedSize secretBytes)
  let pk = Ed25519.toPublic sk
      msg = TE.encodeUtf8 (fingerprint ni)
      sig = Ed25519.sign sk pk msg
      sigB64 = TE.decodeLatin1 (B64.encode (convert sig))
  pure (keyName <> keySeparator <> sigB64)

-- | Verify a @keyname:base64sig@ signature against a narinfo and public key.
--
-- The signature's key name must match this key's name (Nix looks the public key
-- up BY name) before the Ed25519 check runs.  Returns 'False' for any malformed
-- or non-matching input rather than failing.
verify :: PublicKey -> NarInfo -> Text -> Bool
verify (PublicKey trustedName pubBytes) ni sigLine =
  case T.breakOn keySeparator sigLine of
    (sigName, sigRest)
      | T.null sigRest || sigName /= trustedName -> False
      | otherwise -> case extractSignaturePayload sigLine of
          Nothing -> False
          Just sigRaw -> verifyRaw pubBytes (TE.encodeUtf8 (fingerprint ni)) sigRaw

-- | Extract the raw signature bytes from a @keyname:base64sig@ line.
extractSignaturePayload :: Text -> Maybe ByteString
extractSignaturePayload sigLine = case T.breakOn keySeparator sigLine of
  (_, rest)
    | T.null rest -> Nothing
    | otherwise -> either (const Nothing) Just (decodeBase64 (T.drop 1 rest))

-- | Low-level Ed25519 verification of raw bytes.
verifyRaw :: ByteString -> ByteString -> ByteString -> Bool
verifyRaw pubBytes msg sigBytes =
  case (cryptoPublicKey pubBytes, cryptoSignature sigBytes) of
    (Right pk, Right sig) -> Ed25519.verify pk msg sig
    _ -> False

-- ---------------------------------------------------------------------------
-- Cryptographic primitives (thin wrappers over crypton)
-- ---------------------------------------------------------------------------

-- | Decode base64 text to bytes.
decodeBase64 :: Text -> Either String ByteString
decodeBase64 = B64.decode . TE.encodeUtf8

-- | Lift a 'CryptoFailable' to 'Either' with a descriptive label.
liftCrypto :: String -> CryptoFailable a -> Either String a
liftCrypto _ (CryptoPassed x) = Right x
liftCrypto label (CryptoFailed err) = Left ("invalid " ++ label ++ ": " ++ show err)

-- | Parse raw bytes as an Ed25519 secret key.
cryptoSecretKey :: ByteString -> Either String Ed25519.SecretKey
cryptoSecretKey = liftCrypto "Ed25519 secret key" . Ed25519.secretKey

-- | Parse raw bytes as an Ed25519 public key.
cryptoPublicKey :: ByteString -> Either String Ed25519.PublicKey
cryptoPublicKey = liftCrypto "Ed25519 public key" . Ed25519.publicKey

-- | Parse raw bytes as an Ed25519 signature.
cryptoSignature :: ByteString -> Either String Ed25519.Signature
cryptoSignature = liftCrypto "Ed25519 signature" . Ed25519.signature
