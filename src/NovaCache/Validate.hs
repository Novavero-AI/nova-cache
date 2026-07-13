-- | Pure protocol validation for narinfo and NAR content.
--
-- Validates narinfo field semantics (sizes, store paths, hash formats),
-- NAR/file content hashes against declared values, and Ed25519 signatures.
-- All functions are pure - no IO, no side effects.
module NovaCache.Validate
  ( ValidationError (..),
    validateNarInfo,
    validateNarHash,
    validateFileHash,
    validateSignature,
    validateFull,
  )
where

import Data.ByteString (ByteString)
import Data.Text (Text)
import qualified Data.Text as T
import NovaCache.Hash (formatNixHash, hashBytes, parseNixHash)
import NovaCache.NarInfo (NarInfo (..))
import NovaCache.Signing (PublicKey, verify)
import NovaCache.StorePath (defaultStoreDir, parseAbsoluteStorePath, parseStorePathBaseName)

-- ---------------------------------------------------------------------------
-- Types
-- ---------------------------------------------------------------------------

-- | Validation errors for narinfo and NAR content.
data ValidationError
  = -- | FileSize field is negative.
    NegativeFileSize !Integer
  | -- | NarSize field is negative.
    NegativeNarSize !Integer
  | -- | StorePath field does not parse. (raw value, parse error)
    InvalidStorePath !Text !String
  | -- | FileHash field does not parse. (raw value, parse error)
    InvalidFileHash !Text !String
  | -- | NarHash field does not parse. (raw value, parse error)
    InvalidNarHash !Text !String
  | -- | A reference does not parse as a store path basename. (raw value, parse error)
    InvalidReference !Text !String
  | -- | Computed NAR hash differs from declared. (expected, actual)
    NarHashMismatch !Text !Text
  | -- | Computed file hash differs from declared. (expected, actual)
    FileHashMismatch !Text !Text
  | -- | A signature line failed verification.
    SignatureInvalid !Text
  | -- | The narinfo has zero signatures.
    NoSignatures
  | -- | StorePath is a derivation (.drv) - binary caches serve build outputs only.
    DerivationStorePath !Text
  deriving (Eq, Show)

-- ---------------------------------------------------------------------------
-- NarInfo field validation
-- ---------------------------------------------------------------------------

-- | Validate narinfo field semantics: sizes non-negative, store path parses,
-- hash fields parse, references parse. Collects all errors (not short-circuit).
-- Returns the 'NarInfo' unchanged on success for composition.
validateNarInfo :: NarInfo -> Either [ValidationError] NarInfo
validateNarInfo ni =
  case concat [sizeErrors, drvErrors, storePathErrors, fileHashErrors, narHashErrors, refErrors] of
    [] -> Right ni
    errs -> Left errs
  where
    sizeErrors =
      [NegativeFileSize declared | Just declared <- [niFileSize ni], declared < 0]
        ++ [NegativeNarSize (niNarSize ni) | niNarSize ni < 0]

    drvErrors =
      [DerivationStorePath (niStorePath ni) | ".drv" `T.isSuffixOf` niStorePath ni]

    -- The wire format fixes each field's spelling: StorePath is absolute,
    -- References and Deriver are basenames.  Accepting the other spelling
    -- would sign narinfos (bare StorePath, absolute references) that every
    -- real Nix client rejects at parse time - and a bare StorePath also
    -- derives an empty store dir in the signed fingerprint.
    storePathErrors = case parseAbsoluteStorePath defaultStoreDir (niStorePath ni) of
      Left err -> [InvalidStorePath (niStorePath ni) err]
      Right _ -> []

    fileHashErrors = case niFileHash ni of
      Nothing -> []
      Just declared -> case parseNixHash declared of
        Left err -> [InvalidFileHash declared err]
        Right _ -> []

    narHashErrors = case parseNixHash (niNarHash ni) of
      Left err -> [InvalidNarHash (niNarHash ni) err]
      Right _ -> []

    refErrors = concatMap checkRef (niReferences ni)

    checkRef ref = case parseStorePathBaseName ref of
      Left err -> [InvalidReference ref err]
      Right _ -> []

-- ---------------------------------------------------------------------------
-- Content hash validation
-- ---------------------------------------------------------------------------

-- | Validate that the SHA-256 hash of raw uncompressed NAR bytes matches
-- the declared 'niNarHash'.
validateNarHash :: NarInfo -> ByteString -> Either ValidationError ()
validateNarHash ni narBytes =
  -- Compare DECODED hash bytes, not re-formatted strings.  Only the
  -- canonical sha256:<nix-base32> spelling parses - deliberately strict,
  -- since the fingerprint signs the NarHash TEXT verbatim; accepting other
  -- encodings on the read side arrives with the foreign-cache substitution
  -- feature that needs them.
  case parseNixHash (niNarHash ni) of
    Left err -> Left (InvalidNarHash (niNarHash ni) err)
    Right declared
      | declared == hashBytes narBytes -> Right ()
      | otherwise -> Left (NarHashMismatch (niNarHash ni) (formatNixHash (hashBytes narBytes)))

-- | Validate that the SHA-256 hash of compressed file bytes matches
-- the declared 'niFileHash'.  An absent FileHash declares nothing to
-- check (upstream treats the field as optional); integrity then rests on
-- the always-required NarHash.
validateFileHash :: NarInfo -> ByteString -> Either ValidationError ()
validateFileHash ni fileBytes = case niFileHash ni of
  Nothing -> Right ()
  Just declaredText -> case parseNixHash declaredText of
    Left err -> Left (InvalidFileHash declaredText err)
    Right declared
      | declared == hashBytes fileBytes -> Right ()
      | otherwise -> Left (FileHashMismatch declaredText (formatNixHash (hashBytes fileBytes)))

-- ---------------------------------------------------------------------------
-- Signature validation
-- ---------------------------------------------------------------------------

-- | Validate signatures against a trusted public key. At least one signature
-- must verify (matches Nix behaviour - any trusted key suffices).
-- Returns 'Left [NoSignatures]' when there are no signatures at all.
validateSignature :: PublicKey -> NarInfo -> Either [ValidationError] ()
validateSignature pk ni
  | null sigs = Left [NoSignatures]
  | any (verify pk ni) sigs = Right ()
  | otherwise = Left (map SignatureInvalid sigs)
  where
    sigs = niSigs ni

-- ---------------------------------------------------------------------------
-- Full validation
-- ---------------------------------------------------------------------------

-- | Compose all validation stages: narinfo fields, NAR hash, file hash,
-- and signatures. Collects all errors from all stages.
validateFull ::
  PublicKey ->
  NarInfo ->
  ByteString ->
  ByteString ->
  Either [ValidationError] ()
validateFull pk ni narBytes fileBytes =
  case concat [narInfoErrors, narHashErrors, fileHashErrors, sigErrors] of
    [] -> Right ()
    errs -> Left errs
  where
    narInfoErrors = case validateNarInfo ni of
      Left errs -> errs
      Right _ -> []

    narHashErrors = case validateNarHash ni narBytes of
      Left err -> [err]
      Right _ -> []

    fileHashErrors = case validateFileHash ni fileBytes of
      Left err -> [err]
      Right _ -> []

    sigErrors = case validateSignature pk ni of
      Left errs -> errs
      Right _ -> []
