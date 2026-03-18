module Main (main) where

import Data.Bifunctor (first)
import Data.ByteArray (constEq)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Network.HTTP.Types as HTTP
import Network.Wai
  ( Application,
    Request,
    RequestBodyLength (..),
    Response,
    ResponseReceived,
    pathInfo,
    requestBodyLength,
    requestHeaders,
    requestMethod,
    responseLBS,
    strictRequestBody,
  )
import qualified Network.Wai.Handler.Warp as Warp
import NovaCache.NarInfo (NarInfo (..), parseNarInfo, renderNarInfo)
import NovaCache.Signing (SecretKey, parseSecretKey, sign)
import NovaCache.Store (FileStore, getCacheInfo, listNarInfoHashes, newFileStore, readNar, readNarInfo, writeNar, writeNarInfo)
import NovaCache.Validate (validateNarInfo)
import System.Environment (getArgs, lookupEnv)
import System.IO (hPutStrLn, stderr)
import Text.Read (readMaybe)

-- ---------------------------------------------------------------------------
-- Constants
-- ---------------------------------------------------------------------------

-- | Default server port.
defaultPort :: Int
defaultPort = 5000

-- | Default store directory.
defaultStoreRoot :: FilePath
defaultStoreRoot = "./nix-cache"

-- | Environment variable for the write API key.
apiKeyEnvVar :: String
apiKeyEnvVar = "CACHE_API_KEY"

-- | Environment variable for the signing key file path.
signingKeyEnvVar :: String
signingKeyEnvVar = "SIGNING_KEY_FILE"

-- | Maximum allowed request body size (100 MB).
maxBodySize :: Int
maxBodySize = 100 * 1024 * 1024

-- ---------------------------------------------------------------------------
-- Server configuration
-- ---------------------------------------------------------------------------

-- | Runtime server configuration.
data Config = Config
  { cfgStore :: !FileStore,
    cfgApiKey :: !(Maybe BS.ByteString),
    cfgSigningKey :: !(Maybe SecretKey)
  }

-- ---------------------------------------------------------------------------
-- Main
-- ---------------------------------------------------------------------------

main :: IO ()
main = do
  args <- getArgs
  portEnv <- lookupEnv "PORT"
  storeEnv <- lookupEnv "NIX_CACHE_DIR"
  apiKeyEnv <- lookupEnv apiKeyEnvVar
  sigKeyPath <- lookupEnv signingKeyEnvVar

  let port = case args of
        ("--port" : p : _) -> fromMaybe defaultPort (readMaybe p)
        _ -> maybe defaultPort (fromMaybe defaultPort . readMaybe) portEnv
      storeRoot = case args of
        ("--store" : s : _) -> s
        _ -> fromMaybe defaultStoreRoot storeEnv

  store <- newFileStore storeRoot
  sigKey <- loadSigningKey sigKeyPath

  let cfg =
        Config
          { cfgStore = store,
            cfgApiKey = TE.encodeUtf8 . T.pack <$> apiKeyEnv,
            cfgSigningKey = sigKey
          }

  putStrLn ("nova-cache-server listening on port " ++ show port)
  putStrLn ("store root: " ++ storeRoot)
  putStrLn ("signing: " ++ maybe "disabled" (const "enabled") sigKey)
  putStrLn ("write auth: " ++ maybe "disabled (open writes!)" (const "enabled") (cfgApiKey cfg))
  Warp.run port (app cfg)

-- | Load a signing key from a file, if configured.
loadSigningKey :: Maybe FilePath -> IO (Maybe SecretKey)
loadSigningKey Nothing = pure Nothing
loadSigningKey (Just path) = do
  raw <- BS.readFile path
  case first show (TE.decodeUtf8' raw) >>= parseSecretKey . T.strip of
    Left err -> do
      putStrLn ("WARNING: failed to load signing key: " ++ err)
      pure Nothing
    Right sk -> pure (Just sk)

-- ---------------------------------------------------------------------------
-- WAI application
-- ---------------------------------------------------------------------------

-- | WAI application implementing the Nix binary cache HTTP protocol.
app :: Config -> Application
app cfg req respond = case (requestMethod req, pathInfo req) of
  -- GET /nix-cache-info
  ("GET", ["nix-cache-info"]) ->
    respond (responseLBS HTTP.status200 textHeaders (BL.fromStrict (renderCacheInfo (cfgStore cfg))))
  -- GET /narinfo-hashes
  ("GET", ["narinfo-hashes"]) -> do
    hashes <- listNarInfoHashes (cfgStore cfg)
    let body = TE.encodeUtf8 (T.unlines hashes)
    respond (responseLBS HTTP.status200 textHeaders (BL.fromStrict body))
  -- GET /<hash>.narinfo
  ("GET", [hashNarinfo])
    | Just hashKey <- T.stripSuffix ".narinfo" hashNarinfo -> do
        result <- readNarInfo (cfgStore cfg) hashKey
        case result of
          Just content ->
            respond (responseLBS HTTP.status200 narInfoHeaders (BL.fromStrict content))
          Nothing ->
            respond (responseLBS HTTP.status404 textHeaders "not found")
  -- GET /nar/<file>
  ("GET", ["nar", fileName]) -> do
    result <- readNar (cfgStore cfg) fileName
    case result of
      Just content ->
        respond (responseLBS HTTP.status200 octetHeaders (BL.fromStrict content))
      Nothing ->
        respond (responseLBS HTTP.status404 textHeaders "not found")
  -- PUT /<hash>.narinfo (auth required, validated)
  ("PUT", [hashNarinfo])
    | Just hashKey <- T.stripSuffix ".narinfo" hashNarinfo ->
        requireAuth cfg req respond $ do
          bodyResult <- readBodyLimited req
          case bodyResult of
            Nothing ->
              respond (responseLBS HTTP.status413 textHeaders "request body too large")
            Just body -> case decodeAndValidate body of
              Left err ->
                respond (badRequest err)
              Right ni -> do
                signed <- signNarInfo (cfgSigningKey cfg) ni
                ok <- writeNarInfo (cfgStore cfg) hashKey signed
                if ok
                  then respond (responseLBS HTTP.status200 textHeaders "ok")
                  else respond (badRequest "invalid path")
  -- PUT /nar/<file> (auth required)
  ("PUT", ["nar", fileName]) ->
    requireAuth cfg req respond $ do
      bodyResult <- readBodyLimited req
      case bodyResult of
        Nothing ->
          respond (responseLBS HTTP.status413 textHeaders "request body too large")
        Just body -> do
          ok <- writeNar (cfgStore cfg) fileName body
          if ok
            then respond (responseLBS HTTP.status200 textHeaders "ok")
            else respond (badRequest "invalid path")
  -- Fallback
  _ ->
    respond (responseLBS HTTP.status404 textHeaders "not found")

-- ---------------------------------------------------------------------------
-- Validation pipeline
-- ---------------------------------------------------------------------------

-- | Decode a raw narinfo body and validate it in a single pure pipeline.
--
-- Composes UTF-8 decoding, narinfo parsing, and field validation. Returns
-- the validated 'NarInfo' on success, or a user-facing error message.
decodeAndValidate :: BS.ByteString -> Either Text NarInfo
decodeAndValidate body = do
  decoded <- first (const "request body is not valid UTF-8") (TE.decodeUtf8' body)
  ni <- first T.pack (parseNarInfo decoded)
  first (T.unlines . map (T.pack . show)) (validateNarInfo ni)

-- ---------------------------------------------------------------------------
-- Request body limiting
-- ---------------------------------------------------------------------------

-- | Read the request body, rejecting payloads over 'maxBodySize'.
--
-- Returns 'Nothing' if the declared @Content-Length@ exceeds the limit.
-- For chunked transfers the body is read and checked after the fact.
readBodyLimited :: Request -> IO (Maybe BS.ByteString)
readBodyLimited req = case requestBodyLength req of
  KnownLength len
    | len > fromIntegral maxBodySize -> pure Nothing
  _ -> do
    body <- BL.toStrict <$> strictRequestBody req
    if BS.length body > maxBodySize
      then pure Nothing
      else pure (Just body)

-- ---------------------------------------------------------------------------
-- Auth
-- ---------------------------------------------------------------------------

-- | Gate a handler behind API key authentication.
--
-- If no key is configured, all writes are permitted (open mode).
-- Otherwise the request must carry @Authorization: Bearer \<key\>@.
-- Uses constant-time comparison to prevent timing attacks.
requireAuth :: Config -> Request -> (Response -> IO ResponseReceived) -> IO ResponseReceived -> IO ResponseReceived
requireAuth cfg req respond action = case cfgApiKey cfg of
  Nothing -> action
  Just expected ->
    let provided = lookup HTTP.hAuthorization (requestHeaders req)
        expectedHeader = "Bearer " <> expected
     in if maybe False (constEq expectedHeader) provided
          then action
          else respond (responseLBS HTTP.status401 textHeaders "unauthorized")

-- ---------------------------------------------------------------------------
-- Signing
-- ---------------------------------------------------------------------------

-- | Sign a validated 'NarInfo' if a signing key is configured.
--
-- Logs a warning to stderr if signing fails, then returns the unsigned
-- rendering so the upload is not rejected.
signNarInfo :: Maybe SecretKey -> NarInfo -> IO BS.ByteString
signNarInfo Nothing ni = pure (renderNarInfoBytes ni)
signNarInfo (Just sk) ni = case sign sk ni of
  Left err -> do
    hPutStrLn stderr ("WARNING: signNarInfo: sign failed: " ++ err)
    pure (renderNarInfoBytes ni)
  Right sig ->
    let signed = ni {niSigs = niSigs ni ++ [sig]}
     in pure (renderNarInfoBytes signed)

-- | Render a 'NarInfo' to its UTF-8 encoded wire format.
renderNarInfoBytes :: NarInfo -> BS.ByteString
renderNarInfoBytes = TE.encodeUtf8 . renderNarInfo

-- ---------------------------------------------------------------------------
-- Response helpers
-- ---------------------------------------------------------------------------

-- | Render the nix-cache-info response body.
renderCacheInfo :: FileStore -> BS.ByteString
renderCacheInfo store =
  let (storeDir, wantMassQuery, priority) = getCacheInfo store
   in TE.encodeUtf8 $
        T.unlines
          [ "StoreDir: " <> storeDir,
            "WantMassQuery: " <> boolText wantMassQuery,
            "Priority: " <> T.pack (show priority)
          ]

-- | Render a Bool as @1@ or @0@.
boolText :: Bool -> Text
boolText True = "1"
boolText False = "0"

-- | 400 Bad Request with a text error message.
badRequest :: Text -> Response
badRequest msg = responseLBS HTTP.status400 textHeaders (BL.fromStrict (TE.encodeUtf8 msg))

-- | Content-Type: text/plain headers.
textHeaders :: HTTP.ResponseHeaders
textHeaders = [(HTTP.hContentType, "text/plain")]

-- | Content-Type: application/x-nix-narinfo headers.
-- Narinfo files are content-addressed (keyed by store path hash) and
-- immutable once written, so they are safe to cache indefinitely at the
-- CDN edge.
narInfoHeaders :: HTTP.ResponseHeaders
narInfoHeaders =
  [ (HTTP.hContentType, "text/x-nix-narinfo"),
    (HTTP.hCacheControl, "public, max-age=31536000, immutable")
  ]

-- | Content-Type: application/octet-stream headers.
-- NAR files are content-addressed (keyed by content hash) and immutable
-- once written, so they are safe to cache indefinitely at the CDN edge.
octetHeaders :: HTTP.ResponseHeaders
octetHeaders =
  [ (HTTP.hContentType, "application/octet-stream"),
    (HTTP.hCacheControl, "public, max-age=31536000, immutable")
  ]
