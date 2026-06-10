module Main (main) where

import Control.Exception (SomeException)
import Data.Bifunctor (first)
import Data.ByteArray (constEq)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
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
    getRequestBodyChunk,
    pathInfo,
    requestBodyLength,
    requestHeaders,
    requestMethod,
    responseLBS,
  )
import qualified Network.Wai.Handler.Warp as Warp
import Network.Wai.Middleware.RequestLogger (logStdout)
import NovaCache.NarInfo (NarInfo (..), parseNarInfo, renderNarInfo)
import NovaCache.Signing (SecretKey, parseSecretKey, sign)
import NovaCache.Store (CacheInfo (..), FileStore, getCacheInfo, listNarInfoHashes, newFileStore, readNar, readNarInfo, writeNar, writeNarInfo)
import NovaCache.StorePath (defaultStoreDir, parseStorePath, storePathHashString)
import NovaCache.Validate (validateNarInfo)
import System.Environment (getArgs, lookupEnv)
import System.Exit (exitFailure)
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

-- | Environment variable to disable request logging.
requestLogEnvVar :: String
requestLogEnvVar = "LOG_REQUESTS"

-- | Maximum narinfo request body — narinfo is small text, so a tight cap.
maxNarInfoBodySize :: Int
maxNarInfoBodySize = 4 * 1024 * 1024 -- 4 MB

-- | Maximum NAR request body.  A real store path's NAR can be very large
-- (toolchains, GHC, LLVM), so this is far higher than the narinfo cap while
-- still bounding memory.
maxNarBodySize :: Int
maxNarBodySize = 4 * 1024 * 1024 * 1024 -- 4 GB

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
  logRequestsEnv <- lookupEnv requestLogEnvVar

  -- Order-independent flag parsing: take the value following a flag wherever it
  -- appears, so e.g. `--allow-open-writes --port 8080` still honours --port.
  let argValue flag = case dropWhile (/= flag) args of
        (_ : v : _) -> Just v
        _ -> Nothing
      port = case argValue "--port" >>= readMaybe of
        Just p -> p
        Nothing -> maybe defaultPort (fromMaybe defaultPort . readMaybe) portEnv
      storeRoot = fromMaybe (fromMaybe defaultStoreRoot storeEnv) (argValue "--store")
      allowOpenWrites = "--allow-open-writes" `elem` args

  store <- newFileStore storeRoot
  sigKey <- loadSigningKey sigKeyPath

  let cfg =
        Config
          { cfgStore = store,
            cfgApiKey = TE.encodeUtf8 . T.pack <$> apiKeyEnv,
            cfgSigningKey = sigKey
          }

  let logRequests = logRequestsEnv /= Just "0"
      requestLogger = if logRequests then logStdout else id

  putStrLn ("nova-cache-server listening on port " ++ show port)
  putStrLn ("store root: " ++ storeRoot)
  putStrLn ("signing: " ++ maybe "disabled" (const "enabled") sigKey)
  putStrLn ("write auth: " ++ maybe "disabled (open writes!)" (const "enabled") (cfgApiKey cfg))
  putStrLn ("request logging: " ++ if logRequests then "enabled" else "disabled (LOG_REQUESTS=0)")

  case cfgApiKey cfg of
    Nothing
      | not allowOpenWrites -> do
          hPutStrLn stderr $
            "FATAL: "
              ++ apiKeyEnvVar
              ++ " is not set — refusing to start with unauthenticated writes. "
              ++ "Set "
              ++ apiKeyEnvVar
              ++ ", or pass --allow-open-writes to override (not recommended on a public host)."
          exitFailure
    _ -> pure ()

  let settings =
        Warp.setPort port $
          Warp.setOnExceptionResponse onExceptionResponse Warp.defaultSettings
  Warp.runSettings settings (requestLogger (app cfg))

-- | Load a signing key from a file, if configured.
loadSigningKey :: Maybe FilePath -> IO (Maybe SecretKey)
loadSigningKey Nothing = pure Nothing
loadSigningKey (Just path) = do
  raw <- BS.readFile path
  case first show (TE.decodeUtf8' raw) >>= parseSecretKey . T.strip of
    Left err -> do
      hPutStrLn stderr ("WARNING: failed to load signing key: " ++ err)
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
            respond notFound
  -- GET /nar/<file>
  ("GET", ["nar", fileName]) -> do
    result <- readNar (cfgStore cfg) fileName
    case result of
      Just content ->
        respond (responseLBS HTTP.status200 octetHeaders (BL.fromStrict content))
      Nothing ->
        respond notFound
  -- PUT /<hash>.narinfo (auth required, validated)
  ("PUT", [hashNarinfo])
    | Just hashKey <- T.stripSuffix ".narinfo" hashNarinfo ->
        requireAuth cfg req respond $
          withLimitedBody maxNarInfoBodySize req respond $ \body ->
            case decodeAndValidate body of
              Left err -> do
                logWarn req ("INVALID: " <> T.unpack err)
                respond (badRequest err)
              Right ni
                | not (narInfoHashMatches hashKey ni) -> do
                    logWarn req "HASHMISMATCH"
                    respond (badRequest "narinfo StorePath hash does not match request")
                | otherwise -> do
                    signedResult <- signNarInfo (cfgSigningKey cfg) ni
                    case signedResult of
                      Left err -> do
                        logWarn req ("SIGNFAIL: " <> err)
                        respond (responseLBS HTTP.status500 textHeaders "signing failed")
                      Right signed -> do
                        ok <- writeNarInfo (cfgStore cfg) hashKey signed
                        if ok
                          then respond (responseLBS HTTP.status200 textHeaders "ok")
                          else do
                            logWarn req "BADPATH"
                            respond (badRequest "invalid path")
  -- PUT /nar/<file> (auth required)
  ("PUT", ["nar", fileName]) ->
    requireAuth cfg req respond $
      withLimitedBody maxNarBodySize req respond $ \body -> do
        ok <- writeNar (cfgStore cfg) fileName body
        if ok
          then respond (responseLBS HTTP.status200 textHeaders "ok")
          else do
            logWarn req "BADPATH"
            respond (badRequest "invalid path")
  -- Fallback
  _ ->
    respond notFound

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

-- | Whether the narinfo's declared StorePath actually carries the requested
-- hash — so an authenticated writer cannot store a narinfo describing path X
-- under path Y's key (a cache-poisoning / confused-deputy shape).
narInfoHashMatches :: Text -> NarInfo -> Bool
narInfoHashMatches hashKey ni =
  case parseStorePath defaultStoreDir (niStorePath ni) of
    Right sp -> storePathHashString sp == hashKey
    Left _ -> False

-- ---------------------------------------------------------------------------
-- Request body limiting
-- ---------------------------------------------------------------------------

-- | Read the request body, rejecting payloads over the given limit.
--
-- A declared @Content-Length@ over the limit is rejected up front; otherwise
-- (including unsized/chunked transfers) the body is read in bounded chunks with
-- a running size check that aborts before exceeding the limit, so memory stays
-- bounded regardless of the declared length.
readBodyLimited :: Int -> Request -> IO (Maybe BS.ByteString)
readBodyLimited limit req = case requestBodyLength req of
  KnownLength len
    | len > fromIntegral limit -> pure Nothing
  _ -> readChunks [] 0
  where
    readChunks acc total = do
      chunk <- getRequestBodyChunk req
      if BS.null chunk
        then pure (Just (BS.concat (reverse acc)))
        else
          let newTotal = total + BS.length chunk
           in if newTotal > limit
                then pure Nothing
                else readChunks (chunk : acc) newTotal

-- | Run an action with the limited request body, responding 413 if too large.
withLimitedBody :: Int -> Request -> (Response -> IO ResponseReceived) -> (BS.ByteString -> IO ResponseReceived) -> IO ResponseReceived
withLimitedBody limit req respond action = do
  bodyResult <- readBodyLimited limit req
  case bodyResult of
    Nothing -> do
      logWarn req "OVERLIMIT"
      respond (responseLBS HTTP.status413 textHeaders "request body too large")
    Just body -> action body

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
          else do
            logWarn req "REJECTED"
            respond (responseLBS HTTP.status401 textHeaders "unauthorized")

-- ---------------------------------------------------------------------------
-- Signing
-- ---------------------------------------------------------------------------

-- | Sign a validated 'NarInfo' if a signing key is configured.
--
-- With no key, returns the unsigned rendering (intentional — the operator
-- configured none).  With a key, FAILS CLOSED: a signing error returns 'Left'
-- so the handler refuses the write rather than persisting an unsigned narinfo
-- on a cache that is supposed to sign.
signNarInfo :: Maybe SecretKey -> NarInfo -> IO (Either String BS.ByteString)
signNarInfo Nothing ni = pure (Right (renderNarInfoBytes ni))
signNarInfo (Just sk) ni = case sign sk ni of
  Left err -> do
    hPutStrLn stderr ("ERROR: signNarInfo: sign failed: " ++ err)
    pure (Left err)
  Right sig ->
    let signed = ni {niSigs = niSigs ni ++ [sig]}
     in pure (Right (renderNarInfoBytes signed))

-- | Render a 'NarInfo' to its UTF-8 encoded wire format.
renderNarInfoBytes :: NarInfo -> BS.ByteString
renderNarInfoBytes = TE.encodeUtf8 . renderNarInfo

-- ---------------------------------------------------------------------------
-- Logging
-- ---------------------------------------------------------------------------

-- | Log a server-side warning to stderr with request context.
logWarn :: Request -> String -> IO ()
logWarn req msg =
  hPutStrLn stderr $
    msg
      <> " "
      <> BS8.unpack (requestMethod req)
      <> " /"
      <> T.unpack (T.intercalate "/" (pathInfo req))

-- ---------------------------------------------------------------------------
-- Response helpers
-- ---------------------------------------------------------------------------

-- | Render the nix-cache-info response body.
renderCacheInfo :: FileStore -> BS.ByteString
renderCacheInfo store =
  let info = getCacheInfo store
   in TE.encodeUtf8 $
        T.unlines
          [ "StoreDir: " <> ciStoreDir info,
            "WantMassQuery: " <> boolText (ciWantMassQuery info),
            "Priority: " <> T.pack (show (ciPriority info))
          ]

-- | Render a Bool as @1@ or @0@.
boolText :: Bool -> Text
boolText True = "1"
boolText False = "0"

-- | 404 Not Found response.
notFound :: Response
notFound = responseLBS HTTP.status404 textHeaders "not found"

-- | 400 Bad Request with a text error message.
badRequest :: Text -> Response
badRequest msg = responseLBS HTTP.status400 textHeaders (BL.fromStrict (TE.encodeUtf8 msg))

-- | Map any uncaught handler exception to a generic 500, so internal error
-- detail (filesystem paths, exception text) is never leaked to clients.
onExceptionResponse :: SomeException -> Response
onExceptionResponse _ = responseLBS HTTP.status500 textHeaders "internal server error"

-- | Content-Type: text/plain headers.
textHeaders :: HTTP.ResponseHeaders
textHeaders = [(HTTP.hContentType, "text/plain")]

-- | Content-Type and caching headers for a narinfo response.
-- A narinfo body is NOT immutable for a fixed key — re-uploading the same store
-- path to add or rotate a signature changes it — so it is cacheable but must
-- stay revalidatable (no @immutable@).
narInfoHeaders :: HTTP.ResponseHeaders
narInfoHeaders =
  [ (HTTP.hContentType, "text/x-nix-narinfo"),
    (HTTP.hCacheControl, "public, max-age=3600, must-revalidate")
  ]

-- | Content-Type: application/octet-stream headers.
-- NAR files are content-addressed (keyed by content hash) and immutable
-- once written, so they are safe to cache indefinitely at the CDN edge.
octetHeaders :: HTTP.ResponseHeaders
octetHeaders =
  [ (HTTP.hContentType, "application/octet-stream"),
    (HTTP.hCacheControl, "public, max-age=31536000, immutable")
  ]
