module Main (main) where

import Control.Exception (SomeException)
import Data.Bifunctor (first)
import Data.ByteArray (constEq)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString.Lazy as BL
import Data.Maybe (fromMaybe, isJust)
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
import NovaCache.Signing (SecretKey, normalizeKeyText, parseSecretKey, renderPublicKey, sign, toPublicKey)
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

-- | Maximum narinfo request body - narinfo is small text, so a tight cap.
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
    cfgSigningKey :: !(Maybe SecretKey),
    -- | The rendered @name:base64@ public key line, derived from the
    -- signing key at startup; shown on the landing page.
    cfgPublicKey :: !(Maybe Text)
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
  pubKey <- derivePublicKeyLine sigKey

  let cfg =
        Config
          { cfgStore = store,
            cfgApiKey = TE.encodeUtf8 . normalizeKeyText . T.pack <$> apiKeyEnv,
            cfgSigningKey = sigKey,
            cfgPublicKey = pubKey
          }

  let logRequests = logRequestsEnv /= Just "0"
      requestLogger = if logRequests then logStdout else id

  putStrLn ("nova-cache-server listening on port " ++ show port)
  putStrLn ("store root: " ++ storeRoot)
  putStrLn ("signing: " ++ maybe "disabled" (const "enabled") sigKey)
  mapM_ (\k -> putStrLn ("public key: " ++ T.unpack k)) pubKey
  putStrLn ("write auth: " ++ maybe "disabled (open writes!)" (const "enabled") (cfgApiKey cfg))
  putStrLn ("request logging: " ++ if logRequests then "enabled" else "disabled (LOG_REQUESTS=0)")

  case cfgApiKey cfg of
    Nothing
      | not allowOpenWrites -> do
          hPutStrLn stderr $
            "FATAL: "
              ++ apiKeyEnvVar
              ++ " is not set - refusing to start with unauthenticated writes. "
              ++ "Set "
              ++ apiKeyEnvVar
              ++ ", or pass --allow-open-writes to override (not recommended on a public host)."
          exitFailure
    _ -> pure ()

  let settings =
        Warp.setPort port $
          Warp.setOnExceptionResponse onExceptionResponse Warp.defaultSettings
  Warp.runSettings settings (requestLogger (app cfg))

-- | Load a signing key from a file, if configured.  A configured key that
-- fails to load is FATAL: falling back to unsigned would persist narinfos
-- no trust anchor can verify (the same fail-closed policy as 'signNarInfo').
loadSigningKey :: Maybe FilePath -> IO (Maybe SecretKey)
loadSigningKey Nothing = pure Nothing
loadSigningKey (Just path) = do
  raw <- BS.readFile path
  case first show (TE.decodeUtf8' raw) >>= parseSecretKey . normalizeKeyText of
    Left err -> do
      hPutStrLn stderr ("FATAL: cannot load the signing key from " ++ path ++ ": " ++ err)
      exitFailure
    Right sk -> pure (Just sk)

-- | Derive the rendered public key line from the signing key, if any.
-- The landing page shows this line, so the published trust anchor always
-- matches the key in use; on a derivation failure the page omits it.
derivePublicKeyLine :: Maybe SecretKey -> IO (Maybe Text)
derivePublicKeyLine Nothing = pure Nothing
derivePublicKeyLine (Just sk) = case toPublicKey sk of
  Left err -> do
    hPutStrLn stderr ("WARNING: cannot derive the public key from the signing key: " ++ err)
    pure Nothing
  Right pk -> pure (Just (renderPublicKey pk))

-- ---------------------------------------------------------------------------
-- WAI application
-- ---------------------------------------------------------------------------

-- | WAI application implementing the Nix binary cache HTTP protocol.
app :: Config -> Application
app cfg req respond = case (requestMethod req, pathInfo req) of
  -- GET / - human-facing landing page (the protocol lives at the other routes)
  ("GET", []) -> do
    pathCount <- length <$> listNarInfoHashes (cfgStore cfg)
    let info = getCacheInfo (cfgStore cfg)
        signingEnabled = isJust (cfgSigningKey cfg)
        body = TE.encodeUtf8 (landingHtml info signingEnabled (cfgPublicKey cfg) pathCount)
    respond (responseLBS HTTP.status200 htmlHeaders (BL.fromStrict body))
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
-- hash - so an authenticated writer cannot store a narinfo describing path X
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
-- With no key, returns the unsigned rendering (intentional - the operator
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

-- | The landing page served at @GET /@.  Static apart from four live
-- values (store-path count, store dir, signing status, public key); styled
-- to match novavero.ai.  Nothing user-supplied is interpolated - the key
-- line is operator configuration - so no escaping is needed.
landingHtml :: CacheInfo -> Bool -> Maybe Text -> Int -> Text
landingHtml info signingEnabled pubKey pathCount =
  T.unlines
    [ "<!DOCTYPE html>",
      "<html lang=\"en\">",
      "<head>",
      "<meta charset=\"UTF-8\" />",
      "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />",
      "<title>cache.novavero.ai - Nix binary cache</title>",
      "<meta name=\"description\" content=\"The Novavero Nix binary cache, serving store paths for nova-nix - the Windows-native Nix.\" />",
      "<link rel=\"icon\" type=\"image/svg+xml\" href=\"data:image/svg+xml," <> novaveroLogoSvgEscaped <> "\" />",
      "<style>",
      "* { margin: 0; padding: 0; box-sizing: border-box; }",
      "body { background: #0a0b0e; color: #d6d9de; -webkit-font-smoothing: antialiased; font-family: 'Inter', system-ui, sans-serif; line-height: 1.75; }",
      "body::before { content: ''; position: fixed; inset: 0 0 auto 0; height: 320px; pointer-events: none; background: radial-gradient(ellipse 70% 100% at 50% -20%, rgba(52,211,153,0.07), transparent 70%); }",
      ".container { max-width: 720px; margin: 0 auto; padding: 80px 24px; position: relative; }",
      "a { color: #34d399; text-decoration: none; }",
      "a:hover { text-decoration: underline; }",
      ".brand { display: flex; align-items: center; gap: 14px; margin-bottom: 0.75rem; }",
      ".brand svg { width: 44px; height: 44px; border-radius: 10px; }",
      "h1 { color: #fff; font-size: 1.6rem; font-family: ui-monospace, Consolas, monospace; }",
      ".tagline { color: #9ca3af; margin-bottom: 2.5rem; }",
      ".stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 2.5rem; }",
      ".stat { padding: 16px; border: 1px solid #232733; border-radius: 12px; text-align: center; }",
      ".stat .value { color: #fff; font-size: 1.4rem; font-weight: 600; }",
      ".stat .label { color: #6b7280; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }",
      "h2 { color: #fff; font-size: 1rem; margin: 2rem 0 0.5rem; }",
      "p { font-size: 0.9rem; margin-bottom: 0.75rem; }",
      "pre { background: #0d0f14; border: 1px solid #232733; border-radius: 8px; padding: 14px; white-space: pre-wrap; word-break: break-all; margin: 0.75rem 0; }",
      "code { font-family: ui-monospace, Consolas, monospace; font-size: 0.85rem; color: #e5e7eb; }",
      ".footer { margin-top: 3rem; padding-top: 1.5rem; border-top: 1px solid #232733; font-size: 0.85rem; color: #6b7280; }",
      "</style>",
      "</head>",
      "<body>",
      "<div class=\"container\">",
      "<div class=\"brand\">" <> novaveroLogoSvg <> "<h1>cache.novavero.ai</h1></div>",
      "<p class=\"tagline\">Nix binary cache - serving store paths for <a href=\"https://github.com/Novavero-AI/nova-nix\">nova-nix</a>, the Windows-native Nix.</p>",
      "<div class=\"stats\">",
      "<div class=\"stat\"><div class=\"value\">" <> T.pack (show pathCount) <> "</div><div class=\"label\">store paths</div></div>",
      "<div class=\"stat\"><div class=\"value\">" <> (if signingEnabled then "ed25519" else "off") <> "</div><div class=\"label\">signing</div></div>",
      "<div class=\"stat\"><div class=\"value\">" <> T.pack (show (ciPriority info)) <> "</div><div class=\"label\">priority</div></div>",
      "</div>",
      "<h2>Use it</h2>",
      "<pre><code>substituters = https://cache.novavero.ai" <> trustAnchorLine <> "</code></pre>",
      "<p>Store dir: <code>" <> ciStoreDir info <> "</code> &middot; protocol endpoints: <code>/nix-cache-info</code>, <code>/&lt;hash&gt;.narinfo</code>, <code>/nar/&lt;file&gt;</code></p>",
      "<h2>What this is</h2>",
      "<p>The binary cache behind the Novavero Nix toolchain. Powered by <a href=\"https://github.com/Novavero-AI/nova-cache\">nova-cache</a>, a Haskell implementation of the Nix binary cache protocol. Read about the first package built by Nix natively on Windows on <a href=\"https://novavero.ai/blog/first-native-windows-nix-build.html\">the blog</a>.</p>",
      "<div class=\"footer\"><a href=\"https://novavero.ai\">Novavero AI</a> &middot; Waterloo, Canada</div>",
      "</div>",
      "</body>",
      "</html>"
    ]
  where
    trustAnchorLine = maybe "" ("\ntrusted-public-keys = " <>) pubKey

-- | The Novavero mark (the novavero.ai favicon), inlined so the page stays
-- a single self-contained response with no external assets.
novaveroLogoSvg :: Text
novaveroLogoSvg =
  "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 64 64\" role=\"img\" aria-label=\"Novavero\">"
    <> "<g fill=\"#0a0f1a\"><rect width=\"64\" height=\"64\" rx=\"14\" ry=\"14\"/></g>"
    <> "<g fill=\"#ffffff\"><path d=\"M12 54L19 54L23 10L16 10Z\"/><path d=\"M16 10L23 10L48 54L41 54Z\"/><path d=\"M41 54L48 54L52 10L45 10Z\"/></g>"
    <> "</svg>"

-- | The same mark, URL-escaped for a data-URI favicon link.
novaveroLogoSvgEscaped :: Text
novaveroLogoSvgEscaped =
  T.concatMap escapeForDataUri novaveroLogoSvg
  where
    escapeForDataUri c = case c of
      '<' -> "%3C"
      '>' -> "%3E"
      '"' -> "%22"
      '#' -> "%23"
      other -> T.singleton other

-- | Content-Type and caching headers for the landing page.  Stats change as
-- paths are added, so it stays briefly cacheable but revalidates.
htmlHeaders :: HTTP.ResponseHeaders
htmlHeaders =
  [ (HTTP.hContentType, "text/html; charset=utf-8"),
    (HTTP.hCacheControl, "public, max-age=300, must-revalidate")
  ]

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
-- A narinfo body is NOT immutable for a fixed key - re-uploading the same store
-- path to add or rotate a signature changes it - so it is cacheable but must
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
