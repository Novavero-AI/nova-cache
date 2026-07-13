module Main (main) where

import Control.Applicative ((<|>))
import Data.Bifunctor (first)
import qualified Data.ByteString as BS
import Data.Maybe (fromMaybe, isJust)
import Data.String (fromString)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import LandingPage (landingResponse)
import qualified Network.Wai.Handler.Warp as Warp
import Network.Wai.Middleware.RequestLogger (logStdout)
import NovaCache.Server (ServerConfig (..), cacheApp, onExceptionResponse)
import NovaCache.Signing (SecretKey, normalizeKeyText, parseSecretKey, renderPublicKey, toPublicKey)
import NovaCache.Store (newFileStore)
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

-- | Default bind host.  @*@ binds every interface - the server's
-- historical behavior, kept as the default so existing deployments do
-- not silently rebind; a deployment opts into loopback itself via
-- @--host@ or @HOST@.
defaultBindHost :: String
defaultBindHost = "*"

-- | Default store directory.
defaultStoreRoot :: FilePath
defaultStoreRoot = "./nix-cache"

-- | Environment variable for the server port.
portEnvVar :: String
portEnvVar = "PORT"

-- | Environment variable for the bind host.
hostEnvVar :: String
hostEnvVar = "HOST"

-- | Environment variable for the store root directory.
storeEnvVar :: String
storeEnvVar = "NIX_CACHE_DIR"

-- | Environment variable for the write API key.
apiKeyEnvVar :: String
apiKeyEnvVar = "CACHE_API_KEY"

-- | Environment variable for the signing key file path.
signingKeyEnvVar :: String
signingKeyEnvVar = "SIGNING_KEY_FILE"

-- | Environment variable to disable request logging.
requestLogEnvVar :: String
requestLogEnvVar = "LOG_REQUESTS"

-- ---------------------------------------------------------------------------
-- Main
-- ---------------------------------------------------------------------------

main :: IO ()
main = do
  args <- getArgs
  portEnv <- lookupEnv portEnvVar
  hostEnv <- lookupEnv hostEnvVar
  storeEnv <- lookupEnv storeEnvVar
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
      bindHost = fromMaybe defaultBindHost (argValue "--host" <|> hostEnv)
      storeRoot = fromMaybe (fromMaybe defaultStoreRoot storeEnv) (argValue "--store")
      allowOpenWrites = "--allow-open-writes" `elem` args

  store <- newFileStore storeRoot
  apiKey <- loadApiKey apiKeyEnv
  sigKey <- loadSigningKey sigKeyPath
  pubKey <- derivePublicKeyLine sigKey

  let cfg =
        ServerConfig
          { scStore = store,
            scApiKey = apiKey,
            scSigningKey = sigKey,
            scRootResponse = landingResponse store (isJust sigKey) pubKey
          }

  let logRequests = logRequestsEnv /= Just "0"
      requestLogger = if logRequests then logStdout else id

  putStrLn ("nova-cache-server listening on " ++ bindHost ++ ":" ++ show port)
  putStrLn ("store root: " ++ storeRoot)
  putStrLn ("signing: " ++ maybe "disabled" (const "enabled") sigKey)
  mapM_ (\k -> putStrLn ("public key: " ++ T.unpack k)) pubKey
  putStrLn ("write auth: " ++ maybe "disabled (open writes!)" (const "enabled") apiKey)
  putStrLn ("request logging: " ++ if logRequests then "enabled" else "disabled (LOG_REQUESTS=0)")

  case apiKey of
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
        Warp.setHost (fromString bindHost) $
          Warp.setPort port $
            Warp.setOnExceptionResponse onExceptionResponse Warp.defaultSettings
  Warp.runSettings settings (requestLogger (cacheApp cfg))

-- ---------------------------------------------------------------------------
-- Credential loading
-- ---------------------------------------------------------------------------

-- | Normalize and validate the write API key.  A key that normalizes to
-- empty (BOM or whitespace only - the classic copy-paste artifact) would
-- arm the auth gate with an empty secret that an empty bearer token
-- matches, so it is a startup error, never an armed guard.
loadApiKey :: Maybe String -> IO (Maybe BS.ByteString)
loadApiKey Nothing = pure Nothing
loadApiKey (Just raw)
  | T.null normalized = do
      hPutStrLn stderr $
        "FATAL: "
          ++ apiKeyEnvVar
          ++ " is set but empty after normalization - refusing to arm write auth with an empty key. "
          ++ "Set a real key, or unset it and pass --allow-open-writes to run open."
      exitFailure
  | otherwise = pure (Just (TE.encodeUtf8 normalized))
  where
    normalized = normalizeKeyText (T.pack raw)

-- | Load a signing key from a file, if configured.  A configured key that
-- fails to load is FATAL: falling back to unsigned would persist narinfos
-- no trust anchor can verify (the same fail-closed policy as signing).
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
