-- | The Nix binary cache HTTP protocol as a WAI 'Network.Wai.Application'.
--
-- An IO-boundary module like "NovaCache.Store": routing, write
-- authentication, request-body limits, and the narinfo
-- validation\/signing pipeline of a cache server.  Deployment identity
-- stays out of the library: the root page is supplied per deployment via
-- 'scRootResponse' ('defaultRootResponse' otherwise), so the published
-- package carries no operator branding.
--
-- Protocol surface:
--
-- @
-- GET  \/nix-cache-info      cache metadata
-- GET  \/\<hash\>.narinfo      narinfo by store-path hash
-- GET  \/nar\/\<file\>          NAR payload (streamed from disk)
-- GET  \/narinfo-hashes      stored-hash listing (authenticated; push-tool plumbing)
-- PUT  \/\<hash\>.narinfo      validated, checked against its stored NAR, signed, stored (authenticated)
-- PUT  \/nar\/\<file\>          streamed to disk under a size cap (authenticated)
-- @
--
-- HEAD is answered wherever GET is: routing treats the two identically
-- and Warp elides the body while keeping the status and headers.
module NovaCache.Server
  ( -- * Configuration
    ServerConfig (..),
    defaultRootResponse,
    newTTLCache,

    -- * Application
    cacheApp,
    onExceptionResponse,

    -- * Body limits
    maxNarInfoBodySize,
    maxNarBodySize,

    -- * Handler pieces (exported for tests)
    requireAuth,
    readBodyLimited,
    withLimitedBody,
    decodeAndValidate,
    narInfoHashMatches,
    signNarInfo,
    renderCacheInfo,

    -- * Stored NAR check
    NarClaim (..),
    StoredNar (..),
    NarRefusal (..),
    narUrlFileName,
    narClaim,
    judgeStoredNar,
    renderNarRefusal,
  )
where

import Control.Exception (IOException, try)
import Data.Bifunctor (first)
import Data.ByteArray (constEq)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString.Lazy as BL
import Data.IORef (newIORef, readIORef, writeIORef)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import GHC.Clock (getMonotonicTime)
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
    responseFile,
    responseLBS,
  )
import NovaCache.Hash (NixHash, formatNixHash, hashFinalize, hashInit, hashUpdate, parseNixHash)
import NovaCache.NarInfo (NarInfo (..), parseNarInfo, renderNarInfo)
import NovaCache.Signing (SecretKey, sign)
import NovaCache.Store
  ( CacheInfo (..),
    FileStore,
    NarWriteResult (..),
    getCacheInfo,
    listNarInfoHashes,
    narFilePath,
    readNarInfo,
    sanitizePath,
    writeNarInfo,
    writeNarStreaming,
  )
import NovaCache.StorePath (defaultStoreDir, parseStorePath, storePathHashString)
import NovaCache.Validate (validateNarInfo)
import System.IO (IOMode (ReadMode), hPutStrLn, stderr, withBinaryFile)

-- ---------------------------------------------------------------------------
-- Constants
-- ---------------------------------------------------------------------------

-- | Maximum narinfo request body - narinfo is small text, so a tight cap.
maxNarInfoBodySize :: Int
maxNarInfoBodySize = 4 * 1024 * 1024 -- 4 MB

-- | Maximum NAR request body.  A real store path's NAR can be very large
-- (toolchains, GHC, LLVM), so this is far higher than the narinfo cap.
-- Uploads stream to disk, so the cap bounds storage abuse, not memory.
maxNarBodySize :: Int
maxNarBodySize = 4 * 1024 * 1024 * 1024 -- 4 GB

-- | Suffix of narinfo request paths (@\/\<hash\>.narinfo@).
narInfoSuffix :: Text
narInfoSuffix = ".narinfo"

-- | First path segment of NAR request paths (@\/nar\/\<file\>@).
narRouteSegment :: Text
narRouteSegment = "nar"

-- | Bytes read per step while hashing a stored NAR.
storedNarReadBytes :: Int
storedNarReadBytes = 128 * 1024

-- ---------------------------------------------------------------------------
-- Configuration
-- ---------------------------------------------------------------------------

-- | Server configuration: the store, the write credential, the signing
-- key, and the deployment's root page.
data ServerConfig = ServerConfig
  { scStore :: !FileStore,
    -- | Write API key.  'Nothing' permits unauthenticated writes (open
    -- mode); arming it with an empty key is the embedder's bug to
    -- prevent - an empty bearer token would then authenticate.
    scApiKey :: !(Maybe ByteString),
    -- | Narinfo signing key.  'Nothing' stores uploads unsigned.
    scSigningKey :: !(Maybe SecretKey),
    -- | Response for @GET \/@, recomputed per request so it can carry
    -- live stats.  Branding belongs to the embedding executable, never
    -- this library.
    scRootResponse :: !(IO Response)
  }

-- | Root response for embedders that do not supply a landing page:
-- enough for a human to identify the service, nothing else.
defaultRootResponse :: IO Response
defaultRootResponse =
  pure (responseLBS HTTP.status200 textHeaders "nova-cache: a Nix binary cache\n")

-- | Memoize an action's result for a time-to-live, in seconds
-- (monotonic clock, so wall-time jumps cannot starve the refresh).
--
-- An unauthenticated route must do bounded work per request: a root
-- response that counts the store, for example, must not scan the whole
-- narinfo directory per hit.  Wrap the expensive read once at startup
-- and hand the returned action to 'scRootResponse'.
--
-- Concurrent requests near expiry may run the action more than once;
-- the last write wins.  Acceptable for idempotent reads, which is the
-- intended use.
newTTLCache :: Double -> IO a -> IO (IO a)
newTTLCache ttlSeconds action = do
  ref <- newIORef Nothing
  pure $ do
    now <- getMonotonicTime
    cached <- readIORef ref
    case cached of
      Just (refreshedAt, held) | now - refreshedAt < ttlSeconds -> pure held
      _ -> do
        fresh <- action
        writeIORef ref (Just (now, fresh))
        pure fresh

-- ---------------------------------------------------------------------------
-- WAI application
-- ---------------------------------------------------------------------------

-- | WAI application implementing the Nix binary cache HTTP protocol.
cacheApp :: ServerConfig -> Application
cacheApp cfg req respond = case (routeMethod, pathInfo req) of
  -- GET / - the deployment's page (protocol lives at the other routes)
  ("GET", []) ->
    respond =<< scRootResponse cfg
  -- GET /nix-cache-info
  ("GET", ["nix-cache-info"]) ->
    respond (responseLBS HTTP.status200 textHeaders (BL.fromStrict (renderCacheInfo (scStore cfg))))
  -- GET /narinfo-hashes - push-tool plumbing: it enumerates the whole
  -- store (something the public protocol deliberately never offers) and
  -- lists a directory per hit, so it is gated behind the write key and
  -- marked uncacheable.
  ("GET", ["narinfo-hashes"]) ->
    requireAuth cfg req respond $ do
      hashes <- listNarInfoHashes (scStore cfg)
      let body = TE.encodeUtf8 (T.unlines hashes)
      respond (responseLBS HTTP.status200 hashListHeaders (BL.fromStrict body))
  -- GET /<hash>.narinfo
  ("GET", [hashNarinfo])
    | Just hashKey <- T.stripSuffix narInfoSuffix hashNarinfo -> do
        result <- readNarInfo (scStore cfg) hashKey
        case result of
          Just content ->
            respond (responseLBS HTTP.status200 narInfoHeaders (BL.fromStrict content))
          Nothing ->
            respond notFound
  -- GET /nar/<file> - handed to the transport layer as a file so the
  -- OS streams it; a multi-GB NAR never transits the Haskell heap.
  ("GET", segments)
    | Just fileName <- narRoute segments -> do
        found <- narFilePath (scStore cfg) fileName
        case found of
          Just path ->
            respond (responseFile HTTP.status200 octetHeaders path Nothing)
          Nothing ->
            respond notFound
  -- PUT /<hash>.narinfo (auth required, validated)
  ("PUT", [hashNarinfo])
    | Just hashKey <- T.stripSuffix narInfoSuffix hashNarinfo ->
        requireAuth cfg req respond $
          withLimitedBody maxNarInfoBodySize req respond (putNarInfo cfg req respond hashKey)
  -- PUT /nar/<file> (auth required, streamed)
  ("PUT", segments)
    | Just fileName <- narRoute segments ->
        requireAuth cfg req respond (putNar cfg req respond fileName)
  -- Fallback
  _ ->
    respond notFound
  where
    -- HEAD is served as GET: the handlers build the same response and
    -- Warp elides the body while keeping status, headers, and the
    -- computed Content-Length.
    routeMethod =
      if requestMethod req == HTTP.methodHead
        then HTTP.methodGet
        else requestMethod req

-- | The file a @\/nar\/\<file\>@ request path names.
narRoute :: [Text] -> Maybe Text
narRoute [segment, fileName] | segment == narRouteSegment = Just fileName
narRoute _ = Nothing

-- | Validate a narinfo upload, check it against the NAR it names, then
-- sign and store it.
putNarInfo :: ServerConfig -> Request -> (Response -> IO ResponseReceived) -> Text -> ByteString -> IO ResponseReceived
putNarInfo cfg req respond hashKey body = case decodeAndValidate body of
  Left err -> do
    logWarn req ("INVALID: " <> T.unpack err)
    respond (badRequest err)
  Right ni
    | not (narInfoHashMatches hashKey ni) -> do
        logWarn req "HASHMISMATCH"
        respond (badRequest "narinfo StorePath hash does not match request")
    | otherwise -> requireStoredNar (scStore cfg) req respond ni $ do
        signedResult <- signNarInfo (scSigningKey cfg) ni
        case signedResult of
          Left err -> do
            logWarn req ("SIGNFAIL: " <> err)
            respond (responseLBS HTTP.status500 textHeaders "signing failed")
          Right signed -> do
            ok <- writeNarInfo (scStore cfg) hashKey signed
            if ok
              then respond (responseLBS HTTP.status200 textHeaders "ok")
              else do
                logWarn req "BADPATH"
                respond (badRequest "invalid path")

-- | Stream a NAR upload into the store.  A declared @Content-Length@ over
-- the cap is refused before reading anything; chunked or lying transfers
-- are cut off by the store's running size check, so memory and storage
-- stay bounded either way.
putNar :: ServerConfig -> Request -> (Response -> IO ResponseReceived) -> Text -> IO ResponseReceived
putNar cfg req respond fileName = case requestBodyLength req of
  KnownLength len
    | len > fromIntegral maxNarBodySize -> overLimit
  _ -> do
    result <- writeNarStreaming (scStore cfg) fileName maxNarBodySize (getRequestBodyChunk req)
    case result of
      NarWriteOk -> respond (responseLBS HTTP.status200 textHeaders "ok")
      NarWriteTooLarge -> overLimit
      NarWriteBadPath -> do
        logWarn req "BADPATH"
        respond (badRequest "invalid path")
  where
    overLimit = do
      logWarn req "OVERLIMIT"
      respond (responseLBS HTTP.status413 textHeaders "request body too large")

-- ---------------------------------------------------------------------------
-- Validation pipeline
-- ---------------------------------------------------------------------------

-- | Decode a raw narinfo body and validate it in a single pure pipeline.
--
-- Composes UTF-8 decoding, narinfo parsing, and field validation. Returns
-- the validated 't:NarInfo' on success, or a user-facing error message.
decodeAndValidate :: ByteString -> Either Text NarInfo
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
-- Stored NAR check
-- ---------------------------------------------------------------------------

-- | What a narinfo declares about the NAR its URL names: the file's name
-- under @nar\/@, and the size and SHA-256 it must have.
data NarClaim = NarClaim
  { ncFileName :: !Text,
    ncFileSize :: !Integer,
    ncFileHash :: !NixHash
  }
  deriving (Eq, Show)

-- | A stored NAR as read: its size in bytes and its SHA-256.
data StoredNar = StoredNar
  { snSize :: !Integer,
    snHash :: !NixHash
  }
  deriving (Eq, Show)

-- | Why a narinfo is refused over the NAR its URL names.
data NarRefusal
  = -- | The URL names no file this cache serves under @nar\/@.
    NarUrlNotServed !Text
  | -- | No FileSize, so a short NAR could not be told from a whole one.
    NarFileSizeUndeclared
  | -- | No FileHash, so a NAR of the right size and the wrong content
    -- could not be told from the right one.
    NarFileHashUndeclared
  | -- | The FileHash does not parse. (raw value, parse error)
    NarFileHashInvalid !Text !String
  | -- | No file is stored under the name.
    NarNotStored !Text
  | -- | The stored file has another size. (name, declared, stored)
    NarSizeMismatch !Text !Integer !Integer
  | -- | The stored file has other content. (name, declared, stored)
    NarHashMismatch !Text !NixHash !NixHash
  deriving (Eq, Show)

-- | The file under @nar\/@ a GET for a narinfo's URL is routed to.
-- Upstream requests a relative URL at the cache URI joined by a slash
-- (@HttpBinaryCacheStore::makeRequest@), and Warp cuts the request
-- target at its first @?@ and splits and percent-decodes the path with
-- 'HTTP.decodePathSegments' into 'pathInfo', which is what
-- 'HTTP.decodePath' does to the same bytes.  An absolute URL is fetched
-- from its own host, and resolves here to segments no route matches.
narUrlFileName :: Text -> Maybe Text
narUrlFileName url = narRoute (fst (HTTP.decodePath ("/" <> TE.encodeUtf8 url)))

-- | Read what a narinfo declares about its NAR.  A writer that omits
-- FileSize or FileHash is refused rather than half-checked: upstream's
-- @BinaryCacheStore::addToStoreCommon@ and nova-nix's push both always
-- send them, and the signature this cache adds does not cover them, so
-- they are the only record of which file the narinfo describes.
narClaim :: NarInfo -> Either NarRefusal NarClaim
narClaim ni = do
  fileName <- maybe (Left (NarUrlNotServed (niUrl ni))) Right (narUrlFileName (niUrl ni) >>= storable)
  fileSize <- maybe (Left NarFileSizeUndeclared) Right (niFileSize ni)
  declaredHash <- maybe (Left NarFileHashUndeclared) Right (niFileHash ni)
  fileHash <- first (NarFileHashInvalid declaredHash) (parseNixHash declaredHash)
  pure NarClaim {ncFileName = fileName, ncFileSize = fileSize, ncFileHash = fileHash}
  where
    -- The router percent-decodes leniently, but every name the store
    -- admits is ASCII, so bytes that are not UTF-8 never name a file.
    storable name = name <$ sanitizePath name

-- | Accept the stored NAR only when it is the file the narinfo declares:
-- present, FileSize bytes long, and hashing to FileHash.
judgeStoredNar :: NarClaim -> Maybe StoredNar -> Either NarRefusal ()
judgeStoredNar claim stored = case stored of
  Nothing -> Left (NarNotStored name)
  Just (StoredNar size digest)
    | size /= ncFileSize claim -> Left (NarSizeMismatch name (ncFileSize claim) size)
    | digest /= ncFileHash claim -> Left (NarHashMismatch name (ncFileHash claim) digest)
    | otherwise -> Right ()
  where
    name = ncFileName claim

-- | The message a refused narinfo upload answers with.
renderNarRefusal :: NarRefusal -> Text
renderNarRefusal refusal = case refusal of
  NarUrlNotServed url ->
    "narinfo URL " <> url <> " does not name a file under " <> narRouteSegment <> "/"
  NarFileSizeUndeclared ->
    "narinfo declares no FileSize to check its NAR against"
  NarFileHashUndeclared ->
    "narinfo declares no FileHash to check its NAR against"
  NarFileHashInvalid raw err ->
    "narinfo FileHash " <> raw <> " does not parse: " <> T.pack err
  NarNotStored name ->
    "NAR " <> narPath name <> " is not stored; upload it before its narinfo"
  NarSizeMismatch name declared stored ->
    "NAR " <> narPath name <> " is " <> showText stored <> " bytes, narinfo FileSize is " <> showText declared
  NarHashMismatch name declared stored ->
    "NAR " <> narPath name <> " hashes to " <> formatNixHash stored <> ", narinfo FileHash is " <> formatNixHash declared
  where
    showText = T.pack . show

-- | The request path, relative to the cache root, that serves a NAR.
narPath :: Text -> Text
narPath name = narRouteSegment <> "/" <> name

-- | Gate a narinfo write on the NAR it names (see 'narClaim' and
-- 'judgeStoredNar').  A refusal is a 400 naming the problem.  A stored
-- NAR that cannot be read is the server's own failure, a 500 like a
-- signing failure, with the exception logged and kept out of the
-- response.
requireStoredNar :: FileStore -> Request -> (Response -> IO ResponseReceived) -> NarInfo -> IO ResponseReceived -> IO ResponseReceived
requireStoredNar store req respond ni action = case narClaim ni of
  Left refusal -> refuse refusal
  Right claim -> do
    stored <- readStoredNar store (ncFileName claim)
    case stored of
      Left err -> do
        logWarn req ("NARREAD: " <> show err)
        respond (responseLBS HTTP.status500 textHeaders (textBody ("NAR " <> narPath (ncFileName claim) <> " could not be read")))
      Right found -> either refuse (const action) (judgeStoredNar claim found)
  where
    refuse refusal = do
      let msg = renderNarRefusal refusal
      logWarn req ("BADNAR: " <> T.unpack msg)
      respond (badRequest msg)

-- | Read a stored NAR through once in constant memory, for its size and
-- SHA-256; 'Nothing' when no file is stored under the name.  The name
-- resolves through 'narFilePath', as @GET \/nar\/\<file\>@ does.
--
-- An upload of the same name while this reads is renamed into place,
-- and on POSIX the open handle keeps reading the file it opened, so
-- the result describes one whole upload or the other, never a mix.
readStoredNar :: FileStore -> Text -> IO (Either IOException (Maybe StoredNar))
readStoredNar store fileName = try (traverse measure =<< narFilePath store fileName)
  where
    measure path = withBinaryFile path ReadMode (consume 0 hashInit)
    consume !size !ctx handle = do
      chunk <- BS.hGetSome handle storedNarReadBytes
      if BS.null chunk
        then pure StoredNar {snSize = size, snHash = hashFinalize ctx}
        else consume (size + fromIntegral (BS.length chunk)) (hashUpdate ctx chunk) handle

-- ---------------------------------------------------------------------------
-- Request body limiting
-- ---------------------------------------------------------------------------

-- | Read the request body, rejecting payloads over the given limit.
--
-- A declared @Content-Length@ over the limit is rejected up front; otherwise
-- (including unsized/chunked transfers) the body is read in bounded chunks with
-- a running size check that aborts before exceeding the limit, so memory stays
-- bounded regardless of the declared length.
readBodyLimited :: Int -> Request -> IO (Maybe ByteString)
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
withLimitedBody :: Int -> Request -> (Response -> IO ResponseReceived) -> (ByteString -> IO ResponseReceived) -> IO ResponseReceived
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
-- If no key is configured, the action is permitted (open mode).
-- Otherwise the request must carry @Authorization: Bearer \<key\>@.
-- Uses constant-time comparison to prevent timing attacks.
requireAuth :: ServerConfig -> Request -> (Response -> IO ResponseReceived) -> IO ResponseReceived -> IO ResponseReceived
requireAuth cfg req respond action = case scApiKey cfg of
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

-- | Sign a validated 't:NarInfo' if a signing key is configured.
--
-- With no key, returns the unsigned rendering (intentional - the operator
-- configured none).  With a key, FAILS CLOSED: a signing error returns 'Left'
-- so the handler refuses the write rather than persisting an unsigned narinfo
-- on a cache that is supposed to sign.
signNarInfo :: Maybe SecretKey -> NarInfo -> IO (Either String ByteString)
signNarInfo Nothing ni = pure (Right (renderNarInfoBytes ni))
signNarInfo (Just sk) ni = case sign sk ni of
  Left err -> do
    hPutStrLn stderr ("ERROR: signNarInfo: sign failed: " ++ err)
    pure (Left err)
  Right sig ->
    let signed = ni {niSigs = niSigs ni ++ [sig]}
     in pure (Right (renderNarInfoBytes signed))

-- | Render a 't:NarInfo' to its UTF-8 encoded wire format.
renderNarInfoBytes :: NarInfo -> ByteString
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
renderCacheInfo :: FileStore -> ByteString
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
badRequest msg = responseLBS HTTP.status400 textHeaders (textBody msg)

-- | A text response body.
textBody :: Text -> BL.ByteString
textBody = BL.fromStrict . TE.encodeUtf8

-- | Map any uncaught handler exception to a generic 500, so internal error
-- detail (filesystem paths, exception text) is never leaked to clients.
onExceptionResponse :: e -> Response
onExceptionResponse _ = responseLBS HTTP.status500 textHeaders "internal server error"

-- | Content-Type: text/plain headers.
textHeaders :: HTTP.ResponseHeaders
textHeaders = [(HTTP.hContentType, "text/plain")]

-- | Headers for the authenticated hash listing: push-tool plumbing that
-- changes with every upload, so intermediaries must never cache it.
hashListHeaders :: HTTP.ResponseHeaders
hashListHeaders =
  [ (HTTP.hContentType, "text/plain"),
    (HTTP.hCacheControl, "no-store")
  ]

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
