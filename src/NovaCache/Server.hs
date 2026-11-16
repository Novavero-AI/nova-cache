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
--
-- POST \/nar\/\<file\>\/uploads              begin a multipart upload (authenticated)
-- PUT  \/nar\/\<file\>\/uploads\/\<id\>\/\<n\>     part n, streamed to disk under the same cap (authenticated)
-- POST \/nar\/\<file\>\/uploads\/\<id\>         join the parts into nar\/\<file\> (authenticated)
-- @
--
-- HEAD is answered wherever GET is: routing treats the two identically
-- and Warp elides the body while keeping the status and headers.
--
-- A multipart upload carries a NAR past a proxy that refuses large
-- request bodies.  Its parts are staged outside @nar\/@ (see
-- "NovaCache.Store"), and the NAR appears there only when the request
-- that completes the upload joins them.
module NovaCache.Server
  ( -- * Configuration
    ServerConfig (..),
    defaultRootResponse,
    htmlRootResponse,
    newTTLCache,

    -- * Application
    cacheApp,
    onExceptionResponse,

    -- * Body limits
    maxNarInfoBodySize,
    maxNarBodySize,
    maxUploadTotalsBodySize,

    -- * Multipart upload
    parseUploadTotals,
    renderUploadTotals,

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
import qualified Data.Text.Read as TR
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
    CompletionResult (..),
    FileStore,
    NarWriteResult (..),
    PartWriteResult (..),
    UploadId,
    UploadTotals (..),
    beginUpload,
    completeUpload,
    getCacheInfo,
    listNarInfoHashes,
    maxUploadParts,
    narFilePath,
    parsePartNumber,
    parseUploadId,
    readNarInfo,
    renderPartNumber,
    renderUploadId,
    sanitizePath,
    writeNarInfo,
    writeNarStreaming,
    writeUploadPart,
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

-- | Maximum body of the request that completes a multipart upload: two
-- short lines (see 'renderUploadTotals').
maxUploadTotalsBodySize :: Int
maxUploadTotalsBodySize = 1024

-- | Suffix of narinfo request paths (@\/\<hash\>.narinfo@).
narInfoSuffix :: Text
narInfoSuffix = ".narinfo"

-- | First path segment of NAR request paths (@\/nar\/\<file\>@).
narRouteSegment :: Text
narRouteSegment = "nar"

-- | Path segment under @\/nar\/\<file\>@ that holds the file's multipart
-- uploads.
uploadsRouteSegment :: Text
uploadsRouteSegment = "uploads"

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

-- | Root response serving a deployment's own HTML page, such as a page
-- about the cache, as the embedder read it.
htmlRootResponse :: ByteString -> IO Response
htmlRootResponse page = pure (responseLBS HTTP.status200 htmlHeaders (BL.fromStrict page))

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
  -- /nar/<file>/uploads... - multipart upload (auth required)
  (method, segments)
    | Just route <- uploadRoute segments ->
        uploadRequest cfg req respond method route
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
              then respond okResponse
              else badPath req respond

-- | Stream a NAR upload into the store.  A declared @Content-Length@ over
-- the cap is refused before reading anything; chunked or lying transfers
-- are cut off by the store's running size check, so memory and storage
-- stay bounded either way.
putNar :: ServerConfig -> Request -> (Response -> IO ResponseReceived) -> Text -> IO ResponseReceived
putNar cfg req respond fileName = refuseDeclaredOver maxNarBodySize req respond $ do
  result <- writeNarStreaming (scStore cfg) fileName maxNarBodySize (getRequestBodyChunk req)
  case result of
    NarWriteOk -> respond okResponse
    NarWriteTooLarge -> overLimit req respond
    NarWriteBadPath -> badPath req respond

-- ---------------------------------------------------------------------------
-- Multipart upload
-- ---------------------------------------------------------------------------

-- | A request path under @\/nar\/\<file\>\/uploads@.
data UploadRoute
  = -- | @\/nar\/\<file\>\/uploads@, where an upload of the file begins.
    UploadsOf !Text
  | -- | @\/nar\/\<file\>\/uploads\/\<id\>@, one upload. (file, id)
    UploadOf !Text !Text
  | -- | @\/nar\/\<file\>\/uploads\/\<id\>\/\<n\>@, one part of it.
    -- (file, id, part number)
    PartOf !Text !Text !Text

-- | The upload request a path names.  A NAR's name holds no @\/@, so no
-- such path names a file under @nar\/@.
uploadRoute :: [Text] -> Maybe UploadRoute
uploadRoute (segment : fileName : uploads : rest)
  | segment == narRouteSegment && uploads == uploadsRouteSegment = case rest of
      [] -> Just (UploadsOf fileName)
      [uploadId] -> Just (UploadOf fileName uploadId)
      [uploadId, part] -> Just (PartOf fileName uploadId part)
      _ -> Nothing
uploadRoute _ = Nothing

-- | Answer a request under @\/nar\/\<file\>\/uploads@, each one
-- authenticated as the other writes are.
uploadRequest :: ServerConfig -> Request -> (Response -> IO ResponseReceived) -> HTTP.Method -> UploadRoute -> IO ResponseReceived
uploadRequest cfg req respond method route = case (method, route) of
  ("POST", UploadsOf fileName) ->
    authed (beginNarUpload cfg req respond fileName)
  ("PUT", PartOf fileName rawId rawPart) ->
    authed (withUpload req respond fileName rawId (putNarPart cfg req respond fileName rawPart))
  ("POST", UploadOf fileName rawId) ->
    authed (withUpload req respond fileName rawId (completeNarUpload cfg req respond fileName))
  _ -> respond notFound
  where
    authed = requireAuth cfg req respond

-- | Run an action on the upload a request names: 400 when the NAR's name
-- is not one the store admits, 404 when the id is not one the server
-- issues.
withUpload :: Request -> (Response -> IO ResponseReceived) -> Text -> Text -> (UploadId -> IO ResponseReceived) -> IO ResponseReceived
withUpload req respond fileName rawId action = case (sanitizePath fileName, parseUploadId rawId) of
  (Nothing, _) -> badPath req respond
  (Just _, Nothing) -> unknownUpload req respond fileName rawId
  (Just _, Just uid) -> action uid

-- | Begin a multipart upload: 201, with the upload's id as the body and
-- its path in @Location@.  The path is relative to the request's, so it
-- stays right when the cache is served under a path prefix.
beginNarUpload :: ServerConfig -> Request -> (Response -> IO ResponseReceived) -> Text -> IO ResponseReceived
beginNarUpload cfg req respond fileName = do
  begun <- beginUpload (scStore cfg) fileName
  case begun of
    Nothing -> badPath req respond
    Just uid ->
      let location = TE.encodeUtf8 (uploadsRouteSegment <> "/" <> renderUploadId uid)
       in respond
            ( responseLBS
                HTTP.status201
                ((HTTP.hLocation, location) : textHeaders)
                (textBody (renderUploadId uid <> "\n"))
            )

-- | Stream one part of an upload to disk.  A declared @Content-Length@
-- over the NAR cap is refused before anything is read, as for a whole
-- NAR; otherwise the store's running check holds the part, with the
-- parts the upload holds, to the same cap.
putNarPart :: ServerConfig -> Request -> (Response -> IO ResponseReceived) -> Text -> Text -> UploadId -> IO ResponseReceived
putNarPart cfg req respond fileName rawPart uid = case parsePartNumber rawPart of
  Nothing -> do
    logWarn req "BADPART"
    respond (badRequest ("part number must be a whole number from 1 to " <> showText maxUploadParts))
  Just part -> refuseDeclaredOver maxNarBodySize req respond $ do
    result <- writeUploadPart (scStore cfg) fileName uid part maxNarBodySize (getRequestBodyChunk req)
    case result of
      PartWritten -> respond okResponse
      PartTooLarge -> overLimit req respond
      PartOutOfOrder held ->
        refuseConflict
          req
          respond
          ( "upload of "
              <> narPath fileName
              <> " holds "
              <> countedParts held
              <> ", so the next is part "
              <> showText (held + 1)
              <> ", not part "
              <> renderPartNumber part
          )
      PartUploadUnknown -> unknownUpload req respond fileName (renderUploadId uid)
      PartBadPath -> badPath req respond

-- | Complete an upload from the totals its body declares.
completeNarUpload :: ServerConfig -> Request -> (Response -> IO ResponseReceived) -> Text -> UploadId -> IO ResponseReceived
completeNarUpload cfg req respond fileName uid =
  withLimitedBody maxUploadTotalsBodySize req respond $ \body -> case parseUploadTotals body of
    Left err -> do
      logWarn req ("BADTOTALS: " <> T.unpack err)
      respond (badRequest err)
    Right totals -> do
      result <- completeUpload (scStore cfg) fileName uid maxNarBodySize totals
      case result of
        UploadCompleted -> respond okResponse
        UploadCompletedStagingKept err -> do
          logWarn req ("STAGINGKEPT: " <> show err)
          respond okResponse
        CompletionPartsMismatch declared held ->
          refuseConflict req respond ("upload of " <> narPath fileName <> " holds " <> countedParts held <> ", Parts is " <> showText declared)
        CompletionSizeMismatch declared joined ->
          refuseConflict req respond ("upload of " <> narPath fileName <> " joins to " <> showText joined <> " bytes, FileSize is " <> showText declared)
        CompletionTooLarge declared -> do
          logWarn req "OVERLIMIT"
          respond
            ( responseLBS
                HTTP.status413
                textHeaders
                (textBody ("FileSize " <> showText declared <> " is over the " <> showText maxNarBodySize <> " bytes a NAR may hold"))
            )
        CompletionUploadUnknown -> unknownUpload req respond fileName (renderUploadId uid)
        CompletionBadPath -> badPath req respond

-- | A count of parts with its noun.
countedParts :: Int -> Text
countedParts 1 = "1 part"
countedParts n = showText n <> " parts"

-- | Keys of the body that completes an upload.
partsKey, fileSizeKey :: Text
partsKey = "Parts"
fileSizeKey = "FileSize"

-- | Separates a key from its value, as in a narinfo.
fieldSeparator :: Text
fieldSeparator = ": "

-- | Digits in a declared size: at most a uint64's 20, as for a narinfo's
-- FileSize.  The length is bounded before the parse, so an overlong
-- number costs nothing to refuse; a size past 'maxNarBodySize' is
-- refused when the upload is completed.
maxByteCountDigits :: Int
maxByteCountDigits = 20

-- | The body that completes an upload: how many parts it holds and how
-- many bytes they join to, as @Parts@ and @FileSize@ lines in narinfo's
-- @Key: value@ form.
renderUploadTotals :: UploadTotals -> ByteString
renderUploadTotals totals =
  TE.encodeUtf8 $
    T.unlines
      [ partsKey <> fieldSeparator <> renderPartNumber (utParts totals),
        fileSizeKey <> fieldSeparator <> showText (utFileSize totals)
      ]

-- | Read the body that completes an upload: a @Parts@ line and a
-- @FileSize@ line, in either order, each once, each value in canonical
-- decimal.  Any other line is refused rather than skipped, so a field a
-- client means to have checked is never silently ignored.
parseUploadTotals :: ByteString -> Either Text UploadTotals
parseUploadTotals body = do
  text <- first (const "completion body is not valid UTF-8") (TE.decodeUtf8' body)
  fields <- traverse splitField (T.lines text)
  parts <- field partsKey fields >>= orRefuse ("Parts must be a whole number from 1 to " <> showText maxUploadParts) . parsePartNumber
  size <- field fileSizeKey fields >>= orRefuse "FileSize must be a whole number of bytes" . parseByteCount
  pure UploadTotals {utParts = parts, utFileSize = size}
  where
    splitField line = case T.stripPrefix fieldSeparator <$> T.breakOn fieldSeparator line of
      (key, Just value)
        | key `elem` [partsKey, fileSizeKey] -> Right (key, value)
        | otherwise -> Left ("completion body has an unknown field " <> key)
      (_, Nothing) -> Left ("completion body line is not Key: value: " <> line)
    field key fields = case [value | (named, value) <- fields, named == key] of
      [value] -> Right value
      [] -> Left ("completion body has no " <> key <> " line")
      _ -> Left ("completion body has more than one " <> key <> " line")
    orRefuse msg = maybe (Left msg) Right

-- | A byte count in canonical decimal: digits only, with no sign and no
-- leading zero.
parseByteCount :: Text -> Maybe Integer
parseByteCount txt
  | T.length txt > maxByteCountDigits = Nothing
  | otherwise = case TR.decimal txt of
      Right (n, _) | showText n == txt -> Just n
      _ -> Nothing

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
  maybe (overLimit req respond) action bodyResult

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

-- | 200, the answer to every write that succeeds.
okResponse :: Response
okResponse = responseLBS HTTP.status200 textHeaders "ok"

-- | Refuse a request naming a file the store cannot hold.
badPath :: Request -> (Response -> IO ResponseReceived) -> IO ResponseReceived
badPath req respond = do
  logWarn req "BADPATH"
  respond (badRequest "invalid path")

-- | Refuse a request body over its cap.
overLimit :: Request -> (Response -> IO ResponseReceived) -> IO ResponseReceived
overLimit req respond = do
  logWarn req "OVERLIMIT"
  respond (responseLBS HTTP.status413 textHeaders "request body too large")

-- | Refuse a body whose declared @Content-Length@ is over the cap before
-- reading any of it, or run the action.
refuseDeclaredOver :: Int -> Request -> (Response -> IO ResponseReceived) -> IO ResponseReceived -> IO ResponseReceived
refuseDeclaredOver limit req respond action = case requestBodyLength req of
  KnownLength len
    | len > fromIntegral limit -> overLimit req respond
  _ -> action

-- | Refuse a request naming no staged upload of the file: one never
-- begun, already completed, or removed by @reclaim-nars@.
unknownUpload :: Request -> (Response -> IO ResponseReceived) -> Text -> Text -> IO ResponseReceived
unknownUpload req respond fileName rawId = do
  logWarn req "NOUPLOAD"
  respond (responseLBS HTTP.status404 textHeaders (textBody ("no upload " <> rawId <> " of " <> narPath fileName)))

-- | Refuse a well-formed request that disagrees with the upload as
-- stored, with 409: the client can resolve it (send the missing part,
-- declare what it sent) and try again.
refuseConflict :: Request -> (Response -> IO ResponseReceived) -> Text -> IO ResponseReceived
refuseConflict req respond msg = do
  logWarn req ("CONFLICT: " <> T.unpack msg)
  respond (responseLBS HTTP.status409 textHeaders (textBody msg))

-- | A value shown as text.
showText :: (Show a) => a -> Text
showText = T.pack . show

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

htmlHeaders :: HTTP.ResponseHeaders
htmlHeaders = [(HTTP.hContentType, "text/html; charset=utf-8")]

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
