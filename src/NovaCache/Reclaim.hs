-- | Reclaiming what a file store holds and nothing needs: the NARs no
-- narinfo names, and the multipart uploads begun there and abandoned.
--
-- A client uploads a path's NAR before its narinfo (upstream's
-- @BinaryCacheStore::addToStoreCommon@ does, and so does nova-nix's
-- push), so a NAR whose narinfo is refused, or never sent because the
-- push died, stays under @nar\/@ with nothing pointing at it, as does a
-- NAR whose narinfo was removed or replaced by one naming another file.
-- Which NARs those are is decided purely ('planStore' over a
-- 't:StoreScan'); 'scanStore' is the IO edge that reads the store, and
-- 'reclaim' removes what the plan selects.
--
-- 'reclaim' holds the store's gate alone ('NovaCache.Store.withRemoval')
-- from its scan through its last removal, and a narinfo upload holds it
-- from the check of its NAR through its write, as does each rename into
-- @nar\/@ for the rename.  So a narinfo stored before a run keeps its
-- NAR, one sent during a run is checked after it, and a NAR that arrives
-- during a run lands after it.  Those uploads wait while the run reads
-- the store, which takes longer the more narinfos it holds.  A client that skipped uploading a NAR
-- because the cache held it, as upstream's @nix copy@ does, can still
-- find it removed when its narinfo arrives: the narinfo is refused and
-- stores nothing, and the client's next attempt uploads the NAR.
--
-- Three rules keep a run from removing a NAR the cache still needs.  A
-- NAR younger than the minimum age is never eligible, because a NAR is
-- unreferenced legitimately until its push sends the narinfo.  A narinfo
-- that cannot be read, parsed, or resolved to a file under @nar\/@
-- blocks the whole run: the NAR it names is unknown, so no NAR can be
-- shown to be unreferenced.  And a store holding NARs and no narinfo at
-- all blocks it too ('NoNarInfos').
--
-- A multipart upload begun and never completed leaves its parts under
-- @uploads\/@ ("NovaCache.Store").  No narinfo can reference a staged
-- upload, so the minimum age alone decides ('selectAbandoned'), counted
-- from the upload's last activity.
module NovaCache.Reclaim
  ( -- * Narinfo references
    NarInfoTarget (..),
    narInfoTarget,
    narInfoNarName,
    Unresolved (..),
    collectReferences,

    -- * Selection
    defaultMinimumAge,
    ReclaimPlan (..),
    selectUnreferenced,
    ReclaimBlocked (..),
    planReclaim,
    UploadPlan (..),
    selectAbandoned,
    StorePlan (..),
    planStore,

    -- * Scanning a store
    StoreScan (..),
    scanStore,

    -- * Reclaiming
    listReclaimable,
    Reclaimed (..),
    reclaim,
  )
where

import Control.Exception (IOException, try)
import Data.Bifunctor (first)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.List (partition)
import Data.List.NonEmpty (NonEmpty, nonEmpty)
import Data.Set (Set)
import qualified Data.Set as Set
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time.Clock (NominalDiffTime, UTCTime, diffUTCTime, nominalDay)
import NovaCache.NarInfo (NarInfo (..), parseNarInfo)
import NovaCache.Store
  ( FileStore,
    NarFile (..),
    NarRemoveResult,
    StagedUpload (..),
    UploadRemoveResult,
    listNarFiles,
    listNarInfoFiles,
    listStagedUploads,
    removeNar,
    removeUpload,
    sanitizePath,
    withRemoval,
    withoutRemoval,
  )
import System.IO.Error (ioeGetErrorString)

-- ---------------------------------------------------------------------------
-- Narinfo references
-- ---------------------------------------------------------------------------

-- | The URL prefix under which the server serves NARs
-- (@GET \/nar\/\<file\>@), and the one every writer puts in a narinfo.
narUrlPrefix :: Text
narUrlPrefix = "nar/"

-- | What one stored narinfo says about the NARs.
data NarInfoTarget
  = -- | It names this file under @nar\/@.
    NamesNar !Text
  | -- | It could not be read, decoded, parsed or resolved, for this
    -- reason, so the NAR it names is unknown.
    Unresolvable !String
  deriving (Eq, Show)

-- | Resolve a narinfo file's contents, or the error reading them.
narInfoTarget :: Either IOException ByteString -> NarInfoTarget
narInfoTarget contents = either Unresolvable NamesNar $ do
  bytes <- first ioeGetErrorString contents
  text <- first (const "not valid UTF-8") (TE.decodeUtf8' bytes)
  parseNarInfo text >>= narInfoNarName

-- | The file under @nar\/@ a narinfo names.  The URL is authoritative:
-- upstream fetches @info->url@ as written (appended to the cache URI,
-- or verbatim when absolute) and never rebuilds a name from FileHash
-- and Compression, so the compression suffix is whatever the URL
-- carries.  Only the spelling writers produce resolves, @nar\/\<name\>@
-- with a name 'sanitizePath' admits.  Any other URL (absolute, with a
-- percent-escape, a dot segment or a query) might still reach a file
-- here through the server's routing, so it is unresolvable rather than
-- read as naming nothing.
narInfoNarName :: NarInfo -> Either String Text
narInfoNarName ni = case T.stripPrefix narUrlPrefix (niUrl ni) of
  -- A copy, so the reference set holds the name and not the whole
  -- narinfo text it was sliced from.
  Just name | Just _ <- sanitizePath name -> Right (T.copy name)
  _ -> Left ("URL " ++ show (niUrl ni) ++ " does not name a file under " ++ T.unpack narUrlPrefix)

-- | A narinfo that blocks the run, and why.
data Unresolved = Unresolved
  { unresolvedPath :: !FilePath,
    unresolvedReason :: !String
  }
  deriving (Eq, Show)

-- | The NARs the narinfos name, or every narinfo whose NAR is unknown.
-- One unknown is enough to block: skipping it would leave the NAR it
-- names looking unreferenced.
collectReferences :: [(FilePath, NarInfoTarget)] -> Either (NonEmpty Unresolved) (Set Text)
collectReferences narInfos =
  case nonEmpty [Unresolved path reason | (path, Unresolvable reason) <- narInfos] of
    Just unresolved -> Left unresolved
    Nothing -> Right (Set.fromList [name | (_, NamesNar name) <- narInfos])

-- ---------------------------------------------------------------------------
-- Selection
-- ---------------------------------------------------------------------------

-- | How old an unreferenced NAR must be before it is eligible: two
-- weeks.
--
-- A NAR stays unreferenced for the rest of the push that uploaded it,
-- and nothing bounds that: nova-nix uploads every NAR of a closure
-- before the first narinfo, with no response timeout.  Removing one
-- early has its narinfo refused when it comes, which fails that push or
-- costs it the upload again, while waiting costs only disk.  git guards
-- the same race, between gc and a writer that has stored an object but
-- not yet referenced it, with the same two weeks (@gc.pruneExpire@).
defaultMinimumAge :: NominalDiffTime
defaultMinimumAge = 14 * nominalDay

-- | The unreferenced NARs of a store, split by the minimum age.
data ReclaimPlan = ReclaimPlan
  { -- | Old enough to delete.
    rpEligible :: ![NarFile],
    -- | Younger than the minimum age: a push may yet reference them.
    rpTooYoung :: ![NarFile]
  }
  deriving (Eq, Show)

-- | Split the NARs no reference names by their age at the given time,
-- counted from the modification time.  A NAR uploaded again is renamed
-- over the old file, which restarts its age.
selectUnreferenced :: NominalDiffTime -> UTCTime -> Set Text -> [NarFile] -> ReclaimPlan
selectUnreferenced minimumAge now references nars =
  ReclaimPlan {rpEligible = old, rpTooYoung = young}
  where
    (old, young) = partitionByAge nfModified minimumAge now (filter unreferenced nars)
    unreferenced nar = Set.notMember (nfName nar) references

-- | Split by age at the given time, counted from a modification time:
-- those at least the minimum age old, then the younger.
partitionByAge :: (a -> UTCTime) -> NominalDiffTime -> UTCTime -> [a] -> ([a], [a])
partitionByAge modified minimumAge now =
  partition (\item -> diffUTCTime now (modified item) >= minimumAge)

-- | Why a run cannot be planned.
data ReclaimBlocked
  = -- | These narinfos name NARs that are unknown.
    UnresolvedNarInfos !(NonEmpty Unresolved)
  | -- | The store holds NARs and no narinfo.  A store whose every NAR is
    -- unreferenced looks like this, and so does one that lost its
    -- @narinfo\/@ directory, which the server recreates empty when it
    -- starts.  Deleting is right for the first and destroys the second,
    -- and a scan cannot tell them apart.
    NoNarInfos
  deriving (Eq, Show)

-- | Plan a run's NARs from a scan: the unreferenced ones by age, or why
-- the run is blocked.
planReclaim :: NominalDiffTime -> StoreScan -> Either ReclaimBlocked ReclaimPlan
planReclaim minimumAge scan
  | null (scanNarInfos scan) && not (null (scanNars scan)) = Left NoNarInfos
  | otherwise = do
      references <- first UnresolvedNarInfos (collectReferences (scanNarInfos scan))
      pure (selectUnreferenced minimumAge (scanTime scan) references (scanNars scan))

-- | The staged uploads of a store, split by the minimum age.
data UploadPlan = UploadPlan
  { -- | Idle for at least the minimum age: abandoned.
    upEligible :: ![StagedUpload],
    -- | Active within the minimum age: a push may yet complete them.
    upTooYoung :: ![StagedUpload]
  }
  deriving (Eq, Show)

-- | Split staged uploads by the time since their last activity, by the
-- same minimum age as unreferenced NARs.  A staged upload holds only
-- parts, which nothing serves and no narinfo names, so removing one
-- never leaves a narinfo without its NAR: a push that resumes an upload
-- removed under it is refused and begins a new one.  The age is there
-- for that push, which is the only thing the removal can hurt.
selectAbandoned :: NominalDiffTime -> UTCTime -> [StagedUpload] -> UploadPlan
selectAbandoned minimumAge now uploads =
  UploadPlan {upEligible = old, upTooYoung = young}
  where
    (old, young) = partitionByAge suModified minimumAge now uploads

-- | What a run removes and keeps: a store's NARs and its staged uploads.
data StorePlan = StorePlan
  { spNars :: !ReclaimPlan,
    spUploads :: !UploadPlan
  }
  deriving (Eq, Show)

-- | Plan a run from a scan: its NARs as 'planReclaim' splits them and its
-- staged uploads as 'selectAbandoned' does, or why the run is blocked.
-- A blocked run removes no upload either.
planStore :: NominalDiffTime -> StoreScan -> Either ReclaimBlocked StorePlan
planStore minimumAge scan = do
  nars <- planReclaim minimumAge scan
  pure
    StorePlan
      { spNars = nars,
        spUploads = selectAbandoned minimumAge (scanTime scan) (scanStagedUploads scan)
      }

-- ---------------------------------------------------------------------------
-- Scanning a store
-- ---------------------------------------------------------------------------

-- | What a scan read: each narinfo's target, each NAR, each staged
-- upload, and the time once they were listed.
data StoreScan = StoreScan
  { scanNarInfos :: ![(FilePath, NarInfoTarget)],
    scanNars :: ![NarFile],
    scanStagedUploads :: ![StagedUpload],
    scanTime :: !UTCTime
  }
  deriving (Eq, Show)

-- | Read a store for 'planStore', with the time from @clock@, read after
-- every listing so nothing a listing saw is in its future.  A directory
-- that cannot be listed, or a NAR that cannot be stat'd, fails the scan
-- with its 'IOException'; an unreadable narinfo is recorded as
-- 'Unresolvable'.  The scan takes no gate: its caller holds one, as
-- 'listReclaimable' and 'reclaim' do, so nothing is removed while it
-- reads.
--
-- The narinfos are read before the NARs are listed, the order git's
-- prune uses (reachability first, then each object's age): in a scan
-- that runs alongside uploads, as 'listReclaimable' runs one, a NAR
-- uploaded again while the narinfos are read shows its new modification
-- time.
scanStore :: FileStore -> IO UTCTime -> IO StoreScan
scanStore store clock = do
  narInfos <- traverse readTarget =<< listNarInfoFiles store
  nars <- listNarFiles store
  uploads <- listStagedUploads store
  now <- clock
  pure
    StoreScan
      { scanNarInfos = narInfos,
        scanNars = nars,
        scanStagedUploads = uploads,
        scanTime = now
      }
  where
    -- Forced per file, so each narinfo's bytes are garbage once its
    -- target is known instead of held until the scan is planned.
    readTarget path = do
      contents <- try (BS.readFile path)
      let !target = narInfoTarget contents
      pure (path, target)

-- ---------------------------------------------------------------------------
-- Reclaiming
-- ---------------------------------------------------------------------------

-- | What 'reclaim' would remove now, and what it would keep for its age,
-- removing nothing.  The scan holds the gate shared, so uploads go on
-- while it reads and no removal does.
listReclaimable :: FileStore -> NominalDiffTime -> IO UTCTime -> IO (Either ReclaimBlocked StorePlan)
listReclaimable store minimumAge clock =
  withoutRemoval store (planStore minimumAge <$> scanStore store clock)

-- | What a run removed: its plan, and the outcome of each removal.
data Reclaimed = Reclaimed
  { rdPlan :: !StorePlan,
    rdNars :: ![(NarFile, NarRemoveResult)],
    rdUploads :: ![(StagedUpload, UploadRemoveResult)]
  }
  deriving (Eq, Show)

-- | Scan the store, plan, and remove every eligible NAR and abandoned
-- upload, holding the gate alone throughout, or say why the run is
-- blocked and remove nothing.  A scan that fails throws its
-- 'IOException' before anything is removed; a removal that fails is an
-- outcome in t'Reclaimed'.
reclaim :: FileStore -> NominalDiffTime -> IO UTCTime -> IO (Either ReclaimBlocked Reclaimed)
reclaim store minimumAge clock = withRemoval store $ do
  planned <- planStore minimumAge <$> scanStore store clock
  traverse removePlanned planned
  where
    removePlanned plan = do
      nars <- traverse (\nar -> (,) nar <$> removeNar store (nfName nar)) (rpEligible (spNars plan))
      uploads <- traverse (\upload -> (,) upload <$> removeUpload store (suFileName upload) (suUploadId upload)) (upEligible (spUploads plan))
      pure Reclaimed {rdPlan = plan, rdNars = nars, rdUploads = uploads}
