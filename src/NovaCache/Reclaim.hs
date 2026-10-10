-- | Finding the NARs a file store holds that no narinfo references.
--
-- A client uploads a path's NAR before its narinfo (upstream's
-- @BinaryCacheStore::addToStoreCommon@ does, and so does nova-nix's
-- push), so a NAR whose narinfo is refused, or never sent because the
-- push died, stays under @nar\/@ with nothing pointing at it.  Which
-- NARs those are is decided purely ('planReclaim' over a 't:StoreScan');
-- 'scanStore' is the IO edge that reads the store, and deletion is
-- 'NovaCache.Store.removeNar'.
--
-- Two rules keep a run from breaking a cache in use.  A NAR younger
-- than the minimum age is never eligible, because a NAR is unreferenced
-- legitimately until its push sends the narinfo.  And a narinfo that
-- cannot be read, parsed, or resolved to a file under @nar\/@ blocks
-- the whole run: the NAR it names is unknown, so no NAR can be shown
-- to be unreferenced.
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
    planReclaim,

    -- * Scanning a store
    StoreScan (..),
    scanStore,
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
import Data.Time.Clock (NominalDiffTime, UTCTime, diffUTCTime, getCurrentTime, nominalDay)
import NovaCache.NarInfo (NarInfo (..), parseNarInfo)
import NovaCache.Store (FileStore, NarFile (..), listNarFiles, listNarInfoFiles, sanitizePath)
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
-- before the first narinfo, with no response timeout.  Deleting one
-- early leaves a narinfo naming a missing NAR, which no later push
-- repairs (a push skips paths whose narinfo exists), while waiting
-- costs only disk.  git guards the same race, between gc and a writer
-- that has stored an object but not yet referenced it, with the same
-- two weeks (@gc.pruneExpire@).
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
    (old, young) = partition oldEnough (filter unreferenced nars)
    unreferenced nar = Set.notMember (nfName nar) references
    oldEnough nar = diffUTCTime now (nfModified nar) >= minimumAge

-- | Plan a run from a scan: the unreferenced NARs by age, or every
-- narinfo that blocks it.
planReclaim :: NominalDiffTime -> StoreScan -> Either (NonEmpty Unresolved) ReclaimPlan
planReclaim minimumAge scan = do
  references <- collectReferences (scanNarInfos scan)
  pure (selectUnreferenced minimumAge (scanTime scan) references (scanNars scan))

-- ---------------------------------------------------------------------------
-- Scanning a store
-- ---------------------------------------------------------------------------

-- | What a scan read: each narinfo's target, each NAR, and the time the
-- NARs were listed.
data StoreScan = StoreScan
  { scanNarInfos :: ![(FilePath, NarInfoTarget)],
    scanNars :: ![NarFile],
    scanTime :: !UTCTime
  }
  deriving (Eq, Show)

-- | Read a store for 'planReclaim'.  A directory that cannot be listed,
-- or a NAR that cannot be stat'd, fails the scan with its
-- 'IOException'; an unreadable narinfo is recorded as 'Unresolvable'.
--
-- The narinfos are read before the NARs are listed, the order git's
-- prune uses (reachability first, then each object's age): a NAR
-- uploaded again while the narinfos are read shows its new
-- modification time.  What remains is a narinfo that arrives after the
-- narinfo listing for a NAR older than the minimum age.  That is a push
-- slower than the minimum age, or a client (upstream @nix copy@) that
-- skips re-uploading a NAR already present, and only a lock shared with
-- the server would close it.
scanStore :: FileStore -> IO StoreScan
scanStore store = do
  narInfos <- traverse readTarget =<< listNarInfoFiles store
  nars <- listNarFiles store
  now <- getCurrentTime
  pure StoreScan {scanNarInfos = narInfos, scanNars = nars, scanTime = now}
  where
    -- Forced per file, so each narinfo's bytes are garbage once its
    -- target is known instead of held until the scan is planned.
    readTarget path = do
      contents <- try (BS.readFile path)
      let !target = narInfoTarget contents
      pure (path, target)
