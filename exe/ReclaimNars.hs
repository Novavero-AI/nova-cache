-- | The @reclaim-nars@ subcommand: list, and with @--delete@ remove,
-- the NARs in a store directory that no narinfo references, and the
-- multipart uploads begun there and abandoned.
--
-- A host tool run against the store directory rather than a route,
-- since nothing over HTTP should be able to delete.  The decision is
-- "NovaCache.Reclaim"'s; this module parses arguments, prints, and
-- deletes.
module ReclaimNars (reclaimCommand, reclaimMain) where

import Control.Exception (IOException, displayException, try)
import Control.Monad (when)
import Data.Foldable (for_, traverse_)
import Data.Time.Clock (NominalDiffTime)
import NovaCache.Reclaim
  ( ReclaimBlocked (..),
    ReclaimPlan (..),
    Unresolved (..),
    UploadPlan (..),
    UploadScan (..),
    defaultMinimumAge,
    planReclaim,
    scanStore,
    scanUploads,
    selectAbandoned,
  )
import NovaCache.Store
  ( FileStore,
    NarFile (..),
    NarRemoveResult (..),
    StagedUpload (..),
    UploadRemoveResult (..),
    fileStoreAt,
    removeNar,
    removeUpload,
  )
import System.Exit (exitFailure)
import System.IO (BufferMode (LineBuffering), hPutStrLn, hSetBuffering, stderr, stdout)
import System.IO.Error (ioeGetErrorString)
import Text.Read (readMaybe)

-- ---------------------------------------------------------------------------
-- Arguments
-- ---------------------------------------------------------------------------

-- | The subcommand's name, the first argument to the executable.
reclaimCommand :: String
reclaimCommand = "reclaim-nars"

storeFlag, minAgeFlag, deleteFlag :: String
storeFlag = "--store"
minAgeFlag = "--min-age-hours"
deleteFlag = "--delete"

usage :: String
usage =
  "usage: nova-cache-server "
    ++ reclaimCommand
    ++ " ["
    ++ storeFlag
    ++ " DIR] ["
    ++ minAgeFlag
    ++ " N] ["
    ++ deleteFlag
    ++ "]"

secondsPerHour :: NominalDiffTime
secondsPerHour = 3600

-- | Whether a run removes what it finds.  Listing is the default.
data Mode = ListOnly | Delete

data Options = Options
  { optStoreRoot :: !FilePath,
    optMinimumAge :: !NominalDiffTime,
    optMode :: !Mode
  }

-- | Parse the subcommand's arguments over the store root the
-- environment chose.  Unlike the server's flags, an unknown or
-- malformed argument is an error: a typo here must not run with a
-- default the operator did not choose.
parseOptions :: FilePath -> [String] -> Either String Options
parseOptions storeRoot =
  go Options {optStoreRoot = storeRoot, optMinimumAge = defaultMinimumAge, optMode = ListOnly}
  where
    go opts [] = Right opts
    go opts (flag : value : rest)
      | flag == storeFlag = go opts {optStoreRoot = value} rest
      | flag == minAgeFlag = case readMaybe value of
          Just hours
            | hours >= (0 :: Integer) ->
                go opts {optMinimumAge = fromInteger hours * secondsPerHour} rest
          _ -> Left (minAgeFlag ++ " takes a whole number of hours, not " ++ show value)
    go opts (flag : rest)
      | flag == deleteFlag = go opts {optMode = Delete} rest
      | flag == storeFlag || flag == minAgeFlag = Left (flag ++ " needs a value")
      | otherwise = Left ("unknown argument: " ++ flag)

-- ---------------------------------------------------------------------------
-- Command
-- ---------------------------------------------------------------------------

-- | Run the subcommand.  Exits nonzero when the arguments are wrong,
-- the store cannot be listed, the run is blocked, or a deletion fails.
-- A blocked run lists and deletes nothing, abandoned uploads included.
reclaimMain :: FilePath -> [String] -> IO ()
reclaimMain storeRoot args = case parseOptions storeRoot args of
  Left err -> do
    hPutStrLn stderr err
    hPutStrLn stderr usage
    exitFailure
  Right opts -> do
    -- Piped stdout is block buffered by default, which would print the
    -- report out of order with the FAILED and FATAL lines on stderr.
    hSetBuffering stdout LineBuffering
    let root = optStoreRoot opts
        store = fileStoreAt root
    putStrLn ("store root: " ++ root)
    putStrLn ("minimum age: " ++ counted (wholeHours (optMinimumAge opts)) "hour")
    scanned <- try ((,) <$> scanStore store <*> scanUploads store)
    case scanned of
      Left err ->
        fatal ("cannot scan the store: " ++ displayException (err :: IOException))
      Right (scan, uploadScan) -> case planReclaim (optMinimumAge opts) scan of
        Left blocked -> refuse blocked
        Right plan -> do
          let uploads = selectAbandoned (optMinimumAge opts) (uploadScanTime uploadScan) (uploadScanUploads uploadScan)
          case optMode opts of
            ListOnly -> listPlan plan uploads
            Delete -> deletePlan store plan uploads

-- | List what a deleting run would remove.
listPlan :: ReclaimPlan -> UploadPlan -> IO ()
listPlan plan uploads = do
  traverse_ (putStrLn . ("unreferenced: " ++) . describe) (rpEligible plan)
  traverse_ (putStrLn . ("abandoned: " ++) . describeUpload) (upEligible uploads)
  putStrLn
    ( "eligible: "
        ++ totals (rpEligible plan) (upEligible uploads)
        ++ " (pass "
        ++ deleteFlag
        ++ " to remove)"
    )
  reportTooYoung plan uploads

-- | Remove every eligible NAR and upload, reporting each, and exit
-- nonzero if any removal failed.
deletePlan :: FileStore -> ReclaimPlan -> UploadPlan -> IO ()
deletePlan store plan uploads = do
  narOutcomes <- traverse removeOne (rpEligible plan)
  uploadOutcomes <- traverse removeOneUpload (upEligible uploads)
  let removed = [nar | (nar, NarRemoved) <- narOutcomes]
      removedUploads = [upload | (upload, UploadRemoved) <- uploadOutcomes]
      narFailures = length narOutcomes - length removed
      uploadFailures = length uploadOutcomes - length removedUploads
  putStrLn ("reclaimed: " ++ totals removed removedUploads)
  reportTooYoung plan uploads
  when (narFailures + uploadFailures > 0) $
    fatal ("failed to delete " ++ counted narFailures "NAR" ++ " and " ++ counted uploadFailures "upload")
  where
    removeOne nar = do
      outcome <- removeNar store (nfName nar)
      case outcome of
        NarRemoved -> putStrLn ("deleted: " ++ describe nar)
        NarRemoveFailed err -> failed (nfPath nar) (ioeGetErrorString err)
        NarRemoveBadPath -> failed (nfPath nar) "not a NAR filename"
      pure (nar, outcome)
    removeOneUpload upload = do
      outcome <- removeUpload store (suFileName upload) (suUploadId upload)
      case outcome of
        UploadRemoved -> putStrLn ("deleted: " ++ describeUpload upload)
        UploadRemoveFailed err -> failed (suPath upload) (ioeGetErrorString err)
        UploadRemoveBadPath -> failed (suPath upload) "not an upload of a NAR filename"
      pure (upload, outcome)
    failed path reason = hPutStrLn stderr ("FAILED: " ++ path ++ ": " ++ reason)

-- | Report what blocks the run and exit nonzero.
refuse :: ReclaimBlocked -> IO ()
refuse (UnresolvedNarInfos unresolved) = do
  for_ unresolved $ \u ->
    hPutStrLn stderr ("UNRESOLVED: " ++ unresolvedPath u ++ ": " ++ unresolvedReason u)
  fatal
    ( counted (length unresolved) "unresolved narinfo"
        ++ ": nothing was listed or deleted, since the NAR an unresolved narinfo names"
        ++ " would look unreferenced.  Fix or remove each one and run again."
    )
refuse NoNarInfos =
  fatal
    ( "the store holds NARs and no narinfo: nothing was listed or deleted, since a store"
        ++ " that lost its narinfos looks the same as one whose every NAR is unreferenced."
        ++ "  Restore the narinfos, or remove the NARs by hand if none is referenced."
    )

reportTooYoung :: ReclaimPlan -> UploadPlan -> IO ()
reportTooYoung plan uploads =
  putStrLn
    ( "kept, younger than the minimum age: "
        ++ counted (length (rpTooYoung plan)) "NAR"
        ++ ", "
        ++ counted (length (upTooYoung uploads)) "upload"
    )

-- | How many NARs and uploads, and how many bytes each hold.
totals :: [NarFile] -> [StagedUpload] -> String
totals nars uploads =
  counted (length nars) "NAR"
    ++ ", "
    ++ counted (sum (map nfSize nars)) "byte"
    ++ "; "
    ++ counted (length uploads) "abandoned upload"
    ++ ", "
    ++ counted (sum (map suSize uploads)) "byte"

describe :: NarFile -> String
describe nar = nfPath nar ++ " (" ++ counted (nfSize nar) "byte" ++ ")"

describeUpload :: StagedUpload -> String
describeUpload upload = suPath upload ++ " (" ++ counted (suSize upload) "byte" ++ ")"

fatal :: String -> IO ()
fatal msg = do
  hPutStrLn stderr ("FATAL: " ++ msg)
  exitFailure

wholeHours :: NominalDiffTime -> Integer
wholeHours age = round (age / secondsPerHour)

-- | A count with its noun: @1 NAR@, @2 NARs@.
counted :: (Show a, Eq a, Num a) => a -> String -> String
counted 1 noun = "1 " ++ noun
counted n noun = show n ++ " " ++ noun ++ "s"
