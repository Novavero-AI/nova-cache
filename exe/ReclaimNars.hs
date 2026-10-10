-- | The @reclaim-nars@ subcommand: list, and with @--delete@ remove,
-- the NARs in a store directory that no narinfo references.
--
-- A host tool run against the store directory rather than a route,
-- since nothing over HTTP should be able to delete.  The decision is
-- "NovaCache.Reclaim"'s; this module parses arguments, prints, and
-- deletes.
module ReclaimNars (reclaimCommand, reclaimMain) where

import Control.Exception (IOException, displayException, try)
import Control.Monad (when)
import Data.Foldable (for_, traverse_)
import Data.List.NonEmpty (NonEmpty)
import Data.Time.Clock (NominalDiffTime)
import NovaCache.Reclaim (ReclaimPlan (..), Unresolved (..), defaultMinimumAge, planReclaim, scanStore)
import NovaCache.Store (FileStore, NarFile (..), NarRemoveResult (..), fileStoreAt, removeNar)
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
-- the store cannot be listed, a narinfo blocks the run, or a deletion
-- fails.
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
    scanned <- try (scanStore store)
    case scanned of
      Left err ->
        fatal ("cannot scan the store: " ++ displayException (err :: IOException))
      Right scan -> case planReclaim (optMinimumAge opts) scan of
        Left unresolved -> refuse unresolved
        Right plan -> case optMode opts of
          ListOnly -> listPlan plan
          Delete -> deletePlan store plan

-- | List what a deleting run would remove.
listPlan :: ReclaimPlan -> IO ()
listPlan plan = do
  traverse_ (putStrLn . ("unreferenced: " ++) . describe) (rpEligible plan)
  putStrLn
    ( "eligible: "
        ++ counted (length (rpEligible plan)) "NAR"
        ++ ", "
        ++ counted (sum (map nfSize (rpEligible plan))) "byte"
        ++ " (pass "
        ++ deleteFlag
        ++ " to remove)"
    )
  reportTooYoung plan

-- | Remove every eligible NAR, reporting each, and exit nonzero if any
-- removal failed.
deletePlan :: FileStore -> ReclaimPlan -> IO ()
deletePlan store plan = do
  outcomes <- traverse removeOne (rpEligible plan)
  let removed = [nar | (nar, NarRemoved) <- outcomes]
      failures = length outcomes - length removed
  putStrLn
    ( "reclaimed: "
        ++ counted (length removed) "NAR"
        ++ ", "
        ++ counted (sum (map nfSize removed)) "byte"
    )
  reportTooYoung plan
  when (failures > 0) $
    fatal ("failed to delete " ++ counted failures "NAR")
  where
    removeOne nar = do
      outcome <- removeNar store (nfName nar)
      case outcome of
        NarRemoved -> putStrLn ("deleted: " ++ describe nar)
        NarRemoveFailed err -> failed nar (ioeGetErrorString err)
        NarRemoveBadPath -> failed nar "not a NAR filename"
      pure (nar, outcome)
    failed nar reason = hPutStrLn stderr ("FAILED: " ++ nfPath nar ++ ": " ++ reason)

-- | Report the narinfos that block the run and exit nonzero.
refuse :: NonEmpty Unresolved -> IO ()
refuse unresolved = do
  for_ unresolved $ \u ->
    hPutStrLn stderr ("UNRESOLVED: " ++ unresolvedPath u ++ ": " ++ unresolvedReason u)
  fatal
    ( counted (length unresolved) "unresolved narinfo"
        ++ ": nothing was listed or deleted, since the NAR an unresolved narinfo names"
        ++ " would look unreferenced.  Fix or remove each one and run again."
    )

reportTooYoung :: ReclaimPlan -> IO ()
reportTooYoung plan =
  putStrLn ("kept, younger than the minimum age: " ++ counted (length (rpTooYoung plan)) "NAR")

describe :: NarFile -> String
describe nar = nfPath nar ++ " (" ++ counted (nfSize nar) "byte" ++ ")"

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
