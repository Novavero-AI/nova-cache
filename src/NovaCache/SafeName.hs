-- | Windows-unsafe name categories, shared by the store-key allowlist
-- ('NovaCache.Store.sanitizePath') and the NAR entry-name guard in
-- "NovaCache.NAR": names Windows resolves to something other than an
-- ordinary file of that exact spelling.  Both guards reject the same
-- categories from one definition, so they cannot drift apart.
module NovaCache.SafeName
  ( isReservedDeviceName,
    hasTrailingDotOrSpace,
  )
where

import Data.Text (Text)
import qualified Data.Text as T

-- | Is the name a Windows reserved device (@con@, @prn@, @aux@, @nul@,
-- @com1@-@com9@, @lpt1@-@lpt9@)? Matched case-insensitively on the portion
-- before the first dot, since @nul.txt@ also opens the device. Enforced on
-- every platform so a Windows-hosted consumer is safe too.
isReservedDeviceName :: Text -> Bool
isReservedDeviceName txt = T.toLower (T.takeWhile (/= '.') txt) `elem` reservedNames
  where
    reservedNames =
      ["con", "prn", "aux", "nul"]
        ++ ["com" <> n | n <- digits]
        ++ ["lpt" <> n | n <- digits]
    digits = [T.pack (show n) | n <- [1 .. 9 :: Int]]

-- | Does the name end with a dot or a space?  NTFS strips both at
-- create time, so the on-disk name silently diverges from the requested
-- one and the materialized tree no longer matches what named it.
hasTrailingDotOrSpace :: Text -> Bool
hasTrailingDotOrSpace name = case T.unsnoc name of
  Just (_, end) -> end == '.' || end == ' '
  Nothing -> False
