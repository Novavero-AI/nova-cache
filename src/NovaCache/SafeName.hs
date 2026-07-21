-- | Windows-unsafe name categories, shared by the store-key allowlist
-- ('NovaCache.Store.sanitizePath') and the NAR entry-name guard in
-- "NovaCache.NAR": names Windows resolves to something other than an
-- ordinary file of that exact spelling.  Both guards reject the same
-- categories from one definition, so they cannot drift apart.
--
-- The predicates take raw bytes, the form NAR entry names have.  Every
-- category here is ASCII-structural, and UTF-8 lead and continuation
-- bytes are all @>= 0x80@, so byte-level matching is exact - inside
-- valid UTF-8 and inside names that decode as nothing at all.  Text
-- callers encode with 'Data.Text.Encoding.encodeUtf8' first.
module NovaCache.SafeName
  ( isReservedDeviceName,
    hasTrailingDotOrSpace,
  )
where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BS8
import Data.Char (isAsciiUpper, toLower)

-- | Is the name a Windows reserved device (@con@, @prn@, @aux@, @nul@,
-- @com1@-@com9@, @lpt1@-@lpt9@)? Matched case-insensitively on the portion
-- before the first dot, since @nul.txt@ also opens the device. Enforced on
-- every platform so a Windows-hosted consumer is safe too.
--
-- Device matching is ASCII case-insensitive, so only @A@-@Z@ fold; any
-- other byte passes through and can never match the reserved set.
isReservedDeviceName :: ByteString -> Bool
isReservedDeviceName name =
  BS8.map asciiLower (BS8.takeWhile (/= '.') name) `elem` reservedNames
  where
    asciiLower c = if isAsciiUpper c then toLower c else c
    reservedNames =
      ["con", "prn", "aux", "nul"]
        ++ [device <> digit | device <- ["com", "lpt"], digit <- digits]
    digits = [BS8.pack (show n) | n <- [1 .. 9 :: Int]]

-- | Does the name end with a dot or a space?  NTFS strips both at
-- create time, so the on-disk name silently diverges from the requested
-- one and the materialized tree no longer matches what named it.
hasTrailingDotOrSpace :: ByteString -> Bool
hasTrailingDotOrSpace name = case BS8.unsnoc name of
  Just (_, end) -> end == '.' || end == ' '
  Nothing -> False
