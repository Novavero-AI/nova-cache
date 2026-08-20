-- | Windows-unsafe name categories, shared by the store-key allowlist
-- ('NovaCache.Store.sanitizePath') and the NAR entry-name guard in
-- "NovaCache.NAR": names Windows resolves to something other than an
-- ordinary file of that exact spelling.  Both guards reject the same
-- categories from one definition, so they cannot drift apart.
--
-- The predicates take raw bytes, the form NAR entry names have.  The
-- categories are ASCII-structural - except the superscript device
-- digits, matched as their exact UTF-8 sequences - and UTF-8 lead and
-- continuation bytes are all @>= 0x80@, so byte-level matching is
-- exact inside valid UTF-8 and inside names that decode as nothing at
-- all.  Text callers encode with 'Data.Text.Encoding.encodeUtf8'
-- first.
module NovaCache.SafeName
  ( isReservedDeviceName,
    hasTrailingDotOrSpace,
  )
where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Data.Char (isAsciiUpper, isDigit, toLower)

-- | Is the name a Windows reserved device (@con@, @prn@, @aux@, @nul@,
-- @com0@-@com9@, @lpt0@-@lpt9@, or a superscript-digit @com@\/@lpt@
-- form)?  The comparison runs on the stem - the portion before the
-- first dot, trailing spaces trimmed - since @nul.txt@ and @NUL .txt@
-- also open the device.  Enforced on every platform so a
-- Windows-hosted consumer is safe too, and kept in step with the twin
-- guard nova-nix applies when it materializes NAR entries.
--
-- Device matching is ASCII case-insensitive, so only @A@-@Z@ fold; any
-- other byte passes through and can never match the named set.
isReservedDeviceName :: ByteString -> Bool
isReservedDeviceName name = stem `elem` namedDevices || isNumberedDevice stem
  where
    stem = BS8.map asciiLower (deviceStem name)
    asciiLower c = if isAsciiUpper c then toLower c else c
    namedDevices = ["con", "prn", "aux", "nul"]

-- | The portion of a name Win32 device parsing compares against the
-- reserved set: up to the first dot, trailing spaces trimmed.
deviceStem :: ByteString -> ByteString
deviceStem = BS8.dropWhileEnd (== ' ') . BS8.takeWhile (/= '.')

-- | A numbered device stem: @com@ or @lpt@ followed by exactly one
-- device digit (@com10@ is an ordinary name).
isNumberedDevice :: ByteString -> Bool
isNumberedDevice stem = case BS.splitAt numberedDevicePrefixLen stem of
  (prefix, digit) -> (prefix == "com" || prefix == "lpt") && isDeviceDigit digit

-- | Bytes @com@\/@lpt@ occupy in a numbered device stem.
numberedDevicePrefixLen :: Int
numberedDevicePrefixLen = 3

-- | One device digit: ASCII @0@-@9@, or superscript one\/two\/three as
-- UTF-8 bytes - Windows reserves the superscript @COM@\/@LPT@ forms
-- alongside the plain ones.  Only the UTF-8 spelling is matched: a
-- lone Latin-1 superscript byte is not valid UTF-8, so no UTF-8 write
-- boundary ever lands it on a Windows filesystem, and on POSIX it
-- names an ordinary file.
isDeviceDigit :: ByteString -> Bool
isDeviceDigit bytes =
  (BS.length bytes == 1 && BS8.all isDigit bytes)
    || bytes `elem` superscriptDigits

-- | The UTF-8 encodings of U+00B9, U+00B2, U+00B3 (superscript one,
-- two, three).
superscriptDigits :: [ByteString]
superscriptDigits =
  [BS.pack [0xC2, 0xB9], BS.pack [0xC2, 0xB2], BS.pack [0xC2, 0xB3]]

-- | Does the name end with a dot or a space?  NTFS strips both at
-- create time, so the on-disk name silently diverges from the requested
-- one and the materialized tree no longer matches what named it.
hasTrailingDotOrSpace :: ByteString -> Bool
hasTrailingDotOrSpace name = case BS8.unsnoc name of
  Just (_, end) -> end == '.' || end == ' '
  Nothing -> False
