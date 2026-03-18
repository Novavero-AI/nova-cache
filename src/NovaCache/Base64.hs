-- | Base64 encoding and decoding for the Nix ecosystem.
--
-- Thin wrappers over @base64-bytestring@, re-exported so downstream
-- packages don't need a direct dependency on the same lib.
module NovaCache.Base64
  ( encode,
    decode,
  )
where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Base64 as B64
import Data.Text (Text)
import qualified Data.Text.Encoding as TE

-- | Encode bytes to base64 'Text'.
encode :: ByteString -> Text
encode = TE.decodeLatin1 . B64.encode

-- | Decode base64 'Text' to bytes.
decode :: Text -> Either String ByteString
decode = B64.decode . TE.encodeUtf8
