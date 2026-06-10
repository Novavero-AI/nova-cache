{-# LANGUAGE ScopedTypeVariables #-}

-- | xz compression and decompression for NAR files.
--
-- Thin wrappers around the @lzma@ package, converting between strict
-- 'ByteString' and the underlying lazy interface.
module NovaCache.Compression
  ( compressXz,
    decompressXz,
  )
where

import qualified Codec.Compression.Lzma as Lzma
import Control.Exception (SomeAsyncException, SomeException, evaluate, fromException, throwIO, try)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as BL

-- | Compress a strict 'ByteString' with xz.
compressXz :: ByteString -> ByteString
compressXz = BL.toStrict . Lzma.compress . BL.fromStrict

-- | Decompress an xz-compressed strict 'ByteString'.
--
-- Returns 'Left' with an error message if the input is not valid xz data.
decompressXz :: ByteString -> IO (Either String ByteString)
decompressXz bs = do
  result <- try (evaluate (BL.toStrict (Lzma.decompress (BL.fromStrict bs))))
  case result of
    Right decompressed -> pure (Right decompressed)
    -- Catch only SYNCHRONOUS failures; re-raise async exceptions (timeout,
    -- ThreadKilled) so a caller's timeout/cancellation still works on this
    -- untrusted-input decoder.
    Left err
      | Just (_ :: SomeAsyncException) <- fromException err -> throwIO err
      | otherwise -> pure (Left ("xz decompression failed: " ++ show (err :: SomeException)))
