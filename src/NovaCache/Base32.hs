-- | Nix-specific base32 encoding and decoding.
--
-- Nix uses a non-standard base32 alphabet that omits @e@, @o@, @u@, @t@,
-- and encodes bytes in reverse order compared to RFC 4648. The encoding
-- extracts 5-bit groups from the raw bytes in descending position order.
module NovaCache.Base32
  ( encode,
    decode,
    isBase32Char,
  )
where

import Control.Monad (when)
import Control.Monad.ST (runST)
import Data.Bits (shiftL, shiftR, (.&.), (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Unsafe as BSU
import Data.Char (ord)
import Data.STRef (newSTRef, readSTRef, writeSTRef)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Vector.Unboxed (Vector)
import qualified Data.Vector.Unboxed as V
import qualified Data.Vector.Unboxed.Mutable as MV
import Data.Word (Word8)

-- ---------------------------------------------------------------------------
-- Alphabet
-- ---------------------------------------------------------------------------

-- | Nix base32 alphabet: @0123456789abcdfghijklmnpqrsvwxyz@
--
-- 32 characters, deliberately omitting @e@, @o@, @u@, @t@ to avoid
-- visually ambiguous characters and accidental English words.
nixAlphabet :: Vector Char
nixAlphabet = V.fromList "0123456789abcdfghijklmnpqrsvwxyz"

-- | Reverse lookup table: ASCII ordinal to 5-bit value.
-- Invalid characters map to 'invalidMarker'.
nixDecodeLut :: Vector Word8
nixDecodeLut =
  V.generate asciiTableSize $ \c ->
    maybe invalidMarker fromIntegral (V.findIndex (== toEnum c) nixAlphabet)

-- | Size of the ASCII lookup table.
asciiTableSize :: Int
asciiTableSize = 256

-- | Sentinel value for characters outside the alphabet.
invalidMarker :: Word8
invalidMarker = 0xFF

-- | Is a character part of the Nix base32 alphabet
-- (@0123456789abcdfghijklmnpqrsvwxyz@)?  Used to validate store-path hashes.
isBase32Char :: Char -> Bool
isBase32Char c = case nixDecodeLut V.!? ord c of
  Just v -> v /= invalidMarker
  Nothing -> False

-- | Bits per base32 character.
bitsPerChar :: Int
bitsPerChar = 5

-- | Bits per byte.
bitsPerByte :: Int
bitsPerByte = 8

-- | Bit mask for extracting 5 bits.
fiveBitMask :: Int
fiveBitMask = 0x1F

-- | Bit mask for byte-within-8 alignment.
byteAlignMask :: Int
byteAlignMask = 7

-- ---------------------------------------------------------------------------
-- Encode
-- ---------------------------------------------------------------------------

-- | Number of base32 characters for a given input byte length.
--
-- @\lceil len \times 8 / 5 \rceil@
encodedLength :: Int -> Int
encodedLength n =
  let totalBits = n * bitsPerByte
   in totalBits `div` bitsPerChar
        + (if totalBits `mod` bitsPerChar > 0 then 1 else 0)

-- | Encode a 'ByteString' to Nix-base32 'Text'.
--
-- Each output character position @n@ maps to a 5-bit group extracted from
-- the input at bit offset @n * 5@. Characters are emitted from the highest
-- position down, matching the Nix reference implementation.
encode :: ByteString -> Text
encode bs = T.pack [charAtPosition n | n <- [encLen - 1, encLen - 2 .. 0]]
  where
    len = BS.length bs
    encLen = encodedLength len

    charAtPosition :: Int -> Char
    charAtPosition n = V.unsafeIndex nixAlphabet (extract5Bits n)

    extract5Bits :: Int -> Int
    extract5Bits n =
      let bitOff = n * bitsPerChar
          byteIdx = bitOff `shiftR` 3
          bitIdx = bitOff .&. byteAlignMask
          lo = safeByte byteIdx
          hi = safeByte (byteIdx + 1)
          combined = fromIntegral lo .|. (fromIntegral hi `shiftL` bitsPerByte :: Int)
       in (combined `shiftR` bitIdx) .&. fiveBitMask

    safeByte :: Int -> Word8
    safeByte i
      | i < len = BSU.unsafeIndex bs i
      | otherwise = 0

-- ---------------------------------------------------------------------------
-- Decode
-- ---------------------------------------------------------------------------

-- | Decode Nix-base32 'Text' to a 'ByteString'.
--
-- For each character at string position @n@, the corresponding bit offset
-- in the output is @5 * (inputLen - 1 - n)@. Each 5-bit value's bits are
-- scattered into the output byte array via an O(n) mutable vector pass.
decode :: Text -> Either String ByteString
decode txt
  | T.null txt = Right BS.empty
  | otherwise = do
      values <- traverse lookupChar (T.unpack txt)
      scatterDecode values inputLen outputLen
  where
    inputLen = T.length txt
    outputLen = (inputLen * bitsPerChar) `div` bitsPerByte

-- | Resolve a character to its 5-bit value, failing on invalid input.
lookupChar :: Char -> Either String Word8
lookupChar c
  | ci >= asciiTableSize = Left (invalidCharMsg c)
  | val == invalidMarker = Left (invalidCharMsg c)
  | otherwise = Right val
  where
    ci = ord c
    val = V.unsafeIndex nixDecodeLut ci

-- | Scatter 5-bit values into an output byte array using a mutable vector.
--
-- O(n) in the number of input characters. Each character contributes
-- exactly 5 bits, placed at the correct byte and bit offset.
scatterDecode :: [Word8] -> Int -> Int -> Either String ByteString
scatterDecode values inputLen outputLen = runST $ do
  arr <- MV.replicate outputLen (0 :: Word8)
  canonical <- newSTRef True
  scatterAll arr canonical 0 values
  ok <- readSTRef canonical
  if ok
    then do
      frozen <- V.unsafeFreeze arr
      pure (Right (BS.pack (V.toList frozen)))
    else pure (Left "non-canonical nix-base32: padding bits must be zero")
  where
    scatterAll _ _ !_ [] = pure ()
    scatterAll arr canonical !n (c5 : rest) = do
      let bitsStart = bitsPerChar * (inputLen - 1 - n)
      scatterBits arr canonical c5 bitsStart 0
      scatterAll arr canonical (n + 1) rest

    scatterBits arr canonical c5 bitsStart !bit
      | bit >= bitsPerChar = pure ()
      | otherwise = do
          let b = bitsStart + bit
              byteIdx = b `shiftR` 3
              bitIdx = b .&. byteAlignMask
              bitVal = (c5 `shiftR` bit) .&. 1
          if byteIdx < outputLen
            then do
              old <- MV.unsafeRead arr byteIdx
              MV.unsafeWrite arr byteIdx (old .|. (bitVal `shiftL` bitIdx))
            -- A set bit landing outside the output is a non-canonical encoding
            -- (Nix requires these padding bits to be zero); reject it.
            else when (bitVal /= 0) (writeSTRef canonical False)
          scatterBits arr canonical c5 bitsStart (bit + 1)

invalidCharMsg :: Char -> String
invalidCharMsg c = "invalid nix-base32 character: " ++ [c]
