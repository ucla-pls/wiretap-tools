{-# LANGUAGE CPP, MagicHash, BangPatterns #-}
module Wiretap.Data.MiniParser where

import GHC.Base
import GHC.Int
import           GHC.Word

import           Data.Word
import           Data.Bits

import           Data.Binary.Get
import qualified Data.Binary.Get.Internal as I

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Unsafe as BU

newtype MiniParser a = MiniParser
  { runMiniParser :: BL.ByteString -> Maybe (a, BL.ByteString)
  }

instance Functor MiniParser where
  fmap f a = MiniParser $ \ !bs -> do
    (a', rest) <- runMiniParser a bs
    return (f a', rest)

instance Applicative MiniParser where
  pure a = MiniParser $ \ !bs -> Just (a, bs)
  f <*> m =
    MiniParser $ \ !bs -> do
      (f', !rest) <- runMiniParser f bs
      (m', !rest') <- runMiniParser m rest
      return (f' m', rest')

instance Monad MiniParser where
  m1 >>= m2 = MiniParser $ \ bs -> do
    (a, !rest) <- runMiniParser m1 bs
    runMiniParser (m2 a) rest

parseError :: MiniParser a
parseError = MiniParser $ \bs -> Nothing
{-# INLINABLE parseError #-}

drawWord8 :: MiniParser Word8
drawWord8 = MiniParser $ BL.uncons
{-# INLINABLE drawWord8 #-}

drawN :: Int64 -> MiniParser BL.ByteString
drawN n = MiniParser $ Just . BL.splitAt n
{-# INLINABLE drawN #-}

drawInt32be :: MiniParser Int32
drawInt32be =
  fromIntegral <$> drawWord32be
{-# INLINABLE drawInt32be #-}

drawWord16be :: MiniParser Word16
drawWord16be = MiniParser $ \bs ->
  let (bs', rest) = BL.splitAt 4 bs in
  case BL.unpack bs' of
    [w1, w2] ->
    -- Borrowed from Data.Binary.Get
      Just ( fromIntegral w1 `shiftl_w16` 8
         .|. fromIntegral w2
         , rest)
    otherwise -> Nothing
{-# INLINABLE drawWord16be #-}

drawWord32be :: MiniParser Word32
drawWord32be = MiniParser $ \bs ->
  let (bs', rest) = BL.splitAt 4 bs in
    if BL.length bs' == 4 then
      let strict = BL.toStrict bs'
          w1 = BU.unsafeIndex strict 1
          w2 = BU.unsafeIndex strict 2
          w3 = BU.unsafeIndex strict 3
          w4 = BU.unsafeIndex strict 4 in
        Just  ( fromIntegral w1 `shiftl_w32` 24
            .|. fromIntegral w2 `shiftl_w32` 16
            .|. fromIntegral w3 `shiftl_w32` 8
            .|. fromIntegral w4
              , rest)
    else
      Nothing
{-# INLINABLE drawWord32be #-}

drawWord64be :: MiniParser Word64
drawWord64be = do
  w1 <- drawWord8
  w2 <- drawWord8
  w3 <- drawWord8
  w4 <- drawWord8
  w5 <- drawWord8
  w6 <- drawWord8
  w7 <- drawWord8
  w8 <- drawWord8
  -- Borrowed from Data.Binary.Get
  return $ fromIntegral w1 `shiftl_w64` 56
       .|. fromIntegral w2 `shiftl_w64` 48
       .|. fromIntegral w3 `shiftl_w64` 40
       .|. fromIntegral w4 `shiftl_w64` 32
       .|. fromIntegral w5 `shiftl_w64` 24
       .|. fromIntegral w6 `shiftl_w64` 16
       .|. fromIntegral w7 `shiftl_w64` 8
       .|. fromIntegral w8

-- Borrowed from Data.Binary.Get
------------------------------------------------------------------------
-- Unchecked shifts

shiftl_w16 :: Word16 -> Int -> Word16
shiftl_w32 :: Word32 -> Int -> Word32
shiftl_w64 :: Word64 -> Int -> Word64

shiftl_w16 (W16# w) (I# i) = W16# (w `uncheckedShiftL#`   i)
shiftl_w32 (W32# w) (I# i) = W32# (w `uncheckedShiftL#`   i)
shiftl_w64 (W64# w) (I# i) = W64# (w `uncheckedShiftL64#` i)
