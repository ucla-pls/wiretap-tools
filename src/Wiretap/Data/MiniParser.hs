{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE CPP          #-}
{-# LANGUAGE MagicHash    #-}
module Wiretap.Data.MiniParser where

import           GHC.Base
import           GHC.Int
import           GHC.Word

import           Data.Bits

import qualified Data.ByteString        as B
import qualified Data.ByteString.Lazy   as BL
import qualified Data.ByteString.Unsafe as BU


newtype MiniParser a = MiniParser
  { runMiniParser :: BL.ByteString -> Maybe (a, BL.ByteString)
  }

instance MonadPlus MiniParser where
  mzero = parseError
  a `mplus` b = MiniParser $ \bs -> do
    (_, bs') <- runMiniParser a bs
    (b', bs'') <- runMiniParser b bs'
    return (b', bs'')

instance Alternative MiniParser where
  empty = mzero
  a <|> b = MiniParser $ \bs ->
    runMiniParser a bs <|> runMiniParser b bs

instance Functor MiniParser where
  fmap f a = MiniParser $ \ bs -> do
    (a', rest) <- runMiniParser a bs
    return (f a', rest)
  {-# INLINE fmap #-}

instance Applicative MiniParser where
  pure a = MiniParser $ \ !bs -> Just (a, bs)
  {-# INLINE pure #-}
  f <*> m =
    MiniParser $ \ !bs -> do
      (f', !rest) <- runMiniParser f bs
      (m', !rest') <- runMiniParser m rest
      return (f' m', rest')
  {-# INLINE (<*>) #-}

instance Monad MiniParser where
  m1 >>= m2 = MiniParser $ \ bs -> do
    (a, !rest) <- runMiniParser m1 bs
    runMiniParser (m2 a) rest
  {-# INLINE (>>=) #-}

parseError :: MiniParser a
parseError = MiniParser $ \_ -> Nothing
{-# INLINABLE parseError #-}

drawN :: Int64 -> MiniParser BL.ByteString
drawN n = MiniParser $ Just . BL.splitAt n
{-# INLINABLE drawN #-}

drawWord8 :: MiniParser Word8
drawWord8 = MiniParser $ BL.uncons
{-# INLINABLE drawWord8 #-}

drawInt32be :: MiniParser Int32
drawInt32be =
  fromIntegral <$> drawWord32be
{-# INLINABLE drawInt32be #-}

drawWord16be :: MiniParser Word16
drawWord16be = MiniParser $ \bs ->
  let (bs', rest) = BL.splitAt 4 bs in
    if BL.length bs' == 4 then
      let w1 = BL.index bs' 0
          w2 = BL.index bs' 1
      in
    -- Borrowed from Data.Binary.Get
      Just ( fromIntegral w1 `shiftl_w16` 8
          .|. fromIntegral w2
           , rest)
    else Nothing
{-# INLINABLE drawWord16be #-}

drawWord32be :: MiniParser Word32
drawWord32be = MiniParser $ \bs ->
  let (bs', rest) = BL.splitAt 4 bs in
    if BL.length bs' == 4 then
      let w1 = BL.index bs' 0
          w2 = BL.index bs' 1
          w3 = BL.index bs' 2
          w4 = BL.index bs' 3 in
        Just  ( fromIntegral w1 `shiftl_w32` 24
            .|. fromIntegral w2 `shiftl_w32` 16
            .|. fromIntegral w3 `shiftl_w32` 8
            .|. fromIntegral w4
              , rest)
    else
      Nothing
{-# INLINABLE drawWord32be #-}

drawWord64be :: MiniParser Word64
drawWord64be = MiniParser $ \bs ->
  let (bs', rest) = BL.splitAt 8 bs in
    if BL.length bs' == 8 then
      let w1 = BL.index bs' 0
          w2 = BL.index bs' 1
          w3 = BL.index bs' 2
          w4 = BL.index bs' 3
          w5 = BL.index bs' 4
          w6 = BL.index bs' 5
          w7 = BL.index bs' 6
          w8 = BL.index bs' 7
      in
        -- Borrowed from Data.Binary.Get
        Just (  fromIntegral w1 `shiftl_w64` 56
            .|. fromIntegral w2 `shiftl_w64` 48
            .|. fromIntegral w3 `shiftl_w64` 40
            .|. fromIntegral w4 `shiftl_w64` 32
            .|. fromIntegral w5 `shiftl_w64` 24
            .|. fromIntegral w6 `shiftl_w64` 16
            .|. fromIntegral w7 `shiftl_w64` 8
            .|. fromIntegral w8
             ,  rest)
    else
      Nothing
{-# INLINABLE drawWord64be #-}

type MP a = B.ByteString -> Int -> (Int, a)

parseWord8 :: MP Word8
parseWord8 bs !i = (i + 1, BU.unsafeIndex bs i)
{-# INLINABLE parseWord8 #-}

parseWord16be :: MP Word16
parseWord16be bs !i =
  (i + 2, fromIntegral w1 `shiftl_w16` 8 .|. fromIntegral w2)
  where
    w1 = BU.unsafeIndex bs (i + 0)
    w2 = BU.unsafeIndex bs (i + 1)
{-# INLINABLE parseWord16be #-}

parseInt32be :: MP Int32
parseInt32be bs !i =
  fromIntegral <$> parseWord32be bs i
{-# INLINABLE parseInt32be #-}

parseWord32be :: MP Word32
parseWord32be bs !i =
  (i + 4,
     fromIntegral w1 `shiftl_w32` 24
 .|. fromIntegral w2 `shiftl_w32` 16
 .|. fromIntegral w3 `shiftl_w32` 8
 .|. fromIntegral w4
  )
  where
    w1 = BU.unsafeIndex bs (i + 0)
    w2 = BU.unsafeIndex bs (i + 1)
    w3 = BU.unsafeIndex bs (i + 2)
    w4 = BU.unsafeIndex bs (i + 3)
{-# INLINABLE parseWord32be #-}

parseWord64be :: MP Word64
parseWord64be bs !i =
-- Borrowed from Data.Binary.Get
     ( i + 8
     ,  fromIntegral w1 `shiftl_w64` 56
    .|. fromIntegral w2 `shiftl_w64` 48
    .|. fromIntegral w3 `shiftl_w64` 40
    .|. fromIntegral w4 `shiftl_w64` 32
    .|. fromIntegral w5 `shiftl_w64` 24
    .|. fromIntegral w6 `shiftl_w64` 16
    .|. fromIntegral w7 `shiftl_w64` 8
    .|. fromIntegral w8
     )
  where
    w1 = BU.unsafeIndex bs (i + 0)
    w2 = BU.unsafeIndex bs (i + 1)
    w3 = BU.unsafeIndex bs (i + 2)
    w4 = BU.unsafeIndex bs (i + 3)
    w5 = BU.unsafeIndex bs (i + 4)
    w6 = BU.unsafeIndex bs (i + 5)
    w7 = BU.unsafeIndex bs (i + 6)
    w8 = BU.unsafeIndex bs (i + 7)
{-# INLINABLE parseWord64be #-}


-- Borrowed from Data.Binary.Get
------------------------------------------------------------------------
-- Unchecked shifts

shiftl_w16 :: Word16 -> Int -> Word16
shiftl_w32 :: Word32 -> Int -> Word32
shiftl_w64 :: Word64 -> Int -> Word64

shiftl_w16 (W16# w) (I# i) = W16# (w `uncheckedShiftL#`   i)
shiftl_w32 (W32# w) (I# i) = W32# (w `uncheckedShiftL#`   i)
shiftl_w64 (W64# w) (I# i) = W64# (w `uncheckedShiftL64#` i)
