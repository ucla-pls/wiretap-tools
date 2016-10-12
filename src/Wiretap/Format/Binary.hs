module Wiretap.Format.Binary where

import System.IO

import GHC.Int (Int64)

import qualified Data.ByteString.Lazy as BL

import qualified Data.Vector.Unboxed as V
import qualified Data.List as L

import Data.Binary.Get
import Data.Word
import Data.Bits

import Wiretap.Data.Event
import Wiretap.Data.Program

-- Read the binary format.
-- (...) = (.) . (.)
-- {-# INLINE (...) #-}

readEvents :: Thread -> Handle -> IO [Event]
readEvents t handle = do
  bytes <- BL.hGetContents handle
  return $ (Event t 0 nullInst Begin): getEvents t 1 bytes

getEvents :: Thread -> Int -> BL.ByteString -> [Event]
getEvents t i bytes =
  case BL.uncons bytes of
    Just (w, o) ->
      let (eventData, rest) = BL.splitAt (size w) o in
      readEvent t i w eventData : getEvents t (i + 1) rest
    Nothing -> [Event t i nullInst End]
  where
    size = eventSize -- V.unsafeIndex sizes . fromIntegral

sizes :: V.Vector Int64
sizes = V.fromList $ L.map eventSize [ 0 .. 255 ]


eventSize :: Word8 -> Int64
eventSize w =
  4 + case w .&. 0x0f of
        6 -> 8 + valueSize w
        7 -> 8 + valueSize w
        8 -> 0; 9 -> 0
        _ -> 4
  where
    {-# INLINE valueSize #-}
    valueSize w =
      case (w .&. 0xf0) `shiftR` 4 of
        0 -> 1
        1 -> 1
        2 -> 2
        3 -> 4
        4 -> 8
        5 -> 4
        6 -> 8
        7 -> 4
        a -> 0

readEvent :: Thread -> Int -> Word8 -> BL.ByteString -> Event
readEvent t i w bytes =
  Event
    { thread = t
    , order = i
    , operation = readOperation w oper
    , instruction = runGet (getInstruction) inst
    }
  where
    (inst, oper) = BL.splitAt 4 bytes
    getInstruction =
      Instruction . fromIntegral <$> getWord32be

readOperation :: Word8 -> BL.ByteString -> Operation
readOperation w bytes =
  case w .&. 0x0f of

    1 -> -- Fork
      Fork $ runGet getThread bytes

    2 -> -- Join
      Join $ runGet getThread bytes

    3 -> -- Request
      Request $ runGet getRef bytes

    4 -> -- Acquire
      Acquire $ runGet getRef bytes

    5 -> -- Release
      Release $ runGet getRef bytes

    6 -> -- Read
      let (locs, rest) = BL.splitAt 8 bytes in
      Read (runGet getLocation locs) (runGet (getValue w) rest)

    7 -> -- Write
      let (locs, rest) = BL.splitAt 8 bytes in
      Write (runGet getLocation locs) (runGet (getValue w) rest)

    a ->
      error $ "Problem in getOperation: "
               ++ show a ++ " from: "
               ++ show w

  where
    getThread =
      Thread . fromIntegral <$> getWord32be

    getRef =
      Ref <$> getWord32be

    getField =
      Field . fromIntegral <$> getWord32be

    getLocation = do
      object <- getRef
      if pointer object == 0
        then Static <$> getField
        else Array object . fromIntegral <$> getWord32be

    getValue :: Word8 -> Get Value
    getValue operation =
      case (operation .&. 0xf0) `shiftR` 4 of
        0 -> -- Byte
          Byte <$> getWord8
        1 -> -- Char
          Char <$> getWord8
        2 -> -- Short
          Short <$> getWord16be
        3 -> -- Int
          Integer <$> getWord32be
        4 -> -- Long
          Long <$> getWord64be
        5 -> -- Float
          Float <$> getWord32be
        6 -> -- Double
          Double <$> getWord64be
        7 -> -- Object
          Object <$> getWord32be
        a ->
          error $ "Problem in getValue: " ++ show a
