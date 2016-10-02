module Wiretap.Format.Binary where

import System.IO

import qualified Data.ByteString.Lazy as BL

import Data.Binary.Get
import Data.Word
import Data.Bits

import Wiretap.Data.Event
import Wiretap.Data.Program

-- Read the binary format.
(...) = (.) . (.)

readEvents :: Thread -> Handle -> IO [Event]
readEvents t handle = do
  bytes <- BL.hGetContents handle
  return . ((Event t 0 nullInst Begin):) $ runGet (getEvents t 1) bytes

getEvents :: Thread -> Int -> Get [Event]
getEvents t i = do
  empty <- isEmpty
  if empty
    then return [ Event t i nullInst End ]
    else do
      event <- getEvent t i
      rest <- getEvents t (i + 1)
      return (event : rest)

getEvent :: Thread -> Int -> Get Event
getEvent t i = do
  operation <- getWord8
  instruction <- getInstruction
  let newEvent = Event t i instruction
  case operation .&. 0x0f of

    1 -> -- Fork
      newEvent . Fork <$> getThread

    2 -> -- Join
      newEvent . Join <$> getThread

    3 -> -- Request
      newEvent . Request <$> getRef

    4 -> -- Acquire
      newEvent . Acquire <$> getRef

    5 -> -- Release
      newEvent . Release <$> getRef

    6 -> -- Read
      newEvent ... Read <$> getLocation <*> getValue operation

    7 -> -- Write
      newEvent ... Write <$> getLocation <*> getValue operation

    a ->
      error $ "Problem in getEvent: " ++ show a ++ " from: " ++ show operation ++ " inst: " ++ show instruction

  where
    getThread =
      Thread . fromIntegral <$> getWord32be

    getRef =
      Ref <$> getWord32be

    getField =
      Field . fromIntegral <$> getWord32be

    getInstruction =
      Instruction . fromIntegral <$> getWord32be

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
