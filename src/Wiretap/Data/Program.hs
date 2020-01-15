module Wiretap.Data.Program
  ( Program
  , fromFolder
  , empty
  , nullInst
  , findInstruction

  , Method(..)
  , Field(..)
  , Instruction(..)
  , instName
  , fieldName
  , methodName
  ) where

-- The programs of wiretap are represented in this module. This module therefore
-- contains all the static information about the program. For dynamic
-- information about the program see (Wiretap.Data.Event).

import           Data.Binary
import           Data.Binary.Get
import           Data.Binary.Put
import           GHC.Int
import           System.IO  (withFile, IOMode (ReadMode))

import qualified Data.IntMap.Strict          as IM
import           Data.Maybe

import qualified Data.ByteString.Lazy as BL
import           System.FilePath

data Program = Program
  { _fieldNames        :: !(IM.IntMap String)
  , _instructionNames  :: !(IM.IntMap String)
  , _methodNames       :: !(IM.IntMap String)
  , _instructionFolder :: !(Maybe FilePath)
  }

fromFolder :: FilePath -> IO Program
fromFolder folder = do
  fields <- IM.map cleanField <$> intMapFromFile "fields.txt"
  instructions <- intMapFromFile "instructions.txt"
  methods <- intMapFromFile "methods.txt"
  return $ Program
    { _fieldNames = fields
    , _instructionNames = instructions
    , _instructionFolder = Just $ folder </> "instructions"
    , _methodNames = methods
    }
  where
    intMapFromFile f =
      IM.fromAscList . zip [0..] . lines <$> readFile (folder </> f)

    cleanField = takeWhile (/= ':') . tail . dropWhile (/= '.')

empty :: Program
empty =
  Program { _fieldNames = IM.empty
          , _instructionNames = IM.empty
          , _instructionFolder = Nothing
          , _methodNames = IM.empty
          }

findInstruction :: Program -> Int32 -> Int32 -> IO Instruction
findInstruction p tid oid =
  case _instructionFolder p of
    Just folder -> do
      withFile (folder </> show tid) ReadMode $ \h -> do
        bs <- BL.hGetContents h
        return $! (decode $ BL.drop (fromIntegral oid * 4) bs)
    Nothing -> do
      return nullInst

instName :: Program -> Instruction -> String
instName p i =
  fromMaybe missing $ IM.lookup (fromIntegral $ instructionId i) (_instructionNames p)
  where missing = "<missing-" ++ show (instructionId i) ++ ">"

fieldName :: Program -> Field -> String
fieldName p f =
  fromMaybe missing $ IM.lookup (fromIntegral $ fieldId f) (_fieldNames p)
  where missing = "<missing-" ++ show (fieldId f) ++ ">"

methodName :: Program -> Method -> String
methodName p m =
  fromMaybe missing $ IM.lookup (fromIntegral $ methodId m) (_methodNames p)
  where missing = "<missing-" ++ show (methodId m) ++ ">"

newtype Instruction =
  Instruction
  { instructionId :: Int32
  } deriving (Show, Eq, Ord)

instance Binary Instruction where
  put = putInt32be . instructionId
  get = Instruction <$> getInt32be

nullInst :: Instruction
nullInst = Instruction (-1)

newtype Field = Field
  { fieldId :: Int32
  } deriving (Show, Eq, Ord)

instance Binary Field where
  put = putInt32be . fieldId
  get = Field <$> getInt32be

newtype Method = Method
  { methodId :: Int32
  } deriving (Show, Eq, Ord)

instance Binary Method where
  put = putInt32be . methodId
  get = Method <$> getInt32be
