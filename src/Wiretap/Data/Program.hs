module Wiretap.Data.Program where

-- The programs of wiretap are represented in this module. This module therefor
-- contains all the static information about the program. For dynamic
-- information about the program see (Wiretap.Data.Event).

import           Data.Binary
import           Data.Binary.Get
import           Data.Binary.Put
import           GHC.Int

import qualified Data.IntMap     as IM
import           Data.Maybe

import           System.FilePath
import qualified Data.ByteString.Lazy  as BL

data Program = Program
  { _fieldNames       :: IM.IntMap String
  , _instructionNames :: IM.IntMap String
  , _instructionFolder :: Maybe FilePath
  }

fromFolder :: FilePath -> IO Program
fromFolder folder = do
  fields <- IM.map cleanField <$> intMapFromFile "fields.txt"
  instructions <- intMapFromFile "instructions.txt"
  return $ Program
    { _fieldNames = fields
    , _instructionNames = instructions
    , _instructionFolder = Just $ folder </> "instructions"
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
          }

findInstruction :: Program -> Int32 -> Int32 -> IO Instruction
findInstruction p tid oid =
  case _instructionFolder p of
    Just folder -> do
      bs <- BL.readFile (folder </> show tid)
      return . decode $ BL.drop (fromIntegral oid * 4) bs
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

newtype Instruction =
  Instruction
  { instructionId :: Int32
  } deriving (Show, Eq, Ord)

instance Binary Instruction where
  put = putInt32be . instructionId
  get = Instruction <$> getInt32be

nullInst = Instruction (-1)

newtype Field = Field
  { fieldId :: Int32
  } deriving (Show, Eq, Ord)

instance Binary Field where
  put = putInt32be . fieldId
  get = Field <$> getInt32be
