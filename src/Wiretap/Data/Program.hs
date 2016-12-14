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

data Program = Program
  { _fieldNames       :: IM.IntMap String
  , _instructionNames :: IM.IntMap String
  }

fromFolder :: FilePath -> IO Program
fromFolder folder = do
  fields <- IM.fromAscList . zip [0..] . lines <$> readFile (folder </> "fields.txt")
  return $ Program { _fieldNames = fields, _instructionNames = IM.empty}

empty :: Program
empty =
  Program { _fieldNames = IM.empty
          , _instructionNames = IM.empty
          }

instName :: Program -> Instruction -> String
instName p i= fromMaybe missing $ IM.lookup (fromIntegral $ instructionId i) (_instructionNames p)
  where missing = "<missing-" ++ show (instructionId i) ++ ">"

fieldName :: Program -> Field -> String
fieldName p f = fromMaybe missing $ IM.lookup (fromIntegral $ fieldId f) (_fieldNames p)
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
