module Wiretap.Data.Program where

-- The programs of wiretap are represented in this module. This module therefor
-- contains all the static information about the program. For dynamic
-- information about the program see (Wiretap.Data.Event).

import           Data.Binary
import           Data.Binary.Put
import           Data.Binary.Get
import           GHC.Int

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
