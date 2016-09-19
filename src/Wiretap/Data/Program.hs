module Wiretap.Data.Program where

-- The programs of wiretap are represented in this module. This module therefor
-- contains all the static information about the program. For dynamic
-- information about the program see (Wiretap.Data.Event).


newtype Instruction = Instruction { instructionId :: Int } deriving (Show, Eq)

newtype Field = Field { fieldId :: Int } deriving (Show, Eq)
