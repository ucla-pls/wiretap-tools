module Wiretap.Data.Event where

import Data.Word

import qualified Wiretap.Data.Program as Program

-- The dynamic information of the program is represented here.

newtype Thread = Thread { threadId :: Int } deriving (Show, Eq, Ord)

data Event = Event { thread :: !Thread
                   , order :: !Int
                   , instruction :: !Program.Instruction
                   , operation :: !Operation
                   } deriving (Show, Eq)

newtype Ref = Ref { pointer :: Word32 } deriving (Show, Eq)

data Location = Dynamic Ref Program.Field
              | Static Program.Field
              | Array Ref Int
              deriving (Show, Eq)

data Value = Byte Word8
           | Char Word8
           | Short Word16
           | Integer Word32
           | Long Word64
           | Float Word32
           | Double Word64
           | Object Word32
           deriving (Show, Eq)

data Operation = Acquire Ref
               | Request Ref
               | Release Ref

               | Fork Thread
               | Join Thread

               | Read Location Value
               | Write Location Value

               | Begin
               | End

               deriving (Show, Eq)


