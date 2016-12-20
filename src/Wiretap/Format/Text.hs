{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
module Wiretap.Format.Text where

import Numeric

import qualified Data.List as L

import Data.Unique

import Wiretap.Data.Event
import Wiretap.Data.Program

data PP a = PP
  { program :: Program
  , item :: a
  }

pp :: Show (PP a) => Program -> a -> String
pp p = show . PP p

instance Show (PP Thread) where
  show (PP p (Thread t)) =
    "t" ++ show t

instance Show (PP Event) where
  show (PP p e) =
    let op = show (order e) in
    pp p (thread e) ++ "." ++ (replicate (4 - length op) '0') ++ op ++ " " ++ pp p (operation e)

instance Show (PP Operation) where
  show (PP p o) =
    L.intercalate " " $ case o of
      Synch i-> ["synch", show i]

      Fork t -> ["fork",  pp p t]
      Join t -> ["join", pp p t]

      Request r -> ["request", pp p r]
      Acquire r -> ["acquire", pp p r]
      Release r -> ["release", pp p r]

      Read l v -> ["read", pp p l, pp p v]
      Write l v -> ["write", pp p l, pp p v]

      Begin -> ["begin"]
      End -> ["end"]

instance Show (PP Location) where
  show (PP p l) =
    case l of
      Dynamic r f ->
        pp p r ++ "." ++ pp p f
      Static f ->
        pp p f
      Array r i ->
        pp p r ++ "[" ++ show i ++ "]"

instance Show (PP Value) where
  show (PP p v) =
    case v of
      Byte v -> "i8!" ++ showHex v ""
      Char v -> show v
      Short v -> "i16!" ++ showHex v ""
      Integer v -> "i32!" ++ showHex v ""
      Long v -> "i64!" ++ showHex v ""
      Float v -> "f32!" ++ showHex v ""
      Double v -> "f64!" ++ showHex v ""
      Object v -> "r!" ++ showHex v ""

instance Show (PP Field) where
  show (PP p f) = fieldName p f

instance Show (PP Ref) where
  show (PP p (Ref r)) =
    "r!" ++ showHex r ""

instance Show (PP Instruction) where
  show (PP p i) =
    instName p i

instance Show (PP a) => Show (PP (Unique a)) where
  show (PP p (Unique i e)) =
    let s = show i in
    (replicate (5 - length s) ' ') ++ s ++ " | " ++ pp p e

instance Show (PP a) => Show (PP [a]) where
  show (PP p as) =
    L.intercalate "\n" $ map (pp p) as
