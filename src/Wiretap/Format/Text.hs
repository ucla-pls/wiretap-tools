{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
module Wiretap.Format.Text where

import Numeric

import qualified Data.List as L

import Data.Unique

import Wiretap.Data.Event
import Wiretap.Data.Program

newtype PP a = PP { item :: a }

pp :: Show (PP a) => a -> String
pp = show . PP

instance Show (PP Thread) where
  show (PP (Thread t)) =
    "t" ++ show t

instance Show (PP Event) where
  show (PP e) =
    let op = show (order e) in
    pp (thread e) ++ "." ++ (replicate (4 - length op) '0') ++ op ++ " " ++ pp (operation e)

instance Show (PP Operation) where
  show (PP o) =
    L.intercalate " " $ case o of
      Synch i-> ["synch", show i]

      Fork t -> ["fork",  pp t]
      Join t -> ["join", pp t]

      Request r -> ["request", pp r]
      Acquire r -> ["acquire", pp r]
      Release r -> ["release", pp r]

      Read l v -> ["read", pp l, pp v]
      Write l v -> ["write", pp l, pp v]

      Begin -> ["begin"]
      End -> ["end"]

instance Show (PP Location) where
  show (PP l) =
    case l of
      Dynamic r f ->
        pp f ++ "@" ++ pp r
      Static f ->
        pp f ++ "@S"
      Array r i ->
        pp r ++ "[" ++ show i ++ "]"

instance Show (PP Value) where
  show (PP v) =
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
  show (PP f) = show f

instance Show (PP Ref) where
  show (PP (Ref r)) =
    "r!" ++ showHex r ""

instance Show (PP a) => Show (PP (Unique a)) where
  show (PP (Unique i e)) =
    let s = show i in
    (replicate (5 - length s) ' ') ++ s ++ " | " ++ pp e

instance Show (PP a) => Show (PP [a]) where
  show (PP as) =
    show $ map PP as
