{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
module Wiretap.Format.Text
  ( pp
  , PP (..)
  )
where

import Numeric

import qualified Data.List as L

import Data.Unique

import Wiretap.Data.Event
import Wiretap.Data.Program

data PP a = PP !Program !a

pp :: Show (PP a) => Program -> a -> String
pp p = show . PP p

instance Show (PP Thread) where
  showsPrec _ (PP _ t) = showsThread t

showsThread :: Thread -> ShowS
showsThread (Thread t )=
  showChar 't' . shows t
{-# INLINEABLE showsThread #-}

instance Show (PP Event) where
  showsPrec _ (PP p e) =
    showsThread (thread e)
    . showChar '.' 
    . shows (order e)
    . showChar ' '
    . shows (PP p (operation e))
  {-# INLINE showsPrec #-}

spp :: Show (PP a) => Program -> a -> ShowS
spp p = shows . PP p
{-# INLINE spp #-}

instance Show (PP Operation) where
  showsPrec _ (PP p o) =
    case o of
      Synch i-> showString "synch" . showChar ' ' . shows i

      Fork t -> showString "fork" . showChar ' ' . showsThread t
      Join t -> showString "join" .showChar ' ' . showsThread t

      Request r -> showString "request" .showChar ' ' . showsRef r
      Acquire r -> showString "acquire" . showChar ' ' . showsRef r
      Release r -> showString "release" . showChar ' ' . showsRef r

      Begin -> showString "begin"
      End -> showString "end"

      Branch -> showString "branch"

      Enter r m -> showString "enter" . showChar ' ' . showsRef r . showChar ' ' . spp p m 

      Read l v -> showString "read" . showChar ' ' . spp p l . showChar ' ' . showsValue v
      Write l v -> showString "write" . showChar ' ' . spp p l . showChar ' ' .  showsValue v
  {-# INLINE showsPrec #-}

instance Show (PP Location) where
  showsPrec _ (PP p l) =
    case l of
      Dynamic r f ->
        showsRef r . showChar '.' . spp p f
      Static f ->
        spp p f
      Array r i ->
        showsRef r . showChar '[' . shows i . showChar ']'
  {-# INLINE showsPrec #-}

instance Show (PP Value) where
  showsPrec _ (PP _ v) = showsValue v

showsValue :: Value -> ShowS
showsValue value =
  case value of
    Byte v -> showString "i8!" . showHex v 
    Char v -> shows v
    Short v -> showString "i16!" . showHex v 
    Integer v -> showString "i32!" . showHex v
    Long v -> showString "i64!" . showHex v 
    Float v -> showString "f32!" . showHex v 
    Double v -> showString "f64!" .  showHex v 
    Object v -> showString "r!" . showHex v 
{-# INLINE showsValue #-}

instance Show (PP Field) where
  show (PP p f) = fieldName p f

instance Show (PP Method) where
  show (PP p m) = methodName p m

instance Show (PP Ref) where
  showsPrec _ (PP _ r) = showsRef r

showsRef :: Ref -> ShowS
showsRef (Ref r) =
  showString "r!" . showHex r
{-# INLINE showsRef #-}

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

instance (Show (PP a), Show (PP b)) => Show (PP (a, b)) where
  show (PP p (a, b)) =
    show (PP p a , PP p b)
