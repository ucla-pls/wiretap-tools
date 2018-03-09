{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE RankNTypes                 #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE TupleSections              #-}
{-# LANGUAGE UndecidableInstances       #-}
module Wiretap.Analysis.HBL
  ( HBL
  , HBL'
  , Logic (..)
  , HBLAtom (..)
  , (~>)
  , (~~)

  , orders
  , totalOrder
  , concurrent

  , toCNF
  , hblSize

   -- * Solver
  , HBLSolver (..)
  , Solver

  -- , evalZ3T
  -- , evalZ3TWithTimeout
  -- , fast
  -- , Z3T

  -- , HBLError (..)
  -- , MonadZ3

--  , solve
--  , toZ3
--  , setupHBL
  -- , setupHBL'
  )
where

import           Prelude                    hiding (product)

-- import qualified Data.IntMap.Strict         as IM
-- import qualified Data.List                  as L
-- import           Data.Unique
import           Control.Monad.IO.Class
import           Wiretap.Utils
import           Data.Foldable (Foldable, toList)

-- import Debug.Trace

-- | Any kind of logic starts with these three operators
data Logic a
  = And [Logic a]
  | Or [Logic a]
  | Atom !a
  deriving (Show, Eq)

-- | The happens before logic atoms
data HBLAtom s e
 = Order e e
 | Concur e e
 | Var s
 deriving (Show)

{-| HBL - Linear integer arithmetic -}
type HBL e = HBL' e e
type HBL' s e = Logic (HBLAtom s e)

hblSize :: HBL' s e -> Integer
hblSize hbl =
  case hbl of
    Atom _ -> 1
    And ls    -> 1 + sum (map hblSize ls)
    Or ls     -> 1 + sum (map hblSize ls)

infixl 8 ~>
(~>) :: e -> e -> HBL' s e
(~>) = Atom ... Order

infixl 8 ~~
(~~) :: e -> e -> HBL' s e
(~~) = Atom ... Concur

totalOrder :: [e] -> HBL' s e
totalOrder = And . pairwise (~>)

orders ::  [e] -> [e] -> HBL' s e
orders as bs = And [ a ~> b | a <- as, b <- bs ]

concurrent :: Foldable f => f e -> HBL' s e
concurrent as =
  And [ a ~~ b | (a, b) <- combinations (toList as)]

toCNF :: Logic a -> [[a]]
toCNF e =
  case e of
    Atom a -> [[ a ]]
    And es ->
      concatMap toCNF es
    Or es ->
      combinate (product (++)) $ map toCNF es

class (Monad m) => HBLSolver s e m where
  assert :: HBL' s e -> m ()
  -- declare :: s -> HBL' s e -> m ()
  sat :: HBL' s e -> m Bool

type Solver s e t m = forall a.
  (MonadIO m, HBLSolver s e (t m)) => [e] -> (s -> HBL' s e) -> (t m) a -> m a

