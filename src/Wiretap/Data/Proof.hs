{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE DeriveFunctor #-}
module Wiretap.Data.Proof
  ( Candidate(..), Proof(..), (~/>), (~/~), Prover
  ) where

import Data.Unique
import Wiretap.Data.History
import Data.PartialOrder
import Wiretap.Analysis.LIA

(~/>) :: UE -> UE -> Bool
(~/>) (Unique _ a) (Unique _ b) =
  not (a !< b)

(~/~) :: UE -> UE -> Bool
(~/~) a b =
  a ~/> b && b ~/> a


class Candidate a where
  toEventPair :: a -> (UE, UE)

data Proof a = Proof
  { candidate   :: a
  , constraints :: LIA UE
  , evidence    :: [UE]
  } deriving Functor

type Prover = forall h . PartialHistory h => h -> (UE, UE) -> LIA UE
