{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE DeriveFunctor #-}
module Wiretap.Data.Proof
  ( Candidate(..), Proof(..), (~/>), (~/~), Prover, CandidateSet
  ) where

import Data.Unique
import Wiretap.Data.History
import Data.PartialOrder
import Data.Set as S
import Wiretap.Analysis.LIA

(~/>) :: UE -> UE -> Bool
(~/>) (Unique _ a) (Unique _ b) =
  not (a !< b)

(~/~) :: UE -> UE -> Bool
(~/~) a b =
  a ~/> b && b ~/> a

type CandidateSet = S.Set UE

class Candidate a where
  candidateSet :: a -> CandidateSet

data Proof a = Proof
  { candidate   :: a
  , constraints :: LIA UE
  , evidence    :: [UE]
  } deriving Functor

type Prover = forall h . PartialHistory h => h -> CandidateSet -> LIA UE
