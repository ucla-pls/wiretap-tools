{-# LANGUAGE DeriveFunctor     #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE RankNTypes        #-}
module Wiretap.Data.Proof
  ( Candidate(..), Proof(..), (~/>), (~/~), Prover, CandidateSet
  ) where

import           Data.PartialOrder
import           Data.Set             as S
import           Data.List            as L
import           Data.Unique
import           Wiretap.Analysis.MHL
import           Wiretap.Data.History
import           Wiretap.Data.Program
import           Wiretap.Data.Event
import           Wiretap.Format.Text

(~/>) :: UE -> UE -> Bool
(~/>) (Unique _ a) (Unique _ b) =
  not (a !< b)

(~/~) :: UE -> UE -> Bool
(~/~) a b =
  a ~/> b && b ~/> a

type CandidateSet = S.Set UE

class Candidate a where
  candidateSet :: a -> CandidateSet
  prettyPrint :: Program -> a -> IO String
  prettyPrint p a =
      L.intercalate " " . L.sort . L.map (pp p) <$>
        mapM (instruction p . normal) (S.toList $ candidateSet a)


data Proof a = Proof
  { candidate   :: a
  , constraints :: MHL UE
  , evidence    :: [UE]
  } deriving Functor

type Prover = forall h . PartialHistory h => h -> CandidateSet -> MHL UE
