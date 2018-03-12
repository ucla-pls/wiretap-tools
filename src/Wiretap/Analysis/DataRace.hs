module Wiretap.Analysis.DataRace
  ( raceCandidates
  , sharedLocations
  , DataRace (..)
  ) where

import           Prelude                  hiding (reads)

import           Data.Function            (on)
import qualified Data.List                as L
import qualified Data.Map                 as M
import qualified Data.Set                 as S
import           Data.Unique

import Control.Monad (liftM2)

import           Wiretap.Data.Event
import           Wiretap.Data.History
import           Wiretap.Analysis.Permute
import           Wiretap.Utils

sharedLocations :: PartialHistory h
  => h
  -> [(Location, [(Unique Event, Unique Event)])]
sharedLocations h =
  filter (not . L.null . snd) . map combineLocation $ byLocation writes
  where
    combineLocation (l, ws) =
      (l, filter (uncurry ((/=) `on` threadOf)) pairs)
      where
        pairs =
          combinations ws ++ readwriteconflicts
        readwriteconflicts =
          crossproduct ws (concat $ M.lookup l readsByLocation)

    readsByLocation =
      M.fromDistinctAscList $ byLocation reads

    byLocation =
      groupOnFst . L.sortOn fst

    reads =
      onReads (\u (l, _) -> (l, u)) h

    writes =
      onWrites (\u (l, _) -> (l, u)) h

data DataRace = DataRace
  { location :: Location
  , eventA   :: UE
  , eventB   :: UE
  } deriving (Show, Eq)

instance Ord DataRace where
  compare = compare `on` (liftM2 (,) eventA eventB)

instance Candidate DataRace where
  candidateSet (DataRace _ a b) =
    S.fromList [a, b]

raceCandidates :: PartialHistory h
  => h
  -> [DataRace]
raceCandidates =
  concatMap toDataRaces . sharedLocations
  where
    toDataRaces (l, events) =
      map (uncurry $ DataRace l) events
