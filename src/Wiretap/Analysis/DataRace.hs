module Wiretap.Analysis.DataRace
  ( raceCandidates
  , sharedLocations
  , DataRace (..)
  ) where

import           Prelude                         hiding (reads)

import           Debug.Trace

import qualified Data.List                       as L
import qualified Data.Map                        as M

import           Data.Function                   (on)
import           Data.Traversable
import           Data.Foldable
import           Data.Unique
import           Control.Monad
import           Control.Lens

import           Wiretap.Analysis.Permute
import           Wiretap.Data.History
import           Wiretap.Utils
import           Wiretap.Data.Event

sharedLocations :: PartialHistory h
  => h
  -> [(Location, [(Unique Event, Unique Event)])]
sharedLocations h =
  filter (not . L.null . snd) . map combineLocation $ byLocation writes
  where
    combineLocation (l, ws) =
      (l, filter (uncurry (~/~)) pairs)
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
      onReads (\u (l, v) -> (l, u)) h

    writes =
      onWrites (\u (l, v) -> (l, u)) h

data DataRace = DataRace
  { location :: Location
  , a :: UE
  , b :: UE
  } deriving (Show, Eq)

instance Ord DataRace where
  compare = compare `on` toEventPair

instance Candidate DataRace where
  toEventPair (DataRace l a b) =
    (a, b)

raceCandidates :: PartialHistory h
  => h
  -> [DataRace]
raceCandidates =
  concatMap toDataRaces . sharedLocations
  where
    toDataRaces (l, events) =
      map (uncurry $ DataRace l) events
