{-# LANGUAGE FlexibleContexts #-}
module Wiretap.Analysis.DataRace where

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

import           Wiretap.Analysis.Lock
import           Wiretap.Data.History
import           Wiretap.Utils
import           Wiretap.Data.Event


readwrites :: PartialHistory h
  => h
  -> ([(Location, Unique Event)], [(Location, Unique Event)])
readwrites =
  simulate acc ([], [])
  where
    acc e =
      case operation . normal $ e of
        Read l _  -> over _1 ((l,e):)
        Write l _ -> over _2 ((l,e):)
        _         -> id

raceCandidates :: PartialHistory h
  => h
  -> [(Unique Event, Unique Event)]
raceCandidates h = candidates
  -- lockfilter lockset candidates
  where
    candidates = concatMap snd . sharedLocations $ h
    lockset = fst $ locksetSimulation M.empty h

sharedLocations :: PartialHistory h
  => h
  -> [(Location, [(Unique Event, Unique Event)])]
sharedLocations h =
  filter (not . L.null . snd) . map combineLocation $ byLocation writes
  where
    combineLocation (l, ws) =
      (l, filter teq pairs)
      where
        pairs =
          combinations ws ++ readwriteconflicts
        readwriteconflicts =
          crossproduct ws (concat $ M.lookup l readsByLocation)
        teq (a, b) =
          thread (normal a) /= thread (normal b)
    readsByLocation =
      M.fromDistinctAscList $ byLocation reads

    byLocation =
      groupOnFst . L.sortOn fst

    (reads, writes) = readwrites h
