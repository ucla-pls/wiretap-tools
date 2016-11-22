module Wiretap.Analysis.RaceCandidates where

import Prelude hiding (reads)

import Debug.Trace

import qualified Data.List          as L
import qualified Data.Map           as M

import Data.Function (on)

import Control.Monad


import           Wiretap.Data.Event

data Collection = Collection
  { reads :: [(Location, Event)]
  , writes :: [(Location, Event)]
  } deriving (Show)

add :: Collection -> Event -> Collection
add c e =
  case operation e of
    Read l _  -> c { reads = (l,e) : reads c }
    Write l _ -> c { writes = (l,e) : writes c }
    _         -> c

readwrites es = (reads c, writes c)
  where c = L.foldl' add (Collection [] []) es

groupOnFst :: Eq a
  => [(a, b)]
  -> [(a, [b])]
groupOnFst []         = []
groupOnFst ((a,b):xs) =
  (a, b : map snd ys) : groupOnFst zs
  where (ys, zs) = span ((==) a . fst) xs

combinations :: [a] -> [(a, a)]
combinations (a:as) =
  [(a,a') | a' <- as] ++ combinations as
combinations []     = []

crossproduct :: [a] -> [b] -> [(a, b)]
crossproduct =
  liftM2 $ \a b -> (a,b)

raceCandidates :: [Event] -> [(Event, Event)]
raceCandidates events = candidates
  where
    candidates = concatMap snd . locations $ events

locations :: [Event] -> [(Location, [(Event, Event)])]
locations events =
  filter (not . L.null . snd) . map combineLocation $ byLocation writes
  where
    combineLocation (l, ws) =
      (l, filter (\(a, b) -> thread a /= thread b) pairs)
      where
        pairs =
          combinations ws ++ crossproduct ws (maybe [] id $ M.lookup l readsByLocation)

    readsByLocation =
      M.fromAscList $ byLocation reads

    byLocation =
      groupOnFst . L.sortOn fst

    (reads, writes) = readwrites events
