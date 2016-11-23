module Wiretap.Analysis.RaceCandidates where

import           Prelude                         hiding (reads)

import           Debug.Trace

import qualified Data.List                       as L
import qualified Data.Map                        as M

import           Data.Function                   (on)
import           Data.Traversable
import           Data.Foldable
import           Data.Unique

import           Wiretap.Analysis.LockCandidates

import           Control.Monad


import           Wiretap.Data.Event

data Collection a = Collection
  { reads  :: [(Location, a)]
  , writes :: [(Location, a)]
  } deriving (Show)

add
  :: (a -> Event)
  -> Collection a
  -> a
  -> Collection a
add f c e =
  case operation . f $ e of
    Read l _  -> c { reads = (l,e) : reads c }
    Write l _ -> c { writes = (l,e) : writes c }
    _         -> c

readwrites :: Foldable t
  => (a -> Event)
  -> t a
  -> ([(Location, a)], [(Location, a)])
readwrites f es = (reads c, writes c)
  where c = foldl' (add f) (Collection [] []) es

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

raceCandidates :: UniqueMap Event -> [(Unique Event, Unique Event)]
raceCandidates events =
  lockfilter events (M.empty) candidates
  where
    candidates = concatMap snd . locations $ events

locations :: UniqueMap Event -> [(Location, [(Unique Event, Unique Event)])]
locations events =
  filter (not . L.null . snd) . map combineLocation $ byLocation writes
  where
    combineLocation (l, ws) =
      (l, filter (\(a, b) -> thread (normal a) /= thread (normal b)) pairs)
      where
        pairs =
          combinations ws ++ readwriteconflicts
        readwriteconflicts =
          crossproduct ws (maybe [] id $ M.lookup l readsByLocation)

    readsByLocation =
      M.fromAscList $ byLocation reads

    byLocation =
      groupOnFst . L.sortOn fst

    (reads, writes) = readwrites normal (toVector events)
