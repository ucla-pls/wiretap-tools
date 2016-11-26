module Wiretap.Analysis.Lock where

import qualified Data.List           as L
import qualified Data.Map            as M

import           Data.Unique
import           Wiretap.Utils

import           Wiretap.Data.Event
import           Wiretap.Data.History

import           Control.Monad
import           Control.Lens
import           Control.Monad.State
import           Data.Foldable

requests :: PartialHistory h => h -> [(Ref, Unique Event)]
requests =
  simulate collect []
  where
    collect e =
      case operation . normal $ e of
        Request l -> ((l, e):)
        _         -> id

locksetSimulation :: PartialHistory h
  => M.Map Thread [Ref]
  -> h
  -> (UMap [Ref], M.Map Thread [Ref])
locksetSimulation state hist =
  over _1 fromUniques $ runState (simulateM step hist) state
  where
    step e =
      let t = thread . normal $ e in
      case operation . normal $ e of
        Acquire l -> updateAndGet t (l:)
        Release l -> updateAndGet t (L.delete l)
        _         -> gets $ maybe [] id . M.lookup t

    updateAndGet :: Thread -> ([Ref] -> [Ref]) -> State (M.Map Thread [Ref]) [Ref]
    updateAndGet t f = do
      m <- get
      let
        bt = M.lookup t m
        rs = case bt of
          Just lst -> f lst
          Nothing  -> f []
      put $ M.insert t rs m
      return rs

seperateLocks :: UMap [Ref] -> (Unique Event, Unique Event) -> Bool
seperateLocks u (a, b) =
  L.null $ L.intersect (u ! a) (u ! b)

lockfilter
  :: UMap [Ref]
  -> [(Unique Event, Unique Event)]
  -> [(Unique Event, Unique Event)]
lockfilter lockset =
  L.filter (seperateLocks lockset)

lockset :: PartialHistory h
  => h
  -> [(Event, [Ref])]
lockset h =
  map (\e -> (normal e, locks ! e)) $ enumerate h
  where locks = fst $ locksetSimulation M.empty h


deadlockCandidates :: PartialHistory h
  => h
  -> [(Unique Event, Unique Event)]
deadlockCandidates h =
  map (tmap snd) $ L.filter sharingLocks pairs
  where
    pairs = combinations (requests h)
    sharingLocks ((l1, a), (l2, b)) =
      l2 `L.elem` (lockset ! a) && l1 `L.elem` (lockset ! b)

    lockset = fst $ locksetSimulation M.empty h
    tmap f (a,b) = (f a, f b)
