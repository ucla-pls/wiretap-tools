module Wiretap.Analysis.LockCandidates where

import qualified Data.List           as L
import qualified Data.Map            as M

import           Data.Unique

import           Wiretap.Data.Event

import           Control.Monad
import           Control.Monad.State
import           Data.Foldable


requests
  :: Foldable t
  => (a -> Event)
  -> t a
  -> [(Ref, a)]
requests f es =
  foldl' collect [] es
  where
    collect es e =
      case operation . f $ e of
        Request l -> (l, e) : es
        _         -> es

simulateStep :: Event -> State (M.Map Thread [Ref]) [Ref]
simulateStep e =
  case operation e of
     Acquire l -> updateAndGet (l:)
     Release l -> updateAndGet (L.delete l)
     _         -> gets $ maybe [] id . M.lookup (thread e)
  where
    updateAndGet :: ([Ref] -> [Ref]) -> State (M.Map Thread [Ref]) [Ref]
    updateAndGet f = do
      m <- get
      let
        bt = M.lookup (thread e) m
        rs = case bt of
          Just lst -> f lst
          Nothing  -> f []
      put $ M.insert (thread e) rs m
      return rs

simulate :: Traversable t
  => t Event
  -> M.Map Thread [Ref]
  -> t [Ref]
simulate es =
  fst . runState (mapM simulateStep es)

lockfilter
  :: UniqueMap Event
  -> M.Map Thread [Ref]
  -> [(Unique Event, Unique Event)]
  -> [(Unique Event, Unique Event)]
lockfilter es m = L.filter notSharingLocks
  where
    notSharingLocks (a, b) =
      L.null $ L.intersect (lockset ! a) (lockset ! b)

    lockset :: UniqueMap [Ref]
    lockset = simulate es m

lockset :: M.Map Thread [Ref] -> [Event] -> [(Event, [Ref])]
lockset m es = zip es $ simulate es m

lockset' :: [Event] -> [(Event, [Ref])]
lockset' = lockset M.empty

lockCandidates
  :: UniqueMap Event
  -> [(Unique Event, Unique Event)]
lockCandidates events =
  map (\(a,b) -> (snd a, snd b)) $ L.filter sharingLocks pairs
  where
    rs = requests normal (toVector events)
    pairs = combinations rs

    sharingLocks ((l1, a), (l2, b)) =
      l2 `L.elem` (lockset ! a) && l1 `L.elem` (lockset ! b)

    lockset = simulate events M.empty

    combinations (a:as) =
      [(a,a') | a' <- as] ++ combinations as
    combinations []     = []
