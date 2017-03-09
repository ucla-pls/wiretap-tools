{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE LambdaCase #-}
module Wiretap.Analysis.Lock
  ( deadlockCandidates
  , deadlockCandidates'
  , locksetSimulation
  , locksetFilter
  , locksetFilter'
  , lockset
  , nonreentrant
  , LockMap
  , DeadlockEdge(..)
  , Deadlock(..)
  )
where

import           Wiretap.Data.Event
import           Wiretap.Data.History
import           Wiretap.Data.Proof
import           Wiretap.Utils

import qualified Data.List                  as L
import qualified Data.Map.Strict            as M
import           Data.Maybe
import           Data.Unique
import qualified Data.Graph   as G
import qualified Data.Set   as S

import           Control.Lens               (over, _1)
import           Control.Monad
import           Control.Monad.State.Strict
import           Control.Monad.Trans.Either

type LockMap = UniqueMap (M.Map Ref UE)

-- | Lockset simulation, walks over a history and calculates the lockset
-- | of each event. The function produces a tuple of an assignment a lockset
-- | to every event, and the hold lockset of every thread.
-- | Notice this function only works if locks are local, and if there no re-entrant
-- | lock.
locksetSimulation :: PartialHistory h
  => M.Map Thread [(Ref, UE)]
  -> h
  -> (LockMap, M.Map Thread [(Ref, UE)])
locksetSimulation !s history =
  (fromUniques $ map (fmap toLockMap) lockstacks, state')
  where
    (lockstacks, !state') = runState (simulateM step history) s

    filterFirst p = L.deleteBy (const p) undefined

    step u@(Unique _ e) =
      case operation e of
        Acquire l ->
          updateAndGet t ((l,u):)
        Release l ->
          updateAndGet t . filterFirst $ (l ==) . fst
        _ ->
          gets $ fromMaybe [] . M.lookup t
      where t = thread e

    updateAndGet
      :: Thread
      -> ([(Ref, UE)] -> [(Ref, UE)])
      -> State (M.Map Thread [(Ref, UE)]) [(Ref,UE)]
    updateAndGet t f = do
      m <- get
      let rs = f . fromMaybe [] $ M.lookup t m
      put $! M.insert t rs m
      return rs

    -- | toLockMap converges the lock stack to a map where all locks reference
    -- | points to the first event to grab it.
    toLockMap :: [(Ref, UE)] -> M.Map Ref UE
    toLockMap =
      M.fromList

sharedLocks :: LockMap -> UE -> UE -> M.Map Ref (UE, UE)
sharedLocks u a b =
  M.intersectionWith (,) (u ! a) (u ! b)

locksetFilter
  :: (Candidate a, PartialHistory h, Monad m)
  => h
  -> a
  -> EitherT [(Ref, (UE,UE))] m a
locksetFilter h =
  locksetFilter' $ lockMap h

locksetFilter'
  :: (Candidate a, Monad m)
  => LockMap
  -> a
  -> EitherT [(Ref, (UE,UE))] m a
locksetFilter' lm c = do
 case L.concatMap (M.assocs) intersections of
   [] -> return c
   ls -> left $ ls
 where
   intersections =
     L.map (uncurry (sharedLocks lm)) $ combinations (S.toList $ candidateSet c)

lockMap
  :: PartialHistory h
  => h
  -> LockMap
lockMap =
  fst . locksetSimulation M.empty

lockset :: PartialHistory h
  => h
  -> [(Event, (M.Map Ref UE))]
lockset h =
  map (\e -> (normal e, locks ! e)) $ enumerate h
  where locks = lockMap h

-- | A deadlock edge is proof that there is exist an happen-before edge from the
-- | acquirement of a lock to a request for another lock.
data DeadlockEdge = DeadlockEdge
  { edgeFrom    :: UE
  , edgeLock    :: Ref
  , edgeAcquire :: UE
  , edgeTo      :: UE
  } deriving (Show, Ord, Eq)

edge :: LockMap -> UE -> (UE, Ref) -> Maybe DeadlockEdge
edge lockmap e (req, l) = do
  guard $ threadOf e /= threadOf req
  acq <- M.lookup l $ lockmap ! req
  return $ DeadlockEdge e l acq req

edge' :: LockMap -> (UE, Ref) -> (UE, Ref) -> Maybe DeadlockEdge
edge' lockmap (req', _) b =
  edge lockmap req' b

-- | A deadlock is a list of deadlock edges such that. The edge To of
-- | i is the edge from of (i + 1 % n).
data Deadlock = Deadlock
  { deadlockCycle :: [UE]
  } deriving (Show, Ord, Eq)

instance Candidate Deadlock where
  candidateSet = S.fromList . deadlockCycle

-- A non reentrant lock has does not have it's own lock in
-- the its own lockset.
nonreentrant :: LockMap -> UE -> Ref -> Bool
nonreentrant lm e l =
  M.notMember l (lm ! e)

myscc :: forall node. Ord node => [(node, node)] -> [[node]]
myscc edges =
  L.concatMap (\case G.CyclicSCC ls -> [ls]; _ -> []) $
     G.stronglyConnComp gEdges
  where
    gEdges = L.map (\(a, es) -> (a, a, es)) $ groupUnsortedOnFst edges

deadlockCandidates'
  :: PartialHistory h
  => h
  -> LockMap
  -> [Deadlock]
deadlockCandidates' h lockmap =
  map Deadlock . myscc $ map (\e -> (edgeFrom e, edgeTo e)) edges
  where
    requests =
      L.filter (uncurry $ nonreentrant lockmap) $ onRequests (,) h

    edges =
      catMaybes $ map (uncurry $ edge' lockmap) $ combinations requests


deadlockCandidates :: PartialHistory h
  => M.Map Thread [(Ref, UE)]
  -> h
  -> ([Deadlock], M.Map Thread [(Ref, UE)])
deadlockCandidates s h =
  over _1 (deadlockCandidates' h) $ locksetSimulation s h
