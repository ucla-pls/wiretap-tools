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
  , Deadlock(..)

  , LockEdgeLabel (..)
  , DeadlockEdge (..)
  )
where

import           Wiretap.Data.Event
import           Wiretap.Data.History
import           Wiretap.Data.Proof
import           Wiretap.Utils
import           Wiretap.Graph

-- import           Debug.Trace

import qualified Data.List                  as L
import qualified Data.Map.Strict            as M
import           Data.Maybe
import           Data.Unique
import qualified Data.Set   as S

-- import Debug.Trace


import           Control.Lens               (over, _1)
import           Control.Monad
import           Control.Monad.State.Strict
import           Control.Monad.Trans.Either

-- import           Debug.Trace


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
      let l = fromMaybe [] $ M.lookup t m
      let rs = f l
      put $! M.insert t rs m
      return l

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

-- A non reentrant lock has does not have it's own lock in
-- the its own lockset.
nonreentrant :: LockMap -> UE -> Ref -> Bool
nonreentrant lm e l =
  M.notMember l (lm ! e)


data LockEdgeLabel = LockEdgeLabel
  { edgeLock :: Ref
  , edgeAcquire :: UE
  } deriving (Show, Ord, Eq)

data DeadlockEdge = DeadlockEdge
  { edgeFrom :: UE
  , edgeLabel :: LockEdgeLabel
  , edgeTo :: UE
  } deriving (Show, Ord, Eq)

-- | A deadlock is a list of deadlock edges such that. The edge To of
-- | i is the edge from of (i + 1 % n).
data Deadlock = Deadlock
  { deadlockCycle :: S.Set DeadlockEdge
  } deriving (Show, Ord, Eq)

instance Candidate Deadlock where
  candidateSet =
    S.map edgeFrom . deadlockCycle

-- edge :: LockMap -> UE -> (UE, Ref) -> Maybe LockEdgeLabel
-- edge lockmap e (req, l) = do
--   guard $ threadOf e /= threadOf req
--   acq <- M.lookup l $ lockmap ! e
--   return $ LockEdgeLabel l acq

-- edge' :: LockMap -> (UE, Ref) -> (UE, Ref) -> Maybe LockEdgeLabel
-- edge' lockmap (req', l) b = do
--   guard $ l /= snd b;
--   edge lockmap req' b

deadlockCandidates'
  :: PartialHistory h
  => h
  -> LockMap
  -> [Deadlock]
deadlockCandidates' h lockmap =
  concatMap fromCycle cycles'
  where
    requests =
      L.filter (uncurry $ nonreentrant lockmap) $ onRequests (,) h

    cycles' =
      cycles (M.keys requestGroups) $ \(r1, t1, ls) (r2, t2, _) -> do
        guard $ r1 /= r2
        guard $ t1 /= t2
        guard $ r2 `S.member` ls
        return r2

    requestGroups :: M.Map (Ref, Thread, S.Set Ref) [UE]
    requestGroups =
      M.fromListWith (++) $ map toLockItem requests

    toLockItem (r, ref_) =
      ((ref_, threadOf r, (S.fromList (M.keys $ lockmap ! r))), [r])

    fromCycle :: Cycle (Ref, Thread, S.Set Ref) Ref -> [Deadlock]
    fromCycle cyc = do
      c <- explode cyc
      return $ Deadlock (S.fromList c)

    explode :: Cycle (Ref, Thread, S.Set Ref) Ref -> [[DeadlockEdge]]
    explode [] = []
    explode cyc@((n, _, _):_) = do
      e <- fromJust $ M.lookup n requestGroups
      go e [] cyc
      where
        go _ edges [] = [edges]
        go e edges ((_, l, n'):rest) = do
          e' <- fromJust $ M.lookup n' requestGroups
          let acq = fromJust . M.lookup l $ lockmap ! e
          go e' ( DeadlockEdge e (LockEdgeLabel l acq) e':edges) rest


deadlockCandidates :: PartialHistory h
  => M.Map Thread [(Ref, UE)]
  -> h
  -> ([Deadlock], M.Map Thread [(Ref, UE)])
deadlockCandidates s h =
  over _1 (deadlockCandidates' h) $ locksetSimulation s h
