module Wiretap.Analysis.Deadlock where

import           Control.Lens               (over, _1)
import           Control.Monad
import qualified Data.List                  as L
import qualified Data.Map                   as M
import qualified Data.Set                   as S
import           Data.Unique
import           Data.Maybe

import           Wiretap.Analysis.Lock
import           Wiretap.Analysis.Permute
import           Wiretap.Data.Event
import           Wiretap.Data.History
import           Wiretap.Graph

data LockEdgeLabel = LockEdgeLabel
  { edgeLock    :: Ref
  , edgeAcquire :: UE
  } deriving (Show, Ord, Eq)

data DeadlockEdge = DeadlockEdge
  { edgeFrom  :: UE
  , edgeLabel :: LockEdgeLabel
  , edgeTo    :: UE
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
          go e' (DeadlockEdge e (LockEdgeLabel l acq) e' : edges ) rest


deadlockCandidates :: PartialHistory h
  => M.Map Thread [(Ref, UE)]
  -> h
  -> ([Deadlock], M.Map Thread [(Ref, UE)])
deadlockCandidates s h =
  over _1 (deadlockCandidates' h) $ locksetSimulation s h
