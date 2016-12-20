module Wiretap.Analysis.Lock
  ( deadlockCandidates
  , locksetSimulation
  )
where

import qualified Data.List                as L
import qualified Data.Map                 as M

import           Data.Maybe
import           Data.Unique
import           Wiretap.Utils

import           Wiretap.Analysis.Permute
import           Wiretap.Data.Event
import           Wiretap.Data.History

import           Control.Lens
import           Control.Monad
import           Control.Monad.State
import           Data.Foldable

-- | Lockset simulation, walks over a history and calculates the lockset
-- | of each event. The function produces a tuple of an assignment a lockset
-- | to every event, and the hold lockset of every thread.
-- | Notice this function only works if locks are local, and if there no re-entrant
-- | lock.
locksetSimulation :: PartialHistory h
  => M.Map Thread [(Ref, UE)]
  -> h
  -> (UniqueMap [(Ref, UE)], M.Map Thread [(Ref, UE)])
locksetSimulation state history =
  (fromUniques locksets, state')
  where
    (locksets, state') = runState (simulateM step history) state

    step u@(Unique _ e) =
      case operation e of
        Acquire l ->
          updateAndGet t ((l,u):)
        Release l ->
          updateAndGet t $ L.filter ((l ==) . fst)
        otherwise ->
          gets $ fromMaybe [] . M.lookup t
      where t = thread e

    updateAndGet
      :: Thread
      -> ([(Ref, UE)] -> [(Ref, UE)])
      -> State (M.Map Thread [(Ref, UE)]) [(Ref,UE)]
    updateAndGet t f = do
      m <- get
      let rs = f . fromMaybe [] $ M.lookup t m
      put $ M.insert t rs m
      return rs

sharedLocks :: UniqueMap [(Ref, UE)] -> UE -> UE -> [(Ref, UE)]
sharedLocks u a b =
  L.intersect (u ! a) (u ! b)

locksetFilter
  :: (Candidate a, PartialHistory h)
  => h
  -> a
  -> Either String a
locksetFilter h =
  locksetFilter' $! lockMap h

locksetFilter'
  :: (Candidate a)
  => UniqueMap [(Ref, UE)]
  -> a
  -> Either String a
locksetFilter' lm a =
  case uncurry (sharedLocks lm) $ toEventPair a of
    [] -> Right a
    ls -> Left $ "Candidates shares lock " ++ show ls

lockMap h =
  fst $ locksetSimulation M.empty h

lockset :: PartialHistory h
  => h
  -> [(Event, [(Ref, UE)])]
lockset h =
  map (\e -> (normal e, locks ! e)) $ enumerate h
  where locks = fst $ locksetSimulation M.empty h

-- | A deadlock edge is proof that there is exist an happen-before edge from the
-- | acquirement of a lock to a request for another lock.
data DeadlockEdge = DeadlockEdge
  { lock :: Ref
  , acquire :: UE
  , request :: UE
  } deriving (Show)

-- | A deadlock is two deadlock edges where (operation . request . a) == Request
-- | (lock . b) and (operation . request . b) == Request (lock a).
data Deadlock = Deadlock
  { a :: DeadlockEdge
  , b :: DeadlockEdge
  } deriving (Show)

instance Candidate Deadlock where
  toEventPair dl =
    (request . a $ dl, request . b $ dl)

deadlockCandidates :: PartialHistory h
  => h
  -> M.Map Thread [(Ref, UE)]
  -> ([Deadlock], M.Map Thread [(Ref, UE)])
deadlockCandidates h state =
  (catMaybes $ L.map getDeadlock pairs, state')
  where
    pairs = combinations $ onRequests (,) h

    getDeadlock ((a, la), (b, lb)) =
      liftM2 Deadlock (getEdge la b) (getEdge lb a)

    getEdge l rel = do
      (_, acq) <- L.find ((l ==) . fst) $ lm ! rel
      return $ DeadlockEdge l acq rel

    (lm, state') = locksetSimulation state h
