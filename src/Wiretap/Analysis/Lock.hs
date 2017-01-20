{-# LANGUAGE BangPatterns #-}
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
  let shared = uncurry (sharedLocks lm) $ toEventPair c
  if M.null shared
    then return c
    else left $ M.assocs shared

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
  { dedgeLock    :: Ref
  , dedgeAcquire :: UE
  , dedgeRequest :: UE
  } deriving (Show, Ord, Eq)

-- | A deadlock is two deadlock edges where (operation . request . a) == Request
-- | (lock . b) and (operation . request . b) == Request (lock a).
data Deadlock = Deadlock
  { edgeA :: DeadlockEdge
  , edgeB :: DeadlockEdge
  } deriving (Show, Ord, Eq)

instance Candidate Deadlock where
  toEventPair dl =
    (dedgeRequest . edgeA $ dl, dedgeRequest . edgeB $ dl)


-- A non reentrant lock has does not have it's own lock in
-- the it's lockset.
nonreentrant :: LockMap -> UE -> Ref -> Bool
nonreentrant lm e l =
  M.notMember l (lm ! e)


deadlockCandidates'
  :: PartialHistory h
  => h
  -> LockMap
  -> [Deadlock]
deadlockCandidates' h lm =
  catMaybes $ L.map getDeadlock pairs
  where
    pairs = combinations $
      L.filter (uncurry $ nonreentrant lm) $ onRequests (,) h

    -- Takes two requests and their locks and tries to create
    -- two conflicting edges.
    getDeadlock ((a, la), (b, lb)) = do
      -- Can't be the same thread
      guard $ threadOf a /= threadOf b
      -- Can't try to get the same lock
      guard $ lb /= la

      Deadlock <$> getEdge la b <*> getEdge lb a

      where threadOf = thread . normal

    -- From a lock an a request figure out if there is a
    -- happens before access from acquire that acquired the
    -- lock to the request.
    getEdge l req = do
      acq <- M.lookup l $ lm ! req
      return $ DeadlockEdge l acq req

deadlockCandidates :: PartialHistory h
  => M.Map Thread [(Ref, UE)]
  -> h
  -> ([Deadlock], M.Map Thread [(Ref, UE)])
deadlockCandidates s h =
  over _1 (deadlockCandidates' h) $ locksetSimulation s h
