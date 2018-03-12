{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE LambdaCase #-}
module Wiretap.Analysis.Lock
  ( locksetSimulation
  , lockset
  , lockMap
  , nonreentrant
  , lockOf
  , LockMap
  , sharedLocks
  )
where

import           Wiretap.Data.Event
import           Wiretap.Data.History
-- import           Wiretap.Utils
-- import           Wiretap.Graph

-- import           Debug.Trace

import qualified Data.List                  as L
import qualified Data.Map.Strict            as M
import           Data.Maybe
import           Data.Unique
-- import qualified Data.Set   as S

-- import Debug.Trace


-- import           Control.Lens               (over, _1)
-- import           Control.Monad
import           Control.Monad.State.Strict
-- import           Control.Monad.Trans.Either

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

lockOf :: UE -> Maybe Ref
lockOf (Unique _ e) =
  case operation e of
    Acquire l -> Just l
    Request l -> Just l
    Release l -> Just l
    _ -> Nothing
