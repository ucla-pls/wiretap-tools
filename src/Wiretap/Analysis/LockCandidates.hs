module Wiretap.Analysis.LockCandidates where

import qualified Data.Map as M
import qualified Data.List as L

import Wiretap.Data.Event

import Control.Monad
import Control.Monad.State

simulate :: Event -> State (M.Map Thread [Ref]) [Ref]
simulate e =
  case operation e of
     Acquire l -> do
       updateAndGet (l:)
     Release l -> do
       updateAndGet (L.delete l)
     _ ->
       gets $ maybe [] id . M.lookup (thread e)

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

lockset :: M.Map Thread [Ref] -> [Event] -> [(Event, [Ref])]
lockset m es = zip es locks
  where locks = fst $ runState (mapM simulate es) m

lockset' :: [Event] -> [(Event, [Ref])]
lockset' = lockset M.empty
