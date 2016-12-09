{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TemplateHaskell  #-}
module Wiretap.Analysis.Permute where

import           Prelude                hiding (reads)

import           Control.Lens
import           Control.Monad.IO.Class
import qualified Data.List              as L
import qualified Data.Map               as M
import qualified Data.Set               as S

import           Debug.Trace

import           Data.PartialOrder
import           Data.Unique

import           Wiretap.Analysis.LIA
import           Wiretap.Data.Event
import           Wiretap.Data.History
import           Wiretap.Utils
import           Wiretap.Format.Text

type UE = Unique Event

sc :: PartialHistory h => h -> LIA UE
sc h =
  And [ totalOrder es | es <- M.elems $ byThread h ]

mhb :: PartialHistory h => h -> LIA UE
mhb h =
  And
  [ And
    [ And
      [ f ~> b
      | f <- forks, b <- begins
      ]
    , And
      [ e ~> j
      | e <- ends, j <- joins
      ]
    ]
  | (joins, forks, begins, ends) <- mhbEventsByThread
  ]
  where
    mhbEventsByThread =
      M.elems $ simulate step M.empty h
    step u@(Unique _ e) =
      case operation e of
        Join t -> update u _1 t
        Fork t -> update u _2 t
        Begin  -> update u _3 $ thread e
        End    -> update u _4 $ thread e
        _      -> id
    update u l =
      updateDefault ([], [], [], []) (over l (u:))

{-| this method expects h to be a true history, so that by thread any lock acquired
will be released by the same thread, and that there is no cross releasing

TODO: Re-entreant locks.
TODO: RWC for the lock.
TODO: Remainders, what do we use them for.
-}
lc :: PartialHistory h => h -> LIA UE
lc h =
  And
  [ And
    [ And
      [ Or [ r ~> a',  r' ~> a ]
      | ((a, r), (a', r')) <-
          combinations lockPairs
      , a ~/> r', r' ~/> a
      ]
    , And
      [ r ~> a
      | ((_, r), a) <-
          crossproduct lockPairs (def [] $ M.lookup l remainders)
      , r ~/> a
      ]
    ]
  | (l, lockPairs) <- lockPairsSet
  ]
  where
    (allLocks, allRemainder) =
      unpair . M.elems $ simulate step M.empty h

    lockPairsSet =
      groupUnsortedOnFst $ concat allLocks

    remainders =
      mapOnFst $ concat allRemainder

    step u@(Unique _ e) =
      case operation e of
        Acquire l -> update (acq l) (thread e)
        Release l -> update rel (thread e)
        _         -> id
      where
        acq l (pairs, stack) =
          (pairs, (l,u):stack)
        rel (pairs, stack) =
          case stack of
            (l, acq):stack' -> ((l, (acq, u)):pairs, stack')
            [] -> error "Can't release a lock that has not been acquired"

    update = updateDefault ([], [])

rwc :: PartialHistory h => h -> LIA UE
rwc h =
  And
  [ Or
    [ And $
      [ Or [ w' ~> w, r ~> w']
      | (_, w') <- writes
      , w' /= w , w' ~/> w, r ~/> w'
      ]
      ++ if w ~/> r then [w ~> r] else []
    | (v', w) <- writes
    , v' == v
    , r ~/> w
    ]
  | (reads, writes) <- readAndWritesBylocation
  , (v, r) <- reads
  , not . L.null $ (filter ((v ==) . fst )) writes
  ]
  where
    readAndWritesBylocation =
      M.elems $ simulate step M.empty h
    step u@(Unique _ e) =
      case operation e of
        Read l v  -> update (v, u) _1 l
        Write l v -> update (v, u) _2 l
        _         -> id
    update u f = updateDefault ([], []) (over f (u:))

-- | returns the control flow to a single event, this flow jumps threads, with
-- | the Join and Fork events.
controlFlow
  :: PartialHistory h
  => h
  -> UE
  -> [UE]
controlFlow h u@(Unique _ e) =
  snd $ simulateReverse step (S.singleton (thread e), []) priorEvents
  where
  priorEvents =
    takeWhile (/= u) $ enumerate h

  step u'@(Unique _ e') s@(threads, events) =
    case operation e' of
      Fork t | t `S.member` threads ->
        (thread e' `S.insert` threads, u':events)
      Join t | thread e' `S.member` threads ->
        (t `S.insert` threads, u':events)
      otherwise | thread e' `S.member` threads ->
        (threads, u':events)
      otherwise -> s

-- | For a given event, choose all the reads, and locks, that needs to be
-- | consistent for this event to also be consistent.
controlFlowDependencies
  :: PartialHistory h
  => h
  -> UE
  -> [UE]
controlFlowDependencies h u@(Unique _ e) =
  dependencies
  where
    (dependencies, _, _) =
      simulateReverse step ([], initialRefs, False) priorEvents

    priorEvents =
       controlFlow h u

    initialRefs =
      case operation e of
        Write l (Object v) ->
          maybe S.empty S.singleton (ref l) `S.union` S.singleton (Ref v)
        Read l _ ->
          maybe S.empty S.singleton (ref l)
        Acquire r ->
          S.singleton r
        Release r ->
          S.singleton r
        Request r ->
          S.singleton r
        otherwise ->
          S.empty

    step u'@(Unique i e') s@(events, refs, branch) =
      case operation e' of
        Read _ _ | branch ->
          over _1 (u':) s
        Read _ (Object v) | Ref v `S.member` refs  ->
          over _1 (u':) s
        Acquire r ->
          (u':events, r `S.insert` refs, branch)
        Release r ->
          (u':events, refs, branch)
        otherwise ->
          s

controlFlowConsistency
  :: PartialHistory h
  => [UE]
  -> h
  -> LIA UE
controlFlowConsistency us h =
  And [ consistent (S.empty) u | u <- us ]
  where
  consistent visited u' =
    if S.null depends then
      lc $ S.toAscList visited
    else
      And $ onReads readConsitency (S.toList depends)
    where
    depends =
      S.fromAscList (controlFlowDependencies h u') S.\\ visited

    visited' =
      visited `S.union` depends

    readConsitency r (l, v) =
      Or
      [ And $ consistent visited' w : w ~> r :
        [ Or [ w' ~> w, r ~> w']
        | (_, w') <- rwrites
        , w' /= w , w' ~/> w, r ~/> w'
        ]
      | (v', w) <- rwrites
      , v' == v , r ~/> w
      ]
      where
        rwrites = writes M.! l


  writes =
    mapOnFst $ onWrites (\w (l, v) -> (l, (v, w))) h

(~/>) (Unique _ a) (Unique _ b) =
  not (a !< b)

{-| permute takes partial history and two events, if the events can be arranged
next to each other return. -}
permute
  :: (PartialHistory h, MonadIO m)
  => h
  -> (UE, UE)
  -> m (Maybe [UE])
permute h (a, b) = do
  solution <- solve (enumerate h) (pcontraints h (a, b))
  return $ withPair (a, b) <$> solution

pcontraints h (a, b) =
  And $ Eq a b :
    ([ sc, mhb, controlFlowConsistency [a, b]] <*> [h])

contraints
  :: PartialHistory h
  => h
  -> LIA UE
contraints h =
  And $ [ sc, mhb, lc] <*> [h]
