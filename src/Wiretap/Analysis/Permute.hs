{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE DeriveFunctor    #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TemplateHaskell  #-}
module Wiretap.Analysis.Permute
  ( kalhauge
  , said
  , free
  , none
  , permute

  , Candidate(..)
  , Proof(..)

  , (~/>)
  , (~/~)
  )
  where

import           Prelude                hiding (reads)

import           Control.Lens           hiding (none)
import           Control.Monad.IO.Class
import           Control.Monad.Trans.Either

import qualified Data.List              as L
import qualified Data.Map               as M
import qualified Data.Set               as S
import           Data.Unique
import           Data.Maybe (catMaybes)
import           Control.Monad

import           Wiretap.Analysis.LIA

import           Wiretap.Data.Event
import           Wiretap.Data.Proof
import           Wiretap.Data.History

import           Wiretap.Analysis.Lock

import           Wiretap.Utils

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
        Acquire l -> update (acqf l) (thread e)
        Release _ -> update relf (thread e)
        _         -> id
      where
        acqf l (pairs, stack) =
          (pairs, (l,u):stack)
        relf (pairs, stack) =
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

-- | Returns the control flow to a single event, this flow jumps threads, with
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
      _ | thread e' `S.member` threads ->
        (threads, u':events)
      _ -> s

-- | Get all refs known by the event at the moment of execution.
knownRefs :: UE -> S.Set Ref
knownRefs (Unique _ e) =
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
    _ ->
      S.empty

-- | For a given event, choose all the reads, and locks, that needs to be
-- | consistent for this event to also be consistent.
controlFlowDependencies
  :: PartialHistory h
  => h
  -> UE
  -> [UE]
controlFlowDependencies h u =
 simulateReverse step ([], knownRefs u, False) (controlFlow h u)  ^. _1
  where
    step u'@(Unique _ e') s@(events, refs, branch) =
      case operation e' of
        Read _ _ | branch ->
          over _1 (u':) s
        Read _ (Object v) | Ref v `S.member` refs  ->
          over _1 (u':) s
        Acquire r ->
          (u':events, r `S.insert` refs, branch)
        Branch ->
          set _3 True s
        Enter r _ | pointer r /= 0 ->
          over _2 (S.insert r) s
        _ ->
          s

controlFlowConsistency
  :: PartialHistory h
  => LockMap
  -> [UE]
  -> h
  -> LIA UE
controlFlowConsistency lm us h =
  consistent (S.empty) (S.unions [ cfc u | u <- us ])
  where
  cfc u = S.fromAscList (controlFlowDependencies h u)

  consistent visited deps =
    And [ And $ onReads readConsitency depends
        , And $ onNonReentrantAcquires lockConsitency depends
        ]
    where
    depends =
      deps S.\\ visited

    visited' =
      visited `S.union` depends

    readConsitency r (l, v) =
      -- Make sure that location has any writes
      case M.lookup l writes of
        Nothing ->
          -- If no writes assume that the read is consistent, ei. Reads what it
          -- is supposed to.
          And []
        Just rwrites ->
          case [ w | (v', w) <- rwrites, v' == v, r ~/> w ] of
            [] ->
              -- If there is no writes with the same value, that not is ordered
              -- after the read, then assume that the read must be reading
              -- something that was written before, ei. ordered before all other writes.
              -- NOTE: This assumption requires the history to be consistent.
              And [ r ~> w' | (_, w') <- rwrites ]
            rvwrites ->
              Or
              [ And $ consistent visited' (cfc w) : w ~> r :
                [ Or [ w' ~> w, r ~> w']
                | (_, w') <- rwrites
                , w' /= w , w' ~/> w, r ~/> w'
                ]
              | w <- rvwrites
              ]

    lockConsitency a ref' =
      -- Any acquire we test is already controlFlowConsistent, covered by the
      -- dependencies in the controlFlowConsistencies.
      case M.lookup a releaseFromAcquire of
        Just r ->
          And $
          [ Or
            [ r' ~> a
              -- ^ Either the other pair has to come before the the current pair
            , r ~> a'
              -- ^ Or it happened afterwards
            ]
          | (a', r') <- pairs
          , a' `S.member` visited'
          , a' /= a, a' ~/> a, a' ~/> a
          ] ++ map (~> a) dr
            -- ^ This might be superfluous.
            ++ map (r ~>) da
            -- ^ If we do not have an release, make sure that we are ordered after all
            -- other locks.
        Nothing ->
          And
          [ r' ~> a
          | (a', r') <- pairs, r' ~/> a
          , a' `S.member` visited'
          ]
      where
        (dr, pairs, da) = case M.lookup ref' lockPairsWithRef of
          Just pairs' -> pairs'
          Nothing ->
            error $ "The ref " ++ show ref'
                 ++ " has no lock-pairs. (Should not happen)"
  writes =
    mapOnFst $ onWrites (\w (l, v) -> (l, (v, w))) h

  onNonReentrantAcquires f deps =
    catMaybes $ onAcquires (\e l -> do
      guard $ nonreentrant lm e l
      return $ f e l
     ) deps

  locksWithRef =
    mapOnFst $ onEvent filter' (flip (,)) h
    where
      filter' (Acquire l) = Just l
      filter' (Release l) = Just l
      filter' _           = Nothing

  releaseFromAcquire :: M.Map UE UE
  releaseFromAcquire =
    M.fromList . concatMap (^. _2) $ M.elems lockPairsWithRef

  lockPairsWithRef :: M.Map Ref ([UE], [(UE, UE)], [UE])
  lockPairsWithRef =
    M.map (simulateReverse pairer ([], [], [])) locksWithRef
    where
      pairer u@(Unique _ e) s@(dr, pairs, da)=
        case operation e of
          Acquire _ ->
            case dr of
              []     -> (dr, pairs, u:da)
              [r]    -> ([], (u, r):pairs, da)
              _:dr'  -> (dr', pairs, da)
          Release _ ->
            (u:dr, pairs, da)
          _ -> s

{-| permute takes partial history and two events, if the events can be arranged
next to each other return. -}
permute
  :: (PartialHistory h, MonadIO m, Candidate a)
  => Prover
  -> h
  -> a
  -> EitherT (LIA UE) m (Proof a)
permute prover h a = do
  solution <- solve (enumerate h) cnts
  case solution of
    Just hist ->
      return $ Proof a cnts (withPair pair hist)
    Nothing ->
      left cnts
  where
    pair = toEventPair a
    cnts = prover h pair

said :: Prover
said h (a, b) =
  And $ Eq a b :
    ([ sc, mhb, lc, rwc ] <*> [h])

kalhauge :: LockMap -> Prover
kalhauge lm h (a, b) =
  And $ Eq a b :
    ([ sc, mhb, controlFlowConsistency lm [a, b]] <*> [h])

free :: Prover
free h (a, b) =
  And $ Eq a b :
    ([ sc, mhb ] <*> [h])

none :: h -> (UE, UE) -> LIA UE
none _ (a, b) =
  And [Eq a b]
