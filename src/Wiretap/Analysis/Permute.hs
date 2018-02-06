{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE DeriveFunctor    #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TemplateHaskell  #-}
module Wiretap.Analysis.Permute
  ( dirk
  , rvpredict
  , said
  , free
  , none
  , permute

  , refsOnly
  , branchOnly
  , valuesOnly

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
import           Data.PartialOrder

import           Wiretap.Data.Event
import           Wiretap.Data.Proof
import           Wiretap.Data.History

import           Wiretap.Analysis.Lock

import           Wiretap.Utils

-- import           Debug.Trace

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
-- lc :: PartialHistory h => h -> LIA UE
-- lc h =
--   And
--   [ And
--     [ And
--       [ Or [ r ~> a',  r' ~> a ]
--       | ((a, r), (a', r')) <-
--           combinations lockPairs
--       , a ~/> r', r' ~/> a
--       ]
--     , And
--       [ r ~> a
--       | ((_, r), a) <-
--           crossproduct lockPairs (def [] $ M.lookup l remainders)
--       , r ~/> a
--       ]
--     ]
--   | (l, lockPairs) <- lockPairsSet
--   ]
--   where
--     (allLocks, allRemainder) =
--       unpair . M.elems $ simulate step M.empty h

--     lockPairsSet =
--       groupUnsortedOnFst $ concat allLocks

--     remainders =
--       mapOnFst $ concat allRemainder

--     step u@(Unique _ e) =
--       case operation e of
--         Acquire l -> update (acqf l) (thread e)
--         Release _ -> update relf (thread e)
--         _         -> id
--       where
--         acqf l (pairs, stack) =
--           (pairs, (l,u):stack)
--         relf (pairs, stack) =
--           case stack of
--             (l, acq):stack' -> ((l, (acq, u)):pairs, stack')
--             [] -> error "Can't release a lock that has not been acquired"

--     update = updateDefault ([], [])

-- rwc :: PartialHistory h => h -> LIA UE
-- rwc h =
--   And
--   [ Or
--     [ And $
--       [ Or [ w' ~> w, r ~> w']
--       | (_, w') <- writes
--       , w' /= w , w' ~/> w, r ~/> w'
--       ]
--       ++ if w ~/> r then [w ~> r] else []
--     | (v', w) <- writes
--     , v' == v
--     , r ~/> w
--     ]
--   | (reads, writes) <- readAndWritesBylocation
--   , (v, r) <- reads
--   , not . L.null $ (filter ((v ==) . fst )) writes
--   ]
--   where
--     readAndWritesBylocation =
--       M.elems $ simulate step M.empty h
--     step u@(Unique _ e) =
--       case operation e of
--         Read l v  -> update (v, u) _1 l
--         Write l v -> update (v, u) _2 l
--         _         -> id
--     update u f = updateDefault ([], []) (over f (u:))

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

data ValueSet = ValueSet
  { vsRefs :: S.Set Ref
  , vsValues :: Bool
  , vsBranch :: Bool
  } deriving (Eq, Show)

instance Monoid ValueSet where
  mempty = ValueSet S.empty False False
  mappend x y =
    ValueSet
      (vsRefs x `S.union` vsRefs y)
      (vsValues x || vsValues y)
      (vsBranch x || vsBranch y)

fromRef :: Ref -> ValueSet
fromRef r =
  ValueSet (S.singleton r) False False

fromLocation :: Location -> ValueSet
fromLocation l =
  case l of
    Dynamic r _ -> fromRef r
    Array r _ -> (fromRef r) { vsValues = True }
    _ -> mempty

fromValue :: Value -> ValueSet
fromValue v =
  case v of
    Object r -> fromRef (Ref r)
    _ -> mempty { vsValues = True }

fromBranch :: ValueSet
fromBranch =
  mempty { vsBranch = True }

-- | Get all refs known by the event at the moment of execution.
-- TODO: Fix problem with write
valuesOf :: UE -> ValueSet
valuesOf (Unique _ e) =
  case operation e of
    Write l _ ->
      fromLocation l
    Read l _ ->
      fromLocation l
    Acquire r ->
      fromRef r
    Release r ->
      fromRef r
    Request r ->
      fromRef r
    Branch ->
      fromBranch
    Enter r _ | pointer r /= 0 ->
      fromRef r
    _ ->
      mempty

cfdFree
  :: PartialHistory h
  => h
  -> ValueSet
  -> UE
  -> [UE]
cfdFree h _ u =
  simulateReverse step [] (controlFlow h u)
  where
    step u'@(Unique _ e') events =
      case operation e' of
        Acquire _ ->
          u':events
        _ ->
          events

cfdSaid
  :: PartialHistory h
  => h
  -> ValueSet
  -> UE
  -> [UE]
cfdSaid h _ u =
  simulateReverse step [] (controlFlow h u)
  where
    step u'@(Unique _ e') events =
      case operation e' of
        Read _ _ ->
          u':events
        Acquire _ ->
          u':events
        _ ->
          events

-- | For a given event, choose all the reads, and locks, that needs to be
-- | consistent for this event to also be consistent.
cfdDirk
  :: PartialHistory h
  => h
  -> ValueSet
  -> UE
  -> [UE]
cfdDirk h v u =
  simulateReverse step ([], valuesOf u `joinV` (v `joinV` (S.empty, False))) (controlFlow h u)  ^. _1
  where
    step u'@(Unique _ e') (events, vs@(refs, branch)) =
      let events' =
            case operation e' of
              Read _ _ | branch ->
                u':events
              Read _ (Object v') | Ref v' `S.member` refs  ->
                u':events
              Acquire _ ->
                u':events
              _ ->
                events
      in (events', valuesOf u' `joinV` vs)

    joinV (ValueSet r1 vs b) (r2, b2) =
      (r1 `S.union` r2, vs || b || b2)

cfdNoBranch
  :: PartialHistory h
  => h
  -> ValueSet
  -> UE
  -> [UE]
cfdNoBranch h v u =
  simulateReverse step ([], valuesOf u `joinV` (v `joinV` (S.empty, False))) (controlFlow h u)  ^. _1
  where
    step u'@(Unique _ e') (events, vs@(refs, branch)) =
      let events' =
            case operation e' of
              Read _ _ | branch ->
                u':events
              Read _ (Object v') | Ref v' `S.member` refs  ->
                u':events
              Acquire _ ->
                u':events
              _ ->
                events
      in (events', valuesOf u' `joinV` vs)

    joinV (ValueSet r1 vs _) (r2, b2) =
      (r1 `S.union` r2, b2)

cfdValuesOnly
  :: PartialHistory h
  => h
  -> ValueSet
  -> UE
  -> [UE]
cfdValuesOnly h v u =
  simulateReverse step ([], valuesOf u `joinV` (v `joinV` False)) (controlFlow h u)  ^. _1
  where
    step u'@(Unique _ e') (events, branch) =
      let events' =
            case operation e' of
              Read _ _ | branch ->
                u':events
              Acquire _ ->
                u':events
              _ ->
                events
      in (events', valuesOf u' `joinV` branch)

    joinV (ValueSet r vs b) b2 =
      (vs || b2)

cfdBranchOnly
  :: PartialHistory h
  => h
  -> ValueSet
  -> UE
  -> [UE]
cfdBranchOnly h v u =
  simulateReverse step ([], valuesOf u `joinV` (v `joinV` False)) (controlFlow h u)  ^. _1
  where
    step u'@(Unique _ e') (events, branch) =
      let events' =
            case operation e' of
              Read _ _ | branch ->
                u':events
              Acquire _ ->
                u':events
              _ ->
                events
      in (events', valuesOf u' `joinV` branch)

    joinV (ValueSet r vs b) b2 =
      (vs || b || b2)

-- | For a given event, choose all the reads, and locks, that needs to be
-- | consistent for this event to also be consistent.
cfdRVPredict
  :: PartialHistory h
  => h
  -> ValueSet
  -> UE
  -> [UE]
cfdRVPredict h v u =
  simulateReverse step ([], (valuesOf u `joinV` (v `joinV` False))) (controlFlow h u)  ^. _1
  where
    step u'@(Unique _ e') (events, branch) =
      let events' =
            case operation e' of
                Read _ _ | branch ->
                  u':events
                Acquire _ ->
                  u':events
                _ ->
                  events
      in (events', valuesOf u' `joinV` branch)

    joinV (ValueSet r vs b) b2 =
      (not (S.null r)) || vs || b || b2

controlFlowConsistency
  :: PartialHistory h
  => LockMap
  -> (h -> ValueSet -> UE -> [UE])
  -> S.Set UE
  -> h
  -> LIA UE
controlFlowConsistency lm cfd us h =
  consistent (S.empty) (S.toList us) (S.unions [ cfc mempty u | u <- S.toList us ])
  where

  cfc v u =
    S.fromAscList (cfd h v u)

  consistent visited path deps =
    And [ And $ onReads readConsitency depends
        , And $ onNonReentrantAcquires lockConsitency depends
        ]
    where
    depends =
      deps S.\\ visited

    visited' =
      visited `S.union` deps

    readConsitency r (l, v) = -- | trace ("read: " ++ (ppEvent $ normal r) ++ " - " ++ show (length path)) True =
      -- Make sure that location has any writes
      case M.lookup l writes of
        Nothing ->
          -- If no writes assume that the read is consistent, ei. Reads what it
          -- is supposed to.
          And []
        Just rwrites ->
          case
            [ w
            | (v', w) <- rwrites
            , v' == v
            , r ~/> w
            , not $ any (!< w) (r:path)
            -- ^ If the write is after any of things in the path, then we know that
            -- it cannot be the write.
            ] of
            [] ->
              -- If there is no writes with the same value, that not is ordered
              -- after the read, then assume that the read must be reading
              -- something that was written before, ei. ordered before all other writes.
              -- NOTE: This assumption requires the history to be consistent.
              And [ r ~> w' | (_, w') <- rwrites ]
            rvwrites ->
              Or
              [ And $ consistent visited' (r:path) (cfc (fromValue v) w) : w ~> r :
                [ Or [ w' ~> w, r ~> w']
                | (_, w') <- rwrites
                , w' /= w , w' ~/> w, r ~/> w'
                ]
              | w <- rvwrites
              ]

    lockConsitency a ref' =
      -- Any acquire we test is already controlFlowConsistent, covered by the
      -- dependencies in the controlFlowConsistencies.
      And $
      [ Or $ [ a ~> a' ]
        ++ if not $ any (!< r') (a:path)
           then [ And [ r' ~> a
                      , consistent visited' (a:path) (cfc mempty r')
                      ]
                ]
           else []
      | (a', r') <- pairs
      , a' /= a, a' ~/> a, a' ~/> a
      ] ++
      [ a ~> a'
      | a' <- da
      , a' /= a, a' ~/> a, a' ~/> a
      ]
      -- case M.lookup a releaseFromAcquire of
      --   Just r ->
      --     And $
      --     [ Or
      --       [ And [ r' ~> a, consistent visited' (cfc (S.empty, False) r') ]
      --         -- ^ Either the other pair has to come before the the current pair
      --       , r ~> a'
      --         -- ^ Or it happened afterwards
      --       ]
      --     | (a', r') <- pairs
      --     , a' `S.member` visited'
      --     , a' /= a, a' ~/> a, a' ~/> a
      --     ] ++ map (~> a) dr
      --       -- ^ This might be superfluous.
      --       ++ map (r ~>) da
      --       -- ^ If we do not have an release, make sure that we are ordered after all
      --       -- other locks.
      --   Nothing ->
      --     And
      --     [ r' ~> a, consistent visited' (cfc (S.empty, False) r')
      --     | (a', r') <- pairs, r' ~/> a
      --     , a' `S.member` visited'
      --     ]
      where
        (_, pairs, da) = case M.lookup ref' lockPairsWithRef of
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

  -- releaseFromAcquire :: M.Map UE UE
  -- releaseFromAcquire =
  --   M.fromList . concatMap (^. _2) $ M.elems lockPairsWithRef

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
  -- traceM $ "Solving: " ++ show (liaSize cnts)
  solution <- solve (enumerate h) cnts
  case solution of
    Just hist ->
      return $ Proof a cnts (prefixContaining es hist)
    Nothing ->
      left cnts
  where
    es = (candidateSet a)
    cnts = prover h es

said :: LockMap -> Prover
said lm h es =
  And $ (equate es):
    ([ sc, mhb, controlFlowConsistency lm cfdSaid es] <*> [h])

dirk :: LockMap -> Prover
dirk lm h es =
  And $ (equate es):
    ([ sc, mhb, controlFlowConsistency lm cfdDirk es] <*> [h])

rvpredict :: LockMap -> Prover
rvpredict lm h es =
  And $ (equate es):
    ([ sc, mhb, controlFlowConsistency lm cfdRVPredict es] <*> [h])

refsOnly :: LockMap -> Prover
refsOnly lm h es =
  And $ (equate es) :
    ([ sc, mhb, controlFlowConsistency lm cfdNoBranch es] <*> [h])

branchOnly :: LockMap -> Prover
branchOnly lm h es =
  And $ (equate es) :
    ([ sc, mhb, controlFlowConsistency lm cfdBranchOnly es] <*> [h])

valuesOnly :: LockMap -> Prover
valuesOnly lm h es =
  And $ (equate es) :
    ([ sc, mhb, controlFlowConsistency lm cfdValuesOnly es] <*> [h])

free :: LockMap -> Prover
free lm h es =
  And $ (equate es) :
    ([ sc, mhb, controlFlowConsistency lm cfdFree es] <*> [h])

none :: h -> CandidateSet -> LIA UE
none _ es =
  equate es

equate :: CandidateSet -> LIA UE
equate es =
  And . L.map (uncurry Eq) $ combinations (S.toList es)
