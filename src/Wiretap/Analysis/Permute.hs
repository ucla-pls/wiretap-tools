{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE DeriveFunctor    #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TemplateHaskell  #-}
{-# LANGUAGE BangPatterns  #-}
module Wiretap.Analysis.Permute
  ( cdfDirk
  , cdfRVPredict
  , cdfSaid
  , cdfFree
  , cdfRefsOnly
  , cdfBranchOnly
  , cdfValuesOnly

  , CDF

  , permute
  , permuteBatch
  , permuteBatch'

  , Candidate(..)
  , Proof(..)

  , (~/>)
  , (~/~)
  )
  where

import           Prelude                hiding (reads)
import           Control.Monad.Trans.Either

import           Control.Lens           hiding (none)
import           Control.Monad.IO.Class
import           Control.Monad.Trans.Class (lift)



import qualified Data.List              as L
import qualified Data.Map               as M
-- import qualified Data.IntMap               as IM
import qualified Data.Set               as S
import           Data.Unique

import Z3.Monad (evalZ3, MonadZ3)

import           Data.Maybe (catMaybes)
import           Control.Monad

import           Wiretap.Analysis.LIA
-- import           Data.PartialOrder

import           Wiretap.Data.Event
import           Wiretap.Data.Proof
import           Wiretap.Data.History

import           Wiretap.Analysis.Lock

import           Wiretap.Utils

-- import           Debug.Trace

onlyNessary :: UE -> Bool
onlyNessary (Unique _ es) =
  case operation es of
    Enter _ _ -> False
    Branch -> False
    _ -> True

sc :: PartialHistory h => h -> LIA UE
sc h =
  And [ totalOrder $ filter onlyNessary es
      | es <- M.elems $ byThread h
      ]

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

-- | Returns the control flow to a single event, this flow jumps threads, with
-- | the Join and Fork events.
controlFlow
  :: PartialHistory h
  => h
  -> UE
  -> [UE]
controlFlow h u@(Unique _ e) =
  takeWhile (/= u)
  . snd
  $ simulateReverse step (S.singleton (thread e), []) h

  where
  step u'@(Unique _ e') s@(!threads, events) =
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

cdfFree
  :: PartialHistory h
  => h
  -> ValueSet
  -> UE
  -> [UE]
cdfFree h _ u =
  simulateReverse step [] (controlFlow h u)
  where
    step u'@(Unique _ e') events =
      case operation e' of
        Acquire _ ->
          u':events
        _ ->
          events

cdfSaid
  :: PartialHistory h
  => h
  -> ValueSet
  -> UE
  -> [UE]
cdfSaid h _ u =
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
cdfDirk
  :: PartialHistory h
  => h
  -> ValueSet
  -> UE
  -> [UE]
cdfDirk h v u =
  simulateReverse step ([], valuesOf u `joinV` (v `joinV` Just S.empty)) (controlFlow h u)  ^. _1
  where
    step u'@(Unique _ e') (!events, !vs) =
      let events' =
            case (operation e', vs)  of
              (Read _ _ , Nothing) ->
                u':events
              (Read _ (Object v'), Just refs) | Ref v' `S.member` refs  ->
                u':events
              (Acquire _, _) ->
                u':events
              _ ->
                events
      in (events', valuesOf u' `joinV` vs)

    joinV _ Nothing = Nothing
    joinV (ValueSet r1 vs b) (Just r2) =
      if vs || b then Nothing else Just (r1 `S.union` r2)

    {-# INLINE joinV #-}

cdfRefsOnly
  :: PartialHistory h
  => h
  -> ValueSet
  -> UE
  -> [UE]
cdfRefsOnly h v u =
  simulateReverse step ([], valuesOf u `joinV` (v `joinV` S.empty)) (controlFlow h u)  ^. _1
  where
    step u'@(Unique _ e') (events, refs) =
      let events' =
            case operation e' of
              Read _ (Object v') | Ref v' `S.member` refs  ->
                u':events
              Acquire _ ->
                u':events
              _ ->
                events
      in (events', valuesOf u' `joinV` refs)

    joinV (ValueSet r1 _ _) r2 =
      (r1 `S.union` r2)

cdfValuesOnly
  :: PartialHistory h
  => h
  -> ValueSet
  -> UE
  -> [UE]
cdfValuesOnly h v u =
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

    joinV (ValueSet _ vs _) b2 =
      (vs || b2)

cdfBranchOnly
  :: PartialHistory h
  => h
  -> ValueSet
  -> UE
  -> [UE]
cdfBranchOnly h v u =
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

    joinV (ValueSet _ vs b) b2 =
      (vs || b || b2)

-- | For a given event, choose all the reads, and locks, that needs to be
-- | consistent for this event to also be consistent.
cdfRVPredict
  :: PartialHistory h
  => h
  -> ValueSet
  -> UE
  -> [UE]
cdfRVPredict h v u =
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

lockPairsWithRef
  :: PartialHistory h
  => h
  -> M.Map Ref ([UE], [(UE, UE)], [UE])
lockPairsWithRef h =
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
    locksWithRef =
      mapOnFst $ onEvent filter' (flip (,)) h
      where
        filter' (Acquire l) = Just l
        filter' (Release l) = Just l
        filter' _           = Nothing

onNonReentrantAcquires
  :: PartialHistory h
  => LockMap
  -> (UE -> Ref -> a)
  -> h
  -> [a]
onNonReentrantAcquires lm f deps =
  catMaybes . flip onAcquires deps $ \e l -> do
    -- traceM $ show (e, l, (lm ! e))
    guard $ nonreentrant lm e l
    -- traceM $ show "good"
    return $ f e l

type CDF = ValueSet -> UE -> [UE]

phiExec
  :: LockMap
  -> CDF
  -> ValueSet
  -> UE
  -> LIA' Int UE
phiExec lm cdf v e =
  And
  [ And $ onReads (\r _ -> Var (idx r)) depends
  , And $ onNonReentrantAcquires lm (\a _ -> Var (idx a)) depends
  ]
  where
    depends = cdf v e

phiRead
  :: LockMap
  -> M.Map Location [(Value, UE)]
  -> CDF
  -> UE -> (Location, Value)
  -> LIA' Int UE
phiRead lm writes cdf r (l, v) =
  case M.lookup l writes of
    Nothing ->
      And []
      -- ^ If no writes assume that the read is consistent, ei. Reads what it
      -- is supposed to.
    Just rwrites ->
      case [ w | (v', w) <- rwrites , v' == v , r ~/> w ] of
        [] ->
          And [ r ~> w' | (_, w') <- rwrites ]
          -- ^ If there is no writes with the same value, that not is ordered
          -- after the read, then assume that the read must be reading
          -- something that was written before, ei. ordered before all other writes.
        rvwrites ->
          Or
          [ And $ phiExec lm cdf (fromValue v) w : w ~> r :
            [ Or [ w' ~> w, r ~> w']
            | (_, w') <- rwrites
            , w' /= w , w' ~/> w, r ~/> w'
            ]
          | w <- rvwrites
          ]

phiAcq
  :: LockMap
  -> (M.Map Ref ([UE], [(UE, UE)], [UE]))
  -> CDF
  -> UE -> Ref
  -> LIA' Int UE
phiAcq lm lpwr cdf a ref' =
  And
  [ And
    [ Or
      [ a ~> a'
      , And [ r' ~> a, phiExec lm cdf mempty (r') ]
      ]
    | (a', r') <- pairs
    , a' /= a, a' ~/> a, a' ~/> a
    ]
  , And
    [ a ~> a'
    | a' <- da
    , a' /= a, a' ~/> a, a' ~/> a
    ]
  ]
  where
    (_, pairs, da) =
      case M.lookup ref' lpwr of
        Just pairs' -> pairs'
        Nothing -> error $ "The ref " ++ show ref' ++ " has no lock-pairs. (Should not happen)"

generateVars
  :: PartialHistory h
  => LockMap
  -> (h -> CDF)
  -> h
  -> [(Int, (LIA' Int UE))]
generateVars lm f h =
  onReads (\r x -> (idx r, phiRead lm writes (f h) r x)) h
  ++ onNonReentrantAcquires lm (\a l -> (idx a, phiAcq lm lpwr (f h) a l)) h
  where
    lpwr = lockPairsWithRef h
    writes = mapOnFst $ onWrites (\w (l, v) -> (l, (v, w))) h

phiExecE
  :: LockMap
  -> CDF
  -> S.Set UE
  -> LIA' Int UE
phiExecE lm cdf es =
  And $ equate es :
  [ phiExec lm cdf mempty e
  | e <- S.toList es
  ]

{-| permute takes partial history and two events, if the events can be arranged
next to each other return. -}
permute
  :: (PartialHistory h, MonadIO m, Candidate a)
  => (LockMap, (h -> CDF))
  -> h
  -> a
  -> m (Either (LIA UE) (Proof a))
permute (lm, cdf) h a = do
  liftIO . evalZ3 . runEitherT $ do
    f <- lift $ permuteBatch (lm, cdf) h
    f a

permuteBatch
  :: (PartialHistory h, MonadZ3 m, Candidate a)
  => (LockMap, (h -> CDF))
  -> h
  -> m (a -> EitherT (LIA UE) m (Proof a))
permuteBatch (lm,cdf) h = do
  solver <- setupLIA (enumerate h) $ generateVars lm cdf h
  return $ \a -> do
    let es = candidateSet a
        x = And $ phiExecE lm (cdf h) es : ([ sc, mhb] <*> [h])
    result <- lift $ solver x
    maybe (left x) (right . Proof a x . prefixContaining es) result

permuteBatch'
  :: (PartialHistory h, MonadZ3 m, Candidate a)
  => (LockMap, (h -> CDF))
  -> h
  -> m (a -> EitherT (LIA UE) m (Proof a))
permuteBatch' (lm,cdf) h = do
  solver <-
    setupLIA'
      (filter onlyNessary $ enumerate h)
      (generateVars lm cdf h)
      (And [sc h, mhb h])
  return $ \a -> do
    let es = candidateSet a
        x = (phiExecE lm (cdf h) es)
    b <- lift $ solver x
    if b
    then return $ Proof a x undefined
    else left $ x

equate :: CandidateSet -> LIA UE
equate es =
  And . L.map (uncurry Eq) $ combinations (S.toList es)
