{-# LANGUAGE BangPatterns     #-}
{-# LANGUAGE DeriveFunctor    #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE RankNTypes       #-}
{-# LANGUAGE TemplateHaskell  #-}
module Wiretap.Analysis.Permute
  ( dfDirk
  , dfRVPredict
  , dfSaid
  , dfFree
  -- , cdfRefsOnly
  -- , cdfBranchOnly
  -- , cdfValuesOnly

  , DF
  , CDF

  , permuteBatch'

  , Candidate(..)
  , Proof(..)

  , (~/>)
  , (~/~)
  )
  where

import           Control.Lens                      hiding (none)
import           Control.Monad


import           Prelude                           hiding (reads)

-- import qualified Data.IntMap                       as IM
import qualified Data.List                         as L
import qualified Data.Map                          as M
-- import           Data.Maybe                        (catMaybes)
import qualified Data.Set                          as S
import           Data.Unique
import           Data.Monoid
import           Data.Functor
import           Data.Maybe

-- import  Wiretap.Format.Text

import           Wiretap.Analysis.MHL
import           Wiretap.Analysis.Lock
import           Wiretap.Analysis.MustHappenBefore
import           Wiretap.Data.Event
import           Wiretap.Data.History
import           Wiretap.Data.Proof
import           Wiretap.Utils

-- import           Debug.Trace

onlyNessary :: UE -> Bool
onlyNessary (Unique _ es) =
  case operation es of
    Enter _ _ -> False
    Branch    -> False
    _         -> True

sc :: PartialHistory h => h -> MHL UE
sc h =
  And [ totalOrder $ filter onlyNessary es
      | es <- M.elems $ byThread h
      ]

mhbLia :: PartialHistory h => h -> MHL UE
mhbLia h =
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
            []    -> (dr, pairs, u:da)
            [r]   -> ([], (u, r):pairs, da)
            _:dr' -> (dr', pairs, da)
            -- ^ Do not report reentrant locks
        Release _ ->
          (u:dr, pairs, da)
        _ -> s
    locksWithRef =
      mapOnFst $ onEvent filter' (flip (,)) h
      where
        filter' (Acquire l) = Just l
        filter' (Release l) = Just l
        filter' _           = Nothing

phiRead
  :: M.Map Location [(Value, UE)]
  -> (UE -> MHL UE)
  -> MHB
  -> UE -> (Location, Value)
  -> MHL UE
phiRead writes cdf mh r (l, v) =
  case [ w | (v', w) <- rwrites , v' == v, not $ mhb mh r w ] of
    [] ->
      And [ r ~> w' | (_, w') <- rwrites]
      -- ^ If there is no writes with the same value, that not is ordered
      -- after the read, then assume that the read must be reading
      -- something that was written before, ei. ordered before all other writes.
    rvwrites ->
      Or
      [ And $ cdf w : w ~> r :
        [ Or [ w' ~> w, r ~> w']
        | (_, w') <- rwrites
        , w' /= w
        , not $ mhb mh w' w
        , not $ mhb mh r w'
        ]
      | w <- rvwrites
      , not $ mhb mh r w
      ]
  where
    rwrites = fromMaybe [] $ M.lookup l writes

phiAcq
  :: (M.Map Ref ([UE], [(UE, UE)], [UE]))
  -> (UE -> MHL UE)
  -> MHB
  -> UE
  -> Ref
  -> MHL UE
phiAcq lpwr cdf mh e ref' =
  And
  [ And
    [ Or
      [ e ~> a
      , And [ r ~> e, cdf r ]
      ]
    | (a, r) <- pairs
    , e /= a
    , not $ mhb mh e a
    ]
  , And
    [ e ~> a
    | a <- da
    , e /= a
    , mhbFree mh e a
    ]
  ]
  where
    (_, pairs, da) =
      case M.lookup ref' lpwr of
        Just pairs' -> pairs'
        Nothing -> error $ "The ref " ++ show ref' ++ " has no lock-pairs. (Should not happen)"

phiExecE
  :: CDF
  -> S.Set UE
  -> MHL UE
phiExecE cdf es =
  And $ equate es :
  [ cdf mempty e
  | e <- S.toList es
  ]

equate :: CandidateSet -> MHL UE
equate es =
  And . L.map (uncurry Eq) $ combinations (S.toList es)

type CDF = ValueSet -> UE -> MHL UE
type DF = ValueSet -> Value -> Bool


initEquations
  :: PartialHistory h
  => (LockMap, MHB, DF)
  -> h
  -> (CDF, UE -> MHL UE)
initEquations (lm, mh, df) h =
  (cdf, (vars !))
  where
    runVar ue@(Unique _ e) =
      case operation e of
        Read l v ->
          phiRead writes Var mh ue (l,v)
        Acquire l ->
          phiAcq lpwr Var mh ue l
        Begin ->
          case mhbForkOf mh ue of
            Just f -> cdf mempty f
            Nothing -> And []
        Join t' ->
          case mhbEndOf mh t' of
            Just e' -> cdf mempty e'
            Nothing -> And []
        Write _ v ->
          cdf (fromValue v) ue
        Release _ ->
          cdf mempty ue
        Branch ->
          And . map (Var) $ filter (onlyVars (ValueSet mempty True True)) (uthread ! ue)
        _ -> error $ "Wrong variable type: " ++ show e

    lpwr =
      lockPairsWithRef h

    writes =
      mapOnFst $ onWrites (\w (l, v) -> (l, (v, w))) h

    cdf vs ue =
      And . map (Var) $ controlFlow vs (uthread ! ue)

    controlFlow :: ValueSet -> [UE] -> [UE]
    controlFlow !vs (ue':rest) =
      ( case operation . normal $ ue' of
        Branch -> const [ue']
        _ | onlyVars vs ue' -> (ue' :)
          | otherwise -> id
      ) $ controlFlow (vs <> valuesOf ue') rest
    controlFlow _ [] = []

    vars =
      fromUniques
      . map (\u -> u $> runVar u)
      $ enumerate h

    onlyVars vs ue' =
      case operation . normal $ ue' of
        Read _ v | df vs v -> True
        Acquire l | nonreentrant lm ue' l -> True
        Begin -> True
        Join _ -> True
        _ -> False

    uthread = threadAt h

threadAt :: PartialHistory h => h -> UniqueMap [UE]
threadAt h =
  fromUniques $ snd (simulate folder (M.empty, id) h) []
  where
    folder ue (threads, cont) =
      let
        t = threadOf ue
        lst = maybe [] (ue:) $ M.lookup t threads
      in
      ( M.insert t lst threads, cont . (fmap (const lst) ue :))

permuteBatch'
  :: (PartialHistory h, MonadZ3 m, Candidate a)
  => (LockMap, MHB, DF)
  -> h
  -> m ([a] -> m (Either (MHL UE) (Proof a)))
permuteBatch' (lm, mh, df) h = do
  solver <-
    setupMHL'
      (filter onlyNessary $ enumerate h)
      fromVar
      (And [sc h, mhbLia h])
  return $ inner solver
  where
    inner solver (a:as) = do
      let batch = phiExecE cdf (candidateSet a)
      b <- solver batch
      if b
      then return . Right $ Proof undefined batch undefined
      else inner solver as
    inner solver [] =
      return (Left undefined)

    (cdf, fromVar) = initEquations (lm, mh, df) h


-- Dfs

dfFree :: DF
dfFree _ _ = False

dfSaid :: DF
dfSaid _ _ = True

dfRVPredict :: DF
dfRVPredict (ValueSet refs hasValue hasBranch) _ =
  not (S.null refs) || hasValue || hasBranch

dfDirk :: DF
dfDirk (ValueSet refs hasValue hasBranch) v =
  case v of
    _ | hasValue || hasBranch -> True
    (Object v') | Ref v' `S.member` refs -> True
    _ -> False


-- The value set.

data ValueSet = ValueSet
  { vsRefs   :: !(S.Set Ref)
  , vsValues :: ! Bool
  , vsBranch :: ! Bool
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
    Array r _   -> (fromRef r) { vsValues = True }
    _           -> mempty

fromValue :: Value -> ValueSet
fromValue v =
  case v of
    Object r -> fromRef (Ref r)
    _        -> mempty { vsValues = True }

fromBranch :: ValueSet
fromBranch =
  mempty { vsBranch = True }

-- | Get all refs known by the event at the moment of execution.
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
