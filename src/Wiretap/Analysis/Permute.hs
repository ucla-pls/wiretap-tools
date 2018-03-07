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
import           Control.Monad.Trans.Class         (lift)
import           Control.Monad.Trans.Either
import           Prelude                           hiding (reads)

-- import qualified Data.IntMap                       as IM
import qualified Data.List                         as L
import qualified Data.Map                          as M
-- import           Data.Maybe                        (catMaybes)
import qualified Data.Set                          as S
import           Data.Unique
import           Data.Monoid

-- import  Wiretap.Format.Text

import           Wiretap.Analysis.LIA
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

sc :: PartialHistory h => h -> LIA UE
sc h =
  And [ totalOrder $ filter onlyNessary es
      | es <- M.elems $ byThread h
      ]

mhbLia :: PartialHistory h => h -> LIA UE
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

type CDF = ValueSet -> UE -> LIA UE
type DF = ValueSet -> Value -> Bool


phiRead
  :: M.Map Location [(Value, UE)]
  -> (UE -> LIA UE)
  -> MHB
  -> UE -> (Location, Value)
  -> LIA UE
phiRead writes cdf mh r (l, v) =
  case M.lookup l writes of
    Nothing ->
      And []
      -- ^ If no writes assume that the read is consistent, ei. Reads what it
      -- is supposed to.
    Just rwrites ->
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
          , not $ mhb mh e a
          ]

phiAcq
  :: (M.Map Ref ([UE], [(UE, UE)], [UE]))
  -> (UE -> LIA UE)
  -> MHB
  -> UE
  -> Ref
  -> LIA' UE UE
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
  -> LIA' UE UE
phiExecE cdf es =
  And $ equate es :
  [ cdf mempty e
  | e <- S.toList es
  ]

equate :: CandidateSet -> LIA UE
equate es =
  And . L.map (uncurry Eq) $ combinations (S.toList es)

mkCDF
  :: PartialHistory h
  => LockMap
  -> h
  -> (ValueSet -> Value -> Bool)
  -> CDF
mkCDF lm h df =
  \vs ue ->
    case operation $ normal ue of
      -- If it is a branch event then we know everything after needs to be
      -- consistent
      Branch ->
        And . map (Var) $ filter onlyVars (uthread ! ue)

      -- Otherwise do your thing
      _ ->
        And . map (Var) $ controlFlow vs (uthread ! ue)
  where
    controlFlow :: ValueSet -> [UE] -> [UE]
    controlFlow !vs (ue':rest) =
      let
        vs' = vs <> valuesOf ue'
        cont = controlFlow vs' rest
      in
      case operation . normal $ ue' of
        Read _ v | df vs v -> ue' : cont
        Acquire l | nonreentrant lm ue' l -> ue' : cont
        Begin -> ue' : cont
        Join _ -> ue' : cont
        -- Branch -> [ue']
        _ -> cont
    controlFlow _ [] = []

    onlyVars ue' =
      case operation . normal $ ue' of
        Read _ _ -> True
        Acquire l | nonreentrant lm ue' l -> True
        Begin -> True
        Join _ -> True
        _ -> False

    uthread :: UniqueMap [UE]
    uthread = fromUniques (imapf [])

    (_, imapf) = simulate folder (M.empty, id) h

    folder ue (threads, cont) =
      let
        t = threadOf ue
        lst = maybe [] (ue:) $ M.lookup t threads
      in
       ( M.insert t lst threads, cont . (fmap (const lst) ue :))


mkVarGenerator
  :: PartialHistory h
  => LockMap
  -> MHB
  -> CDF
  -> h
  -> UE -> LIA UE
mkVarGenerator _ mh cdf h =
  inner
  where
    inner ue@(Unique _ e) =
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
          cdf mempty ue
        _ -> error $ "Wrong variable type: " ++ show e
    lpwr = lockPairsWithRef h
    writes = mapOnFst $ onWrites (\w (l, v) -> (l, (v, w))) h

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


permuteBatch'
  :: (PartialHistory h, MonadZ3 m, Candidate a)
  => (LockMap, MHB, DF)
  -> h
  -> m (a -> EitherT (LIA UE) m (Proof a))
permuteBatch' (lm, mh, df) h = do
  solver <-
    setupLIA'
      (filter onlyNessary $ enumerate h)
      (mkVarGenerator lm mh cdf h)
      (And [sc h, mhbLia h])
  return $ \a -> do
    let es = candidateSet a
        x = (phiExecE cdf es)
    b <- lift $ solver x
    if b
    then return $ Proof a x undefined
    else left $ x

  where cdf = mkCDF lm h df
