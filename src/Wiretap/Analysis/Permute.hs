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

  , PermuteProblem
  , HBLProblem (..)
  , generateProblem
  , solveOne
  , solveAll

  -- * Candidates
  , Candidate(..)
  , locksetFilter'
  , locksetFilter
  , Proof (..)
  )
  where

import           Control.Lens                      hiding (none)
import           Control.Monad
import           Data.Functor
import qualified Data.Map                          as M
import           Data.Maybe
import           Data.Monoid
import           Control.Monad.Trans.Either
import qualified Data.Set                          as S
import qualified Data.List                         as L
import           Data.Unique
import           Prelude                           hiding (reads)

import           Wiretap.Analysis.HBL
import           Wiretap.Analysis.Lock
import           Wiretap.Analysis.MustHappenBefore
import           Wiretap.Data.Event
import           Wiretap.Data.Program
import           Wiretap.Data.History
import           Wiretap.Utils
import           Wiretap.Format.Text

-- import           Data.List (intercalate)
-- import           Debug.Trace


type PHBL = HBL UE UE

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
            -- Do not report reentrant locks
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
  -> (UE -> PHBL)
  -> MHB
  -> UE -> (Location, Value)
  -> PHBL
phiRead writes cdf mh r (l, v) =
  case [ w | (v', w) <- rwrites , v' == v, not $ mhb mh r w ] of
    [] ->
      And [ r ~> w' | (_, w') <- rwrites, not (mhb mh r w')]
      -- If there is no writes with the same value, that not is ordered
      -- after the read, then assume that the read must be reading
      -- something that was written before, ei. ordered before all other writes.
    rvwrites ->
      Or
      [ And $ cdf w : (if not $ mhb mh w r then (w ~> r :) else id)
        [ Or [ w' ~> w, r ~> w']
        | (_, w') <- rwrites
        , w' /= w
        , not $ mhb mh w' w
        , not $ mhb mh r w'
        ]
      | w <- rvwrites
      , not $ mhb mh r w
      , not $ mhb mh w r && any (\(_, w') -> mhb mh w w' && mhb mh w' r) rwrites
      ]
  where
    rwrites = fromMaybe [] $ M.lookup l writes

phiAcq
  :: (M.Map Ref ([UE], [(UE, UE)], [UE]))
  -> (UE -> PHBL)
  -> MHB
  -> UE
  -> Ref
  -> PHBL
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
  -> PHBL
phiExecE cdf es =
  And $ concurrent es :
  [ cdf mempty e
  | e <- S.toList es
  ]

type CDF = ValueSet -> UE -> PHBL
type DF = ValueSet -> Value -> Bool

mhb_ :: PartialHistory h => h -> PHBL
mhb_ h =
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

solveAll
  :: (HBLSolver UE UE m)
  => PermuteProblem a
  -> [a]
  -> m (Maybe [a])
solveAll p as = do
  b <- sat . Or $ map (probGenerate p) as
  return $ if b then Just as else Nothing

solveOne
  :: (HBLSolver UE UE m)
  => PermuteProblem a
  -> [a]
  -> m (Maybe a)
solveOne p (a:as) = do
  b <- sat (probGenerate p a)
  if b then return $ Just a else solveOne p as
solveOne _ [] =
  return Nothing

type PermuteProblem = HBLProblem UE UE

generateProblem ::
  (PartialHistory h, Candidate a)
  => (LockMap, MHB, DF)
  -> h
  -> PermuteProblem a
generateProblem (lm, mh, df) hist =
  HBLProblem
    { probGenerate = phiExecE cdf . candidateSet
    , probBase = And [sc, mhb_ hist]
    , probElements = h
    , probSymbols = enumerate hist
    , probSymbolDef = (vars !!!)
    }
  where
    var = Atom . Symbol

    runVar ue@(Unique _ e) =
      case operation e of
        Read l v ->
          phiRead writes var mh ue (l,v)
        Acquire l ->
          phiAcq lpwr var mh ue l
        Begin ->
          case mhbForkOf mh ue of
            Just f  -> cdf mempty f
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
          And . map (var) $
            filter (onlyVars (ValueSet mempty True True)) (uthread ! ue)
        _ -> error $ "Wrong variable type: " ++ show e

    sc =
      And [ totalOrder t | t <- M.elems $ byThread h ]

    h =
      filter needed $ enumerate hist

    needed ue@(Unique _ e) =
      case operation e of
        Enter _ _ -> False
        Branch -> False
        Request _ -> False
        Read _ _ -> maybe False (not . null) $ M.lookup ue conflicts
        Write _ _ -> ue `S.member` conflictingWrites
        _ -> True

    conflictingWrites =
      S.fromList . concat . M.elems $ conflicts

    -- Conflicts produces a list of pairs of all read to writes events,
    -- we then proceed to remove all conflicts that is must happen related.
    conflicts' :: M.Map UE [UE]
    conflicts' =
      mapOnFst
      . filter (uncurry $ mhbFree mh)
      . concat
      $ onReads conflictsOfRead hist

    conflicts = conflicts'
      -- trace (intercalate "\n" . map (\(a,b) -> show a ++ " : " ++ show (length b) )
      --        $ M.toList conflicts') conflicts'
    -- Pretty print map

    conflictsOfRead r (l, _) =
      [ (r, w)
      | (_, w) <- maybe [] id $ M.lookup l writes
      ]

    lpwr =
      lockPairsWithRef hist

    writes =
      mapOnFst $ onWrites (\w (l, v) -> (l, (v, w))) hist

    cdf vs ue =
      And . map var $ controlFlow vs (uthread ! ue)

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
      $ enumerate hist

    onlyVars vs ue' =
      case operation . normal $ ue' of
        Read _ v  | df vs v -> True
        Acquire l | nonreentrant lm ue' l -> True
        Begin     -> True
        Join _    -> True
        _         -> False

    uthread = threadAt hist

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
    _           | hasValue || hasBranch -> True
    (Object v') | Ref v' `S.member` refs -> True
    _           -> False


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

type CandidateSet = S.Set UE

class Candidate a where
  candidateSet :: a -> CandidateSet
  prettyPrint :: Program -> a -> IO String
  prettyPrint p a =
      L.intercalate " " . L.sort . L.map (pp p) <$>
        mapM (instruction p . normal) (S.toList $ candidateSet a)

data Proof a = Proof
  { candidate   :: a
  , constraints :: PHBL
  , evidence    :: [UE]
  } deriving Functor

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
 case L.concatMap (M.assocs) intersections of
   [] -> return c
   ls -> left $ ls
 where
   intersections =
     L.map (uncurry (sharedLocks lm)) $ combinations (S.toList $ candidateSet c)
