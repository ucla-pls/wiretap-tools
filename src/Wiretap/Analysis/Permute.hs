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

-- import           Control.Lens                      hiding (none)
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
      Or $
-- TODO: Consider adding something on the lines of
--      (And [ r ~> w' | (_, w') <- rwrites, not (mhb mh r w')]):
-- to fix the problem that sometimes we load things from the default value.
      [ And
        -- If the w is the same thread as r, it is executable, because the thread already have
        -- the value of v, because else r would not be executable.
        . (if threadOf w /= threadOf r then (cdf w :) else id)
        -- If we already know w -mh-> r, don't redo it.
        . (if not $ mhb mh w r then (w ~> r :) else id)
        $ [ case () of
              ()
                | mhb mh w w' ->
                   r ~> w'
                | mhb mh w' r ->
                  w' ~> w
                | otherwise ->
                   Or [ w' ~> w , r ~> w']
          | (_, w') <- rwrites
          , w' /= w
          -- this is true if w' -mh-> w
          , not $ mhb mh w' w
          -- this is true if r -mh-> w'
          , not $ mhb mh r w'
          ]
      | w <- rvwrites
      -- It is automatically false if r -mh-> w
      , not $ mhb mh r w
      -- It is automatically false if there exists a write between w -mh-> w' -mh-> r
      , not $ any (\(_, w') -> mhb mh w w' && mhb mh w' r) rwrites
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
      . ( e ~?> a )
      $ [ And
          . ( r ~?> e )
          $ [cdf r]
        ]
    | (a, r) <- pairs
    -- Don't match yourself
    , e /= a
    -- if e -mh-> a then this is true
    , not $ mhb mh e a
    -- if r -mh-> a then it is fine, but only if the thread is the same,
    -- because else we can not be guaranteed that cdf r is true.
    , not $ mhb mh r e && threadOf r == threadOf e
    ]
  , And
    [ e ~> a
    | a <- da
    , e /= a
    -- Automatically true if e -mh-> a
    , not $ mhb mh e a
    ]
  ]
  where
    e' ~?> a' = (if not $ mhb mh e' a' then (e' ~> a':) else id)
    (_, pairs, da) =
      case M.lookup ref' lpwr of
        Just pairs' -> pairs'
        Nothing -> error $ "The ref " ++ show ref' ++ " has no lock-pairs. (Should not happen)"

phiExecE
  :: CDF
  -> (UE -> PHBL)
  -> S.Set UE
  -> PHBL
phiExecE cdf sc es =
  And $ concurrent es :
  [ And [ cdf mempty e, sc e ]
  | e <- S.toList es
  ]

type CDF = ValueSet -> UE -> PHBL
type DF = ValueSet -> Value -> Bool

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
    { probGenerate = phiExecE cdf reInsert . candidateSet
    , probBase = And [sc]
    , probElements = h'
    , probSymbols = enumerate hist
    , probSymbolDef = (vars !!!)
    }
  where
    var = Atom . Symbol

    runVar ue@(Unique _ e) =
      x -- trace (show (idx ue) ++ " --> " ++ show (bimap idx idx <$> x)) x
      where
        x = case operation e of
              Read l v ->
                phiRead writes var mh ue (l,v)
              Acquire l ->
                phiAcq lpwr var mh ue l
              Begin ->
                case mhbForkOf mh ue of
                  Just f  -> And [f  ~> ue, cdf mempty f]
                  Nothing -> And []
              Join t' ->
                case mhbEndOf mh t' of
                  Just e' -> And [e' ~> ue, cdf mempty e']
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
      And [ totalOrder t | t <- M.elems $ byThread h' ]

    h' =
      filter needed $ enumerate hist

    reInsert ue
      | not $ needed ue =
        let (l, n) = lastNext ue $ fromMaybe [] $ M.lookup (threadOf ue) threadwise
        in And . (maybe (id) ((:).(~> ue)) l) $ (maybe (id) ((:).(ue ~>)) n) []
      | otherwise =
        And []

    threadwise = byThread hist

    lastNext ue lst =
      let
        (before, after) = break (== ue) lst
        b = filter needed before
        l = if L.null b then Nothing else Just $ last b
        n = case after of
          [] -> Nothing;
          _:ls -> case filter needed ls of
            a':_ -> Just a'
            _ -> Nothing
      in (l, n)

    needed ue@(Unique _ e) =
      case operation e of
        Enter _ _ -> False
        Branch -> False
        Request _ -> False
        Read _ _ -> maybe False (not . null) $ M.lookup ue conflicts
        Write _ _ ->
          -- trace (show (eshow <$> ue) ++ " " ++ show (ue `S.member` conflictingWrites))
           ue `S.member` conflictingWrites
        _ -> True


    -- A conflicting write exists if just one write event to some
    -- place is conflicting
    conflictingWrites =
      S.fromList . concat . map allWrites . concat . M.elems $ conflicts
      where
        location (Write l _) = l
        location _ = undefined
        allWrites e = maybe [] (map snd) $ M.lookup (location (operation . normal $ e)) writes

    -- Conflicts produces a list of pairs of all read to writes events,
    -- we then proceed to remove all conflicts that is must happen related.
    conflicts' :: M.Map UE [UE]
    conflicts' =
      mapOnFst
      . filter (uncurry $ mhbFree mh)
      . concat
      $ onReads conflictsOfRead hist

    conflicts = conflicts'
      -- trace (L.intercalate "\n" . map (\(a,b) -> (show $ eshow <$> a) ++ " : " ++ show (fmap eshow <$> b) )
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
