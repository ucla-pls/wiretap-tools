{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Wiretap.Analysis.LIA
  ( LIA
  , LIA'(..)
  , LIAAtom (..)
  , (~>)
  , pairwise
  , orders
  , totalOrder
  , evalZ3T
  , Z3T

  , toCNF
  , solve
  , toZ3
  , setupLIA

  , liaSize
  )
where

import Prelude hiding (product)

import qualified Data.IntMap.Strict as IM
import qualified Data.List as L

import Control.Monad.IO.Class
import Control.Monad.Trans.Reader hiding (local)
import Control.Monad.Trans
import Control.Monad.State.Class

import Control.Monad.Fix
import Data.Unique

import Data.Traversable
import Data.Foldable hiding (product)
-- import Data.Void

-- import Debug.Trace
import Z3.Monad
import qualified Z3.Base as Base

{-| LIA - Linear integer arithmetic -}
type LIA e = LIA' Int e

data LIA' s e
  = Order !e !e
  | Eq !e !e
  | And !([LIA' s e])
  | Or !([LIA' s e])
  | Var !s
  deriving (Show)

liaSize :: LIA' s e -> Integer
liaSize lia =
  case lia of
    Order _ _ -> 1
    Eq _ _ -> 1
    And ls -> 1 + sum (map liaSize ls)
    Or ls -> 1 + sum (map liaSize ls)
    Var _ -> 1

infixl 8 ~>
(~>) :: e -> e -> LIA' s e
(~>) = Order

totalOrder :: [e] -> LIA' s e
totalOrder = And . pairwise (~>)

pairwise :: (a -> a -> b) -> [a] -> [b]
pairwise f es = zipWith f es (tail es)

orders ::  [e] -> [e] -> LIA' s e
orders as bs = And [ a ~> b | a <- as, b <- bs ]

data LIAAtom s e
 = AOrder e e
 | AEq e e
 | AVar s
 deriving (Show)

toCNF :: LIA' s e -> [[LIAAtom s e]]
toCNF e =
  case e of
    Order a b -> [[AOrder a b]]
    Eq a b -> [[AEq a b]]
    And es ->
      concatMap toCNF es
    Or es ->
      combinate (product (++)) $ map toCNF es
    Var s ->
      [[AVar s]]


combinate :: ([a] -> [a] -> [a]) -> [[a]] -> [a]
combinate f l =
  case l of
    a':[] -> a'
    a':as -> f a' $ combinate f as
    [] -> []

product :: (a -> b -> c) -> [a] -> [b] -> [c]
product f as bs =
  [ f a b | a <- as, b <- bs ]


{-| `setup`, takes a vector of elements and a list of symbols and setup the
environment.
-}
setupLIA
  :: (MonadZ3 m, Show e)
  => [Unique e]
  -> [(Int, (LIA' Int (Unique e)))]
  -> m (LIA' Int (Unique e) -> m (Maybe [Unique e]))
setupLIA elems vars = do
  eVars <-
    fmap IM.fromDistinctAscList . forM elems $ \e -> do
      o <- mkFreshIntVar "O"
      s <- mkFreshBoolVar "S"
      return (idx e,(e,o,s))

  let solver = toZ3 (lookupOVar eVars) (lookupSVar eVars)

  forM_ vars $ \(var, constraint) -> do
    let s = lookupSVar eVars var
    assert =<< mkImplies s =<< solver constraint

  return $ \ lia -> local $ do
    assert =<< solver lia
    (_, solution) <- withModel $ \m -> do
      solutions <- mapM (\(_, o, _) -> evalInt m o) eVars
      return solutions
    case solution of
      Just assignment -> do
        return . Just $ L.sortOn (\e -> assignment IM.! idx e) elems
      Nothing ->
        return Nothing

lookupOVar :: Show e => IM.IntMap (Unique e, a, b) -> Unique e -> a
lookupOVar vars e =
  case IM.lookup (idx e) vars of
    Just (_, o, _) -> o
    Nothing -> error $ "Could not find " ++ show e ++ " in vars."

lookupSVar :: Show e => IM.IntMap (Unique e, a, b) -> Int -> b
lookupSVar vars e =
  case IM.lookup e vars of
    Just (_, _, s) -> s
    Nothing -> error $ "Could not find " ++ show e ++ " in vars."

data Z3EnvC
  = Z3EnvC {
      envSolver  :: Base.Solver
    , envContext :: Base.Context
    }

newEnvWithC :: (Base.Config -> IO Base.Context) -> Maybe Logic -> Opts -> IO Z3EnvC
newEnvWithC mkContext mbLogic opts =
  Base.withConfig $ \cfg -> do
    setOpts cfg opts
    ctx <- mkContext cfg
    solver <- maybe (Base.mkSolver ctx) (Base.mkSolverForLogic ctx) mbLogic
    return $ Z3EnvC solver ctx

-- | Create a new Z3 environment.
newEnvC :: Maybe Logic -> Opts -> IO Z3EnvC
newEnvC = newEnvWithC Base.mkContext

newtype Z3T m a = Z3T
  { _unZ3 :: ReaderT Z3EnvC m a
  } deriving (Functor, Applicative, Monad, MonadIO, MonadTrans, MonadFix)

instance (MonadState s m) => MonadState s (Z3T m) where
  get = lift get
  put = lift . put
  state = lift . state

instance (MonadIO m) => MonadZ3 (Z3T m) where
  getSolver = Z3T $ asks envSolver
  getContext = Z3T $ asks envContext

evalZ3T
  :: (MonadIO m)
  => Z3T m a
  -> m a
evalZ3T (Z3T s) = do
  env <- liftIO $ newEnvC Nothing stdOpts
  runReaderT s env


{-| solve takes a vector of elements and logic constraints

This function assumes that the list of unique's contains all
the elements in the LIA, and that the uniq list distinct in it's
id and strictly ascending.
-}
solve :: (MonadIO m, Show e)
  => [Unique e]
  -> [(Int, (LIA' Int (Unique e)))]
  -> LIA' Int (Unique e)
  -> m (Maybe [Unique e])
solve elems symbols lia = liftIO $ evalZ3 $ do
  f <- setupLIA elems symbols
  f lia

toZ3 :: MonadZ3 m
  => (e -> AST)
  -> (s -> AST)
  -> LIA' s e
  -> m AST
toZ3 evar svar = go
  where
    go lia =
      case lia of
        And [] ->
          mkTrue
        And cs ->
          mkAnd =<< mapM go cs
        Or cs ->
          mkOr =<< mapM go cs
        Order a b ->
          mkLt (evar a) (evar b)
        Eq a b ->
          mkEq (evar a) (evar b)
        Var s ->
          return $ svar s
