{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE RankNTypes                 #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE TupleSections              #-}
{-# LANGUAGE UndecidableInstances       #-}
module Wiretap.Analysis.LIA
  ( LIA
  , LIA'(..)
  , LIAAtom (..)
  , (~>)
  , pairwise
  , orders
  , totalOrder

  , evalZ3T
  , evalZ3TWithTimeout
  , fast
  , Z3T

  , LIAError (..)
  , MonadZ3

  , toCNF
--  , solve
--  , toZ3
--  , setupLIA
  , setupLIA'

  , liaSize
  )
where

import           Prelude                    hiding (product)

import qualified Data.IntMap.Strict         as IM
-- import qualified Data.List                  as L

import           Control.Monad.Catch
import           Control.Monad.IO.Class
import           Control.Monad.Reader       hiding (local)
import           Control.Monad.State.Class
import           Control.Monad.Trans.Reader (ReaderT)

import           Data.IORef
import           Data.Unique

-- import Debug.Trace
import qualified Z3.Base                    as Base
import           Z3.Monad

{-| LIA - Linear integer arithmetic -}
type LIA e = LIA' e e

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
    Eq _ _    -> 1
    And ls    -> 1 + sum (map liaSize ls)
    Or ls     -> 1 + sum (map liaSize ls)
    Var _     -> 1

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
    []    -> []

product :: (a -> b -> c) -> [a] -> [b] -> [c]
product f as bs =
  [ f a b | a <- as, b <- bs ]

data LIAError
  = LIAZ3Error Z3Error
  | LIACouldNotSolveConstraints
  deriving (Show)

-- {-| `setup`, takes a vector of elements and a list of symbols and setup the
-- environment.
-- -}
-- setupLIA
--   :: (MonadZ3 m, Show e)
--   => [Unique e]
--   -> [(Int, (LIA' Int (Unique e)))]
--   -> m (LIA' Int (Unique e) -> m (Maybe [Unique e]))
-- setupLIA elems vars = do
--   eVars <-
--     fmap IM.fromDistinctAscList . forM elems $ \e -> do
--       o <- mkFreshIntVar "O"
--       s <- mkFreshBoolVar "S"
--       return (idx e,(e,o,s))

--   ctx <- getContext
--   let solver = liftIO $ toZ3 (lookupOVar eVars) (lookupSVar eVars) ctx

--   forM_ vars $ \(var, constraint) -> do
--     let s = lookupSVar eVars var
--     assert =<< mkImplies s =<< solver constraint

--   let outer lia = local $ do
--         assert =<< solver lia
--         (_, solution) <- withModel $ \m -> do
--           solutions <- mapM (\(_, o, _) -> evalInt m o) eVars
--           return solutions
--         case solution of
--           Just assignment -> do
--             return . Just $ L.sortOn (\e -> assignment IM.! idx e) elems
--           Nothing ->
--             return Nothing

--   return outer

setupLIA'
  :: forall m e. (MonadZ3 m, Show e)
  => [Unique e]
  -> (Unique e -> LIA' (Unique e) (Unique e))
  -> LIA' (Unique e) (Unique e)
  -> m (LIA' (Unique e) (Unique e) -> m Bool)
setupLIA' elems f base = do
  events <-
    fmap IM.fromDistinctAscList . forM elems $ \e -> do
      o <- mkFreshIntVar "O"
      return (idx e,(e,o))

  var_ref <- liftIO $ newIORef IM.empty
  ctx <- getContext
  slv <- getSolver

  let
    toAST' :: LIA' (Unique e) (Unique e) -> IO AST
    toAST' = toZ3 (lookupOVar events) lookupS ctx

    toAST :: LIA' (Unique e) (Unique e) -> m AST
    toAST lia = liftIO $ toAST' lia

    lookupS ue = do
      vars <- readIORef var_ref
      case IM.lookup (idx ue) vars of
        Just symbol ->
          return symbol
        Nothing -> do
          -- traceM $ "Adding: "  ++ show ue
          symbol <- Base.mkFreshBoolVar ctx "S"
          writeIORef var_ref (IM.insert (idx ue) symbol vars)
          -- traceM $ "Computing constraints: "
          let x = (f ue)
          -- traceM $ show x
          -- traceM $ "Recursively evaluating ast"
          ast <- toAST' x
          imp <- Base.mkEq ctx symbol ast
          -- traceM $ "Asserting " ++ show ue
          Base.solverAssertCnstr ctx slv imp
          -- traceM $ "Asserted."
          return symbol

    outer lia = do
      -- traceM $ "Compiling top LIA"
      ast <- toAST lia
      vars <- liftIO $ readIORef var_ref
      -- traceM $ "Variables: " ++ show (IM.size vars)
      local $ do
        -- traceM $ "Asserted top LIA"
        assert ast
        -- traceM $ "Checking Consistency"
        rest <- check
        -- traceM $ "Done"
        return $ rest == Sat

  assert =<< toAST base
  return outer

lookupOVar :: Show e => IM.IntMap (Unique e, a) -> Unique e -> a
lookupOVar vars e =
  case IM.lookup (idx e) vars of
    Just (_, o) -> o
    Nothing     -> error $ "Could not find " ++ show e ++ " in vars."

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
  } deriving (Applicative, Monad, MonadIO, MonadTrans, MonadFix, MonadReader Z3EnvC)

instance Functor m => Functor (Z3T m) where
  fmap f (Z3T fa) = Z3T (fmap f $ fa)
  {-# INLINE fmap #-}

instance (MonadState s m) => MonadState s (Z3T m) where
  get = lift get
  {-# INLINE get #-}
  put = lift . put
  {-# INLINE put #-}
  state = lift . state
  {-# INLINE state #-}

instance (MonadIO m) => MonadZ3 (Z3T m) where
  getSolver = Z3T $ asks envSolver
  getContext = Z3T $ asks envContext

fast ::
     (MonadIO m)
  => Z3T IO a
  -> Z3T m a
fast (Z3T z) = do
  env <- ask
  liftIO $ runReaderT z env

evalZ3TWithTimeout
  :: (MonadIO m, MonadCatch m)
  => Integer
  -> Z3T m a
  -> m (Either Z3Error a)
evalZ3TWithTimeout timeout (Z3T s) = do
  let opts = stdOpts +? if timeout > 0
        then (opt "timeout" timeout)
        else mempty
  env <- liftIO $ newEnvC Nothing opts
  (Right <$> runReaderT s env) `catch` (return . Left)

evalZ3T
  :: (MonadIO m, MonadCatch m)
  => Z3T m a
  -> m (Either Z3Error a)
evalZ3T =
  evalZ3TWithTimeout 0


-- {-| solve takes a vector of elements and logic constraints

-- This function assumes that the list of unique's contains all
-- the elements in the LIA, and that the uniq list distinct in it's
-- id and strictly ascending.
-- -}
-- solve :: (MonadIO m, Show e)
--   => [Unique e]
--   -> [(Int, (LIA' Int (Unique e)))]
--   -> LIA' Int (Unique e)
--   -> m (Maybe [Unique e])
-- solve elems symbols lia = liftIO $ evalZ3 $ do
--   f <- setupLIA elems symbols
--   f lia

toZ3 ::
  (e -> AST)
  -> (s -> IO AST)
  -> Base.Context
  -> LIA' s e -> IO AST
toZ3 evar svar ctx = go
  where
  go lia =
    case lia of
      And [] ->
        Base.mkTrue ctx
      And cs ->
        Base.mkAnd ctx =<< mapM go cs
      Or cs ->
        Base.mkOr ctx =<< mapM go cs
      Order a b ->
        Base.mkLt ctx (evar a) (evar b)
      Eq a b ->
        Base.mkEq ctx (evar a) (evar b)
      Var s ->
        svar s
