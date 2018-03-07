{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE RankNTypes                 #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE TupleSections              #-}
{-# LANGUAGE UndecidableInstances       #-}
module Wiretap.Analysis.MHL
  ( MHL
  , MHL'(..)
  , MHLAtom (..)
  , (~>)
  , pairwise
  , orders
  , totalOrder

  , evalZ3T
  , evalZ3TWithTimeout
  , fast
  , Z3T

  , MHLError (..)
  , MonadZ3

  , toCNF
--  , solve
--  , toZ3
--  , setupMHL
  , setupMHL'

  , mhlSize
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

{-| MHL - Linear integer arithmetic -}
type MHL e = MHL' e e

data MHL' s e
  = Order !e !e
  | Eq !e !e
  | And !([MHL' s e])
  | Or !([MHL' s e])
  | Var !s
  deriving (Show)

mhlSize :: MHL' s e -> Integer
mhlSize mhl =
  case mhl of
    Order _ _ -> 1
    Eq _ _    -> 1
    And ls    -> 1 + sum (map mhlSize ls)
    Or ls     -> 1 + sum (map mhlSize ls)
    Var _     -> 1

infixl 8 ~>
(~>) :: e -> e -> MHL' s e
(~>) = Order

totalOrder :: [e] -> MHL' s e
totalOrder = And . pairwise (~>)

pairwise :: (a -> a -> b) -> [a] -> [b]
pairwise f es = zipWith f es (tail es)

orders ::  [e] -> [e] -> MHL' s e
orders as bs = And [ a ~> b | a <- as, b <- bs ]

data MHLAtom s e
 = AOrder e e
 | AEq e e
 | AVar s
 deriving (Show)

toCNF :: MHL' s e -> [[MHLAtom s e]]
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

data MHLError
  = MHLZ3Error Z3Error
  | MHLCouldNotSolveConstraints
  deriving (Show)

-- {-| `setup`, takes a vector of elements and a list of symbols and setup the
-- environment.
-- -}
-- setupMHL
--   :: (MonadZ3 m, Show e)
--   => [Unique e]
--   -> [(Int, (MHL' Int (Unique e)))]
--   -> m (MHL' Int (Unique e) -> m (Maybe [Unique e]))
-- setupMHL elems vars = do
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

--   let outer mhl = local $ do
--         assert =<< solver mhl
--         (_, solution) <- withModel $ \m -> do
--           solutions <- mapM (\(_, o, _) -> evalInt m o) eVars
--           return solutions
--         case solution of
--           Just assignment -> do
--             return . Just $ L.sortOn (\e -> assignment IM.! idx e) elems
--           Nothing ->
--             return Nothing

--   return outer

setupMHL'
  :: forall m e. (MonadZ3 m, Show e)
  => [Unique e]
  -> (Unique e -> MHL' (Unique e) (Unique e))
  -> MHL' (Unique e) (Unique e)
  -> m (MHL' (Unique e) (Unique e) -> m Bool)
setupMHL' elems f base = do
  events <-
    fmap IM.fromDistinctAscList . forM elems $ \e -> do
      o <- mkFreshRealVar "O"
      return (idx e,(e,o))

  var_ref <- liftIO $ newIORef IM.empty
  ctx <- getContext
  slv <- getSolver

  let
    toAST' :: MHL' (Unique e) (Unique e) -> IO AST
    toAST' = toZ3 (lookupOVar events) lookupS ctx

    toAST :: MHL' (Unique e) (Unique e) -> m AST
    toAST mhl = liftIO $ toAST' mhl

    lookupS ue = do
      vars <- readIORef var_ref
      case IM.lookup (idx ue) vars of
        Just symbol ->
          return symbol
        Nothing -> do
          symbol <- Base.mkFreshBoolVar ctx "S"
          writeIORef var_ref (IM.insert (idx ue) symbol vars)
          let x = (f ue)
          ast <- toAST' x
          imp <- Base.mkEq ctx symbol ast
          Base.solverAssertCnstr ctx slv imp
          return symbol

    outer mhl = do
      ast <- toAST mhl
      local $ do
        assert ast
        rest <- check
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
  env <- liftIO $ newEnvC (Just QF_LRA) opts
  (Right <$> runReaderT s env) `catch` (return . Left)

evalZ3T
  :: (MonadIO m, MonadCatch m)
  => Z3T m a
  -> m (Either Z3Error a)
evalZ3T =
  evalZ3TWithTimeout 0

toZ3 ::
  (e -> AST)
  -> (s -> IO AST)
  -> Base.Context
  -> MHL' s e -> IO AST
toZ3 evar svar ctx = go
  where
  go mhl =
    case mhl of
      And [] ->
        Base.mkTrue ctx
      And cs ->
        Base.mkAnd ctx =<< mapM go cs
      Or [] ->
        Base.mkFalse ctx
      Or cs ->
        Base.mkOr ctx =<< mapM go cs
      Order a b ->
        Base.mkLt ctx (evar a) (evar b)
      Eq a b ->
        Base.mkEq ctx (evar a) (evar b)
      Var s ->
        svar s
