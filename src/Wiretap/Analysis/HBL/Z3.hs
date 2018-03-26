{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE RankNTypes                 #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE TupleSections              #-}
{-# LANGUAGE UndecidableInstances       #-}
{-|

Z3 implementations of the hb solver

-}
module Wiretap.Analysis.HBL.Z3 where

import qualified Z3.Base                    as Base
import           Z3.Monad                   as Z3


import           Control.Monad.Catch
import           Control.Monad.IO.Class
import           Control.Monad.Reader       hiding (local)
import           Control.Monad.State.Class
import           Control.Monad.Trans.Reader (ReaderT)

import qualified Data.IntMap as IM
import           Data.IORef
import           Data.Unique
import           Wiretap.Analysis.HBL
import           Wiretap.Data.History

import Debug.Trace


newtype Z3T s e m a = Z3T
  { _unZ3 :: ReaderT (Z3EnvC, Z3HBLSolver s e) m a
  } deriving ( Applicative, Monad, MonadIO
             , MonadTrans, MonadFix
             , MonadReader (Z3EnvC, Z3HBLSolver s e))

instance MonadIO m => HBLSolver s e (Z3T s e m) where
  assert hbl = do
    (env@(Z3EnvC slv ctx), solver) <- ask
    liftIO $ do
      ast <- toZ3 ctx (z3sToAST solver env) hbl
      Base.solverAssertCnstr ctx slv ast

  sat hbl = do
    (env@(Z3EnvC slv ctx), solver) <- ask
    liftIO $ do
      ast <- toZ3 ctx (z3sToAST solver env) hbl
      Base.solverPush ctx slv
      Base.solverAssertCnstr ctx slv ast
      result <- Base.solverCheck ctx slv
      -- (result, model) <- Base.solverCheckAndGetModel ctx slv
      -- case model of
      --   Just m -> do
      --     mstr <- Base.modelToString ctx m
      --     traceM mstr
      --   Nothing ->
      --     traceM "No model"
      Base.solverPop ctx slv 1
      return $ Sat == result

data Z3HBLSolver s e = Z3HBLSolver
  { z3sToAST   :: (Z3EnvC -> HBLAtom s e -> IO AST)
  , z3sLogic   :: Maybe Z3.Logic
  , z3sTimeout :: Integer
  }

toZ3 :: Z3.Context -> (HBLAtom s e -> IO AST) -> HBL s e -> IO (AST)
toZ3 ctx toAST = go
  where
    go hbl =
      case hbl of
        And [] ->
          Base.mkTrue ctx
        And [c] ->
          go c
        And cs ->
          Base.mkAnd ctx =<< mapM go cs
        Or [] ->
          Base.mkFalse ctx
        Or [c] ->
          go c
        Or cs ->
          Base.mkOr ctx =<< mapM go cs
        Atom at ->
          toAST at

runSolver :: (MonadCatch m, MonadIO m)
  => Z3HBLSolver s e
  -> Z3T s e m a
  -> m (Either Z3Error a)
runSolver solver (Z3T s) = do
  env <- liftIO $ newEnvC (z3sLogic solver) opts
  (Right <$> runReaderT s (env, solver)) `catch` (return . Left)
  where
    opts =
      (stdOpts) +? if timeout > 0
         then (opt "timeout" timeout)
         else mempty

    timeout = z3sTimeout solver


remember :: IORef (IM.IntMap b) -> (Unique a -> IO b) -> Unique a -> IO b
remember ioref f =
  remember' ioref (fmap (,return ()) . f)

remember' ::
  IORef (IM.IntMap b)
  -> (Unique a -> IO (b, IO ()))
  -> Unique a -> IO b
remember' ioref f u = do
  m <- readIORef ioref
  case IM.lookup (idx u) m of
    Just x -> return x
    Nothing -> do
      (o, after) <- f u
      modifyIORef ioref (IM.insert (idx u) o)
      after
      return o


runIDLSolver ::
  (MonadIO m, MonadCatch m)
  => Integer
  -> (UE -> HBL UE UE)
  -> Z3T UE UE m a
  -> m (Either Z3Error a)
runIDLSolver timeout f m = do
  solv <- liftIO $ mkIDLSolver timeout f
  runSolver solv m

mkIDLSolver :: Integer -> (UE -> HBL UE UE) -> IO (Z3HBLSolver UE UE)
mkIDLSolver timeout f = do
  liaSolver <- mkLIASolver timeout f
  return $ liaSolver { z3sLogic = Just Z3.QF_IDL }

mkLRASolver :: Integer -> (UE -> HBL UE UE) -> IO (Z3HBLSolver UE UE)
mkLRASolver timeout f = do
  liaSolver <- mkLIASolver timeout f
  return $ liaSolver { z3sLogic = Just Z3.QF_LRA }

mkRDLSolver :: Integer -> (UE -> HBL UE UE) -> IO (Z3HBLSolver UE UE)
mkRDLSolver timeout f = do
  liaSolver <- mkLIASolver timeout f
  return $ liaSolver { z3sLogic = Just Z3.QF_RDL }

runLIASolver ::
  (MonadIO m, MonadCatch m)
  => Integer
  -> (UE -> HBL UE UE)
  -> Z3T UE UE m a
  -> m (Either Z3Error a)
runLIASolver timeout f m = do
  solv <- liftIO $ mkLIASolver timeout f
  runSolver solv m

runRDLSolver ::
  (MonadIO m, MonadCatch m)
  => Integer
  -> (UE -> HBL UE UE)
  -> Z3T UE UE m a
  -> m (Either Z3Error a)
runRDLSolver timeout f m = do
  solv <- liftIO $ mkRDLSolver timeout f
  runSolver solv m

runLRASolver ::
  (MonadIO m, MonadCatch m)
  => Integer
  -> (UE -> HBL UE UE)
  -> Z3T UE UE m a
  -> m (Either Z3Error a)
runLRASolver timeout f m = do
  solv <- liftIO $ mkLRASolver timeout f
  runSolver solv m

mkLIASolver :: Integer -> (UE -> HBL UE UE) -> IO (Z3HBLSolver UE UE)
mkLIASolver timeout f = do
  events <- newIORef IM.empty
  vars <- newIORef IM.empty
  return $ Z3HBLSolver
    { z3sToAST = fromAtom events vars
    , z3sLogic = Just Z3.QF_LIA
    , z3sTimeout = timeout
    }
  where
    fromAtom eref vref env at =
      case at of
        Order a b -> do
          a' <- evar a
          b' <- evar b
          Base.mkLt ctx a' b'
        Concur a b -> do
          a' <- evar a
          b' <- evar b
          Base.mkEq ctx a' b'
        Symbol s ->
          svar s
      where
        ctx = envContext env
        slv = envSolver env
        evar =
          remember eref $ \_ -> do
            Base.mkFreshRealVar ctx "O"

        svar :: UE -> IO AST
        svar =
          remember' vref $ \ue -> do
            let hbl = (f ue)
            symbol <- Base.mkFreshBoolVar ctx "S"
            return
              ( symbol
              , do
                ast <- toZ3 ctx (fromAtom eref vref env) hbl
                imp <- Base.mkImplies ctx symbol ast
                Base.solverAssertCnstr ctx slv imp
                return ()
              )

data Z3EnvC
  = Z3EnvC {
      envSolver  :: Base.Solver
    , envContext :: Base.Context
    }

newEnvWithC :: (Base.Config -> IO Base.Context) -> Maybe Z3.Logic -> Opts -> IO Z3EnvC
newEnvWithC mkContext mbLogic opts =
  Base.withConfig $ \cfg -> do
    setOpts cfg opts
    ctx <- mkContext cfg
    solver <- maybe (Base.mkSolver ctx) (Base.mkSolverForLogic ctx) mbLogic
    return $ Z3EnvC solver ctx

-- | Create a new Z3 environment.
newEnvC :: Maybe Z3.Logic -> Opts -> IO Z3EnvC
newEnvC = newEnvWithC Base.mkContext


instance Functor m => Functor (Z3T s e m) where
  fmap f (Z3T fa) = Z3T (fmap f $ fa)
  {-# INLINE fmap #-}

instance (MonadState s m) => MonadState s (Z3T s e m) where
  get = lift get
  {-# INLINE get #-}
  put = lift . put
  {-# INLINE put #-}
  state = lift . state
  {-# INLINE state #-}

instance (MonadIO m) => MonadZ3 (Z3T s e m) where
  getSolver = Z3T . asks $ envSolver . fst
  getContext = Z3T . asks $ envContext . fst
