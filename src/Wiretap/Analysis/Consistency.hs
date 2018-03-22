{-# LANGUAGE TemplateHaskell #-}

module Wiretap.Analysis.Consistency
  ( checkConsistency
  ) where

import qualified Data.Map.Strict      as M
import qualified Pipes.Prelude        as P
import           Pipes
import           Control.Lens

import Debug.Trace

import           Data.Maybe
import           Data.Unique
import           Wiretap.Data.Event
import           Wiretap.Data.History

data Consistency = Consistency
  { _values :: M.Map Location (UE, Value)
  , _locks  :: M.Map Thread (M.Map Ref UE)
  } deriving (Show, Eq)


makeLenses ''Consistency

check :: Consistency -> UE -> Either String Consistency
check cn ue@(Unique _ e) =
  case operation e of
    Acquire l ->
      case cn^..locks.traverse.at(l)._Just of
        [] ->
          Right
          $ cn & locks.at(threadOf ue)
          %~ Just . (at l .~ Just ue) . fromMaybe M.empty
        as ->
          Left $ "Already locked by " ++ show as
    Release l ->
      case cn^?locks.at(threadOf ue)._Just.at(l) of
        Just _ ->
          Right $ cn & locks.at(threadOf ue)
                %~ Just . sans l . fromMaybe M.empty
        Nothing ->
          Left $ "Not locked yet: " ++ show l

    Read l v ->
      case cn ^. values.at l of
        Just (a, v')
          | v' == v ->
            Right cn
          | otherwise ->
            Left $ "Last value written to " ++ show l ++ " was: " ++ show (a, v')
        Nothing ->
          trace ("No value written to " ++ show l) $ Right cn
    Write l v ->
      Right $ cn & values.at l ?~ (ue, v)
    _ -> Right cn


check' :: Either String Consistency -> UE -> Either String Consistency
check' esc e =
  case esc of
    Right x ->
      either (Left . ((show e ++ ": ") ++)) Right $ check x e
    _ -> esc

checkConsistency ::
  Monad m
  => Producer UE m ()
  -> m (Either String Consistency)
checkConsistency =
  P.fold check' (Right (Consistency M.empty M.empty)) id
