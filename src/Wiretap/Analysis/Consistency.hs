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
import           Wiretap.Data.Program
import           Wiretap.Format.Text

data Consistency = Consistency
  { _values :: M.Map Location (UE, Value)
  , _locks  :: M.Map Thread (M.Map Ref UE)
  } deriving (Show, Eq)


makeLenses ''Consistency

check :: Program -> Consistency -> UE -> Either String Consistency
check p cn ue@(Unique _ e) =
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
            Left $ "Last value written to " ++ pp p l ++ " was: " ++ show (pp p a, pp p v')
        Nothing ->
          trace (pp p ue ++ ": no value") $ Right cn
    Write l v ->
      Right $ cn & values.at l ?~ (ue, v)
    _ -> Right cn


check' :: Program -> Either String Consistency -> UE -> Either String Consistency
check' p esc e =
  case esc of
    Right x ->
      either (Left . ((pp p e ++ ": ") ++)) Right $ check p x e
    _ -> esc

checkConsistency ::
  Monad m
  => Program
  -> Producer UE m ()
  -> m (Either String Consistency)
checkConsistency p =
  P.fold (check' p) (Right (Consistency M.empty M.empty)) id
