module Wiretap.Analysis.LIA where

import qualified Data.Vector as V
import qualified Data.List as L

import Data.Unique

import Z3.Monad (AST, mkLt, mkAnd, mkOr
                , withModel, evalInt
                , mkFreshIntVar, MonadZ3)

{-| LIA - Linear integer arithmetic -}
data LIA e
  = Order e e
  | And [LIA e]
  | Or [LIA e]

infixl 8 ~>
(~>) = Order

totalOrder :: [e] -> LIA e
totalOrder = And . pairwise (~>)

pairwise :: (a -> a -> b) -> [a] -> [b]
pairwise f es = zipWith f es (tail es)

orders ::  [e] -> [e] -> LIA e
orders as bs = And [ a ~> b | a <- as, b <- bs ]

{-| solve takes a vector of elements and logic constraints -}
solve :: MonadZ3 m
  => [Unique e]
  -> LIA (Unique e)
  -> m (Maybe [Unique e])
solve elems lia = do
  vars <- V.replicateM (L.length elems) $ mkFreshIntVar "O"
  ast <- toZ3 (\e -> vars V.! idx e) lia

  (result, solution) <- withModel $ \m -> V.mapM (evalInt m) vars

  case solution of
    Just assignment -> do
       return . Just $ L.sortOn (\e -> assignment V.! idx e) elems
    Nothing ->
      return Nothing

toZ3 :: MonadZ3 m
  => (e -> AST)
  -> LIA e
  -> m AST
toZ3 var lia =
  case lia of
    And cs ->
      mkAnd =<< mapM (toZ3 var) cs
    Or cs ->
      mkOr =<< mapM (toZ3 var) cs
    Order a b ->
      mkLt (var a) (var b)
