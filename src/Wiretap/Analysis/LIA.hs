module Wiretap.Analysis.LIA
  ( LIA (..)
  , LIAAtom (..)
  , (~>)
  , pairwise
  , orders
  , totalOrder

  , toCNF
  , solve
  , toZ3
  )
where

import Prelude hiding (product)

import qualified Data.Vector as V
import qualified Data.List as L

import Control.Monad.IO.Class
import Data.Unique

import Z3.Monad (AST, mkLt, mkAnd, mkOr
                , withModel, evalInt
                , mkFreshIntVar, MonadZ3
                , evalZ3, mkEq, mkTrue, assert
                )

{-| LIA - Linear integer arithmetic -}
data LIA e
  = Order e e
  | Eq e e
  | And [LIA e]
  | Or [LIA e]
  deriving (Show)

infixl 8 ~>
(~>) :: e -> e -> LIA e
(~>) = Order

totalOrder :: [e] -> LIA e
totalOrder = And . pairwise (~>)

pairwise :: (a -> a -> b) -> [a] -> [b]
pairwise f es = zipWith f es (tail es)

orders ::  [e] -> [e] -> LIA e
orders as bs = And [ a ~> b | a <- as, b <- bs ]

data LIAAtom e
 = AOrder e e
 | AEq e e
 deriving (Show)

toCNF :: LIA e -> [[LIAAtom e]]
toCNF e =
  case e of
    Order a b -> [[AOrder a b]]
    Eq a b -> [[AEq a b]]
    And es ->
      concatMap toCNF es
    Or es ->
      combinate (product (++)) $ map toCNF es

combinate :: ([a] -> [a] -> [a]) -> [[a]] -> [a]
combinate f l =
  case l of
    a':[] -> a'
    a':as -> f a' $ combinate f as
    [] -> []

product :: (a -> b -> c) -> [a] -> [b] -> [c]
product f as bs =
  [ f a b | a <- as, b <- bs ]


{-| solve takes a vector of elements and logic constraints -}
solve :: MonadIO m
  => [Unique e]
  -> LIA (Unique e)
  -> m (Maybe [Unique e])
solve elems lia = liftIO $ evalZ3 $ do
  vars <- V.replicateM (L.length elems) $ mkFreshIntVar "O"
  ast <- toZ3 (\e -> vars V.! idx e) lia

  assert ast

  (_, solution) <- withModel $ \m -> V.mapM (evalInt m) vars

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
    And [] ->
      mkTrue
    And cs ->
      mkAnd =<< mapM (toZ3 var) cs
    Or cs ->
      mkOr =<< mapM (toZ3 var) cs
    Order a b ->
      mkLt (var a) (var b)
    Eq a b ->
      mkEq (var a) (var b)
