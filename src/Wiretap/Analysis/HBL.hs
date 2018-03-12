{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE RankNTypes                 #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE TupleSections              #-}
{-# LANGUAGE UndecidableInstances       #-}
module Wiretap.Analysis.HBL
  ( HBL
  , Logic (..)
  , HBLAtom (..)
  , (~>)
  , (~~)

  , orders
  , totalOrder
  , concurrent

  , toCNF
  , hblSize

   -- * Problem definition
  , HBLProblem (..)
  , reduceProblem


  , PartialWorld
  , Linear (..)
  , reduceProblem'
  , add
   -- * Solver
  , HBLSolver (..)
  )
where

import           Prelude                    hiding (product)

-- import qualified Data.IntMap.Strict         as IM
-- import qualified Data.List                  as L
-- import           Data.Unique
-- import           Control.Monad.IO.Class

import Data.Maybe
import qualified Data.Map as M
import qualified Data.IntMap as IM
-- import qualified Data.IntSet as IS
import qualified Data.Set as S
import qualified Data.List as L
import qualified Data.Graph.Inductive.Graph as G
import qualified Data.Graph.Inductive.PatriciaTree as G
import qualified Data.Graph.Inductive.Query.DFS as G
import           Wiretap.Utils
import           Data.Foldable (Foldable, toList)

-- import Debug.Trace

-- | Any kind of logic starts with these three operators
data Logic a
  = And [Logic a]
  | Or [Logic a]
  | Atom !a
  deriving (Show, Eq)

-- | The happens before logic atoms
data HBLAtom s e
 = Order e e
 | Concur e e
 | Symbol s
 deriving (Show)

-- | HBL - Happens before logic
type HBL s e = Logic (HBLAtom s e)

hblSize :: HBL s e -> Integer
hblSize hbl =
  case hbl of
    Atom _ -> 1
    And ls    -> 1 + sum (map hblSize ls)
    Or ls     -> 1 + sum (map hblSize ls)

infixl 8 ~>
(~>) :: e -> e -> HBL s e
(~>) = Atom ... Order

infixl 8 ~~
(~~) :: e -> e -> HBL s e
(~~) = Atom ... Concur

totalOrder :: [e] -> HBL s e
totalOrder = And . pairwise (~>)

orders ::  [e] -> [e] -> HBL s e
orders as bs = And [ a ~> b | a <- as, b <- bs ]

concurrent :: Foldable f => f e -> HBL s e
concurrent as =
  And [ a ~~ b | (a, b) <- combinations (toList as)]

toCNF :: Logic a -> [[a]]
toCNF e =
  case e of
    Atom a -> [[ a ]]
    And es ->
      concatMap toCNF es
    Or es ->
      combinate (product (++)) $ map toCNF es

class (Monad m) => HBLSolver s e m where
  assert :: HBL s e -> m ()
  -- declare :: s -> HBL s e -> m ()
  sat :: HBL s e -> m Bool

data HBLProblem s e a = HBLProblem
  { probGenerate :: a -> HBL s e
  , probBase     :: HBL s e
  , probElements :: [e]
  , probSymbols :: [s]
  , probSymbolDef  :: s -> HBL s e
  }

reduceProblem :: (Ord e, Ord s) => HBLProblem s e a -> HBLProblem s e a
reduceProblem p = p

-- learn :: PartialWorld s e -> HBLProblem s e a -> (PartialWorld s e, HBLProblem s e a)
-- learn pw p =


reduceProblem' :: (Ord e, Ord s) => PartialWorld s e -> HBLProblem s e a -> HBLProblem s e a
reduceProblem' pw@(sm, _) p =
  p { probBase      = reduce pw $ probBase p
    -- , probElements  = probElements p
    , probSymbols   = symbols
    , probSymbolDef =
      \smb -> reduce pw (probSymbolDef p smb)
    }
  where
    symbols = filter (not . (`M.member` sm)) $ probSymbols p


data Linear e = Linear
  { lToGroup :: M.Map e (G.Node, Int)
  , lGroups :: IM.IntMap (S.Set e)
  , lGraph :: G.Gr () ()
  }

ordered :: Ord e => Linear e -> e -> e -> Bool
ordered (Linear m _ gr) a b = fromMaybe False $ do
  (groupa, ordera) <- M.lookup a m
  (groupb, orderb) <- M.lookup b m

  return $
    if groupb == groupa
      then ordera < orderb
      else L.elem orderb $ G.reachable ordera gr

getGroup :: Ord e => e -> Linear e -> (Linear e, G.Node)
getGroup e p =
    case M.lookup e $ lToGroup p of
      Just (x, _) -> (p, x)
      Nothing ->
        let y = M.size $ lToGroup p
        in (p { lToGroup = M.insert e (y, 0) $ lToGroup p }, y)

add :: Ord e => e -> e -> Linear e -> Linear e
add a b p@(Linear _ _ gr) =
  p'' { lGraph = G.insEdge (ai, bi, ()) gr }
  where
    (p',  bi) = getGroup b p
    (p'', ai) = getGroup a p'


type PartialWorld s e = (M.Map s Bool, Linear e)


-- learn :: (Ord e, Ord s) => PartialWorld s e -> HBL s e -> (PartialWorld s e, HBL s e)
-- learn pw l =
--   case l of
--     And as ->
--     Or as ->


reduce :: (Ord e, Ord s) => PartialWorld s e -> HBL s e -> HBL s e
reduce pw l =
  case l of
    And as ->
      let items = map (reduce pw) as
      in case L.foldl' join (Just []) items of
        Just xs -> And xs
        Nothing -> Or []
    Or as ->
      let items = map (reduce pw) as
      in case L.foldl' intersect (Just []) items of
        Just xs -> Or xs
        Nothing -> And []

    Atom a ->
      reduceAtom pw a

  where
    join (Just b) a =
      case a of
        And as -> Just $ as ++ b
        Or [] -> Nothing
        _ -> Just $ [a] ++ b
    join Nothing _ = Nothing

    intersect (Just b) a =
      case a of
        Or as -> Just $ as ++ b
        And [] -> Nothing
        _ -> Just $ [a] ++ b
    intersect Nothing _ = Nothing

reduceAtom :: (Ord e, Ord s) => PartialWorld s e -> HBLAtom s e -> HBL s e
reduceAtom (symbols, lin) l =
  case l of
    Order a b
      | ordered lin a b ->
        And []
      | ordered lin b a ->
        Or []
    Concur a b
      | ordered lin a b || ordered lin b a ->
        Or []
    Symbol s ->
      case M.lookup s symbols of
        Just True -> And []
        Just False -> Or []
        Nothing -> Atom l
    _ ->
      Atom l
