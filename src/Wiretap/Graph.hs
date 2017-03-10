{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Wiretap.Graph
  ( cycles
  , Cycle
  ) where

-- Graph analysis tools

import qualified Data.Graph.Inductive.Graph as G
import qualified Data.Graph.Inductive.PatriciaTree as GP
import Data.Graph.Inductive.Query.DFS (dff')
import Data.Tree
import Data.List
import Data.Maybe
import Data.Unique
import Wiretap.Utils

import qualified Data.Set as S

type Cycle a b = S.Set (a, b, a)

cyclesFrom :: (G.Graph gr, Ord a, Ord b) => gr a b -> G.Node -> [Cycle G.Node b]
cyclesFrom gr = go []
  where
    go path x =
      case dropWhileEnd (\(n, _, _) -> n /= x) path of
        [] -> concatMap (followEdge path x) $ G.lsuc gr x
        cycl -> [S.fromList cycl]

    followEdge path x (n, l) =
      let edge = (x, l, n) in
      go (edge : path) n

    -- cleanPath = reverse . map (\(x,_,_) -> x)

cycles' :: (G.Graph gr, Ord a, Ord b) => gr a b -> [Cycle G.Node b]
cycles' gr =
  concatMap (cyclesFrom gr . rootLabel) $ forest
  where forest = dff' gr


cycles
  :: forall a b. (Ord a , Ord b)
  => [a]
  -> (a -> a -> Maybe b)
  -> [Cycle a b]
cycles elems f =
  S.map fromEdge <$> cycles' graph
  where
    fromEdge (n, l, n') = (fromNode n, l, fromNode n')

    nodes = byIndex elems

    uniquemap = fromUniques nodes

    edges =
      catMaybes . map toEdge $ crossproduct nodes nodes

    graph :: GP.Gr () b
    graph =
      G.mkGraph (fmap (\n -> (idx n, ())) nodes) edges

    toEdge (n, n') = do
      l <- f (normal n) (normal n')
      return (idx n, idx n', l)

    fromNode n =
      case uniquemap !? n of
        Just r -> r
        Nothing ->
          error $ "Could not find node in the UniqeMap"
