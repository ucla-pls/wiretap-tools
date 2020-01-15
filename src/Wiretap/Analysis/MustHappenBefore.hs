{-# LANGUAGE TemplateHaskell #-}
module Wiretap.Analysis.MustHappenBefore where

import           Control.Lens
import qualified Data.Map             as Map
import qualified Data.List             as List
import           Data.Unique

import           Wiretap.Data.History
import           Wiretap.Data.Event
import           Wiretap.Utils

data MHBEvents = MHBEvents
  { _mhbJoins  :: [UE]
  , _mhbForks  :: [UE]
  , _mhbBegins :: [UE]
  , _mhbEnds   :: [UE]
  } deriving (Show, Eq, Ord)

data MHB = MHB
  { _mhbEdges :: [(UE, UE)]
  , _mhbEvents :: Map.Map Thread MHBEvents
  , _mhbEventGraph :: MHBGraph
  } deriving (Show, Eq, Ord)

type MHBGraph =
  Map.Map (Thread, Thread) (Order, Order)

makeLenses ''MHB
makeLenses ''MHBEvents

mhbEmpty :: MHB
mhbEmpty = MHB mempty mempty mempty

mhbForkOf :: MHB -> UE -> Maybe UE
mhbForkOf mh ue =
  case _mhbForks $ _mhbEvents mh Map.! threadOf ue of
    e:[] -> Just e
    _ -> Nothing

mhbEndOf :: MHB -> Thread -> Maybe UE
mhbEndOf mh t =
  case _mhbEnds $ _mhbEvents mh Map.! t of
    e:[] -> Just e
    _ -> Nothing

mhb' :: MHBGraph -> Event -> Event -> Bool
mhb' m e1 e2 =
  maybe False id $ do
    (f, t) <- Map.lookup (thread e1, thread e2) m
    return $ (order e1) <= f && t <= (order e2)

{-# INLINE mhb' #-}

mhb :: MHB -> UE -> UE -> Bool
mhb m (Unique _ e1) (Unique _ e2) = mhb' (m^.mhbEventGraph) e1 e2

{-# INLINE mhb #-}

mhbDependend :: MHB -> UE -> UE -> Bool
mhbDependend m e1 e2 =
  mhb m e1 e2 || mhb m e2 e1

{-# INLINE mhbDependend #-}

mhbFree :: MHB -> UE -> UE -> Bool
mhbFree m e1 e2 = not $ mhbDependend m e1 e2

{-# INLINE mhbFree #-}

mustHappenBefore ::
  PartialHistory h
  => h
  -> MHB
mustHappenBefore h =
  let
    events = mustHappenBeforeEvents Map.empty h
    edges = edgesFromEvents events
  in
    MHB edges events (graphFromEdges edges)

graphFromEdges ::
  [(UE, UE)]
  -> MHBGraph
graphFromEdges edges =
  Map.fromListWithKey pickSmallest $ List.foldl' addEdge [] edges
  where
    pickSmallest k a@(n1, n2) a'@(n3, n4)
      | n1 == n3 = (n1, min n2 n4)
      | otherwise = error $ "This should not happen " ++ show (k,a,a')
    addEdge m (Unique _ e1, Unique _ e2) =
      ((thread e1, thread e2),(order e1, order e2)):
          List.concatMap f m
      where
        f a@((t1, t2), (n1,n2)) =
          if t2 == thread e1 && t1 /= thread e2 && n2 <= order e1 then
            [a, ((t1, thread e2), (n1, order e2))]
          else [a]

edgesFromEvents :: Map.Map Thread MHBEvents -> [(UE, UE)]
edgesFromEvents =
  List.concatMap fn . Map.elems
  where
    fn mhbs =
      [ (f, b)
      | f <- mhbs^.mhbForks, b <- mhbs^.mhbBegins
      ] ++
      [ (e, j)
      | e <- mhbs^.mhbEnds, j <- mhbs^.mhbJoins
      ]

mustHappenBeforeEvents ::
  PartialHistory h
  => Map.Map Thread MHBEvents
  -> h
  -> Map.Map Thread MHBEvents
mustHappenBeforeEvents m h =
  simulate step m h
  where
    step u@(Unique _ e) =
      case operation e of
        Join t -> update mhbJoins t
        Fork t -> update mhbForks t
        Begin  -> update mhbBegins $ thread e
        End    -> update mhbEnds $ thread e
        _      -> id
      where
        update l = updateDefault (MHBEvents [] [] [] []) (over l (u:))
