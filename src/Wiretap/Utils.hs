module Wiretap.Utils where

import qualified Data.List as L
import qualified Data.Map as M
import Control.Monad

{-| a blackbird -}
(...) = (.) . (.)

{-| returns the possible combinations of pairs, without replacements -}
combinations :: [a] -> [(a, a)]
combinations =
  L.concat . go
  where
    go (a:as) =
     [(a,a') | a' <- as] : go as
    go [] = []

{-| all possible pairs of two lists -}
crossproduct :: [a] -> [b] -> [(a, b)]
crossproduct =
  liftM2 (,)

groupOnFst :: Eq a
  => [(a, b)]
  -> [(a, [b])]
groupOnFst =
  groupOn fst ((:[]) . snd)

groupOn :: (Eq a, Monoid m)
  => (x -> a)
  -> (x -> m)
  -> [x]
  -> [(a, m)]
groupOn _ _ []         = []
groupOn f g (x:xs) =
  (f x, mconcat (g x : map g ys)) : groupOn f g zs
  where
    (ys, zs) = span ((f x ==) . f) xs

groupUnsortedOnFst :: Ord a
  => [(a, b)]
  -> [(a, [b])]
groupUnsortedOnFst =
  groupUnsortedOn fst ((:[]). snd)

groupUnsortedOn :: (Ord a, Monoid m)
  => (x -> a)
  -> (x -> m)
  -> [x]
  -> [(a, m)]
groupUnsortedOn f g =
  groupOn f g . L.sortOn f

mapOn :: (Ord a, Monoid m)
  => (x -> a)
  -> (x -> m)
  -> [x]
  -> M.Map a m
mapOn f g =
  M.fromDistinctAscList . groupUnsortedOn f g

mapOnFst :: Ord a
  => [(a, b)]
  -> M.Map a [b]
mapOnFst =
  mapOn fst ((:[]) . snd)

unpair
  :: [(a, b)]
  -> ([a], [b])
unpair as =
  (map fst as, map snd as)

withDefault
  :: a
  -> (a -> b)
  -> Maybe a
  -> Maybe b
withDefault a f =
  Just . f . def a

updateDefault
  :: (Ord k)
  => a
  -> (a -> a)
  -> k
  -> M.Map k a
  -> M.Map k a
updateDefault a f =
  M.alter (withDefault a f)

def :: a -> Maybe a -> a
def = flip maybe id

defM
  :: Monoid m
  => Maybe m
  -> m
defM (Just m) = m
defM (Nothing) = mempty
