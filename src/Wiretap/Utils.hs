module Wiretap.Utils where

import qualified Data.List as L
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
