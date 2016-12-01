{-# LANGUAGE FlexibleInstances #-}
module Wiretap.Data.History where

import qualified Data.Vector as V

import Wiretap.Data.Event

import Data.Unique
import Data.Foldable

import Control.Monad

newtype History = History
  { toVector :: V.Vector Event
  } deriving (Show)

class PartialHistory h where
  enumerate :: h -> [Unique Event]

instance PartialHistory History where
  enumerate =
    byIndex . toList . toVector

instance PartialHistory [Unique Event] where
  enumerate = id

simulate :: PartialHistory h
  => (Unique Event -> a -> a)
  -> a -> h -> a
simulate f a h =
  foldl' (flip f) a (enumerate h)

simulateReverse :: PartialHistory h
  => (Unique Event -> a -> a)
  -> a -> h -> a
simulateReverse f a h =
  foldl' (flip f) a (reverse . enumerate $ h)


simulateM :: (PartialHistory h, Monad m)
  => (Unique Event -> m a)
  -> h -> m [Unique a]
simulateM f h =
  zipWith (\u e -> const e <$> u) uniques <$> mapM f uniques
  where uniques = enumerate h

fromEvents :: Foldable t
   => t Event
   -> History
fromEvents events =
  History . V.fromList $ toList events

hfilter :: PartialHistory h
  => (Unique Event -> Bool) -> h -> [Unique Event]
hfilter f =
  filter f . enumerate

withPair :: PartialHistory h
  => (Unique Event, Unique Event) -> h -> [Unique Event]
withPair (a, b) h =
  case span isNotAB $ enumerate h of
    (xs, ab : ys) ->
      case span isNotAB ys of
        (ys', ab' : rest) -> concat [xs, [ab], ys', [ab']]
        (ys', []) -> concat [xs, [ab], ys']
    (xs, []) -> xs
  where
    isNotAB e = e /= a && e /= b
