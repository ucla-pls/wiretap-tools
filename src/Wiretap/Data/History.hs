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

simulate :: PartialHistory h
  => (Unique Event -> a -> a)
  -> a -> h -> a
simulate f a h =
  foldl' (flip f) a (enumerate h)

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
