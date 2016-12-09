{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE LambdaCase #-}
module Wiretap.Data.History where

import           Control.Monad
import           Data.Foldable
import qualified Data.Map           as M
import qualified Data.Set           as S
import           Data.Unique
import qualified Data.Vector        as V

import           Wiretap.Data.Event
import           Wiretap.Utils


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

instance PartialHistory (S.Set (Unique Event)) where
  enumerate = S.toAscList

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
        (ys', [])         -> concat [xs, [ab], ys']
    (xs, []) -> xs
  where
    isNotAB e = e /= a && e /= b

byThread :: PartialHistory h
  => h
  -> M.Map Thread [Unique Event]
byThread =
  simulateReverse step M.empty
  where
  step u@(Unique _ e) =
    updateDefault [] (u:) $ thread e

onEvent
  :: PartialHistory h
  => (Operation -> Maybe b)
  -> (Unique Event -> b -> a)
  -> h
  -> [a]
onEvent g f =
  simulateReverse (\u -> maybe id ((:) . f u) . g . operation . normal $ u) []

onReads
  :: PartialHistory h
  => (Unique Event -> (Location, Value) -> a)
  -> h
  -> [a]
onReads = onEvent filter
  where filter (Read l v) = Just (l, v)
        filter _ = Nothing

onWrites
  :: PartialHistory h
  => (Unique Event -> (Location, Value) -> a)
  -> h
  -> [a]
onWrites = onEvent filter
  where filter (Write l v) = Just (l, v)
        filter _ = Nothing

onAcquires
  :: PartialHistory h
  => (Unique Event -> Ref -> a)
  -> h
  -> [a]
onAcquires = onEvent filter
  where filter (Acquire r) = Just r
        filter _ = Nothing
