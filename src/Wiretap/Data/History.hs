{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE LambdaCase        #-}
module Wiretap.Data.History where

import           Data.Foldable
import qualified Data.Map           as M
import qualified Data.Set           as S
import           Data.Unique
import qualified Data.Vector        as V

import           Wiretap.Data.Event
import           Wiretap.Utils

type UE = Unique Event

newtype History = History
  { toVector :: V.Vector Event
  } deriving (Show)

class PartialHistory h where
  enumerate :: h -> [UE]
  hfold :: (Monoid m) => (UE -> m) -> h -> m
  hfoldr :: (UE -> b -> b) -> b -> h -> b

instance PartialHistory History where
  enumerate =
    byIndex . toList . toVector
  {-# INLINE enumerate #-}
  hfold f = foldMap f . enumerate
  hfoldr f b = foldr f b . enumerate

instance PartialHistory [UE] where
  enumerate = id
  {-# INLINE enumerate #-}
  hfold = foldMap
  hfoldr = foldr

instance PartialHistory (S.Set (UE)) where
  enumerate = S.toAscList

  {-# INLINE enumerate #-}
  hfold = foldMap
  hfoldr = foldr

simulate :: PartialHistory h
  => (UE -> a -> a)
  -> a -> h -> a
simulate f a h =
  foldl' (flip f) a (enumerate h)

{-# INLINE simulate #-}

simulateReverse :: PartialHistory h
  => (UE -> a -> a)
  -> a -> h -> a
simulateReverse f a h =
  foldl' (flip f) a (reverse . enumerate $ h)

{-# INLINE simulateReverse #-}

simulateM :: (PartialHistory h, Monad m)
  => (UE -> m a)
  -> h -> m [Unique a]
simulateM f h =
  zipWith (\u e -> const e <$> u) uniques <$> mapM f uniques
  where uniques = enumerate h

{-# INLINE simulateM #-}

fromEvents :: Foldable t
   => t Event
   -> History
fromEvents events =
  History . V.fromList $ toList events

hfilter :: PartialHistory h
  => (UE -> Bool) -> h -> [UE]
hfilter f =
  filter f . enumerate

withPair :: PartialHistory h
  => (UE, UE) -> h -> [UE]
withPair (a, b) h =
  case span isNotAB $ enumerate h of
    (xs, ab : ys) ->
      case span isNotAB ys of
        (ys', ab' : _) -> concat [xs, [ab], ys', [ab']]
        (ys', [])      -> concat [xs, [ab], ys']
    (xs, []) -> xs
  where
    isNotAB e = e /= a && e /= b

prefixContaining
  :: PartialHistory h
  => S.Set UE
  -> h
  -> [UE]
prefixContaining es h =
  go es (enumerate h)
  where
    go es' _ | null es' = []
    go _ [] = []
    go es' (e: h') =
      e : if e `S.member` es'
          then go (e `S.delete` es') h'
          else go es' h'

byThread :: PartialHistory h
  => h
  -> M.Map Thread [UE]
byThread =
  simulateReverse step M.empty
  where
  step u@(Unique _ e) =
    updateDefault [] (u:) $ thread e

threadOf :: UE -> Thread
threadOf = thread . normal

onEvent
  :: PartialHistory h
  => (Operation -> Maybe b)
  -> (UE -> b -> a)
  -> h
  -> [a]
onEvent g f =
  simulateReverse (\u -> maybe id ((:) . f u) . g . operation . normal $ u) []

{-# INLINE onEvent #-}

onReads
  :: PartialHistory h
  => (UE -> (Location, Value) -> a)
  -> h
  -> [a]
onReads = onEvent filter'
  where filter' (Read l v) = Just (l, v)
        filter' _          = Nothing

{-# INLINE onReads #-}

onWrites
  :: PartialHistory h
  => (UE -> (Location, Value) -> a)
  -> h
  -> [a]
onWrites = onEvent filter'
  where filter' (Write l v) = Just (l, v)
        filter' _           = Nothing

{-# INLINE onWrites #-}

onAcquires
  :: PartialHistory h
  => (UE -> Ref -> a)
  -> h
  -> [a]
onAcquires = onEvent filter'
  where filter' (Acquire r) = Just r
        filter' _           = Nothing

{-# INLINE onAcquires #-}

onRequests
  :: PartialHistory h
  => (UE -> Ref -> a)
  -> h
  -> [a]
onRequests = onEvent filter'
  where filter' (Request r) = Just r
        filter' _           = Nothing

{-# INLINE onRequests #-}
