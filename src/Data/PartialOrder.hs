module Data.PartialOrder
  ( PartialOrder(..)
  , (!<)
  , (!>)
  , (!>=)
  , (!<=)
  ) where

(...) :: (b -> c) -> (a -> a1 -> b) -> a -> a1 -> c
(...) = (.) . (.)

{-# INLINE (...) #-}

class PartialOrder a where
  cmp :: a -> a -> Maybe Ordering

(!<) :: PartialOrder a => a -> a -> Bool
(!<) = maybe False (LT ==) ... cmp

{-# INLINE (!<) #-}

(!>) :: PartialOrder a => a -> a -> Bool
(!>) = maybe False (GT ==) ... cmp

{-# INLINE (!>) #-}

(!<=) :: PartialOrder a => a -> a -> Bool
(!<=) = maybe False (\x -> LT == x || EQ == x) ... cmp

{-# INLINE (!<=) #-}

(!>=) :: PartialOrder a => a -> a -> Bool
(!>=) = maybe False (GT ==) ... cmp

{-# INLINE (!>=) #-}

-- instance Ord a => PartialOrder a where
--   cmp = Just ... compare
