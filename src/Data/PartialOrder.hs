module Data.PartialOrder
  ( PartialOrder(..)
  , (!<)
  , (!>)
  , (!>=)
  , (!<=)
  ) where

(...) = (.) . (.)

class PartialOrder a where
  cmp :: a -> a -> Maybe Ordering

(!<) :: PartialOrder a => a -> a -> Bool
(!<) = maybe False (LT ==) ... cmp

(!>) :: PartialOrder a => a -> a -> Bool
(!>) = maybe False (GT ==) ... cmp

(!<=) :: PartialOrder a => a -> a -> Bool
(!<=) = maybe False (\x -> LT == x || EQ == x) ... cmp

(!>=) :: PartialOrder a => a -> a -> Bool
(!>=) = maybe False (GT ==) ... cmp

-- instance Ord a => PartialOrder a where
--   cmp = Just ... compare
