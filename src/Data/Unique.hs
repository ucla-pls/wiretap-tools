module Data.Unique where

import           Data.Function    (on)
import qualified Data.IntMap      as M
import           Data.Traversable

import Data.PartialOrder

{-| Takes elements and make them unique by assigning an identifier -}
data Unique e = Unique
 { idx    :: !Int
 , normal :: e
 } deriving (Show)

instance PartialOrder e => PartialOrder (Unique e) where
  cmp (Unique _ a) (Unique _ b) = cmp a b


toPair :: Unique e -> (Int, e)
toPair e = (idx e, normal e)

instance Functor Unique where
  fmap f (Unique i e) = Unique i (f e)

instance Eq (Unique e) where
 (==) (Unique a _ ) (Unique b _) = a == b


instance Ord (Unique e) where
  compare = compare `on` idx

byIndex :: Traversable t
  => t a
  -> t (Unique a)
byIndex = snd . mapAccumL (\i e ->((i + 1), Unique i e)) 0

newtype UniqueMap a = UniqueMap
  { toIntMap :: M.IntMap a
  } deriving (Show)

-- | Assumes that unique is from to
fromUniques :: [Unique a] -> UniqueMap a
fromUniques lst =
  UniqueMap $ M.fromDistinctAscList (map toPair lst)

(!) :: UniqueMap a -> Unique b -> a
m ! u =
  case m !? idx u of
    Just a -> a
    Nothing ->
      error $ "Could not find " ++ (show $ idx u) ++ " in UniqueMap."

(!?) :: UniqueMap a -> Int -> Maybe a
m !? u =
  M.lookup u $ toIntMap m


(!!!) :: Show b => UniqueMap a -> Unique b -> a
m !!! u =
  case m !? idx u of
    Just a -> a
    Nothing ->
      error $ "Could not find " ++ (show $ u) ++ " in UniqueMap."
