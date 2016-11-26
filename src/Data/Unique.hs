module Data.Unique where

import           Data.Traversable
import qualified Data.Vector as V

import           Wiretap.Utils

import           Data.Function    (on)
import qualified Data.IntMap as M

{-| Takes elements and make them unique by assigning an identifier -}
data Unique e = Unique
 { idx    :: !Int
 , normal :: e
 } deriving (Show)

toPair :: Unique e -> (Int, e)
toPair e = (idx e, normal e)

instance Functor Unique where
  fmap f (Unique i e) = Unique i (f e)

instance Eq (Unique e) where
  (==) = (==) `on` idx

instance Ord (Unique e) where
  compare = compare `on` idx

byIndex :: Traversable t
  => t a
  -> t (Unique a)
byIndex = snd . mapAccumL (\i e ->((i + 1), Unique i e)) 0

newtype UMap a = UMap
  { toIntMap :: M.IntMap a
  } deriving (Show)

{-| Assumes that unique is from to  -}
fromUniques :: [Unique a] -> UMap a
fromUniques =
  UMap . M.fromDistinctAscList . map toPair

(!) :: UMap a -> Unique b -> a
m ! u = toIntMap m M.! idx u
