module Data.Unique where

import           Data.Traversable
import qualified Data.Vector as V

import           Data.Function    (on)

(...) = (.) . (.)

{-| Takes elements and make them unique by assigning an identifier -}
data Unique e = Unique
 { idx    :: !Int
 , normal :: e
 } deriving (Show)

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

newtype UniqueMap e = UniqueMap
  { toVector :: V.Vector (Unique e)
  } deriving (Show)

(!*) :: UniqueMap e -> Unique b -> Unique e
(!*) m e = toVector m V.! idx e

(!) :: UniqueMap e -> Unique b -> e
(!) = normal ... (!*)

fromVector :: V.Vector a -> UniqueMap a
fromVector = UniqueMap . byIndex

fromList :: [a] -> UniqueMap a
fromList = UniqueMap . byIndex . V.fromList

instance Functor UniqueMap where
  fmap f =
   UniqueMap . fmap (fmap f) . toVector

instance Foldable UniqueMap where
  foldMap f =
    foldMap (f . normal) . toVector
  foldr f b =
    foldr (f . normal) b . toVector

instance Traversable UniqueMap where
  traverse f es =
    fromVector <$> traverse (f . normal) (toVector es)
