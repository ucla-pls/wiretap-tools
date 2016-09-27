{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE Rank2Types #-}

module Wiretap.Analysis where

import           Control.Monad.State
import           Control.Lens hiding ((...))

import           Data.Monoid
import           Data.Function (on)

import qualified Data.Map as M
import qualified Data.IntMap as IM
import qualified Data.List as L

import qualified Z3.Base

import           Wiretap.Data.Event(Event(..), Operation(..), Thread(..))
import qualified Wiretap.Data.Event as Event

data Order = Order { from :: Int, to :: Int } deriving (Show)

infixl 8 ~>
(~>) = Order


update :: Monoid b => Lens' a b -> a -> a -> a
update l a = l <>~ (a ^. l)

data MhbData =
  MhbData { _mhbFork  :: Last Int
          , _mhbBegin :: Last Int
          , _mhbEnd   :: Last Int
          , _mhbJoins :: [Int]
          } deriving (Show)
makeLenses ''MhbData

emptyMhbData = MhbData mempty mempty mempty mempty

instance Monoid MhbData where
  mempty = emptyMhbData
  mappend a b = update mhbFork b
              . update mhbBegin b
              . update mhbEnd b
              . update mhbJoins b
              $ a

(...) = (.) . (.)

newtype Mhb = Mhb { _mhbMap :: IM.IntMap MhbData } deriving (Show)
makeLenses ''Mhb

instance Monoid Mhb where
  mempty = Mhb IM.empty
  mappend = Mhb ... IM.unionWith (<>) `on` _mhbMap

with :: Monoid a => Lens' a b -> b -> a
with l v = mempty & l .~ v

withM :: (Monoid a, Monad m) => Lens' a (m b) -> b -> a
withM l v = mempty & l .~ return v

atThread :: Thread -> Lens' Mhb (Maybe MhbData)
atThread t = mhbMap . at (threadId t)

withThread :: Monad m => Thread -> Lens' MhbData (m a) -> a -> Mhb
withThread t l v = withM (atThread t) $ withM l v

-- Calculate the must happen before, expects the events to be
-- in order in the threads.
mhb :: Int -> Event -> Mhb
mhb i (Event {thread=t, operation=o}) =
  case o of
    Begin   -> withThread t mhbBegin i
    End     -> withThread t mhbEnd i
    Fork t' -> withThread t' mhbFork i
    Join t' -> withThread t' mhbJoins i
    _ -> mempty

_Last :: Prism' (Last a) a
_Last = prism' (Last . Just) getLast

mhbOrders :: Mhb -> [Order]
mhbOrders = IM.foldMapWithKey (const mhbDataOrders) . (^. mhbMap)
  where
    mhbDataOrders a =
      case (a ^? mhbFork . _Last, a ^? mhbBegin . _Last) of
        (Just i, Just j) -> [ i ~> j ]
        _ -> []
      ++
      case a ^? mhbEnd . _Last of
        Just e -> map (e ~>) $ a ^. mhbJoins
        _ -> []



linearizeTotal :: [Event] -> [Event]
linearizeTotal = id

linearizeTotal' :: [Event] -> IO ()
linearizeTotal' events = do
  let mhb' = mconcat $ L.zipWith mhb [0..] events
  print mhb'
  print (mhbOrders mhb')
