{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE Rank2Types #-}

module Wiretap.Analysis where

import           Debug.Trace

import           Control.Monad.State
import           Control.Monad
import           Control.Lens hiding ((...))

import           Data.Maybe (maybeToList)
import           Data.Monoid
import           Data.Function (on)

import qualified Data.Map as M
import qualified Data.IntMap as IM
import qualified Data.List as L

import qualified Z3.Base

import           Wiretap.Data.Event(Event(..), Operation(..), Thread(..))
import qualified Wiretap.Data.Event as Event


(...) = (.) . (.)

infixl 8 ~>
(~>) = Order

with :: Monoid a => Lens' a b -> b -> a
with l v = mempty & l .~ v

withM :: (Monoid a, Monad m) => Lens' a (m b) -> b -> a
withM l v = mempty & l .~ return v

newtype IdMap a = IdMap { innerMap :: IM.IntMap a} deriving (Show)

instance Monoid a => Monoid (IdMap a) where
  mempty = IdMap IM.empty
  mappend = IdMap ... IM.unionWith (<>) `on` innerMap

instance Foldable IdMap where
  foldMap f = foldMap f . innerMap

atId :: Monoid a => Int -> a -> IdMap a
atId = IdMap ... IM.singleton

atThread :: Monoid a => Thread -> a -> IdMap a
atThread = atId . threadId

onAll :: Applicative f => f (a -> b) -> a -> f b
onAll a = (a <*>) . pure

type EventId = Int

data Order = Order
  { from :: EventId
  , to :: EventId
  } deriving (Show)

class Monoid a => OrderAnalysis a where
  fromEvent :: EventId -> Event -> a
  toOrders :: a -> [[Order]]

fromEvents :: OrderAnalysis a => [Event] -> a
fromEvents =
  mconcat . L.zipWith fromEvent [0..]

-- | orders, takes two lists and create orders between every event in the first
-- list and to every event in the second list.
orders :: [EventId] -> [EventId] -> [[Order]]
orders = map (:[]) ... liftM2 Order

-- | total, takes a list and create orders so that they the containing events
-- are total ordered.
totalOrder :: [EventId] -> [[Order]]
totalOrder = map (:[]) . ap (zipWith $ Order) tail


-- | Get unique pairs in list
pairs :: [a] -> [(a, a)]
pairs (a:rest) = map (\x -> (a, x)) rest ++ pairs rest
pairs [] = []

-- Must Happen Before Analysis
data MhbData = MhbData
  { _mhbForks  :: [EventId]
  , _mhbBegins :: [EventId]
  , _mhbEnds   :: [EventId]
  , _mhbJoins  :: [EventId]
  } deriving (Show)
makeLenses ''MhbData

instance Monoid MhbData where
  mempty = MhbData mempty mempty mempty mempty
  mappend a b =
    MhbData
      { _mhbForks = merge _mhbForks
      , _mhbBegins = merge _mhbBegins
      , _mhbEnds = merge _mhbEnds
      , _mhbJoins = merge _mhbJoins
      }
   where merge f = on mappend f a b

newtype MHB = MHB { mhb :: IdMap MhbData }

instance Monoid MHB where
  mempty = MHB mempty
  mappend = MHB ... mappend `on` mhb

instance OrderAnalysis MHB where
  fromEvent i (Event {thread=t, operation=o}) =
    MHB $ case o of
      Begin   -> atThread t  $ withM mhbBegins i
      End     -> atThread t  $ withM mhbEnds i
      Fork t' -> atThread t' $ withM mhbForks i
      Join t' -> atThread t' $ withM mhbJoins i
      _ -> mempty

  toOrders =
    foldMap mhbDataOrders . mhb
    where
      mhbDataOrders :: MhbData -> [[Order]]
      mhbDataOrders =
        concat . onAll
          [ order mhbForks mhbBegins
          , order mhbEnds mhbJoins
          ]
      order f1 f2 a = on orders (a ^.) f1 f2


-- Sequential Consistency
newtype SC =
  SC { cs :: IdMap [EventId] }

instance Monoid SC where
  mempty = SC mempty
  mappend = SC ... mappend `on` cs

-- Sequential Consistency expects all envents to be represented in order
instance OrderAnalysis SC where
  fromEvent i (Event {thread = t}) =
    SC $ atThread t [i]

  toOrders = foldMap totalOrder . cs

-- Lock Consistency
-- This analysis assumes that all locks are requested, acquired and released by
-- the same thread.


data LcType
  = LcAcquire EventId
  | LcRelease EventId
  deriving (Show)

type LcData =
  IdMap [LcType]

newtype LC =
  LC { lc :: IdMap LcData }
  deriving (Show)

instance Monoid LC where
  mempty = LC mempty
  mappend = LC ... mappend `on` lc

type LcCollector = ([(EventId, EventId)], [EventId])

instance OrderAnalysis LC where
  fromEvent i (Event{operation=o, thread=t}) =
    LC $ case o of
      Acquire ref -> append ref $ [LcAcquire i]
      Release ref -> append ref $ [LcRelease i]
      _ -> mempty
    where
      append ref = atId (fromIntegral . Event.pointer $ ref) . atThread t

  toOrders = foldMap byObject . lc
    where
      byObject :: LcData -> [[Order]]
      byObject a =
        concat
          [ lockOrder <$> pairs lockPairs
          , orderRemainders <$> lockPairs <*> remainders
          ]
        where
          (lockPairs, remainders) =
            foldMap (collectLockPairs . byThread) a

      byThread :: [LcType] -> LcCollector
      byThread types =
        L.foldl' collector ([],[]) types

      collector :: LcCollector -> LcType -> LcCollector
      collector (pairs, stack) (LcAcquire acq) =
        (pairs, acq:stack)

      collector (pairs, stack) (LcRelease rel) =
        case stack of
          acq:[] -> ((acq, rel):pairs, [])
          -- ^ Ignore re-entrant locks
          acq:ls -> (pairs, ls)
          _ -> error "Can't release a lock that has not been acquired"

      collectLockPairs (pairs, stack) =
        (pairs, take 1 stack)

      lockOrder ((a, r), (a', r')) =
        [r ~> a', r' ~> a]

      orderRemainders (_, rel) acq =
        [rel ~> acq]


-- Top level analyses

linearizeTotal :: [Event] -> [Event]
linearizeTotal = id

linearizeTotal' :: [Event] -> IO ()
linearizeTotal' events = do
  let mhb' = fromEvents events :: MHB
  print (toOrders mhb')
  let sc' = fromEvents events :: SC
  print (toOrders sc')
  let lc' = fromEvents events :: LC
  print (toOrders lc')
