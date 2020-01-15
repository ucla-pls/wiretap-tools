module Wiretap.Analysis.Count
  ( countEvents
  , countEventsF
  , counterToRow
  , counterHeader
  , incrCounter
  , Counter (..)
  ) where

import           Prelude            hiding (reads, sum)

import           Pipes
import qualified Pipes.Prelude      as P

import           Wiretap.Data.Event

-- | Counter, counts all the occurrences of each event.

data Counter = Counter
  { synchs   :: !Int
  , acquires :: !Int
  , requests :: !Int
  , releases :: !Int
  , forks    :: !Int
  , joins    :: !Int
  , reads    :: !Int
  , writes   :: !Int
  , begins   :: !Int
  , ends     :: !Int
  , branches :: !Int
  , enters   :: !Int
  } deriving (Show)

instance Semigroup Counter where
  (<>) a b = Counter
    { synchs   = sum synchs
    , acquires = sum acquires
    , requests = sum requests
    , releases = sum releases
    , forks    = sum forks
    , joins    = sum joins
    , reads    = sum reads
    , writes   = sum writes
    , begins   = sum begins
    , ends     = sum ends
    , branches = sum branches
    , enters   = sum enters
    }
    where
      sum f = f a + f b

instance Monoid Counter where
  mempty = Counter 0 0 0 0 0 0 0 0 0 0 0 0

incrCounter :: Counter -> Event -> Counter
incrCounter c Event {operation=o} =
  case o of
   Synch _   -> c { synchs   = synchs c + 1 }
   Acquire _ -> c { acquires = acquires c + 1 }
   Request _ -> c { requests = requests c + 1 }
   Release _ -> c { releases = releases c + 1 }
   Fork _    -> c { forks    = forks c + 1 }
   Join _    -> c { joins    = joins c + 1 }
   Read _ _  -> c { reads    = reads c + 1 }
   Write _ _ -> c { writes   = writes c + 1 }
   Begin     -> c { begins   = begins c + 1 }
   End       -> c { ends     = ends c + 1 }
   Branch    -> c { branches = branches c + 1 }
   Enter _ _ -> c { enters   = enters c + 1 }

counterHeader :: [String]
counterHeader =
  [ "synchs"
  , "acquires"
  , "requests"
  , "releases"
  , "forks"
  , "joins"
  , "reads"
  , "writes"
  , "begins"
  , "ends"
  , "branches"
  , "enters"
  ]

counterToRow :: Counter -> [String]
counterToRow c =
  fmap show $
    [ synchs
    , acquires
    , requests
    , releases
    , forks
    , joins
    , reads
    , writes
    , begins
    , ends
    , branches
    , enters
    ] <*> [c]


countEventsF :: Foldable f => f Event -> Counter
countEventsF = foldMap (incrCounter mempty)

countEvents :: Monad m => Producer Event m () -> m Counter
countEvents = P.fold incrCounter mempty id
