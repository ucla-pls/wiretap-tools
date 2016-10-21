module Wiretap.Analysis.Count
  ( countEvents
  , counterToRow
  , counterHeader
  , incrCounter
  , Counter (..)
  ) where

import Text.Printf
import qualified Data.Foldable as F
import Wiretap.Data.Event

import           Pipes
import qualified Pipes.Prelude as P
import Prelude hiding (reads)

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
  } deriving (Show)

instance Monoid Counter where
  mempty = Counter 0 0 0 0 0 0 0 0 0 0
  mappend a b = Counter
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
    }
    where
      sum f = f a + f b

fromEvent :: Event -> Counter
fromEvent = incrCounter mempty

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
    ] <*> [c]


countEvents :: Monad m => Producer Event m () -> m Counter
countEvents = P.fold incrCounter mempty id
