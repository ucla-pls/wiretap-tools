module Wiretap.Analysis.Count
  ( countEvents
  , printCounter
  , counterToRow
  , counterHeader
  ) where

import Text.Printf
import qualified Data.Foldable as F
import Wiretap.Data.Event
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
      {-# INLINE sum #-}
      sum f = f a + f b

fromEvent :: Event -> Counter
fromEvent Event {operation=o} =
  case o of
   Synch _   -> mempty { synchs = 1 }
   Acquire _ -> mempty { acquires = 1 }
   Request _ -> mempty { requests = 1 }
   Release _ -> mempty { releases = 1 }
   Fork _    -> mempty { forks = 1 }
   Join _    -> mempty { joins = 1 }
   Read _ _  -> mempty { reads = 1 }
   Write _ _ -> mempty { writes = 1 }
   Begin     -> mempty { begins = 1 }
   End       -> mempty { ends = 1 }

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

printCounter :: Counter -> IO ()
printCounter c = do
  printf "synchs   = %d\n" $ synchs c
  printf "acquires = %d\n" $ acquires c
  printf "requests = %d\n" $ requests c
  printf "releases = %d\n" $ releases c
  printf "forks    = %d\n" $ forks c
  printf "joins    = %d\n" $ joins c
  printf "reads    = %d\n" $ reads c
  printf "writes   = %d\n" $ writes c
  printf "begins   = %d\n" $ begins c
  printf "ends     = %d\n" $ ends c


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


countEvents :: Foldable f => f Event -> Counter
countEvents = F.foldl' incrCounter mempty
