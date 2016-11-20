module Wiretap.Analysis.Group where

import Prelude hiding (reads)

import qualified Data.List as L

import Wiretap.Data.Event

data Group a = Group
  { synchs   :: [a]
  , acquires :: [a]
  , requests :: [a]
  , releases :: [a]
  , forks    :: [a]
  , joins    :: [a]
  , reads    :: [a]
  , writes   :: [a]
  , begins   :: [a]
  , ends     :: [a]
  } deriving (Show)

instance Monoid (Group a) where
  mempty = Group [] [] [] [] [] [] [] [] [] []
  mappend a b = Group
    { synchs   = add synchs
    , acquires = add acquires
    , requests = add requests
    , releases = add releases
    , forks    = add forks
    , joins    = add joins
    , reads    = add reads
    , writes   = add writes
    , begins   = add begins
    , ends     = add ends
    }
    where
      add f = f a ++ f b

fromEvent :: Event -> Group Event
fromEvent = addOn id mempty

add :: Group Event -> Event -> Group Event
add = addOn id

addOn :: (a -> Event) -> Group a -> a -> Group a
addOn f c e =
  case operation . f $ e of
   Synch _   -> c { synchs   = e : synchs c }
   Acquire _ -> c { acquires = e : acquires c }
   Request _ -> c { requests = e : requests c }
   Release _ -> c { releases = e : releases c }
   Fork _    -> c { forks    = e : forks c }
   Join _    -> c { joins    = e : joins c }
   Read _ _  -> c { reads    = e : reads c }
   Write _ _ -> c { writes   = e : writes c }
   Begin     -> c { begins   = e : begins c }
   End       -> c { ends     = e : ends c }

groupOn :: (a -> Event) -> [a] -> Group a
groupOn f =
  L.foldl' (addOn f) mempty
