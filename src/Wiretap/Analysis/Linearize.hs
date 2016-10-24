module Wiretap.Analysis.Linearize where

import Pipes

import Pipes.Missing
import qualified Pipes.Prelude as P
import Wiretap.Data.Event
import Data.Foldable
import Data.Function

import Control.Monad

isSynch e =
  case operation e of
    Synch w -> True
    otherwise -> False

synchValue e =
  case operation e of
    Synch w   -> w
    otherwise -> -1

synchOrder =
  compare `on` synchValue

{-| mergeAll folds over a number of producers and create one merged producer.
Ends the producer with a synch event, greater than any synch event in the
product.
-}
mergeAll :: Monad m
  => [Producer Event m ()]
  -> Producer Event m ()
mergeAll ps = do
  s <- pfold (\c -> max c . synchValue) 0 events
  yield $ Event (Synch $ s + 1) (Thread (-1)) (-1)
  where
    events = foldl1 (merge' synchOrder) ps

{-| chunck takes a producer where all synch events are ordered and produces a
list of events that can be solved in one go. -}
chunck :: Monad m => Consumer' Event m ([Event], Event)
chunck =
  asList' $ takeWhileS (not . isSynch)

chuncks :: Monad m
  => Pipe Event ([Event], Event) m ()
chuncks =
  chunck >~ cat

joinChunks :: Monad m
  => Pipe ([Event], Event) Event m ()
joinChunks = do
  (l, e) <- await
  each l
  joinChunks
