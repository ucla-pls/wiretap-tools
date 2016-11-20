module Wiretap.Analysis.Linearize where

import           Control.Monad
import           Data.Foldable
import           Data.Function

import qualified Data.Map           as M
import qualified Data.Vector        as V
import           Data.List          as L

import           Pipes
import           Pipes.Missing
import qualified Pipes.Prelude      as P

import           Z3.Monad

import           Wiretap.Data.Event
import           Wiretap.Analysis.LIA

isSynch e =
  case operation e of
    Synch w   -> True
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
  yield $ Event (Thread (-1)) (-1) (Synch $ s + 1)
  where
    events = foldl1 (merge' synchOrder) ps

{-| chunck takes a producer where all synch events are ordered and produces a
list of events that can be solved in one go. -}
chunck :: Monad m
  => Consumer' Event m ([Event], Event)
chunck =
  asList' $ takeWhileS (not . isSynch)

{-| chuncks generate a stream of chuncks from a stream of events. -}
chuncks :: Monad m
  => Pipe Event ([Event], Event) m ()
chuncks =
  chunck >~ cat

{-| Shows progress for running the chuncking algorithm -}
progress :: MonadIO m
  => Pipe ([Event], Event) ([Event], Event) m ()
progress = forever $ do
  (l, a) <- await
  liftIO . putStrLn $ show (synchValue a) ++ ": " ++ show (length l)
  yield (l, a)

{-| join chunks into a single stream -}
joinChunks :: Monad m
  => Pipe ([Event], Event) Event m ()
joinChunks = do
  (l, e) <- await
  each l
  joinChunks

updateState ::
     [Event]
  -> M.Map Location Value
  -> M.Map Location Value
updateState es state =
  undefined

simpleOrdering :: M.Map Location Value -> [Unique Event] -> LIA (Unique Event)
simpleOrdering state es =
  And [ mhb, sc, rwc, lo ]
  where
    sc =
      And $ map totalOrder byThread

    mhb = undefined

    rwc = undefined

    lo = undefined

    inThread =
      map mhbByThread es

    mhbByThread e =
      case operation . normal $ e of
        Begin   -> [(t,  e)]
        End     -> [(t,  e)]
        Fork t' -> [(t', e)]
        Join t' -> [(t', e)]
      where t = thread . normal $ e

    threadEquality =
      (==) `on` thread . normal

    eventsByThread =
      L.groupBy threadEquality $ L.sortOn (thread . normal) es


{-| linearizeChunk -}
linearizeChunk :: MonadZ3 m
  => M.Map Location Value
  -> [Event]
  -> Pipe ([Event], Event) Event m ()
linearizeChunk state events = do
   (more, synch) <- await
   (linear, rest) <- lift $ linearizeUntil state (events ++ more) synch
   each linear
   linearizeChunk (updateState linear state) rest

{-| linearizeUntil  -}
linearizeUntil :: MonadZ3 m
  => M.Map Location Value
  -> [Event]
  -> Event
  -> m ([Event], [Event])
linearizeUntil state chunk synch = do
  let events = byIndex $ synch:chunk

  solution <- solve events (simpleOrdering events)

  case fmap (map normal) solution >>= split of
    Just pair -> return $ pair
    Nothing ->
      error "Could not linearize constraints."
  where
    split list = do
      idx <- L.elemIndex synch list
      let (first, rest) = splitAt idx list
      return $ (first, tail rest)
