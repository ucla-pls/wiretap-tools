{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TemplateHaskell  #-}
module Wiretap.Analysis.Permute where

import           Prelude                hiding (reads)

import           Control.Lens
import           Control.Monad.IO.Class
import qualified Data.List              as L
import qualified Data.Map               as M

import           Debug.Trace

import           Data.PartialOrder
import           Data.Unique

import           Wiretap.Analysis.LIA
import           Wiretap.Data.Event
import           Wiretap.Data.History
import           Wiretap.Utils

sc h =
  And [ totalOrder t | t <- traces ]
  where
    traces =
      map reverse . M.elems $ simulate step M.empty h
    step u@(Unique _ e) =
      M.alter (Just . (u:) . concat) (thread e)

mhb :: PartialHistory h => h -> LIA (Unique Event)
mhb h =
  And . concat $
    [ [ orders forks begins
      , orders ends joins ]
    | (joins, forks, begins, ends) <- M.elems $ simulate step M.empty h
    ]
  where
    step u@(Unique _ e) =
      case operation e of
        Join t -> update u _1 t
        Fork t -> update u _2 t
        Begin  -> update u _3 $ thread e
        End    -> update u _4 $ thread e
        _      -> id
    update u l t =
      M.alter (Just . over l (u:) . maybe ([], [], [], []) id) t

{-| this method expects h to be a true history, so that by thread any lock acquired
will be released by the same thread, and that there is no cross releasing -}
lc :: PartialHistory h => h -> LIA (Unique Event)
lc h =
  And $ concat
    [
      [ Or [ r ~> a',  r' ~> a ]
      | ((a, r), (a', r')) <- combinations lockPairs
      ]
      ++
      [ r ~> a
      | ((_, r), a) <- crossproduct lockPairs remainders
      ]
    | (lockPairs, remainders) <- M.elems $ simulate step M.empty h
    ]
  where
    step u@(Unique _ e) =
      case operation e of
        Acquire l -> update acq (thread e)
        Release l -> update rel (thread e)
        _         -> id
      where
        acq (pairs, stack) =
          (pairs, u:stack)
        rel (pairs, stack) =
          case stack of
            acq:stack' -> ((acq, u):pairs, stack')
            [] -> error "Can't release a lock that has not been acquired"

    update f t =
      M.alter (Just . f . maybe ([],[]) id) t

rwc :: PartialHistory h => h -> LIA (Unique Event)
rwc h =
  And
    [ Or $
      [ And $ w ~> r :
        [ Or [ w' ~> w, r ~> w']
        | (_, w') <- writes, w' /= w
        ]
      | (_, w) <- filter ((v ==) . fst) writes
      ]
    | (l, (reads, writes)) <- readAndWritesBylocation
    , (v, r) <- reads
    , not $ L.null writes
  ]
  where
    readAndWritesBylocation = M.assocs $ simulate step M.empty h
    step u@(Unique _ e) =
      case operation e of
        Read l v  -> update (v, u) _1 l
        Write l v -> update (v, u) _2 l
        _         -> id
    update u f l =
      M.alter (Just . over f (u:) . maybe ([], []) id) l

{-| permute takes partial history and two events, if the events can be arranged
next to each other return. -}
permute
  :: (PartialHistory h, MonadIO m)
  => h
  -> (Unique Event, Unique Event)
  -> m (Maybe [Unique Event])
permute h (a, b) =
  solve events equation
  where
    events = withPair (a, b) h
    equation =
      And $ (Eq a b) :
        ([ sc, mhb, rwc] <*> [events])
