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
      updateDefault [] (u:) $ thread e

mhb :: PartialHistory h => h -> LIA (Unique Event)
mhb h =
  And
  [ And
    [ And
      [ f ~> b
      | f <- forks, b <- begins
      ]
    , And
      [ e ~> j
      | e <- ends, j <- joins
      ]
    ]
  | (joins, forks, begins, ends) <- mhbEventsByThread
  ]
  where
    mhbEventsByThread =
      M.elems $ simulate step M.empty h
    step u@(Unique _ e) =
      case operation e of
        Join t -> update u _1 t
        Fork t -> update u _2 t
        Begin  -> update u _3 $ thread e
        End    -> update u _4 $ thread e
        _      -> id
    update u l =
      updateDefault ([], [], [], []) (over l (u:))

{-| this method expects h to be a true history, so that by thread any lock acquired
will be released by the same thread, and that there is no cross releasing -}
lc :: PartialHistory h => h -> LIA (Unique Event)
lc h =
  And
  [ And
    [ And
      [ Or [ r ~> a',  r' ~> a ]
      | ((a, r), (a', r')) <-
          combinations lockPairs
      , a ~/> r', r' ~/> a
      ]
    , And
      [ r ~> a
      | ((_, r), a) <-
          crossproduct lockPairs (def [] $ M.lookup l remainders)
      , r ~/> a, a ~/> r
      ]
    ]
  | (l, lockPairs) <- lockPairsSet
  ]
  where
    (allLocks, allRemainder) =
      unpair . M.elems $ simulate step M.empty h

    lockPairsSet =
      groupUnsortedOnFst $ concat allLocks

    remainders =
      mapOnFst $ concat allRemainder

    step u@(Unique _ e) =
      case operation e of
        Acquire l -> update (acq l) (thread e)
        Release l -> update rel (thread e)
        _         -> id
      where
        acq l (pairs, stack) =
          (pairs, (l,u):stack)
        rel (pairs, stack) =
          case stack of
            (l, acq):stack' -> ((l, (acq, u)):pairs, stack')
            [] -> error "Can't release a lock that has not been acquired"

    update = updateDefault ([], [])

rwc :: PartialHistory h => h -> LIA (Unique Event)
rwc h =
  And
  [ Or
    [ And $ w ~> r :
      [ Or [ w' ~> w, r ~> w']
      | (_, w') <- writes
      , w' /= w , w' ~/> w, r ~/> w'
      ]
    | (v', w) <- writes
    , v' == v
    , w ~/> r, r ~/> w
    ]
  | (reads, writes) <- readAndWritesBylocation
  , (v, r) <- reads
  , not $ L.null writes
  ]
  where
    readAndWritesBylocation =
      M.elems $ simulate step M.empty h
    step u@(Unique _ e) =
      case operation e of
        Read l v  -> update (v, u) _1 l
        Write l v -> update (v, u) _2 l
        _         -> id
    update u f = updateDefault ([], []) (over f (u:))


(~/>) (Unique _ a) (Unique _ b) =
  not (a !< b)

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
      And [ Eq a b, contraints h]

contraints
  :: PartialHistory h
  => h
  -> LIA (Unique Event)
contraints h =
  And $ [ sc, mhb, rwc, lc] <*> [h]
