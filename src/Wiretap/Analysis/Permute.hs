{-# LANGUAGE TemplateHaskell #-}
module Wiretap.Analysis.Permute where

import qualified Data.List              as L
import qualified Data.Map               as M
import           Wiretap.Data.Event

import           Data.PartialOrder

import           Debug.Trace

import           Prelude                hiding (reads)

import           Data.Unique
import           Wiretap.Analysis.LIA
import           Wiretap.Data.History

import           Control.Monad.IO.Class

import           Control.Lens

data MHB = MHB
  { _forks  ::  [Unique Event]
  , _joins  ::  [Unique Event]
  , _begins :: [Unique Event]
  , _ends   ::   [Unique Event]
  } deriving (Show)
makeLenses ''MHB

data RWC = RWC
  { _reads  ::  [(Value, Unique Event)]
  , _writes :: [(Value, Unique Event)]
  } deriving (Show)
makeLenses ''RWC

emptyMHB = MHB [] [] [] []

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
    [ [ orders (t ^. forks) (t ^. begins)
      , orders (t ^. ends) (t ^. joins) ]
    | t <- M.elems $ simulate step M.empty h
    ]
  where
    step u@(Unique _ e) =
      case operation e of
        Join t -> update u joins t
        Fork t -> update u forks t
        Begin  -> update u begins $ thread e
        End    -> update u ends $ thread e
        _      -> id
    update u l t =
      M.alter (Just . over l (u:) . maybe emptyMHB id) t


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
    | (l, RWC reads writes) <- locations
    , (v, r) <- reads
    , not $ L.null writes
  ]
  where
    locations = M.assocs $ simulate step M.empty h
    step u@(Unique _ e) =
      case operation e of
        Read l v  -> update (v, u) reads l
        Write l v -> update (v, u) writes l
        _         -> id
    update u f l =
      M.alter (Just . over f (u:) . maybe (RWC [] []) id) l




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
      And $
        [ sc, mhb, rwc] <*> [events]
