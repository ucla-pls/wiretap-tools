{-# LANGUAGE TemplateHaskell #-}
module Wiretap.Analysis.Permute where

import qualified Data.Map               as M
import           Wiretap.Data.Event

import Debug.Trace

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

emptyMHB = MHB [] [] [] []

sc h =
  And [ totalOrder t | t <- traces ]
  where
    traces =
      map reverse . M.elems $ simulate byThread M.empty h
    byThread u@(Unique _ e) =
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


{-| permute takes partial history and two events, if the events can be arranged
next to each other return. -}
permute
  :: (PartialHistory h, MonadIO m)
  => h
  -> (Unique Event, Unique Event)
  -> m (Maybe [Unique Event])
permute h (a, b) =
  solve (enumerate h) equation
  where
    equation =
      And $ Eq a b : ([ sc, mhb ] <*> [h])
