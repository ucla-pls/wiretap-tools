module Wiretap.Data.Log where

import qualified Wiretap.Data.Event as E

data Log = Log { thread :: E.Thread
               , events :: E.Events
               } deriving (Show)
