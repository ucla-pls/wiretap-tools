module Wiretap.Format.Binary where

import System.IO
import           System.FilePath
import Debug.Trace

import GHC.Int (Int32)

import qualified Data.ByteString.Lazy as BL

import Data.Binary.Get
import Data.Word
import Data.Bits

import Wiretap.Data.Event
import Wiretap.Data.Program

import Pipes
import Pipes.ByteString
import Pipes.Binary

import Control.Lens (zoom, view)

readLog' :: FilePath -> IO ()
readLog' fp =
  withFile fp ReadMode $ \handle ->
    runEffect $ readLog (parseThread fp) handle >-> printAll

  where
    parseThread =
      Thread . read . takeBaseName

printAll :: Consumer Event IO ()
printAll = do
  event <- await
  lift $ print event
  printAll

readLog :: MonadIO m => Thread -> Handle -> Producer Event m ()
readLog t handle =
  readLogEvents handle >-> eventsFromLog t
{-# INLINABLE readLog #-}

readLogEvents :: MonadIO m => Handle -> Producer LogEvent m ()
readLogEvents = logEvents . fromHandle
{-# INLINABLE readLogEvents #-}

eventsFromLog :: Monad m => Thread -> Pipe LogEvent Event m ()
eventsFromLog t = go 0
  where
    go o = do
      logEvent <- await
      yield $! withThreadAndOrder logEvent t o
      go $! o + 1
{-# INLINABLE eventsFromLog #-}

logEvents :: Monad m
  => Producer ByteString m r
  -> Producer LogEvent m ()
logEvents p = do
   yield (LogEvent Begin)
   view decoded p
   yield (LogEvent End)
{-# INLINABLE logEvents #-}
