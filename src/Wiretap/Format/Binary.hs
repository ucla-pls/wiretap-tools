module Wiretap.Format.Binary
  ( readLog
  , writeLog
  , readHistory
  , writeHistory
  ) where

import System.IO
import           System.FilePath
import Debug.Trace

import GHC.Int (Int32)

import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString as B

import Data.Binary.Get
import Data.Word
import Data.Bits

import Wiretap.Data.Event
import Wiretap.Data.Program
import Wiretap.Data.MiniParser

import Pipes
import Pipes.ByteString
import Pipes.Binary
import Pipes.Parse
import qualified Pipes.Prelude as P

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

readLog :: MonadIO m
  => Thread
  -> Handle
  -> Producer Event m ()
readLog t handle =
  readLogEvents' handle >-> eventsFromLog t
{-# INLINABLE readLog #-}

writeLog :: MonadIO m
  => Handle
  -> Consumer Event m ()
writeLog handle =
  P.map (fromEvent) >-> writeLogEvents handle
{-# INLINABLE writeLog #-}

readHistory :: MonadIO m
  => Handle
  -> Producer Event m ()
readHistory handle =
  void $ view decoded $ fromHandle handle
{-# INLINABLE readHistory #-}

writeHistory :: MonadIO m
  => Handle
  -> Consumer Event m ()
writeHistory handle =
  for cat encode >-> toHandle handle
{-# INLINABLE writeHistory #-}

readLogEvents :: MonadIO m
  => Handle
  -> Producer LogEvent m ()
readLogEvents = decodeLogEvents . fromHandle
{-# INLINABLE readLogEvents #-}

writeLogEvents :: MonadIO m
  => Handle
  -> Consumer LogEvent m ()
writeLogEvents handle =
  encodeLogEvents >-> toHandle handle
{-# INLINABLE writeLogEvents #-}

decodeLogEvents :: Monad m
  => Producer ByteString m r
  -> Producer LogEvent m ()
decodeLogEvents p = do
   yield (LogEvent Begin)
   view decoded p
   yield (LogEvent End)
{-# INLINABLE decodeLogEvents #-}


readLogEvents' :: MonadIO m
  => Handle
  -> Producer LogEvent m ()
readLogEvents' h = do
  bs <- liftIO $ BL.hGetContents h
  yield (LogEvent Begin)
  go bs
  yield (LogEvent End)
  where
    go bs = do
       case BL.uncons bs of
          Just (w, bs') ->
                let n = eventSize w
                    (bs'', rest) = BL.splitAt n bs'
                    strict = BL.toStrict bs'' in
                if B.length strict /= fromIntegral n
                  then return ()
                  else do
                    yield (LogEvent . snd $ parseOperation w strict 0)
                    go rest
          Nothing -> return ()
{-# INLINABLE readLogEvents' #-}


encodeLogEvents :: Monad m
  => Pipe LogEvent ByteString m ()
encodeLogEvents = await >> go
  where
    go = do
      event <- await
      case event of
        LogEvent End ->
          return ()
        otherwise -> do
          encode event
          go
{-# INLINABLE encodeLogEvents #-}

eventsFromLog :: Monad m
  => Thread
  -> Pipe LogEvent Event m ()
eventsFromLog t = go 0
  where
    go o = do
      logEvent <- await
      yield $! withThreadAndOrder logEvent t o
      go $! o + 1
{-# INLINABLE eventsFromLog #-}
