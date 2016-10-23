{-# LANGUAGE BangPatterns #-}
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
import qualified Data.ByteString.Unsafe as BU

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
  readLogEvents'' handle >-> eventsFromLog t
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
    go bs = {-# SCC go #-}
      case BL.uncons bs of
        Just (w, bs') -> {-# SCC go_just #-}
          let n = eventSize w
              (bs'', rest) = BL.splitAt (fromIntegral n) bs'
              strict = BL.toStrict bs'' in
          if B.length strict /= fromIntegral n
            then return ()
            else do
              yield (LogEvent . snd $ parseOperation w strict 0)
              go rest
        Nothing -> return ()
{-# INLINABLE readLogEvents' #-}


readLogEvents'' :: MonadIO m
  => Handle
  -> Producer LogEvent m ()
readLogEvents'' h = do
  yield (LogEvent Begin)
  go (hGetSome 10242880 h) B.empty
  yield (LogEvent End)
  where
    -- go :: Producer B.ByteString m () -> B.ByteString -> Producer LogEvent m ()
    go !p !rest = do -- {-# SCC go #-} do
      nextBs <- next p
      case nextBs of
        Right (bs, p') ->
          if B.null bs
            then
              go p' rest
            else do
              let bs' = B.append rest bs
              i <- go' bs' 0
              go p' $ BU.unsafeDrop i bs'
        Left _ ->
          return ()

    -- go' :: B.ByteString -> Int -> Producer LogEvent m Int
    go' bs !i = -- {-# SCC go' #-}
      if B.length bs > i then
         let w = BU.unsafeIndex bs i
             n = eventSize w
             i' = (i + 1 + n)
         in
         if B.length bs >= i'
         then do
            yield . LogEvent . snd $ parseOperation w bs (i + 1)
            go' bs i'
         else
           return i
     else return i
{-# INLINABLE readLogEvents'' #-}


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
