{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
module Main where

import           System.Console.Docopt
import           System.Directory
import           System.Environment              (getArgs)
import           System.FilePath
import           System.IO

import           Control.Monad

import           Data.Unique

import qualified Data.List                       as L

import           Pipes
import qualified Pipes.Prelude                   as P

import           Wiretap.Analysis.Count
import           Wiretap.Format.Binary
import           Wiretap.Format.Text

import           Wiretap.Data.History

import           Wiretap.Analysis.Lock
import           Wiretap.Analysis.DataRace
import           Wiretap.Analysis.Permute

patterns :: Docopt
patterns = [docopt|wiretap-tools version 0.1.0.0

Usage:
   wiretap-tools (parse|count|size) [<history>]
   wiretap-tools (race-candidates|shared-locations|dataraces) [<history>]
   wiretap-tools (lockset|deadlock-candidates|deadlocks) [<history>]
   wiretap-tools (-h | --help | --version)
|]

getArgOrExit :: Arguments -> Option -> IO String
getArgOrExit = getArgOrExitWith patterns

helpNeeded args =
  args `isPresent` longOption "help" || args `isPresent` shortOption 'h'

main :: IO ()
main = do
  args <- parseArgsOrExit patterns =<< getArgs
  when (helpNeeded args) $ exitWithUsage patterns
  runcommand args

runcommand :: Arguments -> IO ()
runcommand args = do
  onCommand "parse" $ \events -> do
    runEffect $ for events (lift . print . PP)

  onCommand "count" $ \events -> do
    print =<< countEvents events

  onCommand "size" $ \events -> do
    print =<< P.length events

  onCommand "shared-locations" $ \events -> do
    a <- sharedLocations . fromEvents <$> P.toListM events
    forM_ a $ \(l, es) -> do
      putStrLn $ pp l
      forM_ es $ \(a, b) -> do
        putStrLn $ "  A = " ++ pp a
        putStrLn $ "  B = " ++ pp b
        putStrLn ""

  onCommand "race-candidates" $ \events -> do
    es <- raceCandidates . fromEvents <$> P.toListM events
    forM_ es $ \(a, b) -> do
      putStrLn $ "A = " ++ pp a
      putStrLn $ "B = " ++ pp b
      putStrLn ""

  onCommand "dataraces" $ \events -> do
    h <- fromEvents <$> P.toListM events
    let candidates = raceCandidates h
    forM_ candidates $ \(a, b) -> do
      let s = pp a
      putStrLn $ s ++ L.replicate (55 - length s) ' ' ++ " - " ++ pp b
      r <- permute h (a, b)
      case r of
        Nothing -> putStrLn "FAIL"
        Just t -> do
          putStrLn "SUCCES"
          forM_ t $ \e ->
            putStrLn $ ">>> " ++ pp e

  onCommand "lockset" $ \events -> do
    locks <- lockset . fromEvents <$> P.toListM events
    forM_ locks $ \(e, b) -> do
      let s = pp e
      putStrLn $ s ++ L.replicate (60 - length s) ' ' ++ " - " ++ pp b

  onCommand "deadlock-candidates" $ \events -> do
    es <- deadlockCandidates . fromEvents <$> P.toListM events
    forM_ es $ \(a, b) -> do
      putStrLn $ "A = " ++ pp a
      putStrLn $ "B = " ++ pp b
      putStrLn ""

  onCommand "deadlocks" $ \events -> do
    h <- fromEvents <$> P.toListM events
    let candidates = deadlockCandidates h
    forM_ candidates $ \(a, b) -> do
      let s = pp a
      putStrLn $ s ++ L.replicate (55 - length s) ' ' ++ " - " ++ pp b
      r <- permute h (a, b)
      case r of
        Nothing -> putStrLn "FAIL"
        Just t -> do
          putStrLn "SUCCES"
          forM_ t $ \e ->
            putStrLn $ ">>> " ++ pp e

  where
    withEvents f = do
      case getArg args (argument "events") of
        Just events ->
          withFile events ReadMode f
        Nothing ->
          f stdin
    onCommand cmd f =
      when (args `isPresent` command cmd) $ do
        withEvents (f . readHistory)
