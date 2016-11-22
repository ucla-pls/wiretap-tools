{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
module Main where

import           System.Console.Docopt
import           System.Directory
import           System.Environment              (getArgs)
import           System.FilePath
import           System.IO

import           Control.Monad

import qualified Data.List as L

import           Pipes
import qualified Pipes.Prelude                   as P

import           Wiretap.Analysis.Count
import           Wiretap.Format.Binary
import           Wiretap.Format.Text


import           Wiretap.Analysis.LockCandidates
import           Wiretap.Analysis.RaceCandidates

patterns :: Docopt
patterns = [docopt|wiretap-tools version 0.1.0.0

Usage:
   wiretap-tools (parse|count|size) [<history>]
   wiretap-tools (race-candidates|shared-locations) [<history>]
   wiretap-tools (lockset) [<history>]
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

  let
    withHistory f = do
      case getArg args (argument "history") of
        Just history ->
          withFile history ReadMode f
        Nothing ->
          f stdin
    onCommand cmd f =
      when (args `isPresent` command cmd) $ do
        withHistory (f . readHistory)

  onCommand "parse" $ \history -> do
    runEffect $ for history (lift . print . PP)

  onCommand "count" $ \history -> do
    print =<< countEvents history

  onCommand "size" $ \history -> do
    print =<< P.length history

  onCommand "shared-locations" $ \history -> do
    a <- locations <$> P.toListM history
    forM_ a $ \(l, es) -> do
      print l
      forM_ es $ \(a, b) -> do
        putStrLn $ "  A = " ++ pp a
        putStrLn $ "  B = " ++ pp b
        putStrLn ""

  onCommand "race-candidates" $ \history -> do
    es <- raceCandidates <$> P.toListM history
    forM_ es $ \(a, b) -> do
      putStrLn $ "A = " ++ pp a
      putStrLn $ "B = " ++ pp b
      putStrLn ""

  onCommand "lockset" $ \history -> do
    es <- lockset' <$> P.toListM history
    forM_ es $ \(a, b) -> do
      let s = pp a
      putStrLn $ s ++ L.replicate (60 - length s) ' ' ++ " - " ++ pp b
