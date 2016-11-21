{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
module Main where

import           System.Console.Docopt
import           System.Directory
import           System.Environment     (getArgs)
import           System.FilePath
import           System.IO

import           Control.Monad

import           Pipes
import qualified Pipes.Prelude          as P

import           Wiretap.Format.Binary
import           Wiretap.Analysis.Count

patterns :: Docopt
patterns = [docopt|wiretap-tools version 0.1.0.0

Usage:
   wiretap-tools (parse|count|size) [<history>]
   wiretap-tools (race-candidates|lock-candidates) [<history>]
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
    runEffect $ for history (lift . print)

  onCommand "count" $ \history -> do
    print =<< countEvents history

  onCommand "size" $ \history -> do
    print =<< P.length history
