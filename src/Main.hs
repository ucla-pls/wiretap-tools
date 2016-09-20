{-# LANGUAGE QuasiQuotes #-}
module Main where

import           System.IO
import           System.Environment (getArgs)
import           System.Console.Docopt

import           Control.Monad

import           Wiretap.Data.Event
import           Wiretap.Format.Binary


patterns :: Docopt
patterns = [docopt|
wiretap-tools version 0.1.0.0

Usage:
   wiretap-tools parse [--type TYPE] <file>
   wiretap-tools (-h | --help | --version)
|]

main :: IO ()
main = do
  args <- parseArgsOrExit patterns =<< getArgs

  when (args `isPresent` longOption "help"
        || args `isPresent` shortOption 'h') $ do
    exitWithUsage patterns

  when (args `isPresent` command "parse") $ do
    file <- args `getArgOrExit` argument "file"
    withFile file ReadMode $ \h -> do
      events <- readEvents (Thread 0) h
      putStrLn $ "Successfully parsed " ++ show (length events) ++ " events";


  where
    getArgOrExit = getArgOrExitWith patterns
