{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
module Main where

import           System.IO
import           System.FilePath
import           System.Directory
import           System.Environment (getArgs)
import           System.Console.Docopt

import qualified Data.List as L
import           Control.Monad

import           Wiretap.Data.Event
import           Wiretap.Format.Binary
import           Wiretap.Analysis(linearizeTotal', linearizeTotal)


patterns :: Docopt
patterns = [docopt|wiretap-tools version 0.1.0.0

Usage:
   wiretap-tools parse [--type TYPE] <file>
   wiretap-tools linearize <folder>
   wiretap-tools (-h | --help | --version)
|]

parse :: String -> FilePath -> IO ()
parse "log" file = do
  withFile file ReadMode (\h -> printLength =<< parseLog file h)
parse fileType file =
  exitWithUsageMessage patterns $ "Unknown file type \"" ++ fileType ++ "\"."

linearize :: [FilePath] -> IO ()
linearize files =
  withFiles files ReadMode $ (printAll . linearize' =<<) . parseLogs
  where
    parseLogs = sequence . zipWith parseLog files

    printAll :: [Event] -> IO ()
    printAll events =
      either (putStrLn) (printLength) =<< linearizeTotal' events

printLength :: [Event] -> IO ()
printLength events = do
  forM events $ \event ->
    print event
  putStrLn $ "Successfully linearized " ++ show (length events) ++ " events"


linearize' :: [[Event]] -> [Event]
linearize' = linearizeTotal . L.concat


main :: IO ()
main = do
  args <- parseArgsOrExit patterns =<< getArgs

  let onCommand = when . isPresent args . command

  when (args `isPresent` longOption "help"
        || args `isPresent` shortOption 'h') $ do
    exitWithUsage patterns

  onCommand "parse" $ do
    file <- args `getArgOrExit` argument "file"
    let fileType = getArgWithDefault args
                     (tail $ takeExtension file)
                     (longOption "type")
    parse fileType file

  onCommand "linearize" $ do
    folder <- args `getArgOrExit` argument "folder"
    logs <- filter (L.isSuffixOf ".log") <$> getDirectoryContents folder
    linearize $ map (folder </>) logs

  where
    getArgOrExit = getArgOrExitWith patterns


parseThread =
  Thread . read . takeBaseName

parseLog :: FilePath -> Handle -> IO [Event]
parseLog log h =
  readEvents (parseThread log) h

withFiles :: [FilePath] -> IOMode -> ([Handle] -> IO a) -> IO a
withFiles files mode f =
  withFiles' files []
  where
    withFiles' [] handles = f (reverse handles)
    withFiles' (file:rest) handles =
      withFile file mode $ \h ->
        withFiles' rest (h:handles)
