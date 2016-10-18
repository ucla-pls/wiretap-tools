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

import qualified Data.ByteString.Lazy as BL

import           Wiretap.Data.Event
import           Wiretap.Format.Binary
import           Wiretap.Analysis(linearizeTotal')

import           Wiretap.Analysis.Count


(...) = (.) . (.)
{-# INLINE (...) #-}

patterns :: Docopt
patterns = [docopt|wiretap-tools version 0.1.0.0

Usage:
   wiretap-tools parse <logs>
   wiretap-tools linearize <logs>
   wiretap-tools count <logs>
   wiretap-tools size <logs>
   wiretap-tools (-h | --help | --version)
|]

parse :: [FilePath] -> IO ()
parse files = do
  withLogs files $ \traces -> do
    forM_ traces $ \(f,t) ->
      printAll t

linearize :: [FilePath] -> IO ()
linearize files =
  withLogs files $ \traces -> do
     events <- linearizeTotal' (concatMap snd traces)
     case events of
       Left error -> putStrLn error
       Right events -> printAll events

count :: [FilePath] -> IO ()
count files =
  withLogs files $ \traces -> do
    let table = map mkRow traces
    putStrLn . L.intercalate "," $ "file" : counterHeader
    forM_ table $ \row ->
      putStrLn $ L.intercalate "," row
  where mkRow (f, t) =  f : counterToRow (countEvents t)

main :: IO ()
main = do
  args <- parseArgsOrExit patterns =<< getArgs

  let onCommand = when . isPresent args . command

  when (args `isPresent` longOption "help"
        || args `isPresent` shortOption 'h') $ do
    exitWithUsage patterns

  onCommand "parse" $ do
    logs <- getLogFiles args
    parse logs

  onCommand "linearize" $ do
    logs <- getLogFiles args
    linearize logs

  onCommand "count" $ do
    logs <- getLogFiles args
    count logs

  onCommand "size" $ do
    logs <- getLogFiles args
    withLogs logs $ \traces ->
      forM_ traces $ \(f, t) ->
        putStrLn $ f ++ ": " ++ show (length t)

withLogs :: [FilePath] -> ([(FilePath, [Event])] -> IO a) -> IO a
withLogs files f =
  withFiles files ReadMode (\hs -> parseLogs files hs >>= f . zip files)

parseLogs :: [FilePath] -> [Handle] -> IO [[Event]]
parseLogs = sequence ... zipWith parseLog

parseLog :: FilePath -> Handle -> IO [Event]
parseLog log h =
  readEvents (parseThread log) h

getArgOrExit :: Arguments -> Option -> IO String
getArgOrExit = getArgOrExitWith patterns

getLogFiles :: Arguments -> IO [FilePath]
getLogFiles args = do
  logfolder <- args `getArgOrExit` argument "logs"
  isFolder <- doesDirectoryExist logfolder
  if isFolder
    then do
      logs <- filter (L.isSuffixOf ".log") <$> listDirectory logfolder
      return $ map (logfolder </>) logs
    else return [logfolder]

parseThread =
  Thread . read . takeBaseName


withFiles :: [FilePath] -> IOMode -> ([Handle] -> IO a) -> IO a
withFiles files mode f =
  withFiles' files []
  where
    withFiles' [] handles = f (reverse handles)
    withFiles' (file:rest) handles =
      withFile file mode $ \h ->
        withFiles' rest (h:handles)


printLength :: [Event] -> IO ()
printLength events = do
  putStrLn $ "Successfully worked with " ++ show (length events) ++ " events"


printAll :: [Event] -> IO ()
printAll events = do
  count <- foldM printAndCount 0 events
  putStrLn $ "Successfully linearized " ++ show count ++ " events"


printAndCount :: Show a => Int -> a -> IO Int
printAndCount acc a = do
  print a
  return (acc + 1)
