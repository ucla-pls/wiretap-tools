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

import           Data.Word

import           Wiretap.Data.Event
import           Wiretap.Format.Binary
-- import           Wiretap.Analysis(linearizeTotal')

import           Wiretap.Analysis.Count
import           Wiretap.Analysis.Linearize

import           Pipes
import           Pipes.Binary
import qualified Pipes.ByteString as BP
import qualified Pipes.Prelude as P

import Control.Lens (view)

(...) = (.) . (.)
{-# INLINE (...) #-}

patterns :: Docopt
patterns = [docopt|wiretap-tools version 0.1.0.0

Usage:
   wiretap-tools parse <logs>
   wiretap-tools parse-hist <history>
   wiretap-tools linearize [-o <out>] <logs>
   wiretap-tools count <logs>
   wiretap-tools size <logs>
   wiretap-tools (-h | --help | --version)
|]

parse :: [FilePath] -> IO ()
parse files = do
  withLogs files $ \logs -> do
    forM_ logs $ \(f,logs) ->
      runEffect $ for logs (lift . print)

parseHistory :: FilePath -> IO ()
parseHistory file = do
  withFile file ReadMode $ \h ->
    runEffect $ for (readHistory h) (lift . print)

linearize :: Handle -> [FilePath] -> IO ()
linearize out files =
  withLogs files $ \logs -> do
    runEffect $ linearize logs
      >-> chuncks
      >-> progress
      >-> joinChunks
      >-> writeHistory out
  where
    linearize :: [(f, Producer Event IO ())] -> Producer Event IO ()
    linearize = mergeAll . map snd

count :: [FilePath] -> IO ()
count files =
  withLogs files $ \logs -> do
    printHeader
    counters <- forM logs $ \(f, events) -> do
      counter <- countEvents events
      printRow (f, counter)
      return counter
    printRow ("total", mconcat counters)
  where
    printHeader =
      putStrLn . L.intercalate "," $ "file" : counterHeader
    printRow (f, counter) =
      putStrLn $ f ++ "," ++ L.intercalate "," (counterToRow counter)

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

  onCommand "parse-hist" $ do
    history <- getArgOrExit args (argument "history")
    parseHistory history

  onCommand "linearize" $ do
    logs <- getLogFiles args
    case getArg args (shortOption 'o') of
      Just file ->
        withFile file WriteMode $ \h ->
          linearize h logs
      Nothing ->
        linearize stdout logs

  onCommand "count" $ do
    logs <- getLogFiles args
    count logs

  onCommand "size" $ do
    files <- getLogFiles args
    withLogs files $ \logs -> do
      forM_ logs $ \(f, events) -> do
        len <- P.length events
        putStrLn $ f ++ ": " ++ show len

withLogs :: [FilePath] -> ([(FilePath, Producer Event IO ())] -> IO a) -> IO a
withLogs files f =
  withFiles files ReadMode $ \hs -> do
    f $ zip files $ parseLogs files hs
{-# INLINABLE withLogs #-}

parseLogs :: [FilePath] -> [Handle] -> [Producer Event IO ()]
parseLogs = zipWith parseLog
{-# INLINABLE parseLogs #-}

parseLog :: FilePath -> Handle -> Producer Event IO ()
parseLog log h =
  readLog (parseThread log) h
  where
    parseThread =
      Thread . read . takeBaseName
{-# INLINABLE parseLog #-}

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

withFiles :: [FilePath] -> IOMode -> ([Handle] -> IO a) -> IO a
withFiles files mode f =
  withFiles' files []
  where
    withFiles' [] handles = f (reverse handles)
    withFiles' (file:rest) handles =
      withFile file mode $ \h ->
        withFiles' rest (h:handles)
