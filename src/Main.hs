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
   wiretap-tools linearize <logs>
   wiretap-tools count <logs>
   wiretap-tools size <logs>
   wiretap-tools (-h | --help | --version)
|]

parse :: [FilePath] -> IO ()
parse files = do
  withLogs files $ \logs -> do
    forM_ logs $ \(f,logs) ->
      runEffect $ for logs (lift . print)

-- linearize :: [FilePath] -> IO ()
-- linearize files =
--   withLogs files $ \traces -> do
--      events <- linearizeTotal' (concatMap snd traces)
--      case events of
--        Left error -> putStrLn error
--        Right events -> printAll events

-- count :: [FilePath] -> IO ()
-- count files =
--   withLogs files $ \traces -> do
--     let table = map mkRow traces
--     putStrLn . L.intercalate "," $ "file" : counterHeader
--     forM_ table $ \row ->
--       putStrLn $ L.intercalate "," row
--   where mkRow (f, t) =  f : counterToRow (countEvents t)

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

  -- onCommand "linearize" $ do
  --   logs <- getLogFiles args
  --   linearize logs

  onCommand "count" $ do
    logs <- getLogFiles args
    withFile (head logs) ReadMode $ \h -> do
      len <- readall h
      putStrLn $ (head logs) ++ ": " ++ show len
    -- logs <- getLogFiles args
    -- count logs

  onCommand "size" $ do
    files <- getLogFiles args
    withLogs files $ \logs -> do
      forM_ logs $ \(f, events) -> do
        len <- P.fold (\x e -> x + 1) 0 id events
        putStrLn $ f ++ ": " ++ show len

data A = A
  {-# UNPACK #-}!Word64
  {-# UNPACK #-}!Word64
  {-# UNPACK #-}!Word64

instance Binary A where
  put a = undefined
  get = A <$> get <*> get <*> get

type AS = [A]

readall :: Handle -> IO Int
readall h = do
  let stream = void . view decoded $ BP.fromHandle h
  P.fold ((\x e -> x + 1) :: Int -> A -> Int) 0 id stream

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
