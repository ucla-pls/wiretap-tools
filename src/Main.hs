{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
module Main where

import           System.Console.Docopt
import           System.Directory
import           System.Environment              (getArgs)
import           System.FilePath
import           System.IO

import           Control.Monad
import           Control.Applicative

import           Data.Unique

import qualified Data.List                       as L
import qualified Data.Set                        as S

import           Pipes
import qualified Pipes.Prelude                   as P

import           Wiretap.Analysis.Count
import           Wiretap.Format.Binary
import           Wiretap.Format.Text

import           Wiretap.Data.Event
import           Wiretap.Data.History
import qualified Wiretap.Data.Program as Program

import           Wiretap.Analysis.Lock
import           Wiretap.Analysis.LIA
import           Wiretap.Analysis.DataRace
import           Wiretap.Analysis.Permute

patterns :: Docopt
patterns = [docopt|wiretap-tools version 0.1.0.0

Usage:
   wiretap-tools (parse|count|size) [<history>]
   wiretap-tools lockset [-h] [<history>]
   wiretap-tools dataraces [<history>]
   wiretap-tools deadlocks [<history>]
   wiretap-tools (dot) [<history>]
   wiretap-tools (--help | --version)

Options:
-h, --human-readable           Adds more information about execution
-p PROGRAM, --program PROGRAM  The path to the program information, the default
                               is the folder of the history if one is declared.

|]

getArgOrExit :: Arguments -> Option -> IO String
getArgOrExit = getArgOrExitWith patterns

helpNeeded args =
  args `isPresent` longOption "help"

main :: IO ()
main = do
  args <- parseArgsOrExit patterns =<< getArgs
  when (helpNeeded args) $ exitWithUsage patterns
  runCommand args

runCommand :: Arguments -> IO ()
runCommand args = do

  program <- getProgram args

  onCommand "parse" $ \events -> do
    runEffect $ for events (lift . putStrLn . pp program)

  onCommand "count" $ countEvents >=> print

  onCommand "size" $ P.length >=> print

  onCommand "lockset" $ \events -> do
    locks <- lockset . fromEvents <$> P.toListM events
    forM_ locks $ \(e, b) -> do
      let locks = L.intercalate "," $ map (pp program) b
      if (args `isPresent` (longOption "human-readable"))
      then do
        let s = pp program e
        putStrLn $ s ++ L.replicate (60 - length s) ' ' ++ " - " ++ locks
      else
        putStrLn locks

  onCommand "dataraces" $ \events -> do
    h <- fromEvents <$> P.toListM events
    let candidates = raceCandidates h
    forM_ candidates $ \(a, b) -> do
      let s = pp program a
      putStrLn $ s ++ L.replicate (55 - length s) ' ' ++ " - " ++ pp program b
      r <- permute h (a, b)
      case r of
        Nothing -> putStrLn "FAIL"
        Just t -> do
          putStrLn "SUCCESS"
          forM_ t $ \e ->
            putStrLn $ ">>> " ++ pp program e

  onCommand "deadlock-candidates" $ \events -> do
    es <- deadlockCandidates . fromEvents <$> P.toListM events
    forM_ es $ \(a, b) -> do
      putStrLn $ "A = " ++ pp program a
      putStrLn $ "B = " ++ pp program b
      putStrLn ""

  onCommand "deadlocks" $ \events -> do
    putStrLn "Start!"
    h <- fromEvents <$> P.toListM events
    let candidates = deadlockCandidates h
    forM_ candidates $ \(a, b) -> do
      let s = pp program a
          c = pcontraints h (a, b)
      putStrLn $ s ++ L.replicate (55 - length s) ' ' ++ " - " ++ pp program b
      r <- permute h (a, b)
      case r of
        Nothing -> do
          putStrLn "FAIL"
          writeFile ("fail-" ++ show (idx a) ++ "-" ++ show (idx b) ++ ".dot") $
            (cnf2dot program h . toCNF $ c)
        Just t -> do
          putStrLn "SUCCESS"
          forM_ t $ \e ->
            putStrLn $ ">>> " ++ pp program e
          writeFile ("success-" ++ show (idx a) ++ "-" ++ show (idx b) ++ ".dot") $
            (cnf2dot program t . toCNF $ c)

  onCommand "dot" $ \events -> do
    h <- fromEvents <$> P.toListM events
    let lia = contraints h
    putStrLn . cnf2dot program h $ toCNF lia
  where
    withHistory f = do
      case getArg args (argument "history") of
        Just events ->
          withFile events ReadMode f
        Nothing ->
          f stdin
    onCommand cmd f =
      when (args `isPresent` command cmd) $ do
        withHistory (f . readHistory)

getProgram args =
  case aProgram <|> fmap takeDirectory aHistory of
    Just folder -> Program.fromFolder folder
    Nothing -> return $ Program.empty
  where
  aHistory = getArg args $ argument "history"
  aProgram = getArg args $ argument "program"

cnf2dot :: PartialHistory h => Program.Program -> h -> [[LIAAtom (Unique Event)]] -> String
cnf2dot program h cnf = unlines $
  [ "digraph {"
  , "graph [overlap=false, splines=true];"
  , "edge [ colorscheme = dark28 ]"
  ]
  ++ [ unlines $ zipWith printEvent [0..] (Wiretap.Data.History.enumerate h)]
  ++ [ unlines $ printConjunction color cj
     | (color, cj) <- zip (cycle $ map show [1..8]) cnf
     ]
  ++ [ "}" ]
  where
    p u = "O" ++ show (idx u)
    printEvent id u@(Unique _ event) =
      p u ++ " [ shape = box, fontsize = 10, label = \""
          ++ pp program (operation event) ++ "\", "
          ++ "pos = \"" ++ show (threadId (thread event) * 200)
          ++ "," ++ show (- id * 75) ++ "!\" ];"

    events = S.fromList (Wiretap.Data.History.enumerate h)
    printAtom color constrain atom =
      case atom of
        AOrder a b | a `S.member` events &&  b `S.member` events ->
           "\"" ++ p a ++ "\" -> \"" ++ p b ++ "\" "
           ++ case constrain of
                True -> ";"
                False ->
                  "[ style=dashed, color=\"" ++ color ++ "\"];"
        AEq a b ->
             "\"" ++ p a ++ "\" -> \"" ++ p b ++ "\"; "
          ++ "\"" ++ p b ++ "\" -> \"" ++ p a ++ "\""
        otherwise -> ""

    printConjunction color [e] =
      [ printAtom "black" True e ]
    printConjunction color es =
      map (printAtom color False) es
