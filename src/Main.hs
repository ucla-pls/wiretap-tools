{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
module Main where

import           System.Console.Docopt
import           System.Directory
import           System.Environment              (getArgs)
import           System.FilePath
import           System.IO

import           Control.Monad
import           Control.Lens  (over, _2)
import           Control.Applicative

import           Data.Unique

import qualified Data.List                       as L
import qualified Data.Set                        as S
import           Data.Maybe

import           Pipes
import qualified Pipes.Prelude                   as P

import           Wiretap.Utils
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
   wiretap-tools dataraces [-hpfo] [<history>]
   wiretap-tools deadlocks [-hpfo] [<history>]
   wiretap-tools (--help | --version)

Options:
-h, --human-readable           Adds more information about execution
-P PROGRAM, --program PROGRAM  The path to the program information, the default
                               is the folder of the history if none is declared.
-f FILTER, --filter FILTER     For use in a candidate analysis. The multible filters
                               can be added seperated by commas. See filters.
-p PROVER, --prover PROVER     For use in a candidate analysis, if no prover is provided, un
                               verified candidates are produced.
-o OUT, --proof OUT            Produces the proof in the following directory [ default : ./_proof].

Filters:
Filters are applicable to dataraces and deadlock analyses.
|]

getArgOrExit :: Arguments -> Option -> IO String
getArgOrExit = getArgOrExitWith patterns

helpNeeded args =
  args `isPresent` longOption "help"

main :: IO ()
main = do
  args <- parseArgs patterns <$> getArgs
  case args of
    Right args -> do
      when (helpNeeded args) $ exitWithUsage patterns
      runCommand args
    Left err -> do
      exitWithUsageMessage patterns (show err)

runCommand :: Arguments -> IO ()
runCommand args = do
  program <- getProgram

  onCommand "parse" $ \events -> do
    runEffect $ for events $ \e -> do
      i <- lift (instruction program e)
      let estr = pp program e
      lift . putStrLn $
        estr ++ L.replicate (80 - length estr) ' '
             ++ " - " ++ Program.instName program i

  onCommand "count" $
    countEvents >=> print

  onCommand "size" $
    P.length >=> print

  onCommand "lockset" $ \events -> do
    locks <- lockset . fromEvents <$> P.toListM events
    forM_ locks $ printLockset program . over _2 (L.intercalate "," . map (pp program))

  onCommand "dataraces" $ \events -> do
    histories <- chuncks events
    forM_ histories $ \history -> do
      let filters = getFilters aFilter history
      let proofs = proveCandidates id history . L.sort $ raceCandidates history
      forM_ proofs $ \(c, lia, h') ->
        printDataRace program c

  where
    getFilters aFilter history =
      map aFilter go
      where
        go "lockset" =
        go name = error $ "Unknown filter " ++ name

    printDataRace program (a, b) =
      if aHumanReadable
        then do
          let [ap, bp] = map (pp program) [a, b]
          putStrLn $ padStr ap ' ' 60 ++ bp
        else do
          datarace <- mapM (instruction program . normal) [a, b]
          putStrLn . L.intercalate " " . L.sort $ map (pp program) datarace

    printLockset program (e, locks) | aHumanReadable = do
      putStrLn $ padStr (pp program e) ' ' 60 ++ " - " ++ locks
    printLockset program (e, locks) =
      putStrLn locks

    chuncks events = do
      chunck <- fromEvents <$> P.toListM events
      return [chunck]

    withHistory f = do
      case getArg args (argument "history") of
        Just events ->
          withFile events ReadMode f
        Nothing ->
          f stdin

    onCommand cmd f =
      when (args `isPresent` command cmd) $ do
        withHistory (f . readHistory)

    getProgram =
      case aProgram <|> fmap takeDirectory aHistory of
        Just folder -> Program.fromFolder folder
        Nothing -> return $ Program.empty

    proveCandidate
      :: (PartialHistory h, Candidate a)
      => h
      -> a
      -> m (Result a)
    proveCandidate h candidate =
      case candidate' of
        Right candidate' ->
          proveWithProver aProver h candidate'
        Left message ->
          return $ failedToProve message
      where
        candidate' = L.foldl (\b a -> b >>= applyFilter h a) (Right candidate) aFilters

    proveWithProver name =
      permute prover
      where
        prover =
          case name of
            "said" -> said
            "kalhauge" -> kalhauge
            "free" -> free
            "none" -> none
            otherwise -> error $ "Unknown prover: '" ++ name ++ "'"

    applyFilter
      :: (PartialHistory h, Candidate a)
      => h
      -> String
      -> a
      -> Either String a
    applyFilter h name candidate =
      case name of
        "lockset" ->
          if seperateLocks (lockMap h) . toEventPair candidate then
            Right candidate
          else
            Left $ "lockset : Candidate had overlapping locksets."
        otherwise ->
          error $ "Unknown filter: ''" ++ name ++ "'"


    aHistory = getArg args $ argument "history"
    aProgram = getArg args $ argument "program"
    aFilters = fromMaybe [] $ splitOn ',' <$> getArg args (longOption "filter")
    aProver = getArgWithDefault args "kalhauge" (longOption "prover")
    aHumanReadable = args `isPresent` longOption "human-readable"

    padStr p char size =
      p ++ L.replicate (size - length p) char


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
