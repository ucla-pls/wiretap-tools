{-# LANGUAGE RankNTypes #-}
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
import qualified Data.Map                        as M
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
import           Wiretap.Analysis.LIA  hiding ((~>))
import           Wiretap.Analysis.DataRace
import           Wiretap.Analysis.Permute

patterns :: Docopt
patterns = [docopt|wiretap-tools version 0.1.0.0

Usage:
   wiretap-tools (parse|count|size) [<history>]
   wiretap-tools lockset [-vh] [<history>]
   wiretap-tools dataraces [options] [<history>]
   wiretap-tools deadlocks [options] [<history>]
   wiretap-tools (--help | --version)

Options:
-h, --human-readable           Adds more information about execution
-P PROGRAM, --program PROGRAM  The path to the program information, the default
                               is the folder of the history if none is declared.
-f FILTER, --filter FILTER     For use in a candidate analysis. The multible filters
                               can be added seperated by commas. See filters.
-p PROVER, --prover PROVER     For use in a candidate analysis, if no prover is provided, un
                               verified candidates are produced.
-o OUT, --proof OUT            Produces the proof in the following directory

-v, --verbose                  Produce verbose outputs

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
    Left err ->
      exitWithUsageMessage patterns (show err)

runCommand :: Arguments -> IO ()
runCommand args = do
  program <- getProgram

  onCommand "parse" $ \events ->
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

  onCommand "dataraces" $
    findCandidates raceCandidates dataRaceToString

  onCommand "deadlocks" $
    findCandidates (fst . deadlockCandidates M.empty) deadlockToString
  where

    dataRaceToString = show
    deadlockToString = show

    filterCandidate
      :: Candidate a
      => (a -> String)
      -> [a -> Either String a]
      -> a
      -> Producer a IO ()
    filterCandidate toString filters c =
      case applyFilters c filters of
        Right c -> yield c
        Left msg ->
          lift $ when aVerbose $ do
            hPutStrLn stderr "Filtered candidate away:"
            hPrint stderr $ toString c
            hPutStrLn stderr "The reason was:"
            hPutStrLn stderr msg

    proveCandidate
      :: (Candidate a, PartialHistory h)
      => (a -> String)
      -> h
      -> a
      -> Producer (Proof a) IO ()
    proveCandidate toString h c = do
      p <- lift $ prove aProver h c
      case p of
        Right p -> yield p
        Left msg -> lift $
          when aVerbose $ do
            hPutStrLn stderr "Couldn't prove candidate"
            hPrint stderr $ toString c
            hPutStrLn stderr "The reason was:"
            hPutStrLn stderr msg

    printProofs
      :: Candidate a
      => (a -> String)
      -> Proof a
      -> Effect IO ()
    printProofs toString (Proof c constraints history) = lift $ do
      putStrLn $ toString c
      case aProof of
        Just folder -> do
          createDirectoryIfMissing True folder
          let (Unique ia a, Unique ib b) = toEventPair c
          withFile (folder </> show ia ++ "-" ++ show ib ++ ".hist") WriteMode $ \h ->
            runEffect $ each history >-> P.map normal >-> writeHistory h
        Nothing ->
          return ()

    findCandidates
      :: Candidate a
      => (forall h. PartialHistory h => h -> [a])
         -- ^ A function that can inspect a partial history and find candidates
      -> (a -> String) -- ^ A function that can print the candidates
      -> Producer Event IO ()
      -> IO ()
    findCandidates f toString events = do
      runEffect $ for (chunck events) findCandidatesInChunk
      where
        findCandidatesInChunk :: [UE] -> Effect IO ()
        findCandidatesInChunk history =
          for (each . f $ history) $
            filterCandidate toString (getFilters history)
            ~> proveCandidate toString history
            ~> printProofs toString


    chunck :: Producer Event IO () -> Producer [UE] IO ()
    chunck events = do
      h <- lift $ fromEvents <$> P.toListM events
      yield $ Wiretap.Data.History.enumerate h

    getFilters :: (Candidate a, PartialHistory h) => h -> [a -> Either String a]
    getFilters history =
      map go aFilters
      where
        go "lockset" =
          locksetFilter history
        go "all" =
          const $ Left "Rejected"
        go name =
          error $ "Unknown filter " ++ name

    applyFilters :: Candidate a => a -> [a -> Either String a] -> Either String a
    applyFilters c =
      L.foldl' (>>=) (pure c)

    prove name =
      permute prover
      where
        prover =
          case name of
            "said" -> said
            "kalhauge" -> kalhauge
            "free" -> free
            "none" -> none
            _ -> error $ "Unknown prover: '" ++ name ++ "'"

    printDataRace program (DataRace l a b) =
      if aHumanReadable
        then do
          let [ap, bp] = map (pp program) [a, b]
          putStrLn $ padStr ap ' ' 60 ++ padStr bp ' ' 60 ++ pp program l
        else do
          datarace <- mapM (instruction program . normal) [a, b]
          putStrLn . unwords . L.sort $ map (pp program) datarace

    printLockset program (e, locks) | aHumanReadable =
      putStrLn $ padStr (pp program e) ' ' 60 ++ " - " ++ locks
    printLockset program (e, locks) =
      putStrLn locks

    withHistory :: (Handle -> IO ()) -> IO ()
    withHistory f =
      case aHistory of
        Just events ->
          withFile events ReadMode f
        Nothing ->
          f stdin

    onCommand :: String -> (Producer Event IO () -> IO ()) -> IO ()
    onCommand cmd f =
      when (args `isPresent` command cmd) $
        withHistory (f . readHistory)

    getProgram =
      case aProgram <|> fmap takeDirectory aHistory of
        Just folder -> Program.fromFolder folder
        Nothing -> return Program.empty

    aVerbose = isPresent args $ longOption "verbose"
    aHistory = getArg args $ argument "history"
    aProgram = getArg args $ argument "program"
    aFilters = fromMaybe [] $ splitOn ',' <$> getArg args (longOption "filter")
    aProver = getArgWithDefault args "kalhauge" (longOption "prover")
    aProof = getArg args $ longOption "proof"
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
           ++ if constrain then ";" else "[ style=dashed, color=\"" ++ color ++ "\"];"
        AEq a b ->
             "\"" ++ p a ++ "\" -> \"" ++ p b ++ "\"; "
          ++ "\"" ++ p b ++ "\" -> \"" ++ p a ++ "\""
        _ -> ""

    printConjunction color [e] =
      [ printAtom "black" True e ]
    printConjunction color es =
      map (printAtom color False) es
