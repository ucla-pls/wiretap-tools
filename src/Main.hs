{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
{-# LANGUAGE RankNTypes        #-}
module Main where

import           System.Console.Docopt
import           System.Directory
import           System.Environment        (getArgs)
import           System.FilePath
import           System.IO

import           Control.Applicative
import           Control.Lens              (over, _2)
import           Control.Monad

import           Data.Unique
import           Debug.Trace

import qualified Data.List                 as L
import qualified Data.Map                  as M
import           Data.Maybe
import qualified Data.Set                  as S

import           Pipes
import qualified Pipes.Prelude             as P

import           Wiretap.Analysis.Count
import           Wiretap.Format.Binary
import           Wiretap.Format.Text
import           Wiretap.Utils

import           Wiretap.Data.Event
import           Wiretap.Data.History
import qualified Wiretap.Data.Program      as Program

import           Wiretap.Analysis.DataRace
import           Wiretap.Analysis.LIA      hiding ((~>))
import           Wiretap.Analysis.Lock
import           Wiretap.Analysis.Permute

patterns :: Docopt
patterns = [docopt|wiretap-tools version 0.1.0.0

Usage:
   wiretap-tools (count|size) [<history>]
   wiretap-tools parse [-vPh] [<history>]
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

  lockset:   Remove all candidates with shared locks.
  all:       Rejects all candidates
|]

data Config = Config
  { verbose       :: Bool
  , prover        :: String
  , filters       :: [String]
  , proof         :: Maybe FilePath
  , program       :: Maybe FilePath
  , history       :: Maybe FilePath
  , humanReadable :: Bool
  } deriving (Show, Read)

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
      config <- readConfig args
      runCommand args config
    Left err ->
      exitWithUsageMessage patterns (show err)

readConfig :: Arguments -> IO Config
readConfig args = do
  return $ Config
    { verbose = isPresent args $ longOption "verbose"
    , filters = fromMaybe [] $ splitOn ',' <$> getArg args (longOption "filter")
    , prover = getArgWithDefault args "kalhauge" (longOption "prover")
    , proof = getLongOption "proof"
    , program = getLongOption "program"
    , history = getArgument "history"
    , humanReadable = args `isPresent` longOption "human-readable"
    }
  where
    getLongOption = getArg args . longOption
    getArgument = getArg args . argument


runCommand :: Arguments -> Config -> IO ()
runCommand args config = do
  program <- getProgram config

  let
    pprint :: Show (PP a) => a -> String
    pprint = pp program

  onCommand "parse" $ \events -> do
    runEffect $ for events $ \e -> do
      i <- lift (instruction program e)
      let estr = pprint e
      lift . putStrLn $
        estr ++ L.replicate (80 - length estr) ' '
             ++ " - " ++ Program.instName program i

  onCommand "count" $
    countEvents >=> print

  onCommand "size" $
    P.length >=> print

  onCommand "lockset" $ \events -> do
    locks <- lockset . fromEvents <$> P.toListM events
    forM_ locks $ printLockset pprint . over _2 (L.intercalate "," . map pprint)

  onCommand "dataraces" $
    proveCandidates config (each . raceCandidates) dataRaceToString

  onCommand "deadlocks" $
    proveCandidates config (each . fst . deadlockCandidates M.empty) deadlockToString

  where
    getProgram config =
      maybe (return Program.empty) (Program.fromFolder . traceShowId) $
        program config <|> fmap takeDirectory (history config)

    dataRaceToString = show
    deadlockToString = show

    printDataRace program (DataRace l a b) | humanReadable config =
      putStrLn $ padStr ap ' ' 60 ++ padStr bp ' ' 60 ++ pp program l
      where [ap, bp] = map (pp program) [a, b]

    printDataRace program (DataRace l a b) = do
      datarace <- mapM (instruction program . normal) [a, b]
      putStrLn . unwords . L.sort $ map (pp program) datarace

    printLockset pprint (e, locks) | humanReadable config =
      putStrLn $ padStr (pprint e) ' ' 60 ++ " - " ++ locks
    printLockset pprint (e, locks) =
      putStrLn locks

    withHistory :: (Handle -> IO ()) -> IO ()
    withHistory f =
      case history config of
        Just events -> do
          withFile events ReadMode f
        Nothing -> do
          f stdin

    onCommand :: String -> (Producer Event IO () -> IO ()) -> IO ()
    onCommand cmd f =
      when (args `isPresent` command cmd) $
        withHistory (f . readHistory)

    padStr p char size =
      p ++ L.replicate (size - length p) char

proveCandidates
  :: (Candidate a, MonadIO m)
  => Config
  -> (forall h. PartialHistory h => h -> Producer a m ())
  -> (a -> String)
  -> Producer Event m ()
  -> m ()
proveCandidates config generator toString events = do
  runEffect $ for (chunck events) chunckProver
  where
    chunckProver history =
      for (generator history) $
       filterCandidate (getFilters history)
       ~> proveCandidate history
       ~> printProofs

    filterCandidate filters c =
      case applyFilters c filters of
        Right c -> yield c
        Left msg ->
          liftIO $ when (verbose config) $ do
            hPutStrLn stderr "Filtered candidate away:"
            hPrint stderr $ toString c
            hPutStrLn stderr "The reason was:"
            hPutStrLn stderr msg

    proveCandidate h c = do
      p <- lift $ prove h c
      case p of
        Right p -> yield p
        Left msg -> liftIO $
          when (verbose config) $ do
            hPutStrLn stderr "Couldn't prove candidate"
            hPrint stderr $ toString c
            hPutStrLn stderr "The reason was:"
            hPutStrLn stderr msg

    printProofs (Proof c constraints history) = liftIO $ do
      case proof config of
        Just folder -> do
          createDirectoryIfMissing True folder
          let (Unique ia a, Unique ib b) = toEventPair c
          withFile (folder </> show ia ++ "-" ++ show ib ++ ".hist") WriteMode $ \h ->
            runEffect $ each history >-> P.map normal >-> writeHistory h
        Nothing ->
          return ()

    getFilters history =
      map go (filters config)
      where
        go "lockset" =
          locksetFilter history
        go "all" =
          const $ Left "Rejected"
        go name =
          error $ "Unknown filter " ++ name

    applyFilters c =
      L.foldl' (>>=) (pure c)

    prove =
      permute $
        case (prover config) of
          "said"     -> said
          "kalhauge" -> kalhauge
          "free"     -> free
          "none"     -> none
          name       -> error $ "Unknown prover: '" ++ name ++ "'"

    chunck events = do
      h <- lift $ fromEvents <$> P.toListM events
      yield $ Wiretap.Data.History.enumerate h

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
    pprint = pp program
    p u = "O" ++ show (idx u)
    printEvent id u@(Unique _ event) =
      p u ++ " [ shape = box, fontsize = 10, label = \""
          ++ pprint (operation event) ++ "\", "
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
