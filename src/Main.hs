{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE LambdaCase        #-}
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
   wiretap-tools parse [-Ph] [<history>]
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

Provers:
A prover is an algorithm turns a history into a constraint.

  said:      The prover used in [Said 2011].
  free:      A prover that only uses must-happen-before constraints, and sequential
             consistency.
  none:      No constraints except that the candidate has to be placed next to
             each other.
  kalhauge:  The data flow sentisive control-flow consistency alogrithm [default].
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

helpNeeded :: Arguments -> Bool
helpNeeded args =
  args `isPresent` longOption "help"

main :: IO ()
main = do
  parseArgs patterns <$> getArgs >>= \case
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
  p <- getProgram config

  let
    pprint :: Show (PP a) => a -> String
    pprint = pp p

  onCommand "parse" $ \events -> do
    runEffect $ for events $ \e -> do
      i <- lift (instruction p e)
      lift $ do
        putStrLn $ pprint e
        putStr "        "
        putStrLn $ Program.instName p i

  onCommand "count" $
    countEvents >=> print

  onCommand "size" $
    P.length >=> print

  onCommand "lockset" $ \events -> do
    locks <- lockset . fromEvents <$> P.toListM events
    forM_ locks $ printLockset pprint . over _2 (L.intercalate "," . map pprint)

  onCommand "dataraces" $
    proveCandidates config
      (each . raceCandidates) $ dataRaceToString p

  onCommand "deadlocks" $
    proveCandidates config
      (each . fst . deadlockCandidates M.empty) $ deadlockToString p

  where
    getProgram cfg =
      maybe (return Program.empty) Program.fromFolder $
        program config <|> fmap takeDirectory (history cfg)

    deadlockToString :: Program.Program -> Deadlock -> IO String
    deadlockToString p (Deadlock (DeadlockEdge _ aA aR) (DeadlockEdge _ bA bR)) = do
       as <- sequence . map (instruction p . normal) $ [aA, aR]
       bs <- sequence . map (instruction p . normal) $ [bA, bR]
       return . L.intercalate ";" . L.sort .
         L.map (L.intercalate "," . L.sort . L.map (pp p)) $ [as, bs]


    dataRaceToString p (DataRace l a b) | humanReadable config =
      return $ padStr a' ' ' 60 ++ padStr b' ' ' 60 ++ pp p l
      where [a', b'] = map (pp p) [a, b]

    dataRaceToString p (DataRace _ a b) = do
      datarace <- mapM (instruction p . normal) [a, b]
      return $ unwords . L.sort $ map (pp p) datarace

    printLockset pprint (e, locks) | humanReadable config =
      putStrLn $ padStr (pprint e) ' ' 60 ++ " - " ++ locks
    printLockset _ (_, locks) =
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
  -> (a -> IO String)
  -> Producer Event m ()
  -> m ()
proveCandidates config generator toString events = do
  runEffect $ for (chunck events) chunckProver
  where
    chunckProver hist =
      for (generator hist) $
       filterCandidate (getFilters hist)
       ~> proveCandidate hist
       ~> printProofs

    filterCandidate filters' c =
      case applyFilters c filters' of
        Right c' -> yield c'
        Left msg ->
          liftIO $ when (verbose config) $ do
            hPutStrLn stderr "Filtered candidate away:"
            hPutStrLn stderr =<< toString c
            hPutStrLn stderr "The reason was:"
            hPutStrLn stderr msg

    proveCandidate h c = do
      lift (prove h c) >>= \case
        Right p -> yield p
        Left msg -> liftIO $
          when (verbose config) $ do
            hPutStrLn stderr "Couldn't prove candidate"
            hPutStrLn stderr =<< toString c
            hPutStrLn stderr "The reason was:"
            hPutStrLn stderr msg

    printProofs (Proof c _ hist) = liftIO $ do
      putStrLn =<< toString c
      case proof config of
        Just folder -> do
          createDirectoryIfMissing True folder
          let (Unique ia _, Unique ib _) = toEventPair c
          withFile (folder </> show ia ++ "-" ++ show ib ++ ".hist")
              WriteMode $ \h ->
            runEffect $ each hist >-> P.map normal >-> writeHistory h
        Nothing ->
          return ()

    getFilters history' =
      map go (filters config)
      where
        go "lockset" =
          locksetFilter history'
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

    chunck es = do
      h <- lift $ fromEvents <$> P.toListM es
      yield $ Wiretap.Data.History.enumerate h

cnf2dot
  :: PartialHistory h
  => Program.Program
  -> h
  -> [[LIAAtom (Unique Event)]]
  -> String
cnf2dot p h cnf = unlines $
  [ "digraph {"
  , "graph [overlap=false, splines=true];"
  , "edge [ colorscheme = dark28 ]"
  ]
  ++ [ unlines $ zipWith printEvent [0..] (Wiretap.Data.History.enumerate h)]
  ++ [ unlines $ printConjunction color cj
     | (color, cj) <- zip (cycle $ map show ([1..8] :: [Int])) cnf
     ]
  ++ [ "}" ]
  where
    pprint = pp p
    pr u = "O" ++ show (idx u)

    printEvent :: Int -> UE -> String
    printEvent i u@(Unique _ event) =
      pr u ++ " [ shape = box, fontsize = 10, label = \""
           ++ pprint (operation event) ++ "\", "
           ++ "pos = \"" ++ show (threadId (thread event) * 200)
           ++ "," ++ show (- i * 75) ++ "!\" ];"

    events = S.fromList (Wiretap.Data.History.enumerate h)
    printAtom color constrain atom =
      case atom of
        AOrder a b | a `S.member` events &&  b `S.member` events ->
           "\"" ++ pr a ++ "\" -> \"" ++ pr b ++ "\" "
           ++ if constrain
              then ";"
              else "[ style=dashed, color=\"" ++ color ++ "\"];"
        AEq a b ->
             "\"" ++ pr a ++ "\" -> \"" ++ pr b ++ "\"; "
          ++ "\"" ++ pr b ++ "\" -> \"" ++ pr a ++ "\""
        _ -> ""

    printConjunction _ [e] =
      [ printAtom "black" True e ]
    printConjunction color es =
      map (printAtom color False) es
