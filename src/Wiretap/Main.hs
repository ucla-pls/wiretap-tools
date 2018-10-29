{-# LANGUAGE TupleSections #-}
{-# LANGUAGE BangPatterns        #-}
{-# LANGUAGE FlexibleContexts    #-}
 {-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE QuasiQuotes         #-}
{-# LANGUAGE RankNTypes          #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Wiretap.Main where

import           System.Console.Docopt
-- import           System.Directory
import           System.Environment               (getArgs)
import           System.FilePath
import           System.IO

-- import Debug.Trace

import           Control.Applicative
import           Control.Lens                     (over, _2)
import           Control.Monad
import           Control.Monad.Catch
import           Control.Monad.Trans.Except
import           Control.Monad.Trans.State.Strict (StateT)
import           Control.Monad.State.Class
import           Control.Monad.Writer

-- import           Z3.Monad (evalZ3, MonadZ3)

import qualified Data.List                        as L
import qualified Data.Map.Strict                  as M
import           Data.Maybe                       (catMaybes, fromMaybe)
import qualified Data.Set                         as S
import           Data.Traversable                 (mapM)
import           Data.Unique
-- import           Data.IORef
import           Data.Either
import           Data.Functor

-- import Debug.Trace

import           Pipes
import qualified Pipes.Lift                       as PL
import qualified Pipes.Missing                    as PM
import qualified Pipes.Prelude                    as P
import qualified Pipes.Internal                   as PI

import           Wiretap.Analysis.Count
import           Wiretap.Format.Binary
import           Wiretap.Format.Text
import           Wiretap.Utils
import           Wiretap.Data.Event
import           Wiretap.Data.History
import qualified Wiretap.Data.Program             as Program
import           Wiretap.Analysis.DataRace
import           Wiretap.Analysis.Deadlock
import           Wiretap.Analysis.HBL
import           Wiretap.Analysis.HBL.Z3
import           Wiretap.Analysis.Lock hiding (lockMap)
import           Wiretap.Analysis.Permute
import           Wiretap.Analysis.Consistency
import           Wiretap.Analysis.MustHappenBefore

patterns :: Docopt
patterns = [docopt|wiretap-tools version 0.1.0.0

Usage:
   wiretap-tools (count|size) [<history>]
   wiretap-tools parse [-Ph] [<history>]
   wiretap-tools lockset [-vh] [<history>]
   wiretap-tools dataraces [options] [<history>]
   wiretap-tools deadlocks [options] [<history>]
   wiretap-tools bugs [options] [<history>]
   wiretap-tools check [options] [<history>]
   wiretap-tools (--help | --version)

Options:
-h, --human-readable           Adds more information about execution

-P PROGRAM, --program PROGRAM  The path to the program information, the default
                               is the folder of the history if none is declared.

-f FILTER, --filter FILTER     For use in a candidate analysis. The multible filters
                               can be added seperated by commas. See filters.

-p PROVER, --prover PROVER     For use in a candidate analysis, if no prover is
                               provided, un verified candidates are produced.

-o OUT, --proof OUT            Produces the proof in the following directory

--chunk-size CHUNK_SIZE        For use to set a the size of the chunks, if not
                               set the program will read the entier history.

--chunk-offset CHUNK_OFFSET    Chunk offset is the number of elements dropped each
                               after each chunk. The minimal offset is 1, and the
                               maximal offset, which touches all events is the
                               size.

--solve-time SOLVE_TIME        The time the solver can use before it is timed out
                               (default: 0).

--solver SOLVER                The solver (default: z3:qf_lia)

--ignore IGNORED_FILE          A file containing candidates to ignore.

-v, --verbose                  Produce verbose outputs

Filters:
Filters are applicable to dataraces and deadlock analyses.

  lockset:     Remove all candidates with shared locks.
  reject:      Rejects all candidates
  ignored:     Don't try candidates in the ignore set
  mhb:         Do not check candidates which is must-happen-before related

Provers:
A prover is an algorithm turns a history into a constraint.

  none:       No constraints except that the candidate has to be placed next to
              each other.
  free:       A prover that only uses must-happen-before constraints, and sequential
              consistency.
  valuesonly: An unsound prover that only takes values into account.
  branchonly: An unsound prover that only take branch events into account.
  refsonly:   An unsound prover that only takes refs into account.
  dirk:       The data flow sentisive control-flow consistency alogrithm [default].
  rvpredict:  A prover based on Huang et. al. 2014.
  said:       The prover used in Said et. al. 2011.
|]

data Config = Config
  { verbose       :: Bool
  , prover        :: String
  , filters       :: [String]
  , outputProof   :: Maybe FilePath
  , program       :: Maybe FilePath
  , history       :: Maybe FilePath
  , humanReadable :: Bool
  , ignoreSet     :: S.Set String
  , chunkSize     :: Maybe Int
  , chunkOffset   :: Int
  , solveTime     :: Integer
  , solver        :: String
  } deriving (Show, Read)

getArgOrExit :: Arguments -> Option -> IO String
getArgOrExit = getArgOrExitWith patterns

helpNeeded :: Arguments -> Bool
helpNeeded args =
  args `isPresent` longOption "help"

main :: IO ()
main = do
  mainWithArgs =<< getArgs

mainWithArgs :: [String] -> IO ()
mainWithArgs args =
  case parseArgs patterns args of
    Right args' -> do
      when (helpNeeded args') $ exitWithUsage patterns
      config <- readConfig args'
      runCommand args' config
    Left err ->
      exitWithUsageMessage patterns (show err)

readConfig :: Arguments -> IO Config
readConfig args = do
  ignoreSet' <- case getLongOption "ignore" of
    Just file ->
      S.fromList . lines <$> readFile file
    Nothing ->
      return $ S.empty

  let chunk_size = read <$> getLongOption "chunk-size"

  return $ Config
    { verbose = isPresent args $ longOption "verbose"
    , filters = splitOn ','
        $ getArgWithDefault args "mhb,lockset" (longOption "filter")
    , prover = getArgWithDefault args "dirk" (longOption "prover")
    , outputProof = getLongOption "proof"
    , program = getLongOption "program"
    , history = getArgument "history"
    , chunkSize = chunk_size
    , chunkOffset = fromMaybe (fromMaybe 1 $ (flip div 2) <$> chunk_size)
         (read <$> getLongOption "chunk-offset")
    , humanReadable = args `isPresent` longOption "human-readable"
    , ignoreSet = ignoreSet'
    , solveTime = read $ getArgWithDefault args "0" (longOption "solve-time")
    , solver = getArgWithDefault args "z3:qf_lia" (longOption "solver")
    }
  where
    getLongOption = getArg args . longOption
    getArgument = getArg args . argument

prettyPrintEvents :: Program.Program -> Config -> Proxy X () () Event IO () -> IO ()
prettyPrintEvents !p !config events 
  | humanReadable config = do
    runEffect $ for events $ \e -> do
      PI.M $ do
        print $ PP p e
        i <- instruction p e
        putStr "        "
        putStrLn $ Program.instName p i
        return (PI.Pure ())
  | otherwise = do
    let 
      go !pipe = 
        case pipe of 
          PI.Respond e f -> print (PP p e) >>= go . f 
          PI.M m -> m >>= go
          PI.Pure e -> return e
          _ -> undefined
    go events
    -- runEffect $ for events helper

runCommand :: Arguments -> Config -> IO ()
runCommand args config = do
  p <- getProgram config

  let
    pprint :: Show (PP a) => a -> String
    pprint = pp p

  onCommand "parse" $ prettyPrintEvents p config

  onCommand "count" $
    countEvents >=> print

  onCommand "size" $
    P.length >=> print

  onCommand "lockset" $ \events -> do
    locks <- lockset . fromEvents <$> P.toListM events
    forM_ locks $ printLockset pprint . over _2 (L.intercalate "," . map pprint . M.assocs)

  onCommand "dataraces" $
    proveCandidates config p
      (const . raceCandidates)
      $ prettyPrint p

  onCommand "deadlocks" $
    proveCandidates config p (
      \h s ->
        deadlockCandidates' h $ lockMap s
      ) $ prettyPrint p

  onCommand "bugs" $
    proveCandidates config p (
      \h s ->
        concat
           [ BDeadlock <$> deadlockCandidates' h (lockMap s)
           , BDataRace <$> raceCandidates h
           ]
      ) $ prettyPrint p

  onCommand "check" $
    (\e -> return (e >-> PM.scan' (\i e' -> (i+1, Unique i e')) 0))
    >=> checkConsistency p
    >=> print

  where
    getProgram cfg =
      maybe (return Program.empty) Program.fromFolder $
        program config <|> fmap takeDirectory (history cfg)

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

type LockState = M.Map Thread [(Ref, UE)]

data ProverState = ProverState
  { proven    :: !(S.Set String)
  , lockMap   :: !(UniqueMap (M.Map Ref UE))
  , lockState :: !(LockState)
  , mhbGraph :: !MHB
  } deriving (Show)

addProven :: String -> ProverState -> ProverState
addProven a p =
   p { proven = S.insert a $ proven p }

updateLockState :: PartialHistory h => h -> ProverState -> ProverState
updateLockState h p =
   p { lockState = snd $! locksetSimulation (lockState p) h }

setLockMap :: PartialHistory h => h -> ProverState -> ProverState
setLockMap h p =
  p { lockMap = fst $ locksetSimulation (lockState p) h }

stateFromChunck :: PartialHistory h => h -> ProverState -> ProverState
stateFromChunck h p =
  p { lockMap = fst $ locksetSimulation (lockState p) h
    , mhbGraph = mustHappenBefore h
    }

type ProverT m = StateT ProverState m

proveCandidates
  :: forall a m. (Candidate a, Show a, Ord a, MonadIO m, MonadCatch m)
  => Config
  -> Program.Program
  -> (forall h. PartialHistory h => h -> ProverState -> [a])
  -> (a -> IO String)
  -> Producer Event m ()
  -> m ()
proveCandidates config p findCandidates toString events = do
  say $ "Filters: " ++ show (filters config)
  say $ "Human Readable: " ++ show (humanReadable config)
  runEffect $ uniqueEvents >-> PL.evalStateP initialState proverPipe

  where
    initialState =
      (ProverState S.empty (fromUniques []) M.empty mhbEmpty)

    logV = hPutStrLn stderr

    say :: forall m'. (MonadIO m') => String -> m' ()
    say = when (verbose config) . liftIO . logV

    uniqueEvents =
       PM.finite' (events >-> PM.scan' (\i e -> (i+1, Unique i e)) 0)

    proverPipe =
      chunkate >-> forever (await >>= lift . chunkProver)

    chunkate :: Pipe (Maybe UE) [UE] (ProverT m) ()
    chunkate =
      case chunkSize config of
        Nothing -> do
          -- Read the entire history
          list <- PM.asList $ PM.recoverAll >-> PM.end'
          lift . modify $ stateFromChunck list
          yield list
        Just size ->
          -- Read a little at a time
          getN size >>= go size
      where
        offset = chunkOffset config

        go size chunk = do
          !ls <- lift $ gets lockState
          liftIO . when (verbose config) $
            case chunk of
                a:_ -> do
                  logV $ "At event " ++ show (idx a)
                  forM_ (M.assocs ls) $ \(t, locks) -> when (not $ L.null locks) $ do
                    logV $ (pp p t) ++ " has locks from:"
                    forM_ locks $ \(r, event) -> do
                      _event <- pp p <$> instruction p (normal event)
                      logV $ "  " ++ pp p r ++ "  " ++ _event
                [] -> return ()
          lift . modify $ stateFromChunck chunk
          yield chunk
          if actualChunkSize < size
            then
              say $ "Done"
            else do
              new <- getN offset
              let (dropped, remainder) = splitAt offset chunk
              lift . modify $ updateLockState dropped
              go size $ remainder ++ new
          where actualChunkSize = length chunk

        getN size = do
          catMaybes <$> PM.asList (PM.take' size)

    markProven prv = do
      modify $ addProven prv
      liftIO $ putStrLn prv

    runChosenSolver prv =
        case (solver config) of
          "z3:qf_lia" -> runLIASolver (solveTime config) (probSymbolDef prv)
          "z3:qf_idl" -> runIDLSolver (solveTime config) (probSymbolDef prv)
          "z3:qf_lra" -> runLRASolver (solveTime config) (probSymbolDef prv)
          "z3:qf_rdl" -> runRDLSolver (solveTime config) (probSymbolDef prv)
          a -> error $ "Do not know about solver: " ++ a

    chunkProver
      :: forall h. (PartialHistory h)
      => h
      -> StateT ProverState m ()
    chunkProver chunk = do
      -- Find candidates
      candidates <- findCandidates chunk <$> get
      say $ "Found " ++ show (length candidates) ++ " candidate(s)."

      when (verbose config) . liftIO . forM_ candidates $ \ c -> do
        logV $ " -+ " ++  L.intercalate " ++ " (map (pp p) . S.toList $ candidateSet c)


      -- First we apply filters
      let fs = getFilter (filters config)
      (_, real) <- partitionEithers <$> mapM fs candidates
      say $ "- after filter: " ++ show (length real)

      -- The we group the results by name.
      realByBug <- liftIO $ groupUnsortedOnFst <$> mapM (\c -> (,c) <$> toString c) real
      say $ "- distinct: " ++ show (length realByBug)

      -- And remove any that have been proved before
      ps <- gets proven
      let toBeProven = filter (not . (`S.member` ps) . fst) realByBug
      say $ "- not proven: " ++ show (length toBeProven)

      lm <- gets lockMap
      mh <- gets mhbGraph

      -- Then we start a batch prover, where we prove group in order, reporting
      -- anything we find
      case getProver (prover config) of
        Just df
          | length toBeProven > 0 -> do

              let problem' = generateProblem (lm, mh, df) chunk
              say $ "- Problem: "
              say $ "  + elements: " ++ (show . countEventsF . map normal $ probElements problem')
              say $ "  + symbols:  " ++ (show . countEventsF . map normal $ probSymbols problem')

              let problem = reduceProblem problem'
              -- say $ "- Reduced problem: "
              -- say $ "  + elements: " ++ (show . countEventsF . map normal $ probElements problem)
              -- say $ "  + symbols:  " ++ (show . countEventsF . map normal $ probSymbols problem)

              e <- runChosenSolver problem $ do
                assert (probBase problem)
                forM_ toBeProven $ \(item, cs) -> do
                  say $ "- Trying to prove " ++  item ++ ", with "
                       ++ show (length cs) ++ " candidates."
                  -- forM_ cs $ \c -> do
                  --   say (show c)
                  x <- solveOne problem cs
                  case x of
                    Nothing ->
                      say "  - Could not prove constraints."
                    Just c -> do
                      when (humanReadable config) . liftIO $ do
                        logV ("Found: " ++ item)
                        forM_ (candidateSet c) $ \cs' ->
                            logV ("    -: " ++ pp p cs')
                      lift $ markProven item
                      -- liftIO $ printProof pf
              either (say . show) return $ e
        _ -> do
          forM_ toBeProven $ \(item, cs) -> do
            when (humanReadable config) . liftIO $ do
              logV ("Found: " ++ show item)
              forM_ (candidateSet $ head cs) $ \cs' ->
                  logV ("    -:" ++ pp p cs')
            markProven item

    -- onProverError
    --   :: (PartialHistory h)
    --   => h -> a -> HBL UE
    --   -> IO String
    -- onProverError hist c cnts = do
    --   case outputProof config of
    --     Just folder -> do
    --       createDirectoryIfMissing True folder
    --       let ls = map (show . idx) . L.sort . S.toList $ candidateSet c
    --           file = folder </> (L.intercalate "-" ls ++ ".err.dot")
    --       withFile file WriteMode $ \h ->
    --         hPutStr h $ cnf2dot p hist (toCNF cnts)
    --       return $ "Could solve constraints, outputted to '" ++ file ++ "'"
    --     Nothing -> do
    --       return "Could not solve constraints."

    -- printProof (Proof c hbl hist) = do
    --   case outputProof config of
    --     Just folder -> do
    --       createDirectoryIfMissing True folder
    --       let ls = map (show . idx) . L.sort . S.toList $ candidateSet c
    --       let fn = folder </> L.intercalate "-" ls
    --       withFile (fn ++ ".hist") WriteMode $
    --         \h -> runEffect $ each hist >-> P.map normal >-> writeHistory h
    --       withFile (fn ++ ".dot") WriteMode $ \h ->
    --         hPutStr h $ cnf2dot p hist (toCNF hbl)
    --     Nothing ->
    --       return ()

    getFilter
      :: forall m'. (MonadIO m', MonadState ProverState m')
      => [String]
      -> a -> m' (Either (IO String) a)
    getFilter filterNames = inner
      where
        inner c = runExceptT $ mapM ($c) fs $> c
        fs = map (toFilter p config toString) filterNames

    getProver name =
      case name of
        "said"         -> Just dfSaid
        "dirk"         -> Just dfDirk
        "rvpredict"    -> Just dfRVPredict
        "free"         -> Just dfFree
        "none"         -> Nothing
        _              -> error $ "Unknown prover: '" ++ name ++ "'"



toFilter :: (MonadIO m, Candidate t, MonadState ProverState m) =>
  Program.Program
  -> Config
  -> (t -> IO String)
  -> [Char]
  -> t
  -> ExceptT (IO [Char]) m ()
toFilter p config toString name c =
  case name of
    "lockset" -> do
      lm <- gets lockMap
      void $ withExceptT (\shared -> do
          locks <- forM shared $ \(r, (a, b)) -> do
            inst_a <- instruction p . normal $ a
            inst_b <- instruction p . normal $ b
            return $ L.intercalate "\n"
              [ "    " ++ pp p r
              , "      " ++ pp p inst_a
              , "      " ++ pp p inst_b
              ]
          return . L.intercalate "\n" $
            "Candidates shares locks:" : locks
        ) $ locksetFilter' lm c
    "mhb" -> do
      mg <- gets mhbGraph
      forM_ (crossproduct1 . S.toList $ candidateSet c) $ \(a, b) ->
        if mhb mg a b
        then throwE $ do
            inst_a <- instruction p . normal $ a
            inst_b <- instruction p . normal $ b
            return $ L.intercalate "\n"
              [ "Must happen before related"
              , "    " ++ pp p inst_a
              , "    " ++ pp p inst_b
              ]
        else return ()

    "ignored" -> do
      str <- liftIO $ toString c
      if S.member str (ignoreSet config)
        then throwE . return $ "In ignore set"
        else return ()

    "reject" ->
      throwE . return $ "Rejected"

    _ ->
      error $ "Unknown filter " ++ name

runAll :: (Monad m') => a -> [a -> m' a] -> m' a
runAll a = L.foldl' (>>=) $ pure a

cnf2dot
  :: PartialHistory h
  => Program.Program
  -> h
  -> [[HBLAtom UE UE]]
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
    pprint = concatMap (\c -> if c == '"' then "\\\"" else [c]) . pp p
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
        Order a b | a `S.member` events &&  b `S.member` events ->
           "\"" ++ pr a ++ "\" -> \"" ++ pr b ++ "\" "
           ++ if constrain
              then ";"
              else "[ style=dashed, color=\"" ++ color ++ "\"];"
        Concur a b ->
             "\"" ++ pr a ++ "\" -> \"" ++ pr b ++ "\"; "
          ++ "\"" ++ pr b ++ "\" -> \"" ++ pr a ++ "\""
        _ -> ""
    printConjunction _ [e] =
      [ printAtom "black" True e ]
    printConjunction color es =
      map (printAtom color False) es

data Bug
  = BDataRace DataRace
  | BDeadlock Deadlock
  deriving (Show, Eq, Ord)

instance Candidate Bug where
  candidateSet bug =
    case bug of
      BDataRace a -> candidateSet a
      BDeadlock a -> candidateSet a

  prettyPrint p bug =
    case bug of
      BDataRace a -> ("DR:" ++) <$> prettyPrint p a
      BDeadlock a -> ("DL:" ++) <$> prettyPrint p a
