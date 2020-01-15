{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE Rank2Types #-}

module Wiretap.Analysis where

-- import           Debug.Trace

-- import           Control.Monad.State
-- import           Control.Monad
-- import           Control.Lens hiding ((...))

-- import           Data.Maybe (maybeToList, catMaybes)
-- import           Data.Monoid
-- import           Data.Function (on)

-- import qualified Data.Map as M
-- import           Data.Map (Map)

-- import qualified Data.Vector as V

-- import qualified Data.IntMap as IM
-- import           Data.IntMap (IntMap)

-- import qualified Data.List as L

-- import           Z3.Monad

-- import           Data.PartialOrder

-- import           Wiretap.Data.Event(Event(..), Operation(..), Thread(..))
-- import qualified Wiretap.Data.Event as Event

-- -- helpers

-- (...) = (.) . (.)

-- -- Create a new monoid from lens and internal value
-- with :: Monoid a => Lens' a b -> b -> a
-- with l v = mempty & l .~ v

-- -- Create a new monoid from lens and internal monadic value
-- withM :: (Monoid a, Monad m) => Lens' a (m b) -> b -> a
-- withM l v = mempty & l .~ return v

-- -- | Get unique pairs in list
-- pairs :: [a] -> [(a, a)]
-- pairs (a:rest) = map (\x -> (a, x)) rest ++ pairs rest
-- pairs [] = []

-- -- | Applies a to all functions in every inner element
-- onAll :: Applicative f => f (a -> b) -> a -> f b
-- onAll a = (a <*>) . pure

-- -- Orders

-- -- Makes a element unique
-- data Unique a = Unique
--   { ident :: Int
--   , cnt :: a
--   } deriving (Show)

-- instance Eq (Unique a) where
--   (==) = (==) `on` ident

-- instance Ord (Unique a) where
--   compare = compare `on` ident

-- type EventIx = Unique Event

-- data Constraint =
--   Order EventIx EventIx
--   | And [Constraint]
--   | Or [Constraint]
--   deriving (Show)

-- instance Monoid Constraint where
--   mempty = And []
--   mappend a b =
--     case (a, b) of
--       (And as, And bs) -> And (as ++ bs)
--       (And as, b) -> And $ as <> [b]
--       (a, And bs) -> And $ [a] <> bs
--       (a, b) -> And [a, b]

-- infixl 8 ~>
-- (~>) = Order

-- class Monoid a => OrderAnalysis a where
--   fromEvent :: EventIx -> a
--   toConstraint :: a -> Constraint

-- fromEvents :: OrderAnalysis a => [Event] -> a
-- fromEvents =
--   mconcat . L.zipWith (fromEvent ... Unique) [0..]

-- -- | orders, takes two lists and create orders between every event in the first
-- -- list and to every event in the second list.
-- orders :: [EventIx] -> [EventIx] -> Constraint
-- orders as bs = And [ a ~> b | a <- as, b <- bs ]

-- -- | total, takes a list and create orders so that they the containing events
-- -- are total ordered.
-- totalOrder :: [EventIx] -> Constraint
-- totalOrder = And . totalOrder' Order

-- totalOrder' :: (a -> a -> b) -> [a] -> [b]
-- totalOrder' f = ap (zipWith $ f) tail

-- atThread :: Thread -> a -> IntMap a
-- atThread = IM.singleton . threadId

-- atRef :: Event.Ref -> a -> IntMap a
-- atRef = IM.singleton . (fromIntegral . Event.pointer)

-- -- Must Happen Before Analysis

-- data MhbData = MhbData
--   { _mhbForks  :: [EventIx]
--   , _mhbBegins :: [EventIx]
--   , _mhbEnds   :: [EventIx]
--   , _mhbJoins  :: [EventIx]
--   } deriving (Show)
-- makeLenses ''MhbData

-- instance Monoid MhbData where
--   mempty = MhbData mempty mempty mempty mempty
--   mappend a b =
--     MhbData
--       { _mhbForks = merge _mhbForks
--       , _mhbBegins = merge _mhbBegins
--       , _mhbEnds = merge _mhbEnds
--       , _mhbJoins = merge _mhbJoins
--       }
--    where merge f = on mappend f a b

-- newtype MHB = MHB
--   { mhb :: IntMap MhbData
--   } deriving (Show)

-- instance Monoid MHB where
--   mempty = MHB mempty
--   mappend = MHB ... IM.unionWith mappend `on` mhb

-- instance OrderAnalysis MHB where
--   fromEvent ix =
--     MHB $ case operation . cnt $ ix of
--       Begin   -> atThread t  $ withM mhbBegins ix
--       End     -> atThread t  $ withM mhbEnds ix
--       Fork t' -> atThread t' $ withM mhbForks ix
--       Join t' -> atThread t' $ withM mhbJoins ix
--       _ -> mempty
--     where t = thread . cnt $ ix

--   toConstraint =
--     foldMap inThread . mhb
--     where
--       inThread :: MhbData -> Constraint
--       inThread a =
--         mconcat
--           [ order mhbForks mhbBegins
--           , order mhbEnds mhbJoins
--           ]
--         where order = orders `on` (a ^.)


-- -- Sequential Consistency
-- newtype SC = SC
--   { cs :: IntMap [EventIx]
--   } deriving (Show)

-- instance Monoid SC where
--   mempty = SC mempty
--   mappend = SC ... IM.unionWith (<>) `on` cs

-- -- Sequential Consistency expects all envents to be represented in order
-- instance OrderAnalysis SC where
--   fromEvent ix =
--     SC $ atThread (thread . cnt $ ix) [ix]

--   toConstraint = foldMap totalOrder . cs

-- -- Lock Consistency
-- -- This analysis assumes that all locks are requested, acquired and released by
-- -- the same thread.


-- data LcType
--   = LcAcquire EventIx
--   | LcRelease EventIx
--   deriving (Show)

-- newtype LC =
--   LC { lc :: IntMap (IntMap [LcType]) }
--   deriving (Show)

-- instance Monoid LC where
--   mempty = LC mempty
--   mappend = LC ... IM.unionWith (IM.unionWith (<>)) `on` lc

-- type LcCollector = ([(EventIx, EventIx)], [EventIx])

-- instance OrderAnalysis LC where
--   fromEvent ix =
--     LC $ case operation . cnt $ ix of
--       Acquire ref -> append ref $ [LcAcquire ix]
--       Release ref -> append ref $ [LcRelease ix]
--       _ -> mempty
--     where
--       append ref = atRef ref . atThread (thread . cnt $ ix)

--   toConstraint = foldMap byObject . lc
--     where
--       byObject a =
--         And $ concat
--           [ lockOrder <$> pairs lockPairs
--           , orderRemainders <$> lockPairs <*> remainders
--           ]
--         where
--           (lockPairs, remainders) =
--             foldMap (collectLockPairs . byThread) a

--       byThread :: [LcType] -> LcCollector
--       byThread types =
--         L.foldl' collector ([],[]) types

--       collector :: LcCollector -> LcType -> LcCollector
--       collector (pairs, stack) (LcAcquire acq) =
--         (pairs, acq:stack)

--       collector (pairs, stack) (LcRelease rel) =
--         case stack of
--           acq:[] -> ((acq, rel):pairs, [])
--           -- ^ Ignore re-entrant locks
--           acq:ls -> (pairs, ls)
--           _ -> error "Can't release a lock that has not been acquired"

--       collectLockPairs (pairs, stack) =
--         (pairs, take 1 stack)

--       lockOrder ((a, r), (a', r')) =
--         Or [r ~> a', r' ~> a]

--       orderRemainders (_, rel) acq =
--         rel ~> acq

-- -- Read Write Consistency

-- data RwcData = RwcData
--   { _rwcReads :: [EventIx]
--   , _rwcWrites :: [EventIx]
--   } deriving (Show)
-- makeLenses ''RwcData

-- instance Monoid RwcData where
--   mempty = RwcData mempty mempty
--   mappend a b = RwcData
--     { _rwcReads = merge _rwcReads
--     , _rwcWrites = merge _rwcWrites
--     }
--     where merge f = f a <> f b

-- newtype RWC = RWC
--   { rwc :: M.Map Event.Location (M.Map Event.Value RwcData)
--   } deriving (Show)

-- instance Monoid RWC where
--   mempty = RWC mempty
--   mappend = RWC ... (M.unionWith (M.unionWith (<>))) `on` rwc

-- instance OrderAnalysis RWC where
--   fromEvent ix =
--     RWC $ case operation . cnt $ ix of
--        Read l v  -> M.singleton l $ M.singleton v $ withM rwcReads ix
--        Write l v -> M.singleton l $ M.singleton v $ withM rwcWrites ix
--        _ -> mempty

--   toConstraint =
--     foldMap byLocation . rwc
--     where
--       byLocation :: M.Map Event.Value RwcData -> Constraint
--       byLocation ls = foldMap (combine allWrites) ls
--         where
--           allWrites = foldMap (^. rwcWrites) ls
--       combine allWrites byValue =
--         if null (byValue ^. rwcWrites)
--         then And []
--         else And
--           [ Or
--             [ And $ w ~> r :
--               [ Or [ w' ~> w, r ~> w']
--               | w' <- allWrites, w' /= w ]
--             | w <- byValue ^. rwcWrites
--             , not $ cnt r !<= cnt w ]
--           | r <- byValue ^. rwcReads ]


-- data Linearize = Linearize
--   { _mhb :: MHB
--   , _sc :: SC
--   , _lc :: LC
--   , _rwc :: RWC
--   } deriving (Show)

-- instance Monoid Linearize where
--   mempty = Linearize mempty mempty mempty mempty
--   mappend a b = Linearize
--     { _mhb =  merge _mhb
--     , _sc  = merge _sc
--     , _lc  = merge _lc
--     , _rwc =  merge _rwc
--     }
--     where merge f = f a <> f b

-- instance OrderAnalysis Linearize where
--   fromEvent ix =
--     Linearize eh eh eh eh
--     where
--       eh :: OrderAnalysis a => a
--       eh = fromEvent ix
--   toConstraint =
--     mconcat . onAll [ toConstraint . _mhb
--                     , toConstraint . _sc
--                     , toConstraint . _lc
--                     , toConstraint . _rwc
--                     ]

-- -- Solve constraints
-- solveLIA :: Z3 a -> IO a
-- solveLIA s =
--   evalZ3With (Just QF_LIA) opts s
--   where
--     opts = opt "MODEL" True -- +? opt "MODEL_COMPLETION" True

-- toZ3 :: (EventIx -> AST) -> Constraint -> Z3 AST
-- toZ3 vars (And cs) =
--   mkAnd =<< mapM (toZ3 vars) cs
-- toZ3 vars (Or cs) =
--   mkOr =<< mapM (toZ3 vars) cs
-- toZ3 vars (Order a b) =
--   mkLt (vars a) (vars b)


-- linearize :: [Event] -> Constraint -> Z3 (Maybe [Event])
-- linearize events c = do
--   vars <- V.replicateM (length events) (mkFreshIntVar "O")
--   ast <- toZ3 ((V.!) vars . ident) c
--   assert ast
--   astToString ast

--   orders <- fmap (join . snd) $ withModel $ getSolution (V.toList vars)
--   case orders of
--     Just solution ->
--       return . Just $ map snd $ L.sort $ zip solution events
--     Nothing -> return Nothing

--   where
--     getSolution :: [AST] -> Model -> Z3 (Maybe [Integer])
--     getSolution args m =
--       sequence <$> mapM (evalInt m) args

-- -- Top level analyses

-- linearizeTotal' :: [Event] -> IO (Either String [Event])
-- linearizeTotal' events = do
--   let cons = toConstraint (fromEvents events :: Linearize)
--   sol <- solveLIA $ linearize events cons
--   return $ maybe (Left "Something went wrong") Right sol
