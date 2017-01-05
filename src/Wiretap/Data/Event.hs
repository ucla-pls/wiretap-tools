{-# LANGUAGE CPP, MagicHash #-}
module Wiretap.Data.Event where

import           Data.PartialOrder
import           Data.Word
import           Data.Bits
import           Data.Function (on)

import           Numeric

import           Data.Binary
import           Data.Binary.Put
import           Data.Binary.Get

import           Test.QuickCheck hiding ((.&.), (.|.))

import           GHC.Int

import qualified Wiretap.Data.Program as Program
import           Wiretap.Data.MiniParser as Program


-- The dynamic information of the program is represented here.

newtype Thread = Thread
  { threadId :: Int32
  } deriving (Show, Eq, Ord)

instance Binary Thread where
  put = putInt32be . threadId
  get = Thread <$> getInt32be

instance Arbitrary Thread where
  arbitrary = Thread <$> arbitrary

prop_ThreadIsBinary = prop_isBinary :: Thread -> Bool

data Event = Event
  { thread    :: !Thread
  , order     :: !Int32
  , operation :: !Operation
  } deriving (Show, Eq, Ord)

instance PartialOrder Event where
  cmp a b | thread a == thread b =
    Just $ on compare order a b
  cmp a b =
    Nothing

instance Binary Event where
  put (Event t o opr) = do
    put t
    put o
    put opr

  get =
    Event <$> get <*> getInt32be <*> get

instance Arbitrary Event where
  arbitrary = Event <$> arbitrary <*> arbitrary <*> arbitrary

instruction :: Program.Program -> Event -> IO Program.Instruction
instruction p e =
  Program.findInstruction p (threadId $ thread e) (order e)

prop_EventIsBinary :: Event -> Bool
prop_EventIsBinary = prop_isBinary

newtype LogEvent = LogEvent
  { logOperation :: Operation
  } deriving (Eq, Show)

withThreadAndOrder :: LogEvent -> Thread -> Int32 -> Event
withThreadAndOrder opr t i = Event t i (logOperation opr)

fromEvent :: Event -> LogEvent
fromEvent = LogEvent . operation

instance Binary LogEvent where
  put = put . logOperation
  get = LogEvent <$> get

instance Arbitrary LogEvent where
  arbitrary = LogEvent <$> arbitrary

prop_LogEventIsBinary :: LogEvent -> Bool
prop_LogEventIsBinary = prop_isBinary

newtype Ref = Ref
  { pointer :: Word32 }
  deriving (Show, Eq, Ord)

instance Binary Ref where
  put = put . pointer
  get = Ref <$> get

instance Arbitrary Ref where
  arbitrary = Ref <$> arbitrary

prop_RefIsBinary :: Ref -> Bool
prop_RefIsBinary = prop_isBinary

data Location
  = Dynamic !Ref !Program.Field
  | Static !Program.Field
  | Array !Ref !Int32
  deriving (Show, Eq, Ord)

ref :: Location -> Maybe Ref
ref l =
  case l of
    Dynamic r _ -> Just r
    Array r _ -> Just r
    otherwise -> Nothing

instance Binary Location where
  put (Array r i) = put r >> put i
  put (Static i) = putInt32be 0 >> put i
  put (Dynamic r i) = put r >> putInt32be (Program.fieldId i)
  get = getArrayLocation

getArrayLocation = do
  r <- get
  i <- getInt32be
  return $ Array r (fromIntegral i)

getFieldLocation = do
  r <- get
  f <- Program.Field <$> getInt32be
  if pointer r == 0
    then return $ Static f
    else return $ Dynamic r f

-- TODO Add Dynamic references
instance Arbitrary Location where
  arbitrary = oneof
    [ Static <$> (Program.Field <$> arbitrary)
    , Array <$> arbitrary <*> arbitrary
    , Dynamic <$> arbitrary <*> (Program.Field <$> arbitrary)
    ]

prop_LocationIsBinary :: Location -> Bool
prop_LocationIsBinary = prop_isBinary

data Value
  = Byte !Word8
  | Char !Word8
  | Short !Word16
  | Integer !Word32
  | Long !Word64
  | Float !Word32
  | Double !Word64
  | Object !Word32
  deriving (Show, Eq, Ord)

data ValueType
  = VByte
  | VChar
  | VShort
  | VInteger
  | VLong
  | VFloat
  | VDouble
  | VObject
  deriving (Show, Eq, Ord, Enum)

putValue :: Value -> Put
putValue (Byte w) = put w;
putValue (Char w) = put w;
putValue (Short w) = put w;
putValue (Integer w) = put w;
putValue (Long w) = put w;
putValue (Float w) = put w;
putValue (Double w) = put w;
putValue (Object w) = put w;
{-# INLINE putValue #-}

getValueType :: Word8 -> ValueType
getValueType w =
  toEnum . fromIntegral $ ((w .&. 0xf0) `shiftR` 4)
{-# INLINE getValueType #-}

valueType :: Value -> ValueType
valueType v =
  case v of
    Byte _    -> VByte
    Char _    -> VChar
    Short _   -> VShort
    Integer _ -> VInteger
    Long _    -> VLong
    Float _   -> VFloat
    Double _  -> VDouble
    Object _  -> VObject
{-# INLINE valueType #-}

getValueId :: Value -> Word8
getValueId = fromIntegral . fromEnum . valueType
{-# INLINE getValueId #-}

getValue :: Word8 -> Get Value
getValue w =
  {-# SCC get_value #-}
  case getValueType w of
    VByte    -> Byte <$> get
    VChar    -> Char <$> get
    VShort   -> Short <$> get
    VInteger -> Integer <$> get
    VLong    -> Long <$> get
    VFloat   -> Float <$> get
    VDouble  -> Double <$> get
    VObject  -> Object <$> get
{-# INLINE getValue #-}

instance Arbitrary Value where
  arbitrary = oneof
    [ Byte <$> arbitrary
    , Char <$> arbitrary
    , Short <$> arbitrary
    , Integer <$> arbitrary
    , Long <$> arbitrary
    , Float <$> arbitrary
    , Double <$> arbitrary
    , Object <$> arbitrary
    ]

data Operation
  = Synch Int

  | Fork Thread
  | Join Thread

  | Request Ref
  | Acquire Ref
  | Release Ref

  | Begin
  | End
  | Branch

  | Read Location Value
  | Write Location Value

  deriving (Show, Eq, Ord)

instance Binary Operation where
  put o = case o of
    Synch i -> do
      putWord8 0
      putInt32be $ fromIntegral i

    Fork t -> do
      putWord8 1
      put t

    Join t -> do
      putWord8 2
      put t

    Request r -> do
      putWord8 3
      put r

    Acquire r -> do
      putWord8 4
      put r

    Release r -> do
      putWord8 5
      put r

    Read l v -> do
      let idx = case l of Array _ _ -> 14; _ -> 12
      putWord8 $ (getValueId v `shiftL` 4) .|. idx
      put l
      putValue v

    Write l v -> do
      let idx = case l of Array _ _ -> 15; _ -> 13
      putWord8 $ (getValueId v `shiftL` 4) .|. idx
      put l
      putValue v

    Begin ->
      putWord8 6

    End ->
      putWord8 7

    Branch ->
      putWord8 8

  get = {-# SCC get_operation #-} do
    w <- {-# SCC get_word #-} getWord8
    getOperation w
    -- bs <- getLazyByteString (eventSize w)
    -- return $ runGet (innerGet w) bs

-- parseOperation :: Word8 -> MP Operation
-- parseOperation w bs i = --{-# SCC parseOperation #-}
--   case w .&. 0x0f of
--     0 -> Synch . fromIntegral <$> parseInt32be bs i
--     1 -> Fork <$> parseThread bs i
--     2 -> Join <$> parseThread bs i
--     3 -> Request <$> parseRef bs i
--     4 -> Acquire <$> parseRef bs i
--     5 -> Release <$> parseRef bs i
--     6 ->
--       let (i', l) = parseLocation bs i in
--       Read l <$> parseValue w bs i'
--     7 ->
--       let (i', l) = parseLocation bs i in
--       Write l <$> parseValue w bs i'
--     8 -> (i, Begin)
--     9 -> (i, End)
--     _ -> error $ "Unknown operation '" ++ showHex (fromIntegral w) "'"
-- {-# INLINEABLE parseOperation #-}

-- drawOperation :: Word8 -> MiniParser Operation
-- drawOperation w = {-# SCC drawOperation #-}
--   case w .&. 0x0f of
--     0 -> Synch . fromIntegral <$> drawInt32be
--     1 -> Fork <$> drawThread

--     3 -> Request <$> drawRef
--     4 -> Acquire <$> drawRef
--     5 -> Release <$> drawRef
--     6 -> Read <$> drawLocation <*> drawValue w
--     7 -> Write <$> drawLocation <*> drawValue w
--     8 -> return Begin
--     9 -> return End
--     _ -> error $ "Unknown operation '" ++ showHex w "'"
-- {-# INLINEABLE drawOperation #-}

drawValue :: Word8 -> MiniParser Value
drawValue w =
  case getValueType w of
    VByte    -> Byte <$> drawWord8
    VChar    -> Char <$> drawWord8
    VShort   -> Short <$> drawWord16be
    VInteger -> Integer <$> drawWord32be
    VLong    -> Long <$> drawWord64be
    VFloat   -> Float <$> drawWord32be
    VDouble  -> Double <$> drawWord64be
    VObject  -> Object <$> drawWord32be
{-# INLINEABLE drawValue #-}

parseValue :: Word8 -> MP Value
parseValue w bs i =
  case getValueType w of
    VByte    -> Byte <$> parseWord8 bs i
    VChar    -> Char <$> parseWord8 bs i
    VShort   -> Short <$> parseWord16be bs i
    VInteger -> Integer <$> parseWord32be bs i
    VLong    -> Long <$> parseWord64be bs i
    VFloat   -> Float <$> parseWord32be bs i
    VDouble  -> Double <$> parseWord64be bs i
    VObject  -> Object <$> parseWord32be bs i
{-# INLINEABLE parseValue #-}

drawLocation :: MiniParser Location
drawLocation = do
    w <- drawWord32be
    i <- drawInt32be
    if w == 0
      then return $ Static (Program.Field i)
      else return $ Array (Ref w) (fromIntegral i)
{-# INLINE drawLocation #-}

parseLocation :: MP Location
parseLocation bs i =
    if w == 0
      then Static . Program.Field <$> n
      else Array (Ref w) . fromIntegral <$> n
    where
      n = parseInt32be bs i'
      (i', w) = parseWord32be bs i
{-# INLINE parseLocation #-}

parseRef :: MP Ref
parseRef bs i =
  Ref <$> parseWord32be bs i
{-# INLINE parseRef #-}

drawRef :: MiniParser Ref
drawRef =
  Ref <$> drawWord32be
{-# INLINE drawRef #-}

parseThread :: MP Thread
parseThread bs i =
  Thread . fromIntegral <$> parseInt32be bs i
{-# INLINE parseThread #-}

drawThread :: MiniParser Thread
drawThread =
  Thread . fromIntegral <$> drawInt32be
{-# INLINE drawThread #-}

getOperation :: Word8 -> Get Operation
getOperation w =
  case w .&. 0x0f of
    0 -> Synch . fromIntegral <$> getInt32be
    1 -> Fork <$> get
    2 -> Join <$> get
    3 -> Request <$> get
    4 -> Acquire <$> get
    5 -> Release <$> get
    6 -> return Begin
    7 -> return End
    8 -> return Branch
    12 -> Read <$> getFieldLocation <*> getValue w
    13 -> Write <$> getFieldLocation <*> getValue w
    14 -> Read <$> getArrayLocation <*> getValue w
    15 -> Write <$> getArrayLocation <*> getValue w
    a -> error $ "Unknown event '" ++ showHex a "'"

eventSize :: Word8 -> Int
eventSize w =
  case w .&. 0x0f of
    6 -> 8 + valueSize w
    7 -> 8 + valueSize w
    8 -> 0
    9 -> 0
    a | 0 <= a && a <= 5 -> 4
    a -> error $ "Unknown eventSize '" ++ showHex a "'"
{-# INLINE eventSize #-}

valueSize :: Word8 -> Int
valueSize w =
  case (w .&. 0xf0) `shiftR` 4 of
    0 -> 1
    1 -> 1
    2 -> 2
    3 -> 4
    4 -> 8
    5 -> 4
    6 -> 8
    7 -> 4
    a -> error $ "Bad event value " ++ show a
{-# INLINE valueSize #-}

instance Arbitrary Operation where
  arbitrary = oneof
    [ Synch <$> arbitrary
    , Fork <$> arbitrary
    , Join <$> arbitrary
    , Request <$> arbitrary
    , Acquire <$> arbitrary
    , Release <$> arbitrary
    , Read <$> arbitrary <*> arbitrary
    , Write <$> arbitrary <*> arbitrary
    , return Begin
    , return End
    , return Branch
    ]

prop_OperationIsBinary :: Operation -> Bool
prop_OperationIsBinary = prop_isBinary

prop_isBinary :: (Binary a, Eq a) => a -> Bool
prop_isBinary t = (decode . encode) t == t
