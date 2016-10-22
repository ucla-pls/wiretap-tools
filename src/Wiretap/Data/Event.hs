{-# LANGUAGE CPP, MagicHash #-}
module Wiretap.Data.Event where

import           Data.PartialOrder
import           Data.Word
import           Data.Bits
import           Data.Function (on)

import           Data.Binary
import           Data.Binary.Put
import           Data.Binary.Get
import qualified Data.Binary.Get.Internal as I

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Unsafe as BU


import           Test.QuickCheck hiding ((.&.), (.|.))

import GHC.Base
import           GHC.Int
import           GHC.Word

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
  { operation :: !Operation
  , thread    :: !Thread
  , order     :: !Int32
  } deriving (Show, Eq, Ord)

instance PartialOrder Event where
  cmp a b | thread a == thread b =
    Just $ on compare order a b
  cmp a b =
    Nothing


instance Binary Event where
  put (Event opr t o) = do
    put opr
    put t
    put o

  get =
    Event <$> get <*> get <*> getInt32be

instance Arbitrary Event where
  arbitrary = Event <$> arbitrary <*> arbitrary <*> arbitrary

prop_EventIsBinary = prop_isBinary :: Event -> Bool

newtype LogEvent = LogEvent
  { logOperation :: Operation
  } deriving (Eq, Show)

withThreadAndOrder :: LogEvent -> Thread -> Int32 -> Event
withThreadAndOrder opr t i = Event (logOperation opr) t i

fromEvent :: Event -> LogEvent
fromEvent = LogEvent . operation

instance Binary LogEvent where
  put = put . logOperation
  get = LogEvent <$> get

instance Arbitrary LogEvent where
  arbitrary = LogEvent <$> arbitrary

prop_LogEventIsBinary = prop_isBinary :: LogEvent -> Bool

newtype Ref = Ref
  { pointer :: Word32 }
  deriving (Show, Eq, Ord)

instance Binary Ref where
  put = put . pointer
  get = Ref <$> get

instance Arbitrary Ref where
  arbitrary = Ref <$> arbitrary

prop_RefIsBinary = prop_isBinary :: Ref -> Bool

data Location
  = Dynamic !Ref !Program.Field
  | Static !Program.Field
  | Array !Ref !Int32
  deriving (Show, Eq, Ord)

instance Binary Location where
  put (Array r i) = put r >> put i
  put (Static i) = putInt32be 0 >> put i
  put (Dynamic r i) = put r >> putInt32be (Program.fieldId i)
  get = {-# SCC get_location #-} do
    r <- get
    i <- getInt32be
    if pointer r == 0
      then return $ Static (Program.Field i)
      else return $ Array r (fromIntegral i)

-- TODO Add Dynamic references
instance Arbitrary Location where
  arbitrary = oneof
    [ Static <$> (Program.Field <$> arbitrary)
    , Array <$> arbitrary <*> arbitrary
    ]

prop_LocationIsBinary = prop_isBinary :: Location -> Bool

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
  = Synch Int32

  | Fork Thread
  | Join Thread

  | Request Ref
  | Acquire Ref
  | Release Ref

  | Read Location Value
  | Write Location Value

  | Begin
  | End
  deriving (Show, Eq, Ord)

instance Binary Operation where
  put o = case o of
    Synch i -> do
      putWord8 0
      putInt32be i

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
      putWord8 $ (getValueId v `shiftL` 4) .|. 6
      put l
      putValue v

    Write l v -> do
      putWord8 $ (getValueId v `shiftL` 4) .|. 7
      put l
      putValue v

    Begin ->
      putWord8 8

    End ->
      putWord8 9

  get = {-# SCC get_operation #-} do
    w <- {-# SCC get_word #-} getWord8
    getOperation w
    -- bs <- getLazyByteString (eventSize w)
    -- return $ runGet (innerGet w) bs


drawOperation :: Word8 -> MiniParser Operation
drawOperation w = do
  case w .&. 0x0f of
    0 -> Synch <$> drawInt32be
    1 -> Fork <$> drawThread
    2 -> Join <$> drawThread
    3 -> Request <$> drawRef
    4 -> Acquire <$> drawRef
    5 -> Release <$> drawRef
    6 -> {-# SCC get_operation_read #-} (Read <$> drawLocation <*> drawValue w)
    7 -> {-# SCC get_operation_write #-} (Write <$> drawLocation <*> drawValue w)
    8 -> return Begin
    9 -> return End


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

drawLocation :: MiniParser Location
drawLocation = do
    r <- drawRef
    i <- drawInt32be
    if pointer r == 0
      then return $ Static (Program.Field i)
      else return $ Array r (fromIntegral i)

drawRef :: MiniParser Ref
drawRef =
  Ref <$> drawWord32be

drawThread :: MiniParser Thread
drawThread =
  Thread . fromIntegral <$> drawInt32be


getOperation :: Word8 -> Get Operation
getOperation w =
  case w .&. 0x0f of
    0 -> Synch <$> getInt32be
    1 -> Fork <$> get
    2 -> Join <$> get
    3 -> Request <$> get
    4 -> Acquire <$> get
    5 -> Release <$> get
    6 -> {-# SCC get_operation_read #-} (Read <$> get <*> getValue w)
    7 -> {-# SCC get_operation_write #-} (Write <$> get <*> getValue w)
    8 -> return Begin
    9 -> return End

eventSize :: Word8 -> Int64
eventSize w =
  case w .&. 0x0f of
    6 -> 8 + valueSize w
    7 -> 8 + valueSize w
    8 -> 0
    9 -> 0
    a | 0 <= a && a <= 5 -> 4
{-# INLINE eventSize #-}

valueSize :: Word8 -> Int64
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
    ]

prop_OperationIsBinary = prop_isBinary :: Operation -> Bool

prop_isBinary :: (Binary a, Eq a) => a -> Bool
prop_isBinary t = (decode . encode) t == t
