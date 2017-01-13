{-# LANGUAGE RankNTypes #-}
module Pipes.Missing where

import           Control.Monad
import           Pipes
import qualified Pipes.Prelude as P


done :: Monad m
  => a
  -> Producer' (Either a b) m r'
done a =
  forever $ do
    yield $ Left a

done' :: Monad m
  => Producer' (Maybe b) m r'
done' =
  forever $ do
    yield Nothing

type Finite b m r = forall r'. Producer (Either r b) m r'
type Finite' b m = forall r'. Producer (Maybe b) m r'

{-| finite takes a pipe that ends and runs it forever.

It's up to the user to prove that the producer really is finite

This makes it
easier to figure out if the underlying pipe has been closed or not.
-}
finite :: Monad m
  => Producer b m r
  -> Finite b m r
finite p = do
  r <- p >-> P.map Right
  done r

{-| finite' is the same thing but discards the return value. -}
finite' :: Monad m
  => Producer b m ()
  -> Finite' b m
finite' p = do
  p >-> P.map Just
  done'

{-| end runs a proven finite pipe to the end,
    yielding the return value
-}
end :: Monad m
  => Pipe (Either r b) b m r
end = do
  a <- await
  case a of
    Right b' -> yield b' >> end
    Left r   -> return r

{-| end' is the same as end' but without return value -}
end' :: Monad m
  => Pipe (Maybe b) b m ()
end' = do
  a <- await
  case a of
    Just b' -> yield b' >> end'
    Nothing -> return ()


merge :: Monad m
  => (r1 -> r2 -> r)
  -> (b -> b -> Ordering)
  -> Producer b m r1
  -> Producer b m r2
  -> Producer b m r
merge f cmp ax bx =
  lift (go <$> next ax <*> next bx) >>= id
  where
    go a b =
      case (a, b) of
        (Right a', Right b') ->
          case fst a' `cmp` fst b' of
            GT        -> goB a  b'
            _ -> goA a' b
        (Right a', _) ->
          goA a' b
        (_, Right b') ->
          goB a b'
        (Left r1, Left r2) ->
          return $ f r1 r2
    goA (e, p) b = yield e >> lift (next p) >>= flip go b
    goB a (e, p) = yield e >> lift (next p) >>= go a

merge' :: Monad m
  => (b -> b -> Ordering)
  -> Producer b m r1
  -> Producer b m r2
  -> Producer b m ()
merge' =
  merge (const $ const ())

scan'
  :: Monad m
  => (x -> a -> (x, b))
  -> x
  -> Pipe a b m r
scan' step begin = go begin
  where
    go x = do
      a <- await
      let (x', b) = step x a
      yield b
      go $! x'

{-| Every subpipe is created from the SubProxy, which is esentially just a proxy
with a proxy monad.
-}
type SubProducer' x' x y' y b m r =
  Producer' b (Proxy x' x y' y m) r

type SubROProducer' a' b m r =
  forall t t'. SubProducer' () a' t t' b m r

type SubWOProducer' b' b m r =
  forall t t'. SubProducer' t t' () b' b m r

type SubRWProducer' a' b' b m r =
  SubProducer' () a' () b' b m r

type SubConsumer' x' x y' y a m r =
  Consumer' a (Proxy x' x y' y m ) r

type SubROConsumer' a' a m r =
  forall t t'. SubConsumer' () a' t t' a m r

type SubWOConsumer' b' a m r =
  forall t t'. SubConsumer' t t' () b' a m r

type SubRWConsumer' a' b' a m r =
  SubConsumer' () a' () b' a m r

type SubEffect' x' x y' y m r =
    Effect' (Proxy x' x y' y m) r

type SubROEffect' a' m r =
  forall t t'. SubEffect' () a' t t' m r

type SubWOEffect' b' m r =
  forall t t'. SubEffect' t t' () b' m r

type SubRWEffect' a' b' m r =
  SubEffect' () a' () b' m r

type SubPipe a' b' a b m = Pipe a b (Pipe a' b' m)

type SubEffect a' b' m = Effect (Pipe a' b' m)

type SubProducer a' b' b m = Producer b (Pipe a' b' m)

type SubConsumer a' b' b m = Producer b (Pipe a' b' m)


receive :: Monad m
  => SubROEffect' a m a
receive = lift await

send :: Monad m
  => b -> SubWOEffect' b m ()
send = lift . yield

recover :: Monad m
  => SubROProducer' a a m ()
recover = do
  x <- receive
  yield x

dispatch :: Monad m
  => SubWOConsumer' b b m ()
dispatch = do
  x <- await
  send x

passthrough :: Monad m
  => SubRWEffect' a a m ()
passthrough = do
  lift $ await >>= yield

sample :: Monad m
  => SubRWProducer' a a a m ()
sample = do
  x <- lift $ do
    x <- await
    yield x
    return x
  yield x

recoverAll :: Monad m
  => SubROProducer' b b m r
recoverAll =
  forever recover

dispatchAll :: Monad m
  => SubWOConsumer' b b m r
dispatchAll =
  forever dispatch

{-| take' recovers n elements from the super pipe and
put it in the sub pipe.
-}

take' :: Monad m
  => Int -> SubROProducer' a a m ()
take' n = do
  replicateM_ n recover

{-| takeEvery recovers every n'th element form the super pipe
-}
takeEvery :: Monad m
  => Int -> SubRWProducer' a a a m r
takeEvery n = do
  replicateM_ (n - 1) passthrough
  recover
  takeEvery n

{-| tee' takes every element from the super pipe into the
  sub pipe, while allowing the elements to pass-through . -}

tee' :: Monad m
  => SubRWProducer' a a a m ()
tee' =
  forever sample

{-| copy' takes every element from the super pipe into the
  sub pipe, while allowing the elements to pass-through.

  The copy ends when the super pipe runs out of real values.
-}
copy' :: Monad m
  => SubRWProducer' (Maybe a) a a m ()
copy' = do
  a <- receive
  case a of
    Just a' -> do
      yield a'
      send a'
      copy'
    Nothing ->
      return ()

pfold :: Monad m
  => (b -> a -> b)
  -> b
  -> Producer a m ()
  -> Producer a m b
pfold f begin p =
  finite' p >-> subFold f begin

{-| subFold is a fold in a sub pipe, this enable you to
fold over a stream without consuming the values. A subfold
requires that the pipe eventually runs out of values.
-}
subFold :: Monad m
  => (b -> a -> b)
  -> b
  -> Pipe (Maybe a) a m b
subFold f begin = do
  P.fold f begin id copy'

subEffect :: Monad m
  => SubEffect a' b' m r
  -> Pipe a' b' m r
subEffect = runEffect

joinProducer :: Monad m
  => SubProducer a' b' b' m r
  -> Pipe a' b' m r
joinProducer sp =
  subEffect $ sp >-> dispatchAll

{-| takeWhileS extract elements of the super pipe until the predicate
returns false. The first false element is return as it has already
taken from the super pipe.
-}
takeWhileS :: Monad m
  => (a -> Bool) -> SubROProducer' a a m a
takeWhileS f = do
  a <- receive
  if f a
    then do
      yield a
      takeWhileS f
    else return a

asList :: Monad m
  => SubProducer' x' x y' y a m ()
  -> Proxy x' x y' y m [a]
asList = P.toListM

asList' :: Monad m
  => SubProducer' x' x y' y a m r
  -> Proxy x' x y' y m ([a], r)
asList' = P.toListM'

count :: Monad m
  => Pipe (Maybe a) a m Int
count =
  subFold (\b _ -> b + 1) 0

pcount :: Monad m
  => Producer a m () -> Producer a m Int
pcount p =
  finite' p >-> count

test :: MonadIO m
  => Pipe (Maybe String) String m ()
test = do
  yield $ "Hello World"
  c <- count
  yield $ "Count " ++ show c

testIt :: IO ()
testIt = runEffect $
   finite' (each ([1, 2, 3, 4, 5] :: [Int]) >-> P.show)
   >-> test
   >-> P.print
