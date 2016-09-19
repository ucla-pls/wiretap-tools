module Main where

import System.IO

import Control.Monad

import Wiretap.Data.Event
import Wiretap.Format.Binary

main :: IO ()
main = do
  ((Event t o i opr) : events) <- readEvents (Thread 0) stdin

  forM_ events print
