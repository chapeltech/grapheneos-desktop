{-# LANGUAGE ForeignFunctionInterface #-}
module NativeProbe (splitDesktop, checksum) where

import Control.Exception (SomeException, catch)
import Control.Monad (foldM)
import Foreign.C.Types (CInt(..))
import Foreign.Marshal.Array (pokeArray)
import Foreign.Ptr (Ptr, nullPtr)
import Data.Int (Int32)
import System.Mem (performGC)

-- This is an ABI/runtime probe, not a second implementation of Wonad policy.
-- Keep it independent of the compositor until the Android gates have passed.
splitDesktop :: Int32 -> Int32 -> Maybe [Int32]
splitDesktop width height
    | width < 2 || height < 1 = Nothing
    | otherwise = Just [0, 0, middle, height, middle, 0, width - middle, height]
  where middle = width `div` 2

checksum :: Int32 -> IO Int32
checksum count = foldM step 0 [1 .. count]
  where
    step acc i = do
        -- Exercise allocation and the runtime, not just a constant C ABI value.
        let value = sum [fromIntegral i :: Int .. fromIntegral i + 63]
        value `seq` pure ()
        if i `mod` 31 == 0 then performGC else pure ()
        pure ((acc + i) `mod` 65521)

foreign export ccall wonad_probe_layout :: Int32 -> Int32 -> Ptr Int32 -> IO CInt
wonad_probe_layout :: Int32 -> Int32 -> Ptr Int32 -> IO CInt
wonad_probe_layout width height output = catch run failed
  where
    run | output == nullPtr = pure (-1)
        | otherwise = case splitDesktop width height of
            Nothing -> pure (-1)
            Just boxes -> pokeArray output boxes >> pure 8
    failed :: SomeException -> IO CInt
    failed _ = pure (-2)

foreign export ccall wonad_probe_stress :: Int32 -> IO Int32
wonad_probe_stress :: Int32 -> IO Int32
wonad_probe_stress count
    | count < 0 || count > 4096 = pure (-1)
    | otherwise = checksum count `catch` failed
  where
    failed :: SomeException -> IO Int32
    failed _ = pure (-2)
