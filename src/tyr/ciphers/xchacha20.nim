## -------------------------------------------
## | XChaCha20 <- public surface
## -------------------------------------------
##
## ChaCha20 with a 24-byte nonce, long enough to pick at random safely.
##
##   xchacha20Xor(key, nonce, msg)    the standard, HChaCha20 subkey
##   xchacha20b3Xor / xchacha20giXor  same cipher, subkey from BLAKE3 or
##                                    Gimli instead. Not interoperable.
##
## `./chacha/xchacha20_derive` explains exactly what the variants do and
## do not remove - read it before picking one.
##
## The full implementation lives in `./chacha/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./chacha/xchacha20
import ./chacha/xchacha20_derive

export xchacha20
export xchacha20_derive

## ╭⟢ Public names

proc hchacha20Tyr*(key, nonce: openArray[byte]): array[32, byte] {.inline.} =
  ## Public name for the local HChaCha20 core.
  result = hchacha20(key, nonce)

proc xchacha20TyrXor*(key, nonce: openArray[byte],
    input: openArray[byte]): seq[byte] {.inline.} =
  ## Public name for the local XChaCha20 xor helper.
  result = xchacha20Xor(key, nonce, input)

proc xchacha20TyrStream*(key, nonce: openArray[byte], length: int,
    initialCounter: uint32 = 0'u32): seq[byte] {.inline.} =
  ## Public name for the local XChaCha20 keystream helper.
  result = xchacha20Stream(key, nonce, length, initialCounter)
