## ------------------------------------------
## | ChaCha20 <- public surface
## ------------------------------------------
##
## Stream cipher with a 12-byte nonce. The nonce must never repeat under one key.
##
## The full implementation lives in `./chacha/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./chacha/chacha20

export chacha20

## ╭⟢ Public names

proc chacha20TyrXor*(key, nonce: openArray[byte],
    input: openArray[byte]): seq[byte] {.inline.} =
  ## Public name for the local ChaCha20 xor helper.
  result = chacha20Xor(key, nonce, input)

proc chacha20TyrStream*(key, nonce: openArray[byte], length: int,
    initialCounter: uint32 = 0'u32): seq[byte] {.inline.} =
  ## Public name for the local ChaCha20 keystream helper.
  result = chacha20Stream(key, nonce, length, initialCounter)
