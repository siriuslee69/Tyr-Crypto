## ---------------------------------------
## | SHA-3 <- public surface
## ---------------------------------------
##
## Keccak sponge hash, plus the SHAKE extendable-output functions.
##
## The full implementation lives in `./sha3/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./sha3/sha3

export sha3

## ╭⟢ Public names

proc sha3TyrHash*(input: openArray[byte],
    outLen: int = 32): seq[byte] {.inline.} =
  ## Public name for the local SHA3 hash.
  result = sha3Hash(input, outLen)

proc shake256Tyr*(input: openArray[byte], outLen: int): seq[byte] {.inline.} =
  ## Public name for the local SHAKE256 XOF.
  result = shake256(input, outLen)

proc shake128Tyr*(input: openArray[byte], outLen: int): seq[byte] {.inline.} =
  ## Public name for the local SHAKE128 XOF.
  result = shake128(input, outLen)
