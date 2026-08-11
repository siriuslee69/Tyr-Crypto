## ----------------------------------------
## | BLAKE3 <- public surface
## ----------------------------------------
##
## Fast tree-based hash. Also does keyed mode and key derivation.
##
## The full implementation lives in `./blake3/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./blake3/blake3

export blake3

## ╭⟢ Public names
##
## `blake3Hash` is the internal name the rest of Tyr uses. `blake3TyrHash`
## is the same code under the name other repos call, chosen so it cannot
## collide with a library-backed BLAKE3 imported alongside it.

proc blake3TyrHash*(input: openArray[byte],
    outLen: int = outLenDefault): seq[byte] {.inline.} =
  ## Public name for the local BLAKE3 hash.
  result = blake3Hash(input, outLen)

proc blake3TyrKeyedHash*(key, input: openArray[byte],
    outLen: int = outLenDefault): seq[byte] {.inline.} =
  ## Public name for the local keyed BLAKE3 hash.
  result = blake3KeyedHash(key, input, outLen)
