## ----------------------------------------------
## | Gimli Sponge <- public surface
## ----------------------------------------------
##
## Gimli in sponge mode: stream encryption, hashing and tags.
##
## The full implementation lives in `./gimli/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./gimli/gimli_sponge

export gimli_sponge

## ╭⟢ Public names

proc gimliTyrXof*(ks, ns, ms: openArray[uint8],
    outLen: int): seq[uint8] {.inline.} =
  ## Public name for the local Gimli XOF.
  result = gimliXof(ks, ns, ms, outLen)

proc gimliTyrTag*(ks, ns, ms: openArray[uint8],
    outLen: int): seq[uint8] {.inline.} =
  ## Public name for the local Gimli tag helper.
  result = gimliTag(ks, ns, ms, outLen)

proc gimliTyrStreamXor*(ks, ns, input: openArray[uint8]): seq[uint8] {.inline.} =
  ## Public name for the local Gimli stream-xor helper.
  result = gimliStreamXor(ks, ns, input)
