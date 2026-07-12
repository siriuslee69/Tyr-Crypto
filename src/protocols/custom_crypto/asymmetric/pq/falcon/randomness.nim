## -------------------------------------------------------------------
## Falcon Randomness <- pure-Nim randombytes hook for Falcon internals
## -------------------------------------------------------------------

import ../../../random
import ./util

type
  FalconRandombytesCallback* = proc (random_array: ptr uint8,
    bytes_to_read: csize_t) {.cdecl.}

var falconRandombytesCallback {.threadvar.}: FalconRandombytesCallback

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; random-source and deterministic KAT generation rules for `falconSetRandombytesCallback`; pitfall: use deterministic generation only for KAT replay and system entropy in production.
proc falconSetRandombytesCallback*(cb: FalconRandombytesCallback) =
  falconRandombytesCallback = cb

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; random-source and deterministic KAT generation rules for `falconClearRandombytesCallback`; pitfall: use deterministic generation only for KAT replay and system entropy in production.
proc falconClearRandombytesCallback*() =
  falconRandombytesCallback = nil

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; random-source and deterministic KAT generation rules for `falconRandomBytesInto`; pitfall: use deterministic generation only for KAT replay and system entropy in production.
proc falconRandomBytesInto*(dst: var openArray[byte]) =
  if dst.len == 0:
    return
  if falconRandombytesCallback != nil:
    falconRandombytesCallback(cast[ptr uint8](unsafeAddr dst[0]), csize_t(dst.len))
    return
  var
    rnd: seq[byte] = cryptoRandomBytes(dst.len)
  copyBytes(dst, 0, rnd)
  secureClearBytes(rnd)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; random-source and deterministic KAT generation rules for `falconRandomBytes`; pitfall: use deterministic generation only for KAT replay and system entropy in production.
proc falconRandomBytes*(length: int): seq[byte] =
  if length < 0:
    raise newException(ValueError, "Falcon random byte length must be >= 0")
  result = newSeq[byte](length)
  falconRandomBytesInto(result)
