## -------------------------------------------------------------------
## Falcon Randomness <- pure-Nim randombytes hook for Falcon internals
## -------------------------------------------------------------------

import ../../../random
import ./util

type
  FalconRandombytesCallback* = proc (random_array: ptr uint8,
    bytes_to_read: csize_t) {.cdecl.}

var falconRandombytesCallback {.threadvar.}: FalconRandombytesCallback

proc falconSetRandombytesCallback*(cb: FalconRandombytesCallback) =
  falconRandombytesCallback = cb

proc falconClearRandombytesCallback*() =
  falconRandombytesCallback = nil

proc falconRandomBytesInto*(dst: var openArray[byte]) =
  if dst.len == 0:
    return
  if falconRandombytesCallback != nil:
    falconRandombytesCallback(cast[ptr uint8](unsafeAddr dst[0]), csize_t(dst.len))
    return
  var rnd = cryptoRandomBytes(dst.len)
  copyBytes(dst, 0, rnd)
  clearBytes(rnd)

proc falconRandomBytes*(length: int): seq[byte] =
  if length < 0:
    raise newException(ValueError, "Falcon random byte length must be >= 0")
  result = newSeq[byte](length)
  falconRandomBytesInto(result)
