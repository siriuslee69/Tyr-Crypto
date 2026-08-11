## ------------------------------------------------------------
## Falcon Util <- byte helpers and secret-clearing support
## ------------------------------------------------------------

import std/[typetraits, volatile]

{.push boundChecks: off.}

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; canonical byte and polynomial encoding rules for `mkn`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc mkn*(logn: int): int {.inline.} =
  1 shl logn

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; canonical byte and polynomial encoding rules for `clearBytes`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc clearBytes*(A: var openArray[byte]) {.raises: [].} =
  if A.len > 0:
    zeroMem(addr A[0], A.len)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; canonical byte and polynomial encoding rules for `secureZeroMem`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc secureZeroMem*(p: pointer, l: int) {.raises: [].} =
  var
    i: int = 0
    B: ptr UncheckedArray[byte]
  if p.isNil or l <= 0:
    return
  B = cast[ptr UncheckedArray[byte]](p)
  while i < l:
    volatileStore(addr B[i], 0'u8)
    i = i + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; canonical byte and polynomial encoding rules for `secureClearBytes`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc secureClearBytes*(A: var openArray[byte]) {.raises: [].} =
  if A.len > 0:
    secureZeroMem(addr A[0], A.len)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; canonical byte and polynomial encoding rules for `clearSeqData`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc clearSeqData*[T](A: var seq[T]) {.raises: [].} =
  if A.len > 0:
    zeroMem(addr A[0], A.len * sizeof(T))

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; canonical byte and polynomial encoding rules for `secureClearSeqData`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc secureClearSeqData*[T](A: var seq[T]) {.raises: [].} =
  if A.len > 0:
    secureZeroMem(addr A[0], A.len * sizeof(T))

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; canonical byte and polynomial encoding rules for `clearPlainData`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc clearPlainData*[T](x: var T) {.raises: [].} =
  when supportsCopyMem(T):
    zeroMem(addr x, sizeof(T))
  else:
    {.error: "clearPlainData requires supportsCopyMem(T)".}

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; canonical byte and polynomial encoding rules for `clearSensitivePlainData`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc clearSensitivePlainData*[T](x: var T) {.raises: [].} =
  when supportsCopyMem(T):
    secureZeroMem(addr x, sizeof(T))
  else:
    {.error: "clearSensitivePlainData requires supportsCopyMem(T)".}

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; canonical byte and polynomial encoding rules for `copyBytes`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc copyBytes*(dst: var openArray[byte], dstOffset: int, src: openArray[byte]) {.inline, raises: [].} =
  var
    i: int = 0
  while i < src.len:
    dst[dstOffset + i] = src[i]
    i = i + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; canonical byte and polynomial encoding rules for `appendBytes`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc appendBytes*(dst: var seq[byte], src: openArray[byte]) =
  var start = dst.len
  dst.setLen(start + src.len)
  if src.len > 0:
    copyMem(addr dst[start], unsafeAddr src[0], src.len)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; canonical byte and polynomial encoding rules for `load64Le`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc load64Le*(src: openArray[byte], offset: int = 0): uint64 {.inline.} =
  uint64(src[offset + 0]) or
  (uint64(src[offset + 1]) shl 8) or
  (uint64(src[offset + 2]) shl 16) or
  (uint64(src[offset + 3]) shl 24) or
  (uint64(src[offset + 4]) shl 32) or
  (uint64(src[offset + 5]) shl 40) or
  (uint64(src[offset + 6]) shl 48) or
  (uint64(src[offset + 7]) shl 56)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; canonical byte and polynomial encoding rules for `store64Le`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc store64Le*(dst: var openArray[byte], value: uint64, offset: int = 0) {.inline.} =
  dst[offset + 0] = byte(value)
  dst[offset + 1] = byte(value shr 8)
  dst[offset + 2] = byte(value shr 16)
  dst[offset + 3] = byte(value shr 24)
  dst[offset + 4] = byte(value shr 32)
  dst[offset + 5] = byte(value shr 40)
  dst[offset + 6] = byte(value shr 48)
  dst[offset + 7] = byte(value shr 56)

{.pop.}
