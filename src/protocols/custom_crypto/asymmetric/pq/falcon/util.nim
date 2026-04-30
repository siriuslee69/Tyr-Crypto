## ------------------------------------------------------------
## Falcon Util <- byte helpers and secret-clearing support
## ------------------------------------------------------------

import std/[typetraits, volatile]

{.push boundChecks: off.}

proc mkn*(logn: int): int {.inline.} =
  1 shl logn

proc clearBytes*(A: var openArray[byte]) {.raises: [].} =
  if A.len > 0:
    zeroMem(addr A[0], A.len)

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

proc secureClearBytes*(A: var openArray[byte]) {.raises: [].} =
  if A.len > 0:
    secureZeroMem(addr A[0], A.len)

proc clearSeqData*[T](A: var seq[T]) {.raises: [].} =
  if A.len > 0:
    zeroMem(addr A[0], A.len * sizeof(T))

proc secureClearSeqData*[T](A: var seq[T]) {.raises: [].} =
  if A.len > 0:
    secureZeroMem(addr A[0], A.len * sizeof(T))

proc clearPlainData*[T](x: var T) {.raises: [].} =
  when supportsCopyMem(T):
    zeroMem(addr x, sizeof(T))
  else:
    {.error: "clearPlainData requires supportsCopyMem(T)".}

proc clearSensitivePlainData*[T](x: var T) {.raises: [].} =
  when supportsCopyMem(T):
    secureZeroMem(addr x, sizeof(T))
  else:
    {.error: "clearSensitivePlainData requires supportsCopyMem(T)".}

proc copyBytes*(dst: var openArray[byte], dstOffset: int, src: openArray[byte]) {.inline, raises: [].} =
  var
    i: int = 0
  while i < src.len:
    dst[dstOffset + i] = src[i]
    i = i + 1

proc appendBytes*(dst: var seq[byte], src: openArray[byte]) =
  let start = dst.len
  dst.setLen(start + src.len)
  if src.len > 0:
    copyMem(addr dst[start], unsafeAddr src[0], src.len)

proc load64Le*(src: openArray[byte], offset: int = 0): uint64 {.inline.} =
  uint64(src[offset + 0]) or
  (uint64(src[offset + 1]) shl 8) or
  (uint64(src[offset + 2]) shl 16) or
  (uint64(src[offset + 3]) shl 24) or
  (uint64(src[offset + 4]) shl 32) or
  (uint64(src[offset + 5]) shl 40) or
  (uint64(src[offset + 6]) shl 48) or
  (uint64(src[offset + 7]) shl 56)

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
