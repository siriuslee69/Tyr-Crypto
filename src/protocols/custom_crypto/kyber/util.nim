## -----------------------------------------------------------------
## Kyber Utilities <- little-endian helpers and byte-sequence helpers
## -----------------------------------------------------------------

import std/[typetraits, volatile]

{.push boundChecks: off.}

proc load24Le*(A: openArray[byte], o: int = 0): uint32 {.inline.} =
  ## Load 3 bytes in little-endian order.
  result =
    uint32(A[o]) or
    (uint32(A[o + 1]) shl 8) or
    (uint32(A[o + 2]) shl 16)

proc load32Le*(A: openArray[byte], o: int = 0): uint32 {.inline.} =
  ## Load 4 bytes in little-endian order.
  result =
    uint32(A[o]) or
    (uint32(A[o + 1]) shl 8) or
    (uint32(A[o + 2]) shl 16) or
    (uint32(A[o + 3]) shl 24)

proc appendBytes*(S: var seq[byte], A: openArray[byte]) =
  ## Append `A` to `S`.
  var
    start: int = 0
    i: int = 0
  if A.len == 0:
    return
  start = S.len
  S.setLen(start + A.len)
  i = 0
  while i < A.len:
    S[start + i] = A[i]
    i = i + 1

proc appendByte*(S: var seq[byte], b: byte) =
  ## Append one byte to `S`.
  S.add(b)

proc sliceBytes*(A: openArray[byte], o, l: int): seq[byte] =
  ## Copy `l` bytes from `A` starting at `o`.
  var
    i: int = 0
  result = newSeq[byte](l)
  i = 0
  while i < l:
    result[i] = A[o + i]
    i = i + 1

proc copyBytes*(dst: var openArray[byte], o: int, src: openArray[byte]) =
  ## Copy `src` into `dst` starting at offset `o`.
  var
    i: int = 0
  i = 0
  while i < src.len:
    dst[o + i] = src[i]
    i = i + 1

proc clearBytes*(S: var seq[byte]) =
  ## Zero a byte sequence in place.
  if S.len == 0:
    return
  zeroMem(addr S[0], S.len)

proc clearBytes*[N: static[int]](A: var array[N, byte]) =
  ## Zero a fixed byte array in place.
  when N > 0:
    zeroMem(addr A[0], N)

proc secureZeroMem*(p: pointer, l: int) =
  ## Volatile zeroization for secret-bearing POD scratch.
  var
    i: int = 0
    B: ptr UncheckedArray[byte]
  if p.isNil or l <= 0:
    return
  B = cast[ptr UncheckedArray[byte]](p)
  i = 0
  while i < l:
    volatileStore(addr B[i], 0'u8)
    i = i + 1

proc secureClearBytes*(S: var seq[byte]) =
  ## Volatile zeroization for secret byte sequences.
  if S.len == 0:
    return
  secureZeroMem(addr S[0], S.len)

proc secureClearBytes*[N: static[int]](A: var array[N, byte]) =
  ## Volatile zeroization for secret fixed-size byte arrays.
  when N > 0:
    secureZeroMem(addr A[0], N)

proc clearPod*[T](x: var T) =
  ## Fast bulk zeroization for POD-style scratch.
  static:
    doAssert supportsCopyMem(T), "clearPod requires a POD-style type"
  when sizeof(T) > 0:
    zeroMem(addr x, sizeof(T))

proc secureClearPod*[T](x: var T) =
  ## Volatile zeroization for POD-style stack scratch only.
  static:
    doAssert supportsCopyMem(T), "secureClearPod requires a POD-style type"
  when sizeof(T) > 0:
    secureZeroMem(addr x, sizeof(T))

proc fillArray*[N: static[int]](dst: var array[N, byte], src: openArray[byte]) =
  ## Copy bytes into a fixed-size array.
  var
    i: int = 0
  if src.len != N:
    raise newException(ValueError, "source length does not match fixed array length")
  i = 0
  while i < N:
    dst[i] = src[i]
    i = i + 1

{.pop.}
