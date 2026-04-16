## -----------------------------------------------------------------
## Kyber Utilities <- little-endian helpers and byte-sequence helpers
## -----------------------------------------------------------------

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
  var
    i: int = 0
  i = 0
  while i < S.len:
    S[i] = 0'u8
    i = i + 1

proc clearBytes*[N: static[int]](A: var array[N, byte]) =
  ## Zero a fixed byte array in place.
  var
    i: int = 0
  i = 0
  while i < N:
    A[i] = 0'u8
    i = i + 1

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
