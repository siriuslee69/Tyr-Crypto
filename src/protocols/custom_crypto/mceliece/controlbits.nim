## Control-bit generation for Classic McEliece Benes networks.
## Pure-Nim port of the PQClean clean implementation.

{.compile: "controlbits_fast.c".}

import ../../helpers/otter_support
import ./support
import ./sort

proc cControlBitsUnchecked(outPtr: ptr byte, piPtr: ptr int16, gfbits, n: int) {.
    importc: "tyr_mceliece_controlbits_unchecked", cdecl.}

{.push checks: off.}
proc wrapU32ToI32(x: uint32): int32 {.inline.} =
  cast[int32](x)

proc layer(p: var openArray[int16], cb: openArray[byte], s, n: int) {.inline.} =
  let stride = 1 shl (s and 0x1F)
  var
    index: int = 0
    i: int = 0
    d: int16 = 0
    m: int16 = 0
  while i < n:
    var j: int = 0
    while j < stride:
      d = p[i + j] xor p[i + j + stride]
      m = int16((cb[index shr 3] shr (index and 7)) and 1)
      m = 0'i16 - m
      d = d and m
      p[i + j] = p[i + j] xor d
      p[i + j + stride] = p[i + j + stride] xor d
      inc index
      inc j
    i += stride * 2

proc cbInitAPairs(pi: ptr UncheckedArray[int16], temp: ptr UncheckedArray[int32], n: int) {.inline, otterBench.} =
  var x: int = 0
  while x < n:
    temp[x] = (int32(pi[x] xor 1) shl 16) or int32(pi[x xor 1])
    x = x + 1
  int32SortRaw(temp, n)

proc cbInitB(temp: ptr UncheckedArray[int32], n: int) {.inline, otterBench.} =
  template A(i: int): untyped =
    temp[i]
  template B(i: int): untyped =
    temp[n + i]
  var
    x: int = 0
    aX: int32 = 0
    pX: int32 = 0
    cX: int32 = 0
  while x < n:
    aX = A[x]
    pX = aX and 0xFFFF
    cX = ctMin32(pX, int32(x))
    B[x] = (pX shl 16) or cX
    x = x + 1

proc cbInitAIndex(temp: ptr UncheckedArray[int32], n: int) {.inline, otterBench.} =
  var x: int = 0
  while x < n:
    temp[x] = wrapU32ToI32(uint32(temp[x]) shl 16) or int32(x)
    x = x + 1
  int32SortRaw(temp, n)

proc cbMergeAWithB(temp: ptr UncheckedArray[int32], n: int) {.inline, otterBench.} =
  template A(i: int): untyped =
    temp[i]
  template B(i: int): untyped =
    temp[n + i]
  var x: int = 0
  while x < n:
    A[x] = wrapU32ToI32(uint32(A[x]) shl 16) + (B[x] shr 16)
    x = x + 1
  int32SortRaw(temp, n)

proc cbCompactSmall(temp: ptr UncheckedArray[int32], w, n: int) {.inline, otterBench.} =
  template A(i: int): untyped =
    temp[i]
  template B(i: int): untyped =
    temp[n + i]
  var
    x: int = 0
    i: int = 1
    ppcpx: int32 = 0
    ppcx: int32 = 0
  while x < n:
    B[x] = ((A[x] and 0xFFFF) shl 10) or (B[x] and 0x3FF)
    x = x + 1
  while i < w - 1:
    x = 0
    while x < n:
      A[x] = int32((B[x] and not 0x3FF) shl 6) or int32(x)
      x = x + 1
    int32SortRaw(temp, n)

    x = 0
    while x < n:
      A[x] = wrapU32ToI32(uint32(A[x]) shl 20) or B[x]
      x = x + 1
    int32SortRaw(temp, n)

    x = 0
    while x < n:
      ppcpx = A[x] and 0xFFFFF
      ppcx = (A[x] and 0xFFC00) or (B[x] and 0x3FF)
      B[x] = ctMin32(ppcx, ppcpx)
      x = x + 1
    i = i + 1
  x = 0
  while x < n:
    B[x] = B[x] and 0x3FF
    x = x + 1

proc cbCompactLarge(temp: ptr UncheckedArray[int32], tempB: ptr UncheckedArray[int32], w, n: int) {.inline, otterBench.} =
  template A(i: int): untyped =
    temp[i]
  template B(i: int): untyped =
    temp[n + i]
  var
    x: int = 0
    i: int = 1
    cpx: int32 = 0
  while x < n:
    B[x] = wrapU32ToI32(uint32(A[x]) shl 16) or (B[x] and 0xFFFF)
    x = x + 1
  while i < w - 1:
    x = 0
    while x < n:
      A[x] = (B[x] and not 0xFFFF) or int32(x)
      x = x + 1
    int32SortRaw(temp, n)

    x = 0
    while x < n:
      A[x] = wrapU32ToI32(uint32(A[x]) shl 16) or (B[x] and 0xFFFF)
      x = x + 1

    if i < w - 2:
      x = 0
      while x < n:
        B[x] = (A[x] and not 0xFFFF) or int32(uint32(B[x]) shr 16)
        x = x + 1
      int32SortRaw(tempB, n)
      x = 0
      while x < n:
        B[x] = wrapU32ToI32(uint32(B[x]) shl 16) or (A[x] and 0xFFFF)
        x = x + 1
    int32SortRaw(temp, n)

    x = 0
    while x < n:
      cpx = (B[x] and not 0xFFFF) or (A[x] and 0xFFFF)
      B[x] = ctMin32(B[x], cpx)
      x = x + 1
    i = i + 1
  x = 0
  while x < n:
    B[x] = B[x] and 0xFFFF
    x = x + 1

proc cbLoadAFromPi(pi: ptr UncheckedArray[int16], temp: ptr UncheckedArray[int32], n: int) {.inline, otterBench.} =
  var x: int = 0
  while x < n:
    temp[x] = (int32(pi[x]) shl 16) + int32(x)
    x = x + 1
  int32SortRaw(temp, n)

proc cbEmitFirstLayer(outBits: var openArray[byte], pos, step: int,
    temp: ptr UncheckedArray[int32], tempB: ptr UncheckedArray[int32], n: int): int {.inline, otterBench.} =
  template A(i: int): untyped =
    temp[i]
  template B(i: int): untyped =
    temp[n + i]
  var
    j: int = 0
    localPos: int = pos
    x: int = 0
    fJ: int32 = 0
    fX: int32 = 0
    fX1: int32 = 0
  while j < n div 2:
    x = 2 * j
    fJ = B[x] and 1
    fX = int32(x) + fJ
    fX1 = fX xor 1
    outBits[localPos shr 3] = outBits[localPos shr 3] xor byte(fJ shl (localPos and 7))
    localPos = localPos + step
    B[x] = wrapU32ToI32(uint32(A[x]) shl 16) or fX
    B[x + 1] = wrapU32ToI32(uint32(A[x + 1]) shl 16) or fX1
    j = j + 1
  int32SortRaw(tempB, n)
  result = localPos

proc cbEmitSecondLayer(outBits: var openArray[byte], pos, step: int,
    temp: ptr UncheckedArray[int32], n: int): int {.inline, otterBench.} =
  template A(i: int): untyped =
    temp[i]
  template B(i: int): untyped =
    temp[n + i]
  var
    k: int = 0
    localPos: int = pos
    y: int = 0
    lK: int32 = 0
    lY: int32 = 0
    lY1: int32 = 0
  while k < n div 2:
    y = 2 * k
    lK = B[y] and 1
    lY = int32(y) + lK
    lY1 = lY xor 1
    outBits[localPos shr 3] = outBits[localPos shr 3] xor byte(lK shl (localPos and 7))
    localPos = localPos + step
    A[y] = int32(lY shl 16) or (B[y] and 0xFFFF)
    A[y + 1] = int32(lY1 shl 16) or (B[y + 1] and 0xFFFF)
    k = k + 1
  int32SortRaw(temp, n)
  result = localPos

proc cbBuildQ(temp: ptr UncheckedArray[int32], qPtr: ptr UncheckedArray[int16], n: int) {.inline, otterBench.} =
  var
    j: int = 0
    half: int = n shr 1
  while j < half:
    qPtr[j] = int16((temp[2 * j] and 0xFFFF) shr 1)
    qPtr[j + half] = int16((temp[2 * j + 1] and 0xFFFF) shr 1)
    j = j + 1

proc cbRecursion(outBits: var openArray[byte], pos, step: int,
    pi: ptr UncheckedArray[int16], w, n: int, temp: ptr UncheckedArray[int32]) {.otterBench.} =
  let
    half = n div 2
    qPtr = cast[ptr UncheckedArray[int16]](unsafeAddr temp[n + (n shr 2)])
    tempPtr = temp
    tempBPtr = cast[ptr UncheckedArray[int32]](unsafeAddr temp[n])
  if w == 1:
    outBits[pos shr 3] = outBits[pos shr 3] xor byte(pi[0] shl (pos and 7))
    return

  cbInitAPairs(pi, tempPtr, n)
  cbInitB(tempPtr, n)
  cbInitAIndex(tempPtr, n)
  cbMergeAWithB(tempPtr, n)

  if w <= 10:
    cbCompactSmall(tempPtr, w, n)
  else:
    cbCompactLarge(tempPtr, tempBPtr, w, n)

  cbLoadAFromPi(pi, tempPtr, n)

  var localPos: int = 0
  localPos = cbEmitFirstLayer(outBits, pos, step, tempPtr, tempBPtr, n)
  localPos = localPos + (2 * w - 3) * step * (n div 2)
  localPos = cbEmitSecondLayer(outBits, localPos, step, tempPtr, n)
  localPos = localPos - (2 * w - 2) * step * (n div 2)

  cbBuildQ(tempPtr, qPtr, n)

  cbRecursion(outBits, localPos, step * 2, qPtr, w - 1, half, temp)
  cbRecursion(outBits, localPos + step, step * 2,
    cast[ptr UncheckedArray[int16]](unsafeAddr qPtr[half]), w - 1, half, temp)

proc controlBitsFromPermutationUncheckedC*(pi: openArray[int16]; gfbits: int): seq[byte] =
  ## Generate control bits without the post-generation self-check using the local C helper.
  let n = 1 shl gfbits
  let outLen = ((2 * gfbits - 1) * n div 2 + 7) div 8
  assert pi.len == n, "pi length must be 2^gfbits"

  result = newSeq[byte](outLen)
  cControlBitsUnchecked(addr result[0], cast[ptr int16](unsafeAddr pi[0]), gfbits, n)

proc controlBitsFromPermutationUncheckedNim*(pi: openArray[int16]; gfbits: int): seq[byte] {.otterBench.} =
  ## Generate control bits without the post-generation self-check using the pure-Nim port.
  let n = 1 shl gfbits
  let outLen = ((2 * gfbits - 1) * n div 2 + 7) div 8
  var temp: array[2 * 8192, int32]
  assert pi.len == n, "pi length must be 2^gfbits"

  result = newSeq[byte](outLen)
  cbRecursion(result, 0, 1, cast[ptr UncheckedArray[int16]](unsafeAddr pi[0]),
    gfbits, n, cast[ptr UncheckedArray[int32]](addr temp[0]))

proc controlBitsFromPermutationUnchecked*(pi: openArray[int16]; gfbits: int): seq[byte] =
  ## Generate control bits without the post-generation self-check.
  when defined(mcelieceUseNimControlbits) or defined(mcelieceUseNimFast):
    result = controlBitsFromPermutationUncheckedNim(pi, gfbits)
  else:
    result = controlBitsFromPermutationUncheckedC(pi, gfbits)

proc controlBitsFromPermutation*(pi: openArray[int16]; gfbits: int): seq[byte] =
  ## Generate control bits for a Benes network for a permutation of size 2^gfbits.
  let n = 1 shl gfbits
  assert pi.len == n, "pi length must be 2^gfbits"

  var piTest = newSeq[int16](n)
  result = controlBitsFromPermutationUnchecked(pi, gfbits)

  for i in 0 ..< n:
    piTest[i] = int16(i)

  var offset = 0
  for i in 0 ..< gfbits:
    layer(piTest, result.toOpenArray(offset, result.len - 1), i, n)
    offset += n shr 4

  var i = gfbits - 2
  while i >= 0:
    layer(piTest, result.toOpenArray(offset, result.len - 1), i, n)
    offset += n shr 4
    dec i

  var diff: int16 = 0
  for i in 0 ..< n:
    diff = diff or (pi[i] xor piTest[i])
  assert ctNonZero16(diff) == 0, "control bits verification failed"

proc controlBitsFromPermutation*(pi: openArray[uint16]; gfbits: int): seq[byte] =
  var piSigned = newSeq[int16](pi.len)
  for i, v in pi:
    piSigned[i] = int16(v)
  result = controlBitsFromPermutation(piSigned, gfbits)
{.pop.}
