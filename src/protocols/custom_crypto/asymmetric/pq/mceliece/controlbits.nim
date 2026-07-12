## Control-bit generation for Classic McEliece Benes networks.
## Pure-Nim port of the PQClean clean implementation.

import ../../../../helpers/otter_support
import ./support
import ./sort

{.push checks: off.}
## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `wrapU32ToI32`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc wrapU32ToI32(x: uint32): int32 {.inline.} =
  cast[int32](x)

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `layer`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc layer(p: var openArray[int16], cb: openArray[byte], s, n: int) {.inline.} =
  var
    stride: int = 1 shl (s and 0x1F)
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

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `cbInitAPairs`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc cbInitAPairs(pi: ptr UncheckedArray[int16], temp: ptr UncheckedArray[int32], n: int) {.inline, otterBench.} =
  var x: int = 0
  while x < n:
    temp[x] = (int32(pi[x] xor 1) shl 16) or int32(pi[x xor 1])
    x = x + 1
  int32SortRaw(temp, n)

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `cbInitB`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc cbInitB(temp: ptr UncheckedArray[int32], n: int) {.inline, otterBench.} =
  ## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `A`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  template A(i: int): untyped =
    temp[i]
  ## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `B`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `cbInitAIndex`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc cbInitAIndex(temp: ptr UncheckedArray[int32], n: int) {.inline, otterBench.} =
  var x: int = 0
  while x < n:
    temp[x] = wrapU32ToI32(uint32(temp[x]) shl 16) or int32(x)
    x = x + 1
  int32SortRaw(temp, n)

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `cbMergeAWithB`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc cbMergeAWithB(temp: ptr UncheckedArray[int32], n: int) {.inline, otterBench.} =
  ## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `A`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  template A(i: int): untyped =
    temp[i]
  ## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `B`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  template B(i: int): untyped =
    temp[n + i]
  var x: int = 0
  while x < n:
    A[x] = wrapU32ToI32(uint32(A[x]) shl 16) + (B[x] shr 16)
    x = x + 1
  int32SortRaw(temp, n)

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `cbCompactSmall`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc cbCompactSmall(temp: ptr UncheckedArray[int32], w, n: int) {.inline, otterBench.} =
  ## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `A`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  template A(i: int): untyped =
    temp[i]
  ## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `B`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `cbCompactLarge`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc cbCompactLarge(temp: ptr UncheckedArray[int32], tempB: ptr UncheckedArray[int32], w, n: int) {.inline, otterBench.} =
  ## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `A`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  template A(i: int): untyped =
    temp[i]
  ## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `B`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `cbLoadAFromPi`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc cbLoadAFromPi(pi: ptr UncheckedArray[int16], temp: ptr UncheckedArray[int32], n: int) {.inline, otterBench.} =
  var x: int = 0
  while x < n:
    temp[x] = (int32(pi[x]) shl 16) + int32(x)
    x = x + 1
  int32SortRaw(temp, n)

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `cbEmitFirstLayer`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc cbEmitFirstLayer(outBits: var openArray[byte], pos, step: int,
    temp: ptr UncheckedArray[int32], tempB: ptr UncheckedArray[int32], n: int): int {.inline, otterBench.} =
  ## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `A`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  template A(i: int): untyped =
    temp[i]
  ## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `B`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `cbEmitSecondLayer`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc cbEmitSecondLayer(outBits: var openArray[byte], pos, step: int,
    temp: ptr UncheckedArray[int32], n: int): int {.inline, otterBench.} =
  ## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `A`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  template A(i: int): untyped =
    temp[i]
  ## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `B`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `cbBuildQ`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc cbBuildQ(temp: ptr UncheckedArray[int32], qPtr: ptr UncheckedArray[int16], n: int) {.inline, otterBench.} =
  var
    j: int = 0
    half: int = n shr 1
  while j < half:
    qPtr[j] = int16((temp[2 * j] and 0xFFFF) shr 1)
    qPtr[j + half] = int16((temp[2 * j + 1] and 0xFFFF) shr 1)
    j = j + 1

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `cbRecursion`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc cbRecursion(outBits: var openArray[byte], pos, step: int,
    pi: ptr UncheckedArray[int16], w, n: int, temp: ptr UncheckedArray[int32]) {.otterBench.} =
  var
    half: int = n div 2
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

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `controlBitsFromPermutationUncheckedNim`; pitfall: fail closed and preserve canonical, constant-time comparison where secrets are involved.
proc controlBitsFromPermutationUncheckedNim*(pi: openArray[int16]; gfbits: int): seq[byte] {.otterBench.} =
  ## Generate control bits without the post-generation self-check using the pure-Nim port.
  var
    n: int = 1 shl gfbits
    outLen: int = ((2 * gfbits - 1) * n div 2 + 7) div 8
    temp: array[2 * 8192, int32]
  assert pi.len == n, "pi length must be 2^gfbits"

  result = newSeq[byte](outLen)
  cbRecursion(result, 0, 1, cast[ptr UncheckedArray[int16]](unsafeAddr pi[0]),
    gfbits, n, cast[ptr UncheckedArray[int32]](addr temp[0]))

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `controlBitsFromPermutationUncheckedC`; pitfall: fail closed and preserve canonical, constant-time comparison where secrets are involved.
proc controlBitsFromPermutationUncheckedC*(pi: openArray[int16]; gfbits: int): seq[byte] =
  ## Compatibility alias retained for old benchmark flags; now pure Nim.
  result = controlBitsFromPermutationUncheckedNim(pi, gfbits)

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `controlBitsFromPermutationUnchecked`; pitfall: fail closed and preserve canonical, constant-time comparison where secrets are involved.
proc controlBitsFromPermutationUnchecked*(pi: openArray[int16]; gfbits: int): seq[byte] =
  ## Generate control bits without the post-generation self-check.
  result = controlBitsFromPermutationUncheckedNim(pi, gfbits)

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `controlBitsFromPermutation`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc controlBitsFromPermutation*(pi: openArray[int16]; gfbits: int): seq[byte] =
  ## Generate control bits for a Benes network for a permutation of size 2^gfbits.
  var
    n: int = 1 shl gfbits
    piTest: seq[int16]
    offset: int = 0
    i: int = 0
    diff: int16 = 0
  assert pi.len == n, "pi length must be 2^gfbits"

  piTest = newSeq[int16](n)
  result = controlBitsFromPermutationUnchecked(pi, gfbits)

  i = 0
  while i < n:
    piTest[i] = int16(i)
    i = i + 1

  offset = 0
  i = 0
  while i < gfbits:
    layer(piTest, result.toOpenArray(offset, result.len - 1), i, n)
    offset += n shr 4
    i = i + 1

  i = gfbits - 2
  while i >= 0:
    layer(piTest, result.toOpenArray(offset, result.len - 1), i, n)
    offset += n shr 4
    dec i

  diff = 0
  i = 0
  while i < n:
    diff = diff or (pi[i] xor piTest[i])
    i = i + 1
  assert ctNonZero16(diff) == 0, "control bits verification failed"

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `controlBitsFromPermutation`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc controlBitsFromPermutation*(pi: openArray[uint16]; gfbits: int): seq[byte] =
  var
    piSigned: seq[int16]
  piSigned = newSeq[int16](pi.len)
  for idx, val in pi:
    piSigned[idx] = int16(val)
  result = controlBitsFromPermutation(piSigned, gfbits)
{.pop.}
