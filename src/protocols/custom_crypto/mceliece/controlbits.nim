## Control-bit generation for Classic McEliece Benes networks (Nassimi–Sahni).
## Pure-Nim port of the PQClean “clean” implementation; parameterized by `gfbits`.

import ./support
import ./sort

proc layer(p: var seq[int16], cb: seq[byte], cbOffset: int, s: int, n: int) {.inline.} =
  let stride = 1 shl (s and 0x1F)
  var index = 0
  var i = 0
  while i < n:
    var j = 0
    while j < stride:
      let d = p[i + j] xor p[i + j + stride]
      let m = int16(-int16((cb[cbOffset + (index shr 3)] shr (index and 7)) and 1))
      let dd = d and m
      p[i + j] = p[i + j] xor dd
      p[i + j + stride] = p[i + j + stride] xor dd
      inc index
      inc j
    i += stride * 2

proc cbRecursion(outBits: var seq[byte], pos, step: int, pi: seq[int16], w, n: int) =
  var A = newSeq[int32](n)
  var B = newSeq[int32](n)

  if w == 1:
    outBits[pos shr 3] = outBits[pos shr 3] xor byte(pi[0] shl (pos and 7))
    return

  for x in 0 ..< n:
    A[x] = (int32(pi[x] xor 1) shl 16) or int32(pi[x xor 1])
  int32Sort(A)

  for x in 0 ..< n:
    let Ax = A[x]
    let px = Ax and 0xFFFF
    let cx = ctMin32(px, int32(x))
    B[x] = (px shl 16) or cx

  for x in 0 ..< n:
    A[x] = (int32(uint32(A[x]) shl 16)) or int32(x)
  int32Sort(A)

  for x in 0 ..< n:
    A[x] = (int32(uint32(A[x]) shl 16)) + (B[x] shr 16)
  int32Sort(A)

  if w <= 10:
    for x in 0 ..< n:
      B[x] = ((A[x] and 0xFFFF) shl 10) or (B[x] and 0x3FF)
    var i = 1
    while i < w - 1:
      for x in 0 ..< n:
        A[x] = (int32((B[x] and not 0x3FF) shl 6)) or int32(x)
      int32Sort(A)

      for x in 0 ..< n:
        A[x] = (int32(uint32(A[x]) shl 20)) or B[x]
      int32Sort(A)

      for x in 0 ..< n:
        let ppcpx = A[x] and 0xFFFFF
        let ppcx = (A[x] and 0xFFC00) or (B[x] and 0x3FF)
        B[x] = ctMin32(ppcx, ppcpx)
      inc i
    for x in 0 ..< n:
      B[x] = B[x] and 0x3FF
  else:
    for x in 0 ..< n:
      B[x] = (int32(uint32(A[x]) shl 16)) or (B[x] and 0xFFFF)
    var i = 1
    while i < w - 1:
      for x in 0 ..< n:
        A[x] = (B[x] and not 0xFFFF) or int32(x)
      int32Sort(A)

      for x in 0 ..< n:
        A[x] = (int32(uint32(A[x]) shl 16)) or (B[x] and 0xFFFF)

      if i < w - 2:
        for x in 0 ..< n:
          B[x] = (A[x] and not 0xFFFF) or int32(uint32(B[x]) shr 16)
        int32Sort(B)
        for x in 0 ..< n:
          B[x] = (int32(uint32(B[x]) shl 16)) or (A[x] and 0xFFFF)
      int32Sort(A)
      for x in 0 ..< n:
        let cpx = (B[x] and not 0xFFFF) or (A[x] and 0xFFFF)
        B[x] = ctMin32(B[x], cpx)
      inc i
    for x in 0 ..< n:
      B[x] = B[x] and 0xFFFF

  for x in 0 ..< n:
    A[x] = (int32(pi[x]) shl 16) + int32(x)
  int32Sort(A)

  var j = 0
  var localPos = pos
  while j < n div 2:
    let x = 2 * j
    let fj = B[x] and 1
    let Fx = x + fj
    let Fx1 = Fx xor 1

    outBits[localPos shr 3] = outBits[localPos shr 3] xor byte(fj shl (localPos and 7))
    localPos += step

    B[x] = (int32(uint32(A[x]) shl 16)) or int32(Fx)
    B[x + 1] = (int32(uint32(A[x + 1]) shl 16)) or int32(Fx1)
    inc j
  int32Sort(B)

  localPos += (2 * w - 3) * step * (n div 2)

  var k = 0
  while k < n div 2:
    let y = 2 * k
    let lk = B[y] and 1
    let Ly = y + lk
    let Ly1 = Ly xor 1

    outBits[localPos shr 3] = outBits[localPos shr 3] xor byte(lk shl (localPos and 7))
    localPos += step

    A[y] = int32(Ly shl 16) or (B[y] and 0xFFFF)
    A[y + 1] = int32(Ly1 shl 16) or (B[y + 1] and 0xFFFF)
    inc k
  int32Sort(A)

  localPos -= (2 * w - 2) * step * (n div 2)

  var q = newSeq[int16](n)
  for j in 0 ..< n div 2:
    q[j] = int16((A[2 * j] and 0xFFFF) shr 1)
    q[j + n div 2] = int16((A[2 * j + 1] and 0xFFFF) shr 1)

  cbRecursion(outBits, localPos, step * 2, q[0 ..< n div 2], w - 1, n div 2)
  cbRecursion(outBits, localPos + step, step * 2, q[n div 2 ..< n], w - 1, n div 2)

## Generate control bits for a Benes network for a permutation of size 2^gfbits.
## Returns a byte buffer of length ((2*gfbits-1)*n/2)/8.
proc controlBitsFromPermutation*(pi: openArray[uint16]; gfbits: int): seq[byte] =
  let n = 1 shl gfbits
  assert pi.len == n, "pi length must be 2^gfbits"
  let outLen = ((2 * gfbits - 1) * n div 2 + 7) div 8
  var outBits = newSeq[byte](outLen)
  var piSeq = newSeq[int16](n)
  for i, v in pi:
    piSeq[i] = int16(v)

  var piTest = newSeq[int16](n)

  while true:
    for i in 0 ..< outBits.len:
      outBits[i] = 0
    cbRecursion(outBits, 0, 1, piSeq, gfbits, n)

    for i in 0 ..< n:
      piTest[i] = int16(i)

    var offset = 0
    for i in 0 ..< gfbits:
      layer(piTest, outBits, offset, i, n)
      offset += n shr 4

    var i = gfbits - 2
    while i >= 0:
      layer(piTest, outBits, offset, i, n)
      offset += n shr 4
      dec i

    var diff: int16 = 0
    for i in 0 ..< n:
      diff = diff or (piSeq[i] xor piTest[i])
    if ctNonZero16(diff) == 0:
      break
  result = outBits
