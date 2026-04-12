## Benes network application and support generation for Classic McEliece.
## Pure-Nim port of the PQClean “clean” implementation (f variants).

import std/assertions
import ./support
import ./transpose

proc layerIn(data: var array[2, array[64, uint64]], bits: ptr UncheckedArray[uint64], lgs: int) {.inline.} =
  let s = 1 shl lgs
  var idx = 0
  var i = 0
  while i < 64:
    var j = 0
    while j < s:
      var d0 = data[0][j + i] xor data[0][j + i + s]
      d0 = d0 and bits[idx]; inc idx
      data[0][j + i] = data[0][j + i] xor d0
      data[0][j + i + s] = data[0][j + i + s] xor d0

      var d1 = data[1][j + i] xor data[1][j + i + s]
      d1 = d1 and bits[idx]; inc idx
      data[1][j + i] = data[1][j + i] xor d1
      data[1][j + i + s] = data[1][j + i + s] xor d1
      inc j
    i += s * 2

proc layerEx(data: ptr UncheckedArray[uint64], bits: ptr UncheckedArray[uint64], lgs: int) {.inline.} =
  let s = 1 shl lgs
  var idx = 0
  var i = 0
  while i < 128:
    var j = 0
    while j < s:
      var d = data[j + i] xor data[j + i + s]
      d = d and bits[idx]; inc idx
      data[j + i] = data[j + i] xor d
      data[j + i + s] = data[j + i + s] xor d
      inc j
    i += s * 2

## Apply a Benes network to a 1024-byte bitstring (8192 bits).
## `bits` must contain ((2*gfbits-1)*n/2) bits; for gfbits=13 this is 12800 bytes.
proc applyBenes*(r: var openArray[byte]; bits: openArray[byte]; gfbits: int; rev = false) =
  ## Apply a Benes network to a packed bitstring of length n = 2^gfbits.
  ## The Classic McEliece f-variants all use gfbits=13 (n = 8192, 1024 bytes).
  assert gfbits == 13, "applyBenes currently assumes gfbits=13 (Classic McEliece)"
  let n = 1 shl gfbits                   # 8192 bits
  let blockBytes = n div 8               # 1024 bytes of r
  let stageBytes = blockBytes div 2      # 512-byte control block per layer
  let totalBitsBytes = ((2 * gfbits - 1) * n div 2 + 7) div 8
  assert r.len == blockBytes, "r must hold n bits"
  assert bits.len >= totalBitsBytes, "insufficient control bits"

  var rIntV: array[2, array[64, uint64]]
  var rIntH: array[2, array[64, uint64]]
  var bIntV: array[64, uint64]
  var bIntH: array[64, uint64]

  let startOffset = 2 * (gfbits - 1) * stageBytes # 12288 for gfbits=13
  let inc = if rev: -blockBytes else: 0     # -1024 for gfbits=13
  var bitsPtr = if rev: startOffset else: 0

  template load64At(buf: openArray[byte], start: int): uint64 =
    load64(cast[ptr UncheckedArray[byte]](unsafeAddr buf[start]))
  template store64At(buf: var openArray[byte], start: int, v: uint64) =
    store64(cast[ptr UncheckedArray[byte]](unsafeAddr buf[start]), v)

  for i in 0 ..< 64:
    rIntV[0][i] = load64At(r, i * 16)
    rIntV[1][i] = load64At(r, i * 16 + 8)

  transpose64x64(rIntH[0], rIntV[0])
  transpose64x64(rIntH[1], rIntV[1])

  var iter = 0
  while iter <= 6:
    var localPtr = bitsPtr
    for i in 0 ..< 64:
      bIntV[i] = load64At(bits, localPtr)
      localPtr += 8
    bitsPtr = localPtr + inc
    transpose64x64(bIntH, bIntV)
    layerEx(cast[ptr UncheckedArray[uint64]](unsafeAddr rIntH[0][0]), cast[ptr UncheckedArray[uint64]](unsafeAddr bIntH[0]), iter)
    inc iter
  transpose64x64(rIntV[0], rIntH[0])
  transpose64x64(rIntV[1], rIntH[1])

  iter = 0
  while iter <= 5:
    var localPtr = bitsPtr
    for i in 0 ..< 64:
      bIntV[i] = load64At(bits, localPtr)
      localPtr += 8
    bitsPtr = localPtr + inc
    layerIn(rIntV, cast[ptr UncheckedArray[uint64]](unsafeAddr bIntV[0]), iter)
    inc iter

  iter = 4
  while iter >= 0:
    var localPtr = bitsPtr
    for i in 0 ..< 64:
      bIntV[i] = load64At(bits, localPtr)
      localPtr += 8
    bitsPtr = localPtr + inc
    layerIn(rIntV, cast[ptr UncheckedArray[uint64]](unsafeAddr bIntV[0]), iter)
    dec iter

  transpose64x64(rIntH[0], rIntV[0])
  transpose64x64(rIntH[1], rIntV[1])

  iter = 6
  while iter >= 0:
    var localPtr = bitsPtr
    for i in 0 ..< 64:
      bIntV[i] = load64At(bits, localPtr)
      localPtr += 8
    bitsPtr = localPtr + inc
    transpose64x64(bIntH, bIntV)
    layerEx(cast[ptr UncheckedArray[uint64]](unsafeAddr rIntH[0][0]), cast[ptr UncheckedArray[uint64]](unsafeAddr bIntH[0]), iter)
    dec iter

  transpose64x64(rIntV[0], rIntH[0])
  transpose64x64(rIntV[1], rIntH[1])

  for i in 0 ..< 64:
    store64At(r, i * 16, rIntV[0][i])
    store64At(r, i * 16 + 8, rIntV[1][i])

## Generate the public support set by applying a Benes network to bit-reversed field elements.
proc supportGen*(outSupport: var openArray[GF]; bits: openArray[byte]; gfbits, sysN: int) =
  assert gfbits <= 16
  let n = 1 shl gfbits
  assert outSupport.len == sysN
  assert bits.len >= ((2 * gfbits - 1) * n div 2 + 7) div 8

  var L = newSeq[seq[byte]](gfbits)
  let packedLen = n div 8
  for j in 0 ..< gfbits:
    L[j] = newSeq[byte](packedLen)

  for i in 0 ..< n:
    let a = bitrev(GF(i), gfbits)
    for j in 0 ..< gfbits:
      if ((a shr j) and 1'u16) == 1'u16:
        L[j][i shr 3] = L[j][i shr 3] or (1'u8 shl (i and 7))

  for j in 0 ..< gfbits:
    applyBenes(L[j], bits, gfbits, false)

  for i in 0 ..< sysN:
    var acc: GF = 0
    var j = gfbits - 1
    while j >= 0:
      acc = (acc shl 1) or GF((L[j][i shr 3] shr (i and 7)) and 1)
      dec j
    outSupport[i] = acc
