## Benes network application and support generation for Classic McEliece.
## Pure-Nim port of the PQClean clean implementation.

import std/assertions

from ./support import GF, bitrev
from ./util import load8, store8, clearSensitiveWords
import ./transpose

const
  BenesGfBits = 13
  BenesPackedBytes = (1 shl BenesGfBits) div 8

proc layerIn(data: var array[2, array[64, uint64]], bits: openArray[uint64],
    lgs: int) {.inline.} =
  let s = 1 shl lgs
  var
    idx: int = 0
    i: int = 0
  while i < 64:
    var j: int = 0
    while j < s:
      var d0 = data[0][j + i] xor data[0][j + i + s]
      d0 = d0 and bits[idx]
      inc idx
      data[0][j + i] = data[0][j + i] xor d0
      data[0][j + i + s] = data[0][j + i + s] xor d0

      var d1 = data[1][j + i] xor data[1][j + i + s]
      d1 = d1 and bits[idx]
      inc idx
      data[1][j + i] = data[1][j + i] xor d1
      data[1][j + i + s] = data[1][j + i + s] xor d1
      inc j
    i += s * 2

proc layerEx(data: var array[128, uint64], bits: openArray[uint64], lgs: int) {.inline.} =
  let s = 1 shl lgs
  var
    idx: int = 0
    i: int = 0
  while i < 128:
    var j: int = 0
    while j < s:
      var d = data[j + i] xor data[j + i + s]
      d = d and bits[idx]
      inc idx
      data[j + i] = data[j + i] xor d
      data[j + i + s] = data[j + i + s] xor d
      inc j
    i += s * 2

proc applyBenes*(r: var openArray[byte]; bits: openArray[byte]; gfbits: int;
    rev = false) =
  ## Apply a Benes network to a packed bitstring of length n = 2^gfbits.
  assert gfbits == BenesGfBits, "applyBenes currently assumes gfbits=13"
  let n = 1 shl gfbits
  let blockBytes = n div 8
  let stageBytes = blockBytes div 2
  let totalBitsBytes = ((2 * gfbits - 1) * n div 2 + 7) div 8
  assert r.len == blockBytes
  assert bits.len >= totalBitsBytes

  var
    rIntV: array[2, array[64, uint64]]
    rIntH0: array[64, uint64]
    rIntH1: array[64, uint64]
    rIntH: array[128, uint64]
    bIntV: array[64, uint64]
    bIntH: array[64, uint64]
  defer:
    clearSensitiveWords(rIntV[0])
    clearSensitiveWords(rIntV[1])
    clearSensitiveWords(rIntH0)
    clearSensitiveWords(rIntH1)
    clearSensitiveWords(rIntH)
    clearSensitiveWords(bIntV)
    clearSensitiveWords(bIntH)
  let startOffset = 2 * (gfbits - 1) * stageBytes
  let inc = if rev: -blockBytes else: 0
  var bitsPtr = if rev: startOffset else: 0

  template load64At(buf: openArray[byte], start: int): uint64 =
    load8(buf.toOpenArray(start, start + 7))
  template store64At(buf: var openArray[byte], start: int, v: uint64) =
    store8(buf.toOpenArray(start, start + 7), v)
  template packHorizontal() =
    for i in 0 ..< 64:
      rIntH[i] = rIntH0[i]
      rIntH[i + 64] = rIntH1[i]
  template unpackHorizontal() =
    for i in 0 ..< 64:
      rIntH0[i] = rIntH[i]
      rIntH1[i] = rIntH[i + 64]

  for i in 0 ..< 64:
    rIntV[0][i] = load64At(r, i * 16)
    rIntV[1][i] = load64At(r, i * 16 + 8)

  transpose64x64(rIntH0, rIntV[0])
  transpose64x64(rIntH1, rIntV[1])
  packHorizontal()

  var iter = 0
  while iter <= 6:
    var localPtr = bitsPtr
    for i in 0 ..< 64:
      bIntV[i] = load64At(bits, localPtr)
      localPtr += 8
    bitsPtr = localPtr + inc
    transpose64x64(bIntH, bIntV)
    layerEx(rIntH, bIntH, iter)
    inc iter

  unpackHorizontal()
  transpose64x64(rIntV[0], rIntH0)
  transpose64x64(rIntV[1], rIntH1)

  iter = 0
  while iter <= 5:
    var localPtr = bitsPtr
    for i in 0 ..< 64:
      bIntV[i] = load64At(bits, localPtr)
      localPtr += 8
    bitsPtr = localPtr + inc
    layerIn(rIntV, bIntV, iter)
    inc iter

  iter = 4
  while iter >= 0:
    var localPtr = bitsPtr
    for i in 0 ..< 64:
      bIntV[i] = load64At(bits, localPtr)
      localPtr += 8
    bitsPtr = localPtr + inc
    layerIn(rIntV, bIntV, iter)
    dec iter

  transpose64x64(rIntH0, rIntV[0])
  transpose64x64(rIntH1, rIntV[1])
  packHorizontal()

  iter = 6
  while iter >= 0:
    var localPtr = bitsPtr
    for i in 0 ..< 64:
      bIntV[i] = load64At(bits, localPtr)
      localPtr += 8
    bitsPtr = localPtr + inc
    transpose64x64(bIntH, bIntV)
    layerEx(rIntH, bIntH, iter)
    dec iter

  unpackHorizontal()
  transpose64x64(rIntV[0], rIntH0)
  transpose64x64(rIntV[1], rIntH1)

  for i in 0 ..< 64:
    store64At(r, i * 16, rIntV[0][i])
    store64At(r, i * 16 + 8, rIntV[1][i])

proc supportGen*(outSupport: var openArray[GF]; bits: openArray[byte];
    gfbits, sysN: int) =
  assert gfbits == BenesGfBits
  assert outSupport.len == sysN
  assert bits.len >= ((2 * gfbits - 1) * (1 shl gfbits) div 2 + 7) div 8

  var L: array[BenesGfBits, array[BenesPackedBytes, byte]]
  defer:
    for i in 0 ..< BenesGfBits:
      clearSensitiveWords(L[i])

  for i in 0 ..< (1 shl gfbits):
    let a = bitrev(GF(i), gfbits)
    for j in 0 ..< gfbits:
      if ((a shr j) and 1'u16) == 1'u16:
        L[j][i shr 3] = L[j][i shr 3] or (1'u8 shl (i and 7))

  for j in 0 ..< gfbits:
    applyBenes(L[j], bits, gfbits, false)

  for i in 0 ..< sysN:
    var
      acc: GF = 0
      j = gfbits - 1
    while j >= 0:
      acc = (acc shl 1) or GF((L[j][i shr 3] shr (i and 7)) and 1)
      dec j
    outSupport[i] = acc
