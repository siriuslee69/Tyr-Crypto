## Benes network application and support generation for Classic McEliece.
## Pure-Nim port of the PQClean clean implementation.
##
## A Benes network is a fixed wiring of 2·13 - 1 = 25 layers of swaps that
## can put 2^13 bits into any order. Each swap is on or off according to
## one control bit taken from the secret key:
##
##   pass     1        2        3        4
##   layers   0..6     0..5     4..0     6..0      (7 + 6 + 5 + 7 = 25)
##   kind     outer    inner    inner    outer
##
## The 8192 bits sit in a 64x128 grid of 64-bit words. "Outer" layers swap
## within rows (rIntH), "inner" layers between rows (rIntV); the grid is
## transposed between the two kinds. Every layer reads 64 control words
## (512 bytes), going forward or, for the reverse network, backward.

from ./support import GF, bitrev
from ./util import load8, store8
import ./transpose
import ../../helpers/secure_memory
import runePragmas

const
  BenesGfBits = 13
  BenesPackedBytes = (1 shl BenesGfBits) div 8
  BenesLayerBytes = 64 * 8

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `layerIn`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc layerIn(data: var array[2, array[64, uint64]], bits: openArray[uint64],
    lgs: int) {.inline, role: {math}.} =
  ## One inner layer: rows j and j + 2^lgs trade the bits their control
  ## word marks (masked swap), in both halves of the grid.
  var
    s: int = 1 shl lgs
    idx: int = 0
    k: int = 0
    a: int = 0
    d0: uint64 = 0'u64
    d1: uint64 = 0'u64
  while k < 32:
    a = (k div s) * (2 * s) + (k mod s)
    d0 = (data[0][a] xor data[0][a + s]) and bits[idx]
    idx = idx + 1
    data[0][a] = data[0][a] xor d0
    data[0][a + s] = data[0][a + s] xor d0
    d1 = (data[1][a] xor data[1][a + s]) and bits[idx]
    idx = idx + 1
    data[1][a] = data[1][a] xor d1
    data[1][a + s] = data[1][a + s] xor d1
    k = k + 1

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `layerEx`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc layerEx(data: var array[128, uint64], bits: openArray[uint64], lgs: int) {.inline, role: {math}.} =
  ## One outer layer: words j and j + 2^lgs trade the bits their control
  ## word marks (masked swap).
  var
    s: int = 1 shl lgs
    k: int = 0
    a: int = 0
    d: uint64 = 0'u64
  while k < 64:
    a = (k div s) * (2 * s) + (k mod s)
    d = (data[a] xor data[a + s]) and bits[k]
    data[a] = data[a] xor d
    data[a + s] = data[a + s] xor d
    k = k + 1

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `loadControlWords`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc loadControlWords(B: var array[64, uint64], bits: openArray[byte],
    bitsPtr: var int, incVal: int) {.inline, role: {parser}.} =
  ## B: the next 64 control words. bitsPtr moves past them, then by incVal
  ## (-1024 for the reverse network, so it walks backward).
  var
    i: int = 0
  while i < 64:
    B[i] = load8(bits.toOpenArray(bitsPtr + i * 8, bitsPtr + i * 8 + 7))
    i = i + 1
  bitsPtr = bitsPtr + BenesLayerBytes + incVal

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `toHorizontal`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc toHorizontal(rIntH: var array[128, uint64], rIntH0, rIntH1: var array[64, uint64],
    rIntV: array[2, array[64, uint64]]) {.inline, role: {math}.} =
  ## rIntH: the grid transposed into row form (both halves, side by side).
  var
    i: int = 0
  transpose64x64(rIntH0, rIntV[0])
  transpose64x64(rIntH1, rIntV[1])
  while i < 64:
    rIntH[i] = rIntH0[i]
    rIntH[i + 64] = rIntH1[i]
    i = i + 1

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `toVertical`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc toVertical(rIntV: var array[2, array[64, uint64]], rIntH0, rIntH1: var array[64, uint64],
    rIntH: array[128, uint64]) {.inline, role: {math}.} =
  ## rIntV: the grid transposed back into column form.
  var
    i: int = 0
  while i < 64:
    rIntH0[i] = rIntH[i]
    rIntH1[i] = rIntH[i + 64]
    i = i + 1
  transpose64x64(rIntV[0], rIntH0)
  transpose64x64(rIntV[1], rIntH1)

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `applyBenes`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc applyBenes*(r: var openArray[byte]; bits: openArray[byte]; gfbits: int;
    rev = false) {.role: {math}.} =
  ## r: 2^gfbits packed bits, permuted in place by the network that bits
  ## describes (rev = true runs the network backward).
  var
    n: int = 1 shl gfbits
    blockBytes: int = n div 8
    totalBitsBytes: int = ((2 * gfbits - 1) * n div 2 + 7) div 8
    incVal: int = (if rev: -blockBytes else: 0)
    bitsPtr: int = (if rev: 2 * (gfbits - 1) * (blockBytes div 2) else: 0)
    rIntV: array[2, array[64, uint64]] = default(array[2, array[64, uint64]])
    rIntH0: array[64, uint64] = default(array[64, uint64])
    rIntH1: array[64, uint64] = default(array[64, uint64])
    rIntH: array[128, uint64] = default(array[128, uint64])
    bIntV: array[64, uint64] = default(array[64, uint64])
    bIntH: array[64, uint64] = default(array[64, uint64])
    iter: int = 0
    i: int = 0
  if gfbits != BenesGfBits:
    raise newException(ValueError, "McEliece: applyBenes currently assumes gfbits=13")
  if r.len != blockBytes:
    raise newException(ValueError, "McEliece size check failed: r.len == blockBytes")
  if bits.len < totalBitsBytes:
    raise newException(ValueError, "McEliece size check failed: bits.len >= totalBitsBytes")
  defer:
    secureClearItems(rIntV[0])
    secureClearItems(rIntV[1])
    secureClearItems(rIntH0)
    secureClearItems(rIntH1)
    secureClearItems(rIntH)
    secureClearItems(bIntV)
    secureClearItems(bIntH)
  while i < 64:
    rIntV[0][i] = load8(r.toOpenArray(i * 16, i * 16 + 7))
    rIntV[1][i] = load8(r.toOpenArray(i * 16 + 8, i * 16 + 15))
    i = i + 1
  toHorizontal(rIntH, rIntH0, rIntH1, rIntV)
  while iter <= 6:
    loadControlWords(bIntV, bits, bitsPtr, incVal)
    transpose64x64(bIntH, bIntV)
    layerEx(rIntH, bIntH, iter)
    iter = iter + 1
  toVertical(rIntV, rIntH0, rIntH1, rIntH)
  iter = 0
  while iter <= 5:
    loadControlWords(bIntV, bits, bitsPtr, incVal)
    layerIn(rIntV, bIntV, iter)
    iter = iter + 1
  iter = 4
  while iter >= 0:
    loadControlWords(bIntV, bits, bitsPtr, incVal)
    layerIn(rIntV, bIntV, iter)
    iter = iter - 1
  toHorizontal(rIntH, rIntH0, rIntH1, rIntV)
  iter = 6
  while iter >= 0:
    loadControlWords(bIntV, bits, bitsPtr, incVal)
    transpose64x64(bIntH, bIntV)
    layerEx(rIntH, bIntH, iter)
    iter = iter - 1
  toVertical(rIntV, rIntH0, rIntH1, rIntH)
  i = 0
  while i < 64:
    store8(r.toOpenArray(i * 16, i * 16 + 7), rIntV[0][i])
    store8(r.toOpenArray(i * 16 + 8, i * 16 + 15), rIntV[1][i])
    i = i + 1

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `scatterBitrevBits`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc scatterBitrevBits(L: var array[BenesGfBits, array[BenesPackedBytes, byte]],
    i, gfbits: int) {.inline, role: {math}.} =
  ## L: bit i of row j is set to bit j of bitrev(i).
  var
    a: GF = bitrev(GF(i), gfbits)
    j: int = 0
  while j < gfbits:
    L[j][i shr 3] = L[j][i shr 3] or (byte((a shr j) and 1'u16) shl (i and 7))
    j = j + 1

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `gatherSupportValue`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc gatherSupportValue(L: array[BenesGfBits, array[BenesPackedBytes, byte]],
    i, gfbits: int): GF {.inline, role: {math}.} =
  ## Returns the field element whose bit j is bit i of row j.
  var
    j: int = gfbits - 1
  while j >= 0:
    result = (result shl 1) or GF((L[j][i shr 3] shr (i and 7)) and 1)
    j = j - 1

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; Benes network and permutation-control-bit algorithms for `supportGen`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc supportGen*(outSupport: var openArray[GF]; bits: openArray[byte];
    gfbits, sysN: int) {.role: {math}.} =
  ## outSupport: the secret support (sysN field elements): all elements in
  ## bit-reversed order, permuted by the Benes network, first sysN kept.
  var
    L: array[BenesGfBits, array[BenesPackedBytes, byte]] =
      default(array[BenesGfBits, array[BenesPackedBytes, byte]])
    i: int = 0
  if gfbits != BenesGfBits:
    raise newException(ValueError, "McEliece size check failed: gfbits == BenesGfBits")
  if outSupport.len != sysN:
    raise newException(ValueError, "McEliece size check failed: outSupport.len == sysN")
  if bits.len < ((2 * gfbits - 1) * (1 shl gfbits) div 2 + 7) div 8:
    raise newException(ValueError, "McEliece size check failed: bits.len >= ((2 * gfbits - 1) * (1 shl gfbits) div 2 + 7) div 8")
  defer:
    secureClearPod(L)
  while i < (1 shl gfbits):
    scatterBitrevBits(L, i, gfbits)
    i = i + 1
  i = 0
  while i < gfbits:
    applyBenes(L[i], bits, gfbits, false)
    i = i + 1
  i = 0
  while i < sysN:
    outSupport[i] = gatherSupportValue(L, i, gfbits)
    i = i + 1
