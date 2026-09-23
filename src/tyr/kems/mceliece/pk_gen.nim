## Public-key generation for the pure-Nim Classic McEliece backend.

import std/bitops

import ./params
import ./util
import ./gf
import ./root
import ./sort
import ../../helpers/otter_support

when defined(sse2) and not defined(avx2):
  import nimsimd/sse2 as nsse2
when defined(avx2):
  {.passC: "-mavx2".}
  import simd_nexus/simd/base_operations
  import ./transpose
when defined(neon) or defined(arm64) or defined(aarch64):
  import nimsimd/neon

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key-generation algorithms for `ctMaskEqualU64`; pitfall: fail closed and preserve canonical, constant-time comparison where secrets are involved.
proc ctMaskEqualU64(a, b: uint64): uint64 {.inline.} =
  var x = a xor b
  x = x - 1'u64
  x = x shr 63
  result = 0'u64 - x

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key-generation algorithms for `load64At`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc load64At(mat: openArray[byte], offset: int): uint64 {.inline.} =
  result = load8(mat.toOpenArray(offset, offset + 7))

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key-generation algorithms for `store64At`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc store64At(mat: var openArray[byte], offset: int, v: uint64) {.inline.} =
  store8(mat.toOpenArray(offset, offset + 7), v)

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key-generation algorithms for `load64Copy`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc load64Copy(mat: openArray[byte], offset: int): uint64 {.inline.} =
  result = load64At(mat, offset)

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key-generation algorithms for `store64Copy`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc store64Copy(mat: var openArray[byte], offset: int, v: uint64) {.inline.} =
  store64At(mat, offset, v)

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key-generation algorithms for `xorRowMaskedWords`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc xorRowMaskedWords(mat: var seq[byte], dstStart, srcStart, startByte, fullRowBytes: int,
    mask: byte, maskWord: uint64) {.inline.} =
  var
    c: int = startByte
    v: uint64 = 0
    wordCount: int = 0
    dstWords: ptr UncheckedArray[uint64] = nil
    srcWords: ptr UncheckedArray[uint64] = nil
    w: int = 0
  if c + 8 <= fullRowBytes:
    if ((cast[uint](unsafeAddr mat[dstStart + c]) or cast[uint](unsafeAddr mat[srcStart + c])) and 7'u) == 0'u:
      wordCount = (fullRowBytes - c) shr 3
      dstWords = cast[ptr UncheckedArray[uint64]](unsafeAddr mat[dstStart + c])
      srcWords = cast[ptr UncheckedArray[uint64]](unsafeAddr mat[srcStart + c])
      w = 0
      while w < wordCount:
        dstWords[w] = dstWords[w] xor (srcWords[w] and maskWord)
        w = w + 1
      c = c + (wordCount shl 3)
  while c + 8 <= fullRowBytes:
    v = load64Copy(mat, dstStart + c) xor (load64Copy(mat, srcStart + c) and maskWord)
    store64Copy(mat, dstStart + c, v)
    c = c + 8
  while c < fullRowBytes:
    mat[dstStart + c] = mat[dstStart + c] xor (mat[srcStart + c] and mask)
    c = c + 1

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key-generation algorithms for `loadColumnBlock`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc loadColumnBlock(mat: openArray[byte], rowStart, blockIdx, tail: int): uint64 {.inline.} =
  if tail == 0:
    return load64At(mat, rowStart + blockIdx)

  var tmp: array[9, byte] = default(array[9, byte])
  for j in 0 ..< 9:
    tmp[j] = mat[rowStart + blockIdx + j]
  for j in 0 ..< 8:
    tmp[j] = byte(((int(tmp[j]) shr tail) or (int(tmp[j + 1]) shl (8 - tail))) and 0xFF)
  result = load8(tmp.toOpenArray(0, 7))

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key-generation algorithms for `storeColumnBlock`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc storeColumnBlock(mat: var openArray[byte], rowStart, blockIdx, tail: int, v: uint64) {.inline.} =
  if tail == 0:
    store64At(mat, rowStart + blockIdx, v)
    return

  var tmp: array[9, byte] = default(array[9, byte])
  for j in 0 ..< 9:
    tmp[j] = mat[rowStart + blockIdx + j]
  for j in 0 ..< 8:
    tmp[j] = byte(((int(tmp[j]) shr tail) or (int(tmp[j + 1]) shl (8 - tail))) and 0xFF)

  store8(tmp.toOpenArray(0, 7), v)
  mat[rowStart + blockIdx + 8] = byte(
    (((int(mat[rowStart + blockIdx + 8]) shr tail) shl tail) or
    (int(tmp[7]) shr (8 - tail))) and 0xFF)
  mat[rowStart + blockIdx] = byte(
    ((int(tmp[0]) shl tail) or
    (((int(mat[rowStart + blockIdx]) shl (8 - tail)) shr (8 - tail)))) and 0xFF)
  for j in countdown(7, 1):
    mat[rowStart + blockIdx + j] = byte(
      ((int(tmp[j]) shl tail) or (int(tmp[j - 1]) shr (8 - tail))) and 0xFF)

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; key-generation algorithms for `batchInvertNonZero`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc batchInvertNonZero(vals: var seq[GF], prefix: var seq[GF], n: int) {.inline.} =
  ## Paper note: the Classic McEliece implementation guide uses Montgomery's
  ## trick here: one inversion plus prefix/suffix products replaces many GF inversions.
  if n <= 0:
    return

  prefix[0] = vals[0]
  for i in 1 ..< n:
    prefix[i] = gfMul(prefix[i - 1], vals[i])

  var
    invAcc: GF = gfInv(prefix[n - 1])
    i: int = n - 1
    cur: GF = 0
  while i > 0:
    cur = vals[i]
    vals[i] = gfMul(invAcc, prefix[i - 1])
    invAcc = gfMul(invAcc, cur)
    i = i - 1
  vals[0] = invAcc

include "pk_gen_simd.nim"
include "pk_gen_xor.nim"
include "pk_gen_columns.nim"
