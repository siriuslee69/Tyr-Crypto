## GF(2^13) arithmetic for Classic McEliece f-variants (scalar, constant-time).

import ./params
import ./util

const
  GFBits = 13
  GFMaskConst: GF = (1'u16 shl GFBits) - 1'u16
  ShiftForIsZero = 32 - GFBits
  GfSq2SpreadMask: array[4, uint64] = [0x1111111111111111'u64,
                                       0x0303030303030303'u64,
                                       0x000F000F000F000F'u64,
                                       0x000000FF000000FF'u64]
  GfSq2ReduceMask: array[4, uint64] = [0x0001FF0000000000'u64,
                                       0x000000FF80000000'u64,
                                       0x000000007FC00000'u64,
                                       0x00000000003FE000'u64]
  GfSqMulReduceMask: array[3, uint64] = [0x0000001FF0000000'u64,
                                         0x000000000FF80000'u64,
                                         0x000000000007E000'u64]
  GfSq2MulReduceMask: array[6, uint64] = [0x1FF0000000000000'u64,
                                          0x000FF80000000000'u64,
                                          0x000007FC00000000'u64,
                                          0x00000003FE000000'u64,
                                          0x0000000001FE0000'u64,
                                          0x000000000001E000'u64]

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; finite-field, ring, and transform arithmetic for `gfIsZero`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc gfIsZero*(a: GF): GF {.inline.} =
  ## Returns 0x1FFF when a == 0, else 0x0000 (matches PQClean gf_iszero behavior).
  GF((uint32(a) - 1'u32) shr ShiftForIsZero)

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; finite-field, ring, and transform arithmetic for `gfAdd`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc gfAdd*(a, b: GF): GF {.inline.} =
  a xor b

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; finite-field, ring, and transform arithmetic for `gfMul`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc gfMul*(a, b: GF): GF {.inline.} =
  var tmp = uint64(a) * (uint64(b) and 1)
  for i in 1 ..< GFBits:
    tmp = tmp xor (uint64(a) * (uint64(b) and (1'u64 shl i)))

  var t = tmp and 0x1FF0000'u64
  tmp = tmp xor (t shr 9) xor (t shr 10) xor (t shr 12) xor (t shr 13)

  t = tmp and 0x000E000'u64
  tmp = tmp xor (t shr 9) xor (t shr 10) xor (t shr 12) xor (t shr 13)

  GF(tmp and uint64(GFMaskConst))

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; finite-field, ring, and transform arithmetic for `gfSq2`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc gfSq2(inVal: GF): GF {.inline.} =
  ## (in^2)^2
  var
    x: uint64 = uint64(inVal)
    t: uint64 = 0
    i: int = 0

  x = (x or (x shl 24)) and GfSq2SpreadMask[3]
  x = (x or (x shl 12)) and GfSq2SpreadMask[2]
  x = (x or (x shl 6)) and GfSq2SpreadMask[1]
  x = (x or (x shl 3)) and GfSq2SpreadMask[0]

  i = 0
  while i < 4:
    t = x and GfSq2ReduceMask[i]
    x = x xor (t shr 9) xor (t shr 10) xor (t shr 12) xor (t shr 13)
    i = i + 1

  GF(x and uint64(GFMaskConst))

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; finite-field, ring, and transform arithmetic for `gfSqMul`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc gfSqMul(inVal, m: GF): GF {.inline.} =
  ## (in^2) * m
  var
    t0: uint64 = uint64(inVal)
    t1: uint64 = uint64(m)
    x: uint64 = (t1 shl 6) * (t0 and (1'u64 shl 6))
    t: uint64 = 0
    i: int = 0

  t0 = t0 xor (t0 shl 7)

  x = x xor (t1 * (t0 and 0x04001'u64))
  x = x xor ((t1 * (t0 and 0x08002'u64)) shl 1)
  x = x xor ((t1 * (t0 and 0x10004'u64)) shl 2)
  x = x xor ((t1 * (t0 and 0x20008'u64)) shl 3)
  x = x xor ((t1 * (t0 and 0x40010'u64)) shl 4)
  x = x xor ((t1 * (t0 and 0x80020'u64)) shl 5)

  i = 0
  while i < 3:
    t = x and GfSqMulReduceMask[i]
    x = x xor (t shr 9) xor (t shr 10) xor (t shr 12) xor (t shr 13)
    i = i + 1

  GF(x and uint64(GFMaskConst))

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; finite-field, ring, and transform arithmetic for `gfSq2Mul`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc gfSq2Mul(inVal, m: GF): GF {.inline.} =
  ## ((in^2)^2) * m
  var
    t0: uint64 = uint64(inVal)
    t1: uint64 = uint64(m)
    x: uint64 = (t1 shl 18) * (t0 and (1'u64 shl 6))
    t: uint64 = 0
    i: int = 0

  t0 = t0 xor (t0 shl 21)

  x = x xor (t1 * (t0 and 0x010000001'u64))
  x = x xor ((t1 * (t0 and 0x020000002'u64)) shl 3)
  x = x xor ((t1 * (t0 and 0x040000004'u64)) shl 6)
  x = x xor ((t1 * (t0 and 0x080000008'u64)) shl 9)
  x = x xor ((t1 * (t0 and 0x100000010'u64)) shl 12)
  x = x xor ((t1 * (t0 and 0x200000020'u64)) shl 15)

  i = 0
  while i < 6:
    t = x and GfSq2MulReduceMask[i]
    x = x xor (t shr 9) xor (t shr 10) xor (t shr 12) xor (t shr 13)
    i = i + 1

  GF(x and uint64(GFMaskConst))

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; finite-field, ring, and transform arithmetic for `gfFrac`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc gfFrac*(den, num: GF): GF {.inline.} =
  ## Compute num / den in GF(2^13).
  var
    tmp11: GF = gfSqMul(den, den)
    tmp1111: GF = gfSq2Mul(tmp11, tmp11)
    outVal: GF = gfSq2(tmp1111)
  outVal = gfSq2Mul(outVal, tmp1111)
  outVal = gfSq2(outVal)
  outVal = gfSq2Mul(outVal, tmp1111)
  gfSqMul(outVal, num)

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; finite-field, ring, and transform arithmetic for `gfInv`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc gfInv*(den: GF): GF {.inline.} =
  gfFrac(den, 1'u16)

## Reference: [MCELIECE-20221023] sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms; finite-field, ring, and transform arithmetic for `GFmul`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc GFmul*(p: McElieceParams; outp: var openArray[GF]; in0, in1: openArray[GF]) =
  ## Polynomial multiplication in GF(2^13)[x] / (x^t + x^7 + x^2 + x + 1).
  ## outp.len >= p.sysT, in0.len == in1.len == p.sysT.
  assert outp.len >= p.sysT
  assert in0.len >= p.sysT and in1.len >= p.sysT

  var
    prod: seq[GF] = newSeq[GF](p.sysT * 2 - 1)
    i: int = 0
    j: int = 0
    k: int = 0
    v: GF = 0
  i = 0
  while i < p.sysT:
    j = 0
    while j < p.sysT:
      prod[i + j] = prod[i + j] xor gfMul(in0[i], in1[j])
      j = j + 1
    i = i + 1

  i = (p.sysT - 1) * 2
  while i >= p.sysT:
    v = prod[i]
    j = 0
    while j < p.reductionTermCount:
      prod[i - p.sysT + p.reductionTerms[j]] = prod[i - p.sysT + p.reductionTerms[j]] xor v
      j = j + 1
    dec i
  k = 0
  while k < p.sysT:
    outp[k] = prod[k]
    k = k + 1
