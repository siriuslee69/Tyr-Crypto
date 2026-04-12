## GF(2^13) arithmetic for Classic McEliece f-variants (scalar, constant-time).

import ./params
import ./util

const
  GFBits = 13
  GFMaskConst: GF = (1'u16 shl GFBits) - 1'u16
  ShiftForIsZero = 32 - GFBits

proc gfIsZero*(a: GF): GF {.inline.} =
  ## Returns 0x1FFF when a == 0, else 0x0000 (matches PQClean gf_iszero behavior).
  GF((uint32(a) - 1'u32) shr ShiftForIsZero)

proc gfAdd*(a, b: GF): GF {.inline.} =
  a xor b

proc gfMul*(a, b: GF): GF {.inline.} =
  var tmp = uint64(a) * (uint64(b) and 1)
  for i in 1 ..< GFBits:
    tmp = tmp xor (uint64(a) * (uint64(b) and (1'u64 shl i)))

  var t = tmp and 0x1FF0000'u64
  tmp = tmp xor (t shr 9) xor (t shr 10) xor (t shr 12) xor (t shr 13)

  t = tmp and 0x000E000'u64
  tmp = tmp xor (t shr 9) xor (t shr 10) xor (t shr 12) xor (t shr 13)

  GF(tmp and uint64(GFMaskConst))

proc gfSq2(inVal: GF): GF {.inline.} =
  ## (in^2)^2
  let B = [0x1111111111111111'u64,
           0x0303030303030303'u64,
           0x000F000F000F000F'u64,
           0x000000FF000000FF'u64]
  let M = [0x0001FF0000000000'u64,
           0x000000FF80000000'u64,
           0x000000007FC00000'u64,
           0x00000000003FE000'u64]

  var x = uint64(inVal)
  var t: uint64

  x = (x or (x shl 24)) and B[3]
  x = (x or (x shl 12)) and B[2]
  x = (x or (x shl 6)) and B[1]
  x = (x or (x shl 3)) and B[0]

  for i in 0 .. 3:
    t = x and M[i]
    x = x xor (t shr 9) xor (t shr 10) xor (t shr 12) xor (t shr 13)

  GF(x and uint64(GFMaskConst))

proc gfSqMul(inVal, m: GF): GF {.inline.} =
  ## (in^2) * m
  let M = [0x0000001FF0000000'u64,
           0x000000000FF80000'u64,
           0x000000000007E000'u64]

  var t0 = uint64(inVal)
  let t1 = uint64(m)

  var x = (t1 shl 6) * (t0 and (1'u64 shl 6))
  t0 = t0 xor (t0 shl 7)

  x = x xor (t1 * (t0 and 0x04001'u64))
  x = x xor ((t1 * (t0 and 0x08002'u64)) shl 1)
  x = x xor ((t1 * (t0 and 0x10004'u64)) shl 2)
  x = x xor ((t1 * (t0 and 0x20008'u64)) shl 3)
  x = x xor ((t1 * (t0 and 0x40010'u64)) shl 4)
  x = x xor ((t1 * (t0 and 0x80020'u64)) shl 5)

  for i in 0 .. 2:
    let t = x and M[i]
    x = x xor (t shr 9) xor (t shr 10) xor (t shr 12) xor (t shr 13)

  GF(x and uint64(GFMaskConst))

proc gfSq2Mul(inVal, m: GF): GF {.inline.} =
  ## ((in^2)^2) * m
  let M = [0x1FF0000000000000'u64,
           0x000FF80000000000'u64,
           0x000007FC00000000'u64,
           0x00000003FE000000'u64,
           0x0000000001FE0000'u64,
           0x000000000001E000'u64]

  var t0 = uint64(inVal)
  let t1 = uint64(m)

  var x = (t1 shl 18) * (t0 and (1'u64 shl 6))
  t0 = t0 xor (t0 shl 21)

  x = x xor (t1 * (t0 and 0x010000001'u64))
  x = x xor ((t1 * (t0 and 0x020000002'u64)) shl 3)
  x = x xor ((t1 * (t0 and 0x040000004'u64)) shl 6)
  x = x xor ((t1 * (t0 and 0x080000008'u64)) shl 9)
  x = x xor ((t1 * (t0 and 0x100000010'u64)) shl 12)
  x = x xor ((t1 * (t0 and 0x200000020'u64)) shl 15)

  for i in 0 .. 5:
    let t = x and M[i]
    x = x xor (t shr 9) xor (t shr 10) xor (t shr 12) xor (t shr 13)

  GF(x and uint64(GFMaskConst))

proc gfFrac*(den, num: GF): GF {.inline.} =
  ## Compute num / den in GF(2^13).
  let tmp11 = gfSqMul(den, den)          # ^11
  let tmp1111 = gfSq2Mul(tmp11, tmp11)   # ^1111
  var outVal = gfSq2(tmp1111)
  outVal = gfSq2Mul(outVal, tmp1111)     # ^11111111
  outVal = gfSq2(outVal)
  outVal = gfSq2Mul(outVal, tmp1111)     # ^111111111111
  gfSqMul(outVal, num)                   # ^-1

proc gfInv*(den: GF): GF {.inline.} =
  gfFrac(den, 1'u16)

proc GFmul*(p: McElieceParams; outp: var seq[GF]; in0, in1: openArray[GF]) =
  ## Polynomial multiplication in GF(2^13)[x] / (x^t + x^7 + x^2 + x + 1).
  ## outp.len >= p.sysT, in0.len == in1.len == p.sysT.
  assert in0.len >= p.sysT and in1.len >= p.sysT
  if outp.len < p.sysT:
    outp.setLen(p.sysT)

  var prod = newSeq[GF](p.sysT * 2 - 1)
  for i in 0 ..< p.sysT:
    for j in 0 ..< p.sysT:
      prod[i + j] = prod[i + j] xor gfMul(in0[i], in1[j])

  var i = (p.sysT - 1) * 2
  while i >= p.sysT:
    let v = prod[i]
    prod[i - p.sysT + 7] = prod[i - p.sysT + 7] xor v
    prod[i - p.sysT + 2] = prod[i - p.sysT + 2] xor v
    prod[i - p.sysT + 1] = prod[i - p.sysT + 1] xor v
    prod[i - p.sysT + 0] = prod[i - p.sysT + 0] xor v
    dec i
  for k in 0 ..< p.sysT:
    outp[k] = prod[k]
