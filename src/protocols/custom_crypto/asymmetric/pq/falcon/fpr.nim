## ------------------------------------------------------------------
## Falcon Fpr <- integer-backed binary64 helpers for the pure-Nim port
## ------------------------------------------------------------------

import std/math

type
  FalconFpr* = uint64

const
  fprQ* = FalconFpr(4667981563525332992'u64)
  fprInverseOfQ* = FalconFpr(4545632735260551042'u64)
  fprInv2SqrSigma0* = FalconFpr(4594603506513722306'u64)
  fprLog2* = FalconFpr(4604418534313441775'u64)
  fprInvLog2* = FalconFpr(4609176140021203710'u64)
  fprBnormMax* = FalconFpr(4670353323383631276'u64)
  fprZero* = FalconFpr(0'u64)
  fprOne* = FalconFpr(4607182418800017408'u64)
  fprTwo* = FalconFpr(4611686018427387904'u64)
  fprOneHalf* = FalconFpr(4602678819172646912'u64)
  fprInvSqrt2* = FalconFpr(4604544271217802189'u64)
  fprInvSqrt8* = FalconFpr(4600040671590431693'u64)
  fprPTwo31* = FalconFpr(4746794007248502784'u64)
  fprPTwo31m1* = FalconFpr(4746794007244308480'u64)
  fprMTwo31m1* = FalconFpr(13970166044099084288'u64)
  fprPTwo63m1* = FalconFpr(4890909195324358656'u64)
  fprMTwo63m1* = FalconFpr(14114281232179134464'u64)
  fprPTwo63* = FalconFpr(4890909195324358656'u64)

  fprInvSigma*: array[11, FalconFpr] = [
    FalconFpr(0'u64),
    FalconFpr(4574611497772390042'u64),
    FalconFpr(4574501679055810265'u64),
    FalconFpr(4574396282908341804'u64),
    FalconFpr(4574245855758572086'u64),
    FalconFpr(4574103865040221165'u64),
    FalconFpr(4573969550563515544'u64),
    FalconFpr(4573842244705920822'u64),
    FalconFpr(4573721358406441454'u64),
    FalconFpr(4573606369665796042'u64),
    FalconFpr(4573496814039276259'u64)
  ]

  fprSigmaMin*: array[11, FalconFpr] = [
    FalconFpr(0'u64),
    FalconFpr(4607707126469777035'u64),
    FalconFpr(4607777455861499430'u64),
    FalconFpr(4607846828256951418'u64),
    FalconFpr(4607949175006100261'u64),
    FalconFpr(4608049571757433526'u64),
    FalconFpr(4608148125896792003'u64),
    FalconFpr(4608244935301382692'u64),
    FalconFpr(4608340089478362016'u64),
    FalconFpr(4608433670533905013'u64),
    FalconFpr(4608525754002622308'u64)
  ]

  fprP2Tab*: array[11, FalconFpr] = [
    FalconFpr(4611686018427387904'u64),
    FalconFpr(4607182418800017408'u64),
    FalconFpr(4602678819172646912'u64),
    FalconFpr(4598175219545276416'u64),
    FalconFpr(4593671619917905920'u64),
    FalconFpr(4589168020290535424'u64),
    FalconFpr(4584664420663164928'u64),
    FalconFpr(4580160821035794432'u64),
    FalconFpr(4575657221408423936'u64),
    FalconFpr(4571153621781053440'u64),
    FalconFpr(4566650022153682944'u64)
  ]

proc fprUrsh*(x: uint64, n: int): uint64 {.inline.} =
  var v = x xor ((x xor (x shr 32)) and (0'u64 - uint64(n shr 5)))
  v shr (n and 31)

proc fprIrsh*(x: int64, n: int): int64 {.inline.} =
  var v = x xor ((x xor (x shr 32)) and (0'i64 - int64(n shr 5)))
  v shr (n and 31)

proc fprUlsh*(x: uint64, n: int): uint64 {.inline.} =
  var v = x xor ((x xor (x shl 32)) and (0'u64 - uint64(n shr 5)))
  v shl (n and 31)

proc makeFpr*(s, e: int, m: uint64): FalconFpr {.inline.} =
  var
    exp = e + 1076
    mant = m
    t: uint32
    f: uint
    x: uint64
  t = uint32(exp) shr 31
  mant = mant and (uint64(t) - 1'u64)
  t = uint32(mant shr 54)
  exp = exp and -int(t)
  x = ((uint64(s) shl 63) or (mant shr 2)) + (uint64(uint32(exp)) shl 52)
  f = uint(mant and 7'u64)
  x = x + uint64((0xC8'u32 shr f) and 1'u32)
  FalconFpr(x)

template norm64(m, e: untyped) =
  block:
    var nt: uint32
    e = e - 63
    nt = uint32(m shr 32)
    nt = (nt or (0'u32 - nt)) shr 31
    m = m xor ((m xor (m shl 32)) and (uint64(nt) - 1'u64))
    e = e + int(nt shl 5)
    nt = uint32(m shr 48)
    nt = (nt or (0'u32 - nt)) shr 31
    m = m xor ((m xor (m shl 16)) and (uint64(nt) - 1'u64))
    e = e + int(nt shl 4)
    nt = uint32(m shr 56)
    nt = (nt or (0'u32 - nt)) shr 31
    m = m xor ((m xor (m shl 8)) and (uint64(nt) - 1'u64))
    e = e + int(nt shl 3)
    nt = uint32(m shr 60)
    nt = (nt or (0'u32 - nt)) shr 31
    m = m xor ((m xor (m shl 4)) and (uint64(nt) - 1'u64))
    e = e + int(nt shl 2)
    nt = uint32(m shr 62)
    nt = (nt or (0'u32 - nt)) shr 31
    m = m xor ((m xor (m shl 2)) and (uint64(nt) - 1'u64))
    e = e + int(nt shl 1)
    nt = uint32(m shr 63)
    m = m xor ((m xor (m shl 1)) and (uint64(nt) - 1'u64))
    e = e + int(nt)

proc fprScaled*(i: int64, sc: int): FalconFpr =
  var
    sign: int = int(cast[uint64](i) shr 63)
    value: int64 = i
    exp: int = 9 + sc
    mant: uint64
    t: uint32
  value = value xor -int64(sign)
  value = value + int64(sign)
  mant = uint64(value)
  norm64(mant, exp)
  mant = mant or (uint64(uint32(mant) and 0x1FF'u32) + 0x1FF'u64)
  mant = mant shr 9
  t = uint32((cast[uint64](value or -value)) shr 63)
  mant = mant and (0'u64 - uint64(t))
  exp = exp and -int(t)
  makeFpr(sign, exp, mant)

proc fprOf*(i: int64): FalconFpr {.inline.} =
  fprScaled(i, 0)

proc fprToFloat*(x: FalconFpr): float64 {.inline.} =
  cast[float64](x)

proc fprIsFinite*(x: FalconFpr): bool {.inline.} =
  ((uint64(x) shr 52) and 0x7ff'u64) != 0x7ff'u64

proc floatToFpr*(x: float64): FalconFpr {.inline.} =
  cast[FalconFpr](x)

proc fprRint*(x: FalconFpr): int64 =
  let
    v = fprToFloat(x)
    base = floor(v)
    frac = v - base
  if frac < 0.5:
    return int64(base)
  if frac > 0.5:
    return int64(base + 1.0)
  let even = int64(base)
  if (even and 1'i64) == 0'i64:
    even
  else:
    even + 1'i64

proc fprFloor*(x: FalconFpr): int64 =
  int64(floor(fprToFloat(x)))

proc fprTrunc*(x: FalconFpr): int64 =
  int64(trunc(fprToFloat(x)))

proc fprAdd*(x, y: FalconFpr): FalconFpr =
  floatToFpr(fprToFloat(x) + fprToFloat(y))

proc fprSub*(x, y: FalconFpr): FalconFpr {.inline.} =
  fprAdd(x, y xor (1'u64 shl 63))

proc fprNeg*(x: FalconFpr): FalconFpr {.inline.} =
  x xor (1'u64 shl 63)

proc fprHalf*(x: FalconFpr): FalconFpr {.inline.} =
  floatToFpr(fprToFloat(x) * 0.5)

proc fprDouble*(x: FalconFpr): FalconFpr {.inline.} =
  floatToFpr(fprToFloat(x) * 2.0)

proc fprMul*(x, y: FalconFpr): FalconFpr =
  floatToFpr(fprToFloat(x) * fprToFloat(y))

proc fprSqr*(x: FalconFpr): FalconFpr {.inline.} =
  fprMul(x, x)

proc fprDiv*(x, y: FalconFpr): FalconFpr =
  floatToFpr(fprToFloat(x) / fprToFloat(y))

proc fprInv*(x: FalconFpr): FalconFpr {.inline.} =
  fprDiv(fprOne, x)

proc fprSqrt*(x: FalconFpr): FalconFpr =
  floatToFpr(sqrt(fprToFloat(x)))

proc fprLt*(x, y: FalconFpr): bool {.inline.} =
  fprToFloat(x) < fprToFloat(y)

proc fprExpmP63*(x, ccs: FalconFpr): uint64 =
  const C: array[13, uint64] = [
    0x00000004741183A3'u64,
    0x00000036548CFC06'u64,
    0x0000024FDCBF140A'u64,
    0x0000171D939DE045'u64,
    0x0000D00CF58F6F84'u64,
    0x000680681CF796E3'u64,
    0x002D82D8305B0FEA'u64,
    0x011111110E066FD0'u64,
    0x0555555555070F00'u64,
    0x155555555581FF00'u64,
    0x400000000002B400'u64,
    0x7FFFFFFFFFFF4800'u64,
    0x8000000000000000'u64
  ]
  var
    y = C[0]
    z = uint64(fprTrunc(fprMul(x, fprPTwo63))) shl 1
    u = 1
    z0, z1, y0, y1: uint32
    a, b: uint64
  while u < C.len:
    z0 = uint32(z)
    z1 = uint32(z shr 32)
    y0 = uint32(y)
    y1 = uint32(y shr 32)
    a = uint64(z0) * uint64(y1) + ((uint64(z0) * uint64(y0)) shr 32)
    b = uint64(z1) * uint64(y0)
    var c = (a shr 32) + (b shr 32)
    c = c + ((uint64(uint32(a)) + uint64(uint32(b))) shr 32)
    c = c + uint64(z1) * uint64(y1)
    y = C[u] - c
    inc u
  z = uint64(fprTrunc(fprMul(ccs, fprPTwo63))) shl 1
  z0 = uint32(z)
  z1 = uint32(z shr 32)
  y0 = uint32(y)
  y1 = uint32(y shr 32)
  a = uint64(z0) * uint64(y1) + ((uint64(z0) * uint64(y0)) shr 32)
  b = uint64(z1) * uint64(y0)
  y = (a shr 32) + (b shr 32)
  y = y + ((uint64(uint32(a)) + uint64(uint32(b))) shr 32)
  y = y + uint64(z1) * uint64(y1)
  y

include ./fpr_gm_tab
