## ------------------------------------------------------------------
## Falcon Fpr <- integer-backed binary64 helpers for the pure-Nim port
## ------------------------------------------------------------------

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

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; finite-field, ring, and transform arithmetic for `fprUrsh`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc fprUrsh*(x: uint64, n: int): uint64 {.inline.} =
  var v = x xor ((x xor (x shr 32)) and (0'u64 - uint64(n shr 5)))
  v shr (n and 31)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; finite-field, ring, and transform arithmetic for `fprIrsh`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc fprIrsh*(x: int64, n: int): int64 {.inline.} =
  var
    v: int64 = x
  v = v xor ((v xor ashr(v, 32)) and (0'i64 - int64(n shr 5)))
  result = ashr(v, n and 31)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; finite-field, ring, and transform arithmetic for `fprUlsh`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc fprUlsh*(x: uint64, n: int): uint64 {.inline.} =
  var v = x xor ((x xor (x shl 32)) and (0'u64 - uint64(n shr 5)))
  v shl (n and 31)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; finite-field, ring, and transform arithmetic for `makeFpr`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; finite-field, ring, and transform arithmetic for `norm64`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; finite-field, ring, and transform arithmetic for `fprScaled`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; finite-field, ring, and transform arithmetic for `fprOf`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc fprOf*(i: int64): FalconFpr {.inline.} =
  fprScaled(i, 0)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; finite-field, ring, and transform arithmetic for `fprToFloat`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc fprToFloat*(x: FalconFpr): float64 {.inline.} =
  ## Debug/unsafe-native-backend conversion only. Secret arithmetic uses the
  ## integer helpers below so floating-point latency cannot reveal operands.
  cast[float64](x)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; finite-field, ring, and transform arithmetic for `fprIsFinite`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc fprIsFinite*(x: FalconFpr): bool {.inline.} =
  ((uint64(x) shr 52) and 0x7ff'u64) != 0x7ff'u64

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; finite-field, ring, and transform arithmetic for `floatToFpr`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc floatToFpr*(x: float64): FalconFpr {.inline.} =
  ## Debug/unsafe-native-backend conversion only.
  cast[FalconFpr](x)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; finite-field, ring, and transform arithmetic for `fprRint`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc fprRint*(x: FalconFpr): int64 =
  var
    m: uint64 = 0
    d: uint64 = 0
    e: int = 0
    s: uint32 = 0
    dd: uint32 = 0
    f: uint32 = 0
  m = ((x shl 10) or (1'u64 shl 62)) and ((1'u64 shl 63) - 1'u64)
  e = 1085 - int((x shr 52) and 0x7ff'u64)
  m = m and (0'u64 - uint64(uint32(e - 64) shr 31))
  e = e and 63
  d = fprUlsh(m, 63 - e)
  dd = uint32(d) or (uint32(d shr 32) and 0x1fffffff'u32)
  f = uint32(d shr 61) or ((dd or (0'u32 - dd)) shr 31)
  m = fprUrsh(m, e) + uint64((0xc8'u32 shr f) and 1'u32)
  s = uint32(x shr 63)
  result = (cast[int64](m) xor (0'i64 - int64(s))) + int64(s)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; finite-field, ring, and transform arithmetic for `fprFloor`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc fprFloor*(x: FalconFpr): int64 =
  var
    t: uint64 = 0
    xi: int64 = 0
    e: int = 0
    cc: int = 0
  e = int((x shr 52) and 0x7ff'u64)
  t = x shr 63
  xi = cast[int64](((x shl 10) or (1'u64 shl 62)) and
    ((1'u64 shl 63) - 1'u64))
  xi = (xi xor (0'i64 - int64(t))) + int64(t)
  cc = 1085 - e
  xi = fprIrsh(xi, cc and 63)
  xi = xi xor ((xi xor (0'i64 - int64(t))) and
    (0'i64 - int64(uint32(63 - cc) shr 31)))
  result = xi

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; finite-field, ring, and transform arithmetic for `fprTrunc`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc fprTrunc*(x: FalconFpr): int64 =
  var
    t: uint64 = 0
    xu: uint64 = 0
    e: int = 0
    cc: int = 0
  e = int((x shr 52) and 0x7ff'u64)
  xu = ((x shl 10) or (1'u64 shl 62)) and ((1'u64 shl 63) - 1'u64)
  cc = 1085 - e
  xu = fprUrsh(xu, cc and 63)
  xu = xu and (0'u64 - uint64(uint32(cc - 64) shr 31))
  t = x shr 63
  xu = (xu xor (0'u64 - t)) + t
  result = cast[int64](xu)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; finite-field, ring, and transform arithmetic for `fprAdd`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc fprAdd*(x, y: FalconFpr): FalconFpr =
  var
    xx: uint64 = x
    yy: uint64 = y
    m: uint64 = 0
    xu: uint64 = 0
    yu: uint64 = 0
    za: uint64 = 0
    cs: uint32 = 0
    ex: int = 0
    ey: int = 0
    sx: int = 0
    sy: int = 0
    cc: int = 0
  m = (1'u64 shl 63) - 1'u64
  za = (xx and m) - (yy and m)
  cs = uint32(za shr 63) or
    ((1'u32 - uint32((0'u64 - za) shr 63)) and uint32(xx shr 63))
  m = (xx xor yy) and (0'u64 - uint64(cs))
  xx = xx xor m
  yy = yy xor m
  ex = int(xx shr 52)
  sx = ex shr 11
  ex = ex and 0x7ff
  m = uint64(uint32((ex + 0x7ff) shr 11)) shl 52
  xu = ((xx and ((1'u64 shl 52) - 1'u64)) or m) shl 3
  ex = ex - 1078
  ey = int(yy shr 52)
  sy = ey shr 11
  ey = ey and 0x7ff
  m = uint64(uint32((ey + 0x7ff) shr 11)) shl 52
  yu = ((yy and ((1'u64 shl 52) - 1'u64)) or m) shl 3
  ey = ey - 1078
  cc = ex - ey
  yu = yu and (0'u64 - uint64(uint32(cc - 60) shr 31))
  cc = cc and 63
  m = fprUlsh(1'u64, cc) - 1'u64
  yu = yu or ((yu and m) + m)
  yu = fprUrsh(yu, cc)
  xu = xu + yu - ((yu shl 1) and
    (0'u64 - uint64(sx xor sy)))
  norm64(xu, ex)
  xu = xu or (uint64(uint32(xu) and 0x1ff'u32) + 0x1ff'u64)
  xu = xu shr 9
  ex = ex + 9
  result = makeFpr(sx, ex, xu)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; finite-field, ring, and transform arithmetic for `fprSub`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc fprSub*(x, y: FalconFpr): FalconFpr {.inline.} =
  fprAdd(x, y xor (1'u64 shl 63))

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; finite-field, ring, and transform arithmetic for `fprNeg`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc fprNeg*(x: FalconFpr): FalconFpr {.inline.} =
  x xor (1'u64 shl 63)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; finite-field, ring, and transform arithmetic for `fprHalf`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc fprHalf*(x: FalconFpr): FalconFpr {.inline.} =
  var
    t: uint32 = 0
    y: uint64 = x
  y = y - (1'u64 shl 52)
  t = (((uint32(y shr 52) and 0x7ff'u32) + 1'u32) shr 11)
  result = y and (uint64(t) - 1'u64)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; finite-field, ring, and transform arithmetic for `fprDouble`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc fprDouble*(x: FalconFpr): FalconFpr {.inline.} =
  result = x + (uint64(((uint32(x shr 52) and 0x7ff'u32) +
    0x7ff'u32) shr 11) shl 52)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; finite-field, ring, and transform arithmetic for `fprMul`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc fprMul*(x, y: FalconFpr): FalconFpr =
  var
    xu: uint64 = 0
    yu: uint64 = 0
    w: uint64 = 0
    zu: uint64 = 0
    zv: uint64 = 0
    x0: uint32 = 0
    x1: uint32 = 0
    y0: uint32 = 0
    y1: uint32 = 0
    z0: uint32 = 0
    z1: uint32 = 0
    z2: uint32 = 0
    ex: int = 0
    ey: int = 0
    d: int = 0
    e: int = 0
    s: int = 0
  xu = (x and ((1'u64 shl 52) - 1'u64)) or (1'u64 shl 52)
  yu = (y and ((1'u64 shl 52) - 1'u64)) or (1'u64 shl 52)
  x0 = uint32(xu) and 0x01ffffff'u32
  x1 = uint32(xu shr 25)
  y0 = uint32(yu) and 0x01ffffff'u32
  y1 = uint32(yu shr 25)
  w = uint64(x0) * uint64(y0)
  z0 = uint32(w) and 0x01ffffff'u32
  z1 = uint32(w shr 25)
  w = uint64(x0) * uint64(y1)
  z1 = z1 + (uint32(w) and 0x01ffffff'u32)
  z2 = uint32(w shr 25)
  w = uint64(x1) * uint64(y0)
  z1 = z1 + (uint32(w) and 0x01ffffff'u32)
  z2 = z2 + uint32(w shr 25)
  zu = uint64(x1) * uint64(y1)
  z2 = z2 + (z1 shr 25)
  z1 = z1 and 0x01ffffff'u32
  zu = zu + uint64(z2)
  zu = zu or uint64(((z0 or z1) + 0x01ffffff'u32) shr 25)
  zv = (zu shr 1) or (zu and 1'u64)
  w = zu shr 55
  zu = zu xor ((zu xor zv) and (0'u64 - w))
  ex = int((x shr 52) and 0x7ff'u64)
  ey = int((y shr 52) and 0x7ff'u64)
  e = ex + ey - 2100 + int(w)
  s = int((x xor y) shr 63)
  d = ((ex + 0x7ff) and (ey + 0x7ff)) shr 11
  zu = zu and (0'u64 - uint64(d))
  result = makeFpr(s, e, zu)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; finite-field, ring, and transform arithmetic for `fprSqr`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc fprSqr*(x: FalconFpr): FalconFpr {.inline.} =
  fprMul(x, x)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; finite-field, ring, and transform arithmetic for `fprDiv`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc fprDiv*(x, y: FalconFpr): FalconFpr =
  var
    xu: uint64 = 0
    yu: uint64 = 0
    q: uint64 = 0
    q2: uint64 = 0
    w: uint64 = 0
    b: uint64 = 0
    i: int = 0
    ex: int = 0
    ey: int = 0
    e: int = 0
    d: int = 0
    s: int = 0
  xu = (x and ((1'u64 shl 52) - 1'u64)) or (1'u64 shl 52)
  yu = (y and ((1'u64 shl 52) - 1'u64)) or (1'u64 shl 52)
  while i < 55:
    b = ((xu - yu) shr 63) - 1'u64
    xu = xu - (b and yu)
    q = q or (b and 1'u64)
    xu = xu shl 1
    q = q shl 1
    i = i + 1
  q = q or ((xu or (0'u64 - xu)) shr 63)
  q2 = (q shr 1) or (q and 1'u64)
  w = q shr 55
  q = q xor ((q xor q2) and (0'u64 - w))
  ex = int((x shr 52) and 0x7ff'u64)
  ey = int((y shr 52) and 0x7ff'u64)
  e = ex - ey - 55 + int(w)
  s = int((x xor y) shr 63)
  d = (ex + 0x7ff) shr 11
  s = s and d
  e = e and (0 - d)
  q = q and (0'u64 - uint64(d))
  result = makeFpr(s, e, q)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; finite-field, ring, and transform arithmetic for `fprInv`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc fprInv*(x: FalconFpr): FalconFpr {.inline.} =
  fprDiv(fprOne, x)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; finite-field, ring, and transform arithmetic for `fprSqrt`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc fprSqrt*(x: FalconFpr): FalconFpr =
  var
    xu: uint64 = 0
    q: uint64 = 0
    s: uint64 = 0
    r: uint64 = 0
    t: uint64 = 0
    b: uint64 = 0
    ex: int = 0
    e: int = 0
    i: int = 0
  xu = (x and ((1'u64 shl 52) - 1'u64)) or (1'u64 shl 52)
  ex = int((x shr 52) and 0x7ff'u64)
  e = ex - 1023
  xu = xu + (xu and (0'u64 - uint64(e and 1)))
  e = ashr(e, 1)
  xu = xu shl 1
  r = 1'u64 shl 53
  while i < 54:
    t = s + r
    b = ((xu - t) shr 63) - 1'u64
    s = s + ((r shl 1) and b)
    xu = xu - (t and b)
    q = q + (r and b)
    xu = xu shl 1
    r = r shr 1
    i = i + 1
  q = q shl 1
  q = q or ((xu or (0'u64 - xu)) shr 63)
  e = e - 54
  q = q and (0'u64 - uint64((ex + 0x7ff) shr 11))
  result = makeFpr(0, e, q)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; finite-field, ring, and transform arithmetic for `fprLt`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc fprLt*(x, y: FalconFpr): bool {.inline.} =
  var
    cc0: int = 0
    cc1: int = 0
    sx: int64 = cast[int64](x)
    sy: int64 = cast[int64](y)
  sy = sy and not ashr(sx xor sy, 63)
  cc0 = int(ashr(sx - sy, 63)) and 1
  cc1 = int(ashr(sy - sx, 63)) and 1
  result = (cc0 xor ((cc0 xor cc1) and int((x and y) shr 63))) != 0

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; finite-field, ring, and transform arithmetic for `fprExpmP63`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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
