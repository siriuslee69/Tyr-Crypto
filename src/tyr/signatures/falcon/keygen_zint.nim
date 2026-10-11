## -------------------------------------------------------------------
## Falcon Keygen, level 1 <- big numbers as arrays of 31-bit words
## -------------------------------------------------------------------
##
## A big number is a run of 31-bit words, least significant first, in
## two's complement (bit 30 of the top word is the sign):
##
##   value = w[0] + w[1]·2^31 + w[2]·2^62 + ...
##
## Every routine here runs in constant time: the work never depends on
## the values, because the values are secret.
##
##   zintSub / zintMulSmall / zintAddMulSmall    word-array arithmetic
##   zintModSmallSigned                          big number -> mod p
##   zintBezout                                  x·u - y·v = 1 (GCD)
##   zintAddScaledMulSmall / zintSubScaled       x ± k·y·2^shift

import ./keygen_modp
import runePragmas

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `zintSub`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc zintSub(a: var seq[uint32], aOff: int, b: openArray[uint32], bOff, len: int,
    ctl: uint32): uint32 {.role: {math}.} =
  ## a -= b when ctl = 1 (the work is done either way, constant time).
  ## Returns the final borrow.
  var
    m: uint32 = 0'u32 - ctl
    aw: uint32 = 0'u32
    w: uint32 = 0'u32
    u: int = 0
  while u < len:
    aw = a[aOff + u]
    w = aw - b[bOff + u] - result
    result = w shr 31
    aw = aw xor (((w and 0x7FFFFFFF'u32) xor aw) and m)
    a[aOff + u] = aw
    u = u + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `zintMulSmall`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc zintMulSmall*(m: var seq[uint32], mOff, mLen: int, x: uint32): uint32 {.role: {math}.} =
  ## m *= x in place. Returns the carry word that did not fit.
  var
    z: uint64 = 0'u64
    u: int = 0
  while u < mLen:
    z = uint64(m[mOff + u]) * uint64(x) + uint64(result)
    m[mOff + u] = uint32(z) and 0x7FFFFFFF'u32
    result = uint32(z shr 31)
    u = u + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `zintModSmallUnsigned`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc zintModSmallUnsigned*(d: openArray[uint32], dOff, dLen: int,
    p, p0i, R2: uint32): uint32 {.role: {math}.} =
  ## d: unsigned big number. Returns d mod p, constant time.
  var
    w: uint32 = 0'u32
    u: int = dLen
  while u > 0:
    u = u - 1
    result = modpMontyMul(result, R2, p, p0i)
    w = d[dOff + u] - p
    w += p and (0'u32 - (w shr 31))
    result = modpAdd(result, w, p)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `zintModSmallSigned`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc zintModSmallSigned*(d: openArray[uint32], dOff, dLen: int,
    p, p0i, R2, Rx: uint32): uint32 {.role: {math}.} =
  ## d: signed big number (two's complement on 31-bit words). Returns d mod p.
  ## Rx: 2^(31·dLen) mod p, removed again when d is negative.
  if dLen == 0:
    return 0'u32
  result = zintModSmallUnsigned(d, dOff, dLen, p, p0i, R2)
  result = modpSub(result, Rx and (0'u32 - (d[dOff + dLen - 1] shr 30)), p)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `zintAddMulSmall`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc zintAddMulSmall*(x: var seq[uint32], xOff: int, y: openArray[uint32], yOff, len: int,
    s: uint32) {.role: {math}.} =
  ## x += y·s; x has one more word than y, which receives the top carry.
  var
    z: uint64 = 0'u64
    cc: uint32 = 0'u32
    u: int = 0
  while u < len:
    z = uint64(y[yOff + u]) * uint64(s) + uint64(x[xOff + u]) + uint64(cc)
    x[xOff + u] = uint32(z) and 0x7FFFFFFF'u32
    cc = uint32(z shr 31)
    u = u + 1
  x[xOff + len] = cc

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `zintNormZero`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc zintNormZero*(x: var seq[uint32], xOff: int, p: openArray[uint32], pOff, len: int) {.role: {math}.} =
  ## x: value in 0 ..< p. Subtracts p when x > p/2, so x lands in -p/2 .. p/2.
  var
    r: uint32 = 0'u32
    bb: uint32 = 0'u32
    wx: uint32 = 0'u32
    wp: uint32 = 0'u32
    cc: uint32 = 0'u32
    u: int = len
  while u > 0:
    u = u - 1
    wx = x[xOff + u]
    wp = (p[pOff + u] shr 1) or (bb shl 30)
    bb = p[pOff + u] and 1'u32
    cc = wp - wx
    cc = ((0'u32 - cc) shr 31) or (0'u32 - (cc shr 31))
    r = r or (cc and ((r and 1'u32) - 1'u32))
  discard zintSub(x, xOff, p, pOff, len, r shr 31)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `zintNegate`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc zintNegate(a: var seq[uint32], aOff, len: int, ctl: uint32) {.role: {math}.} =
  ## a = -a when ctl = 1, constant time.
  var
    cc: uint32 = ctl
    m: uint32 = (0'u32 - ctl) shr 1
    aw: uint32 = 0'u32
    u: int = 0
  while u < len:
    aw = (a[aOff + u] xor m) + cc
    a[aOff + u] = aw and 0x7FFFFFFF'u32
    cc = aw shr 31
    u = u + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `zintCoReduce`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc zintCoReduce(a, b: var seq[uint32], aOff, bOff, len: int,
    xa, xb, ya, yb: int64): uint32 {.role: {math}.} =
  ## (a, b) = ((a·xa + b·xb) / 2^31, (a·ya + b·yb) / 2^31), then both made
  ## positive. Returns bit 0 = a was negated, bit 1 = b was negated.
  var
    cca: int64 = 0'i64
    ccb: int64 = 0'i64
    wa: uint32 = 0'u32
    wb: uint32 = 0'u32
    za: uint64 = 0'u64
    zb: uint64 = 0'u64
    nega: uint32 = 0'u32
    negb: uint32 = 0'u32
    u: int = 0
  while u < len:
    wa = a[aOff + u]
    wb = b[bOff + u]
    za = uint64(wa) * uint64(cast[uint64](xa)) + uint64(wb) * uint64(cast[uint64](xb)) + uint64(cast[uint64](cca))
    zb = uint64(wa) * uint64(cast[uint64](ya)) + uint64(wb) * uint64(cast[uint64](yb)) + uint64(cast[uint64](ccb))
    if u > 0:
      a[aOff + u - 1] = uint32(za) and 0x7FFFFFFF'u32
      b[bOff + u - 1] = uint32(zb) and 0x7FFFFFFF'u32
    cca = cast[int64](za) shr 31
    ccb = cast[int64](zb) shr 31
    u = u + 1
  a[aOff + len - 1] = uint32(cca)
  b[bOff + len - 1] = uint32(ccb)
  nega = uint32(cast[uint64](cca) shr 63)
  negb = uint32(cast[uint64](ccb) shr 63)
  zintNegate(a, aOff, len, nega)
  zintNegate(b, bOff, len, negb)
  nega or (negb shl 1)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `zintFinishMod`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc zintFinishMod(a: var seq[uint32], aOff, len: int,
    m: openArray[uint32], mOff: int, neg: uint32) {.role: {math}.} =
  ## a: value in -m .. 2m (neg = 1 when negative). Brought into 0 ..< m by
  ## adding or subtracting m once, constant time.
  var
    cc: uint32 = 0'u32
    xm: uint32 = 0'u32
    ym: uint32 = 0'u32
    aw: uint32 = 0'u32
    mw: uint32 = 0'u32
    u: int = 0
  while u < len:
    cc = (a[aOff + u] - m[mOff + u] - cc) shr 31
    u = u + 1
  xm = (0'u32 - neg) shr 1
  ym = 0'u32 - (neg or (1'u32 - cc))
  cc = neg
  u = 0
  while u < len:
    aw = a[aOff + u]
    mw = (m[mOff + u] xor xm) and ym
    aw = aw - mw - cc
    a[aOff + u] = aw and 0x7FFFFFFF'u32
    cc = aw shr 31
    u = u + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `zintCoReduceMod`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc zintCoReduceMod(a, b: var seq[uint32], aOff, bOff: int,
    m: openArray[uint32], mOff, len: int, m0i: uint32,
    xa, xb, ya, yb: int64) {.role: {math}.} =
  ## Same as zintCoReduce, but modulo m: a multiple of m is added first so
  ## the division by 2^31 is exact (Montgomery style). m0i: -1/m mod 2^31.
  var
    cca: int64 = 0'i64
    ccb: int64 = 0'i64
    fa: uint32 = ((a[aOff] * uint32(xa) + b[bOff] * uint32(xb)) * m0i) and 0x7FFFFFFF'u32
    fb: uint32 = ((a[aOff] * uint32(ya) + b[bOff] * uint32(yb)) * m0i) and 0x7FFFFFFF'u32
    wa: uint32 = 0'u32
    wb: uint32 = 0'u32
    za: uint64 = 0'u64
    zb: uint64 = 0'u64
    u: int = 0
  while u < len:
    wa = a[aOff + u]
    wb = b[bOff + u]
    za = uint64(wa) * uint64(cast[uint64](xa)) + uint64(wb) * uint64(cast[uint64](xb)) +
      uint64(m[mOff + u]) * uint64(fa) + uint64(cast[uint64](cca))
    zb = uint64(wa) * uint64(cast[uint64](ya)) + uint64(wb) * uint64(cast[uint64](yb)) +
      uint64(m[mOff + u]) * uint64(fb) + uint64(cast[uint64](ccb))
    if u > 0:
      a[aOff + u - 1] = uint32(za) and 0x7FFFFFFF'u32
      b[bOff + u - 1] = uint32(zb) and 0x7FFFFFFF'u32
    cca = cast[int64](za) shr 31
    ccb = cast[int64](zb) shr 31
    u = u + 1
  a[aOff + len - 1] = uint32(cca)
  b[bOff + len - 1] = uint32(ccb)
  zintFinishMod(a, aOff, len, m, mOff, uint32(cast[uint64](cca) shr 63))
  zintFinishMod(b, bOff, len, m, mOff, uint32(cast[uint64](ccb) shr 63))

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `bezoutTopWords`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc bezoutTopWords(a, b: openArray[uint32], len: int): tuple[aHi, bHi: uint64]
    {.role: {math}.} =
  ## a/b: big numbers of len words. Returns their top 62 bits, both taken
  ## from the highest word where either is non-zero. Every word is read, so
  ## the time does not depend on the values.
  var
    c0: uint32 = uint32.high
    c1: uint32 = uint32.high
    a0: uint32 = 0'u32
    a1: uint32 = 0'u32
    b0: uint32 = 0'u32
    b1: uint32 = 0'u32
    aw: uint32 = 0'u32
    bw: uint32 = 0'u32
    j: int = len
  while j > 0:
    j = j - 1
    aw = a[j]
    bw = b[j]
    a0 = a0 xor ((a0 xor aw) and c0)
    a1 = a1 xor ((a1 xor aw) and c1)
    b0 = b0 xor ((b0 xor bw) and c0)
    b1 = b1 xor ((b1 xor bw) and c1)
    c1 = c0
    c0 = c0 and ((((aw or bw) + 0x7FFFFFFF'u32) shr 31) - 1'u32)
  a1 = a1 or (a0 and c1)
  a0 = a0 and (not c1)
  b1 = b1 or (b0 and c1)
  b0 = b0 and (not c1)
  result.aHi = (uint64(a0) shl 31) + uint64(a1)
  result.bHi = (uint64(b0) shl 31) + uint64(b1)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `bezoutSteps31`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc bezoutSteps31(aHiIn, bHiIn: uint64, aLoIn, bLoIn: uint32):
    tuple[pa, pb, qa, qb: int64] {.role: {math}.} =
  ## aHi/bHi: top bits of a, b. aLo/bLo: their lowest words.
  ## Runs 31 constant-time binary-GCD steps on these approximations and
  ## returns the factors that apply the same steps to the full numbers:
  ##   a' = (a·pa + b·pb) / 2^31,  b' = (a·qa + b·qb) / 2^31
  var
    aHi: uint64 = aHiIn
    bHi: uint64 = bHiIn
    aLo: uint32 = aLoIn
    bLo: uint32 = bLoIn
    pa: int64 = 1'i64
    pb: int64 = 0'i64
    qa: int64 = 0'i64
    qb: int64 = 1'i64
    rz: uint64 = 0'u64
    rt: uint32 = 0'u32
    oa: uint32 = 0'u32
    ob: uint32 = 0'u32
    cAB: uint32 = 0'u32
    cBA: uint32 = 0'u32
    cA: uint32 = 0'u32
    maskAB: uint64 = 0'u64
    maskBA: uint64 = 0'u64
    maskA: uint64 = 0'u64
    maskNotA: uint64 = 0'u64
    i: int = 0
  while i < 31:
    rz = bHi - aHi
    rt = uint32((rz xor ((aHi xor bHi) and (aHi xor rz))) shr 63)
    oa = (aLo shr i) and 1'u32
    ob = (bLo shr i) and 1'u32
    cAB = oa and ob and rt
    cBA = oa and ob and (rt xor 1'u32)
    cA = cAB or (oa xor 1'u32)
    maskAB = 0'u64 - uint64(cAB)
    maskBA = 0'u64 - uint64(cBA)
    maskA = 0'u64 - uint64(cA)
    maskNotA = uint64.high xor maskA
    aLo = aLo - (bLo and (0'u32 - cAB))
    aHi = aHi - (bHi and maskAB)
    pa = pa - (qa and (0'i64 - int64(cAB)))
    pb = pb - (qb and (0'i64 - int64(cAB)))
    bLo = bLo - (aLo and (0'u32 - cBA))
    bHi = bHi - (aHi and maskBA)
    qa = qa - (pa and (0'i64 - int64(cBA)))
    qb = qb - (pb and (0'i64 - int64(cBA)))
    aLo = aLo + (aLo and (cA - 1'u32))
    pa = pa + (pa and (int64(cA) - 1'i64))
    pb = pb + (pb and (int64(cA) - 1'i64))
    aHi = aHi xor ((aHi xor (aHi shr 1)) and maskA)
    bLo = bLo + (bLo and (0'u32 - cA))
    qa = qa + (qa and (0'i64 - int64(cA)))
    qb = qb + (qb and (0'i64 - int64(cA)))
    bHi = bHi xor ((bHi xor (bHi shr 1)) and maskNotA)
    i = i + 1
  result = (pa, pb, qa, qb)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `zintBezout`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc zintBezout*(u, v: var seq[uint32], x, y: openArray[uint32], len: int): bool {.role: {math}.} =
  ## x/y: odd big numbers of len words. Finds u, v with x·u - y·v = 1
  ## (constant-time binary extended GCD, 30 bits per round).
  ## False when gcd(x, y) != 1 or x, y are not both odd.
  var
    u0: seq[uint32] = @[]
    v0: seq[uint32] = @[]
    u1: seq[uint32] = @[]
    v1: seq[uint32] = @[]
    a: seq[uint32] = @[]
    b: seq[uint32] = @[]
    x0i: uint32 = 0'u32
    y0i: uint32 = 0'u32
    num: uint32 = 62 * uint32(len) + 30'u32
    hi: tuple[aHi, bHi: uint64] = (0'u64, 0'u64)
    f: tuple[pa, pb, qa, qb: int64] = (0'i64, 0'i64, 0'i64, 0'i64)
    r: uint32 = 0'u32
    rc: uint32 = 0'u32
    j: int = 1
  if len == 0:
    return false
  u0 = newSeq[uint32](len)
  v0 = newSeq[uint32](len)
  u1 = newSeq[uint32](len)
  v1 = newSeq[uint32](len)
  a = newSeq[uint32](len)
  b = newSeq[uint32](len)
  x0i = modpNinv31(x[0])
  y0i = modpNinv31(y[0])
  copyMem(addr a[0], unsafeAddr x[0], len * sizeof(uint32))
  copyMem(addr b[0], unsafeAddr y[0], len * sizeof(uint32))
  u0[0] = 1'u32
  copyMem(addr u1[0], unsafeAddr y[0], len * sizeof(uint32))
  copyMem(addr v1[0], unsafeAddr x[0], len * sizeof(uint32))
  dec v1[0]
  while num >= 30'u32:
    hi = bezoutTopWords(a, b, len)
    f = bezoutSteps31(hi.aHi, hi.bHi, a[0], b[0])
    r = zintCoReduce(a, b, 0, 0, len, f.pa, f.pb, f.qa, f.qb)
    f.pa = f.pa - ((f.pa + f.pa) and (0'i64 - int64(r and 1'u32)))
    f.pb = f.pb - ((f.pb + f.pb) and (0'i64 - int64(r and 1'u32)))
    f.qa = f.qa - ((f.qa + f.qa) and (0'i64 - int64(r shr 1)))
    f.qb = f.qb - ((f.qb + f.qb) and (0'i64 - int64(r shr 1)))
    zintCoReduceMod(u0, u1, 0, 0, y, 0, len, y0i, f.pa, f.pb, f.qa, f.qb)
    zintCoReduceMod(v0, v1, 0, 0, x, 0, len, x0i, f.pa, f.pb, f.qa, f.qb)
    num -= 30'u32
  rc = a[0] xor 1'u32
  while j < len:
    rc = rc or a[j]
    j = j + 1
  if ((1'u32 - ((rc or (0'u32 - rc)) shr 31)) and x[0] and y[0]) == 0'u32:
    return false
  u = u0
  v = v0
  true

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `scaledWord`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc scaledWord(y: openArray[uint32], yOff, yLen, v: int, ysign, scl: uint32,
    tw: var uint32): uint32 {.inline, role: {math}.} =
  ## Word v of y·2^scl, with y sign-extended past yLen (ysign: fill word).
  ## tw: bits pushed out of the previous word, updated for the next one.
  var
    wy: uint32 = (if v < yLen: y[yOff + v] else: ysign)
  result = ((wy shl scl) and 0x7FFFFFFF'u32) or tw
  tw = (if scl == 0'u32: 0'u32 else: wy shr (31'u32 - scl))

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `zintAddScaledMulSmall`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc zintAddScaledMulSmall*(x: var seq[uint32], xOff, xLen: int,
    y: openArray[uint32], yOff, yLen: int, k: int32, sch, scl: uint32) {.role: {math}.} =
  ## x += k·y·2^(31·sch + scl), all signed, truncated to xLen words.
  var
    ysign: uint32 = 0'u32
    tw: uint32 = 0'u32
    cc: int32 = 0'i32
    wys: uint32 = 0'u32
    z: uint64 = 0'u64
    u: int = int(sch)
  if yLen == 0:
    return
  ysign = (0'u32 - (y[yOff + yLen - 1] shr 30)) shr 1
  while u < xLen:
    wys = scaledWord(y, yOff, yLen, u - int(sch), ysign, scl, tw)
    z = cast[uint64](int64(wys) * int64(k) + int64(x[xOff + u]) + int64(cc))
    x[xOff + u] = uint32(z) and 0x7FFFFFFF'u32
    cc = cast[int32](uint32(z shr 31))
    u = u + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `zintSubScaled`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc zintSubScaled*(x: var seq[uint32], xOff, xLen: int,
    y: openArray[uint32], yOff, yLen: int, sch, scl: uint32) {.role: {math}.} =
  ## x -= y·2^(31·sch + scl), all signed, truncated to xLen words.
  var
    ysign: uint32 = 0'u32
    tw: uint32 = 0'u32
    cc: uint32 = 0'u32
    wys: uint32 = 0'u32
    w: uint32 = 0'u32
    u: int = int(sch)
  if yLen == 0:
    return
  ysign = (0'u32 - (y[yOff + yLen - 1] shr 30)) shr 1
  while u < xLen:
    wys = scaledWord(y, yOff, yLen, u - int(sch), ysign, scl, tw)
    w = x[xOff + u] - wys - cc
    x[xOff + u] = w and 0x7FFFFFFF'u32
    cc = w shr 31
    u = u + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `zintOneToPlain`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc zintOneToPlain*(x: openArray[uint32], off: int): int32 {.inline, role: {math}.} =
  ## x[off]: one signed 31-bit word, returned as a normal int32.
  var
    w: uint32 = x[off]
  w = w or ((w and 0x40000000'u32) shl 1)
  cast[int32](w)

