## -------------------------------------------------------------------
## Falcon Keygen <- pure-Nim Falcon key generation and NTRU solving
## -------------------------------------------------------------------

import ./codec
import ./fft
import ./fpr
import ./params
when falconCompileHasSimd:
  import ./fpr_simd
import ./randomness
import ./shake
import ./util
import ./vrfy
import ../../../../helpers/otter_support

type
  FalconSmallPrime* = object
    p*: uint32
    g*: uint32
    s*: uint32

  FalconBitlengthStats* = object
    avg*: int
    std*: int

  RnsPoly = object
    n: int
    stride: int
    coeffs: seq[uint32]

  FalconSigned31 = object
    neg: bool
    words: seq[uint32]

include ./keygen_consts

template mknSize(logn: int): int =
  1 shl logn

template rnsAt(poly: RnsPoly, coeff, word: int): untyped =
  poly.coeffs[(coeff) * poly.stride + (word)]

template seqAt(A: seq[uint32], off, idx: int): untyped =
  A[(off) + (idx)]

const
  falconWordMask = 0x7FFFFFFF'u32

proc initRnsPoly(n, stride: int): RnsPoly {.inline.} =
  RnsPoly(n: n, stride: stride, coeffs: newSeq[uint32](n * stride))

proc clonePoly(poly: RnsPoly): RnsPoly =
  result.n = poly.n
  result.stride = poly.stride
  result.coeffs = newSeq[uint32](poly.coeffs.len)
  if poly.coeffs.len > 0:
    copyMem(addr result.coeffs[0], unsafeAddr poly.coeffs[0], poly.coeffs.len * sizeof(uint32))

proc coeffOffset(poly: RnsPoly, coeff: int): int {.inline.} =
  coeff * poly.stride

proc bitReverse10(x: int): int =
  var
    src = x
    dst = 0
    i = 0
  while i < 10:
    dst = (dst shl 1) or (src and 1)
    src = src shr 1
    inc i
  dst

proc modpSet(x: int32, p: uint32): uint32 {.inline.} =
  var w = cast[uint32](x)
  w += p and (0'u32 - (w shr 31))
  w

proc modpNorm(x, p: uint32): int32 {.inline.} =
  cast[int32](x - (p and (((x - ((p + 1'u32) shr 1)) shr 31) - 1'u32)))

proc modpNinv31(p: uint32): uint32 =
  var y = 2'u32 - p
  y *= 2'u32 - p * y
  y *= 2'u32 - p * y
  y *= 2'u32 - p * y
  y *= 2'u32 - p * y
  0x7FFFFFFF'u32 and (0'u32 - y)

proc modpR(p: uint32): uint32 {.inline.} =
  (1'u32 shl 31) - p

proc modpAdd(a, b, p: uint32): uint32 {.inline.} =
  var d = a + b - p
  d += p and (0'u32 - (d shr 31))
  d

proc modpSub(a, b, p: uint32): uint32 {.inline.} =
  var d = a - b
  d += p and (0'u32 - (d shr 31))
  d

proc modpMontyMul(a, b, p, p0i: uint32): uint32 {.inline.} =
  let z = uint64(a) * uint64(b)
  let w = ((z * uint64(p0i)) and 0x7FFFFFFF'u64) * uint64(p)
  var d = uint32((z + w) shr 31) - p
  d += p and (0'u32 - (d shr 31))
  d

proc modpR2(p, p0i: uint32): uint32 =
  var z = modpR(p)
  z = modpAdd(z, z, p)
  var i = 0
  while i < 5:
    z = modpMontyMul(z, z, p, p0i)
    inc i
  (z + (p and (0'u32 - (z and 1'u32)))) shr 1

proc modpRx(x: int, p, p0i, R2: uint32): uint32 {.inline.} =
  var
    e = x - 1
    r = R2
    z = modpR(p)
    i = 0
  while (1 shl i) <= e:
    if (e and (1 shl i)) != 0:
      z = modpMontyMul(z, r, p, p0i)
    r = modpMontyMul(r, r, p, p0i)
    inc i
  z

proc modpDiv(a, b, p, p0i, R: uint32): uint32 =
  var
    z = R
    e = p - 2'u32
    i = 30
  while i >= 0:
    z = modpMontyMul(z, z, p, p0i)
    let z2 = modpMontyMul(z, b, p, p0i)
    z = z xor ((z xor z2) and (0'u32 - ((e shr i) and 1'u32)))
    dec i
  z = modpMontyMul(z, 1'u32, p, p0i)
  modpMontyMul(a, z, p, p0i)

proc modpMkgm2(gm, igm: var seq[uint32], logn: int, g, p, p0i: uint32) =
  let n = mknSize(logn)
  gm.setLen(n)
  igm.setLen(n)
  var
    root = modpMontyMul(g, modpR2(p, p0i), p, p0i)
    k = logn
  while k < 10:
    root = modpMontyMul(root, root, p, p0i)
    inc k
  let ig = modpDiv(modpR2(p, p0i), root, p, p0i, modpR(p))
  let shift = 10 - logn
  var
    x1 = modpR(p)
    x2 = modpR(p)
    u = 0
  while u < n:
    let v = bitReverse10(u shl shift)
    gm[v] = x1
    igm[v] = x2
    x1 = modpMontyMul(x1, root, p, p0i)
    x2 = modpMontyMul(x2, ig, p, p0i)
    inc u

proc modpNtt2Ext(a: var seq[uint32], off, stride: int,
    gm: openArray[uint32], logn: int, p, p0i: uint32) =
  if logn == 0:
    return
  let n = mknSize(logn)
  var
    t = n
    m = 1
  while m < n:
    let ht = t shr 1
    var
      u = 0
      v1 = 0
    while u < m:
      let s = gm[m + u]
      var v = 0
      while v < ht:
        let
          i1 = off + (v1 + v) * stride
          i2 = off + (v1 + ht + v) * stride
          x = a[i1]
          y = modpMontyMul(a[i2], s, p, p0i)
        a[i1] = modpAdd(x, y, p)
        a[i2] = modpSub(x, y, p)
        inc v
      inc u
      v1 += t
    t = ht
    m = m shl 1

proc modpNtt2(a: var seq[uint32], gm: openArray[uint32], logn: int,
    p, p0i: uint32) {.inline.} =
  modpNtt2Ext(a, 0, 1, gm, logn, p, p0i)

proc modpIntt2Ext(a: var seq[uint32], off, stride: int,
    igm: openArray[uint32], logn: int, p, p0i: uint32) =
  if logn == 0:
    return
  let n = mknSize(logn)
  var
    t = 1
    m = n
  while m > 1:
    let
      hm = m shr 1
      dt = t shl 1
    var
      u = 0
      v1 = 0
    while u < hm:
      let s = igm[hm + u]
      var v = 0
      while v < t:
        let
          i1 = off + (v1 + v) * stride
          i2 = off + (v1 + t + v) * stride
          x = a[i1]
          y = a[i2]
        a[i1] = modpAdd(x, y, p)
        a[i2] = modpMontyMul(modpSub(x, y, p), s, p, p0i)
        inc v
      inc u
      v1 += dt
    t = dt
    m = hm
  let ni = uint32(1 shl (31 - logn))
  var k = 0
  while k < n:
    let i = off + k * stride
    a[i] = modpMontyMul(a[i], ni, p, p0i)
    inc k

proc modpIntt2(a: var seq[uint32], igm: openArray[uint32], logn: int,
    p, p0i: uint32) {.inline.} =
  modpIntt2Ext(a, 0, 1, igm, logn, p, p0i)

proc modpPolyRecRes(f: var seq[uint32], logn: int, p, p0i, R2: uint32) =
  let hn = 1 shl (logn - 1)
  var u = 0
  while u < hn:
    let
      w0 = f[(u shl 1) + 0]
      w1 = f[(u shl 1) + 1]
    f[u] = modpMontyMul(modpMontyMul(w0, w1, p, p0i), R2, p, p0i)
    inc u

proc zintSub(a: var seq[uint32], aOff: int, b: openArray[uint32], bOff, len: int,
    ctl: uint32): uint32 =
  var
    cc = 0'u32
    m = 0'u32 - ctl
    u = 0
  while u < len:
    var
      aw = a[aOff + u]
      w = aw - b[bOff + u] - cc
    cc = w shr 31
    aw = aw xor (((w and 0x7FFFFFFF'u32) xor aw) and m)
    a[aOff + u] = aw
    inc u
  cc

proc zintMulSmall(m: var seq[uint32], mOff, mLen: int, x: uint32): uint32 =
  var
    cc = 0'u32
    u = 0
  while u < mLen:
    let z = uint64(m[mOff + u]) * uint64(x) + uint64(cc)
    m[mOff + u] = uint32(z) and 0x7FFFFFFF'u32
    cc = uint32(z shr 31)
    inc u
  cc

proc zintModSmallUnsigned(d: openArray[uint32], dOff, dLen: int,
    p, p0i, R2: uint32): uint32 =
  var
    x = 0'u32
    u = dLen
  while u > 0:
    dec u
    x = modpMontyMul(x, R2, p, p0i)
    var w = d[dOff + u] - p
    w += p and (0'u32 - (w shr 31))
    x = modpAdd(x, w, p)
  x

proc zintModSmallSigned(d: openArray[uint32], dOff, dLen: int,
    p, p0i, R2, Rx: uint32): uint32 =
  if dLen == 0:
    return 0'u32
  var z = zintModSmallUnsigned(d, dOff, dLen, p, p0i, R2)
  z = modpSub(z, Rx and (0'u32 - (d[dOff + dLen - 1] shr 30)), p)
  z

proc zintAddMulSmall(x: var seq[uint32], xOff: int, y: openArray[uint32], yOff, len: int,
    s: uint32) =
  var
    cc = 0'u32
    u = 0
  while u < len:
    let
      xw = x[xOff + u]
      yw = y[yOff + u]
      z = uint64(yw) * uint64(s) + uint64(xw) + uint64(cc)
    x[xOff + u] = uint32(z) and 0x7FFFFFFF'u32
    cc = uint32(z shr 31)
    inc u
  x[xOff + len] = cc

proc zintNormZero(x: var seq[uint32], xOff: int, p: openArray[uint32], pOff, len: int) =
  var
    r = 0'u32
    bb = 0'u32
    u = len
  while u > 0:
    dec u
    let
      wx = x[xOff + u]
      wp = (p[pOff + u] shr 1) or (bb shl 30)
    bb = p[pOff + u] and 1'u32
    var cc = wp - wx
    cc = ((0'u32 - cc) shr 31) or (0'u32 - (cc shr 31))
    r = r or (cc and ((r and 1'u32) - 1'u32))
  discard zintSub(x, xOff, p, pOff, len, r shr 31)

proc zintNegate(a: var seq[uint32], aOff, len: int, ctl: uint32) =
  var
    cc = ctl
    m = (0'u32 - ctl) shr 1
    u = 0
  while u < len:
    var aw = a[aOff + u]
    aw = (aw xor m) + cc
    a[aOff + u] = aw and 0x7FFFFFFF'u32
    cc = aw shr 31
    inc u

proc zintCoReduce(a, b: var seq[uint32], aOff, bOff, len: int,
    xa, xb, ya, yb: int64): uint32 =
  var
    cca = 0'i64
    ccb = 0'i64
    u = 0
  while u < len:
    let
      wa = a[aOff + u]
      wb = b[bOff + u]
      za = uint64(wa) * uint64(cast[uint64](xa)) + uint64(wb) * uint64(cast[uint64](xb)) + uint64(cast[uint64](cca))
      zb = uint64(wa) * uint64(cast[uint64](ya)) + uint64(wb) * uint64(cast[uint64](yb)) + uint64(cast[uint64](ccb))
    if u > 0:
      a[aOff + u - 1] = uint32(za) and 0x7FFFFFFF'u32
      b[bOff + u - 1] = uint32(zb) and 0x7FFFFFFF'u32
    cca = cast[int64](za) shr 31
    ccb = cast[int64](zb) shr 31
    inc u
  a[aOff + len - 1] = uint32(cca)
  b[bOff + len - 1] = uint32(ccb)
  let
    nega = uint32(cast[uint64](cca) shr 63)
    negb = uint32(cast[uint64](ccb) shr 63)
  zintNegate(a, aOff, len, nega)
  zintNegate(b, bOff, len, negb)
  nega or (negb shl 1)

proc zintFinishMod(a: var seq[uint32], aOff, len: int,
    m: openArray[uint32], mOff: int, neg: uint32) =
  var
    cc = 0'u32
    u = 0
  while u < len:
    cc = (a[aOff + u] - m[mOff + u] - cc) shr 31
    inc u
  let
    xm = (0'u32 - neg) shr 1
    ym = 0'u32 - (neg or (1'u32 - cc))
  cc = neg
  u = 0
  while u < len:
    var
      aw = a[aOff + u]
      mw = (m[mOff + u] xor xm) and ym
    aw = aw - mw - cc
    a[aOff + u] = aw and 0x7FFFFFFF'u32
    cc = aw shr 31
    inc u

proc zintCoReduceMod(a, b: var seq[uint32], aOff, bOff: int,
    m: openArray[uint32], mOff, len: int, m0i: uint32,
    xa, xb, ya, yb: int64) =
  var
    cca = 0'i64
    ccb = 0'i64
    fa = ((a[aOff] * uint32(xa) + b[bOff] * uint32(xb)) * m0i) and 0x7FFFFFFF'u32
    fb = ((a[aOff] * uint32(ya) + b[bOff] * uint32(yb)) * m0i) and 0x7FFFFFFF'u32
    u = 0
  while u < len:
    let
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
    inc u
  a[aOff + len - 1] = uint32(cca)
  b[bOff + len - 1] = uint32(ccb)
  zintFinishMod(a, aOff, len, m, mOff, uint32(cast[uint64](cca) shr 63))
  zintFinishMod(b, bOff, len, m, mOff, uint32(cast[uint64](ccb) shr 63))

proc zintBezout(u, v: var seq[uint32], x, y: openArray[uint32], len: int): bool =
  if len == 0:
    return false
  var
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
  var num = 62 * uint32(len) + 30'u32
  while num >= 30'u32:
    var
      c0 = uint32.high
      c1 = uint32.high
      a0 = 0'u32
      a1 = 0'u32
      b0 = 0'u32
      b1 = 0'u32
      j = len
    while j > 0:
      dec j
      let
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
    var
      aHi = (uint64(a0) shl 31) + uint64(a1)
      bHi = (uint64(b0) shl 31) + uint64(b1)
      aLo = a[0]
      bLo = b[0]
      pa = 1'i64
      pb = 0'i64
      qa = 0'i64
      qb = 1'i64
      i = 0
    while i < 31:
      let rz = bHi - aHi
      let rt = uint32((rz xor ((aHi xor bHi) and (aHi xor rz))) shr 63)
      let
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
      inc i
    let r = zintCoReduce(a, b, 0, 0, len, pa, pb, qa, qb)
    pa = pa - ((pa + pa) and (0'i64 - int64(r and 1'u32)))
    pb = pb - ((pb + pb) and (0'i64 - int64(r and 1'u32)))
    qa = qa - ((qa + qa) and (0'i64 - int64(r shr 1)))
    qb = qb - ((qb + qb) and (0'i64 - int64(r shr 1)))
    zintCoReduceMod(u0, u1, 0, 0, y, 0, len, y0i, pa, pb, qa, qb)
    zintCoReduceMod(v0, v1, 0, 0, x, 0, len, x0i, pa, pb, qa, qb)
    num -= 30'u32
  var rc = a[0] xor 1'u32
  var j = 1
  while j < len:
    rc = rc or a[j]
    inc j
  if ((1'u32 - ((rc or (0'u32 - rc)) shr 31)) and x[0] and y[0]) == 0'u32:
    return false
  u = u0
  v = v0
  true

proc zintAddScaledMulSmall(x: var seq[uint32], xOff, xLen: int,
    y: openArray[uint32], yOff, yLen: int, k: int32, sch, scl: uint32) =
  if yLen == 0:
    return
  let ysign = (0'u32 - (y[yOff + yLen - 1] shr 30)) shr 1
  var
    tw = 0'u32
    cc = 0'i32
    u = int(sch)
  while u < xLen:
    let v = u - int(sch)
    let wy = if v < yLen: y[yOff + v] else: ysign
    let wys = ((wy shl scl) and 0x7FFFFFFF'u32) or tw
    tw = if scl == 0'u32: 0'u32 else: wy shr (31'u32 - scl)
    let z = cast[uint64](int64(wys) * int64(k) + int64(x[xOff + u]) + int64(cc))
    x[xOff + u] = uint32(z) and 0x7FFFFFFF'u32
    cc = cast[int32](uint32(z shr 31))
    inc u

proc zintSubScaled(x: var seq[uint32], xOff, xLen: int,
    y: openArray[uint32], yOff, yLen: int, sch, scl: uint32) =
  if yLen == 0:
    return
  let ysign = (0'u32 - (y[yOff + yLen - 1] shr 30)) shr 1
  var
    tw = 0'u32
    cc = 0'u32
    u = int(sch)
  while u < xLen:
    let v = u - int(sch)
    let wy = if v < yLen: y[yOff + v] else: ysign
    let wys = ((wy shl scl) and 0x7FFFFFFF'u32) or tw
    tw = if scl == 0'u32: 0'u32 else: wy shr (31'u32 - scl)
    let w = x[xOff + u] - wys - cc
    x[xOff + u] = w and 0x7FFFFFFF'u32
    cc = w shr 31
    inc u

proc zintOneToPlain(x: openArray[uint32], off: int): int32 {.inline.} =
  var w = x[off]
  w = w or ((w and 0x40000000'u32) shl 1)
  cast[int32](w)

proc trimAbs31(A: var seq[uint32]) =
  while A.len > 0 and A[^1] == 0'u32:
    A.setLen(A.len - 1)

proc cmpAbs31(A, B: openArray[uint32]): int =
  var
    al = A.len
    bl = B.len
  while al > 0 and A[al - 1] == 0'u32:
    dec al
  while bl > 0 and B[bl - 1] == 0'u32:
    dec bl
  if al < bl:
    return -1
  if al > bl:
    return 1
  var i = al
  while i > 0:
    dec i
    if A[i] < B[i]:
      return -1
    if A[i] > B[i]:
      return 1
  0

proc addAbs31(A, B: openArray[uint32]): seq[uint32] =
  let n = max(A.len, B.len)
  result = newSeq[uint32](n + 1)
  var
    carry = 0'u32
    i = 0
  while i < n:
    let aw = if i < A.len: A[i] else: 0'u32
    let bw = if i < B.len: B[i] else: 0'u32
    let z = uint64(aw) + uint64(bw) + uint64(carry)
    result[i] = uint32(z) and falconWordMask
    carry = uint32(z shr 31)
    inc i
  result[n] = carry
  trimAbs31(result)

proc subAbs31(A, B: openArray[uint32]): seq[uint32] =
  result = newSeq[uint32](A.len)
  var
    borrow = 0'u32
    i = 0
  while i < A.len:
    let bw = if i < B.len: B[i] else: 0'u32
    let z = A[i] - bw - borrow
    result[i] = z and falconWordMask
    borrow = z shr 31
    inc i
  trimAbs31(result)

proc addSigned31(a, b: FalconSigned31): FalconSigned31 =
  if a.neg == b.neg:
    result.neg = a.neg
    result.words = addAbs31(a.words, b.words)
  else:
    let c = cmpAbs31(a.words, b.words)
    if c == 0:
      result.words = @[]
      result.neg = false
    elif c > 0:
      result.neg = a.neg
      result.words = subAbs31(a.words, b.words)
    else:
      result.neg = b.neg
      result.words = subAbs31(b.words, a.words)
  if result.words.len == 0:
    result.neg = false

proc negSigned31(a: FalconSigned31): FalconSigned31 {.inline.} =
  result = a
  if result.words.len != 0:
    result.neg = not result.neg

proc subSigned31(a, b: FalconSigned31): FalconSigned31 {.inline.} =
  addSigned31(a, negSigned31(b))

proc mulAbs31(A, B: openArray[uint32]): seq[uint32] =
  if A.len == 0 or B.len == 0:
    return @[]
  result = newSeq[uint32](A.len + B.len)
  var i = 0
  while i < A.len:
    var
      carry = 0'u64
      j = 0
    while j < B.len:
      let idx = i + j
      let z = uint64(result[idx]) + uint64(A[i]) * uint64(B[j]) + carry
      result[idx] = uint32(z) and falconWordMask
      carry = z shr 31
      inc j
    var idx = i + B.len
    while carry != 0'u64:
      let z = uint64(result[idx]) + carry
      result[idx] = uint32(z) and falconWordMask
      carry = z shr 31
      inc idx
    inc i
  trimAbs31(result)

proc mulSigned31(a, b: FalconSigned31): FalconSigned31 =
  result.neg = a.neg xor b.neg
  result.words = mulAbs31(a.words, b.words)
  if result.words.len == 0:
    result.neg = false

proc shiftLeftAbs31(A: openArray[uint32], scale: int): seq[uint32] =
  if A.len == 0:
    return @[]
  let
    sch = scale div 31
    scl = scale mod 31
  result = newSeq[uint32](A.len + sch + (if scl == 0: 0 else: 1))
  var
    carry = 0'u32
    i = 0
  while i < A.len:
    let w = A[i]
    result[sch + i] = ((w shl scl) and falconWordMask) or carry
    carry = if scl == 0: 0'u32 else: w shr (31 - scl)
    inc i
  if scl != 0:
    result[sch + A.len] = carry
  trimAbs31(result)

proc mulAbsSmall31(A: openArray[uint32], s: uint32): seq[uint32] =
  if A.len == 0 or s == 0'u32:
    return @[]
  result = newSeq[uint32](A.len + 1)
  var
    carry = 0'u32
    i = 0
  while i < A.len:
    let z = uint64(A[i]) * uint64(s) + uint64(carry)
    result[i] = uint32(z) and falconWordMask
    carry = uint32(z shr 31)
    inc i
  result[A.len] = carry
  trimAbs31(result)

proc decodeCoeff31(poly: RnsPoly, coeff, wordLen: int): FalconSigned31 =
  if wordLen <= 0:
    return
  let
    off = coeffOffset(poly, coeff)
    negMask = 0'u32 - (poly.coeffs[off + wordLen - 1] shr 30)
    xm = negMask shr 1
  var
    cc = negMask and 1'u32
    i = 0
  result.neg = negMask != 0'u32
  result.words = newSeq[uint32](wordLen)
  while i < wordLen:
    var w = (poly.coeffs[off + i] xor xm) + cc
    cc = w shr 31
    result.words[i] = w and falconWordMask
    inc i
  trimAbs31(result.words)
  if result.words.len == 0:
    result.neg = false

proc divRemAbs31(num, den: openArray[uint32]): tuple[q, r: seq[uint32]]

proc roundDivAbs31(num, den: openArray[uint32]): uint32 =
  let qr = divRemAbs31(num, den)
  if qr.q.len > 1:
    return 0x80000000'u32
  let q = if qr.q.len == 0: 0'u32 else: qr.q[0]
  let twiceRem = addAbs31(qr.r, qr.r)
  let cmp = cmpAbs31(twiceRem, den)
  if cmp > 0 or (cmp == 0 and (q and 1'u32) != 0'u32):
    return q + 1'u32
  q

proc roundDivSigned31(num: FalconSigned31, den: openArray[uint32]): int32 =
  if num.words.len == 0:
    return 0'i32
  let q = roundDivAbs31(num.words, den)
  if q >= 0x80000000'u32:
    raise newException(ValueError, "Falcon exact reducer overflow")
  if num.neg:
    return -cast[int32](q)
  cast[int32](q)

proc cloneWords31(A: openArray[uint32]): seq[uint32] =
  result = newSeq[uint32](A.len)
  if A.len > 0:
    copyMem(addr result[0], unsafeAddr A[0], A.len * sizeof(uint32))

proc signed31One(): FalconSigned31 {.inline.} =
  FalconSigned31(neg: false, words: @[1'u32])

proc bitLen31(w: uint32): int {.inline.} =
  var x = w
  while x != 0'u32:
    inc result
    x = x shr 1

proc divRemAbs31(num, den: openArray[uint32]): tuple[q, r: seq[uint32]] =
  let numCmp = cmpAbs31(num, den)
  if den.len == 0:
    raise newException(ValueError, "division by zero")
  if numCmp < 0:
    result.q = @[]
    result.r = cloneWords31(num)
    trimAbs31(result.r)
    return
  if den.len == 1:
    result.q = newSeq[uint32](num.len)
    var
      rem = 0'u64
      i = num.len
    while i > 0:
      dec i
      let cur = (rem shl 31) + uint64(num[i])
      result.q[i] = uint32(cur div uint64(den[0]))
      rem = cur mod uint64(den[0])
    if rem != 0'u64:
      result.r = @[uint32(rem)]
    trimAbs31(result.q)
    trimAbs31(result.r)
    return
  let shift = 31 - bitLen31(den[^1])
  var
    vn = if shift == 0: cloneWords31(den) else: shiftLeftAbs31(den, shift)
    un = if shift == 0: cloneWords31(num) else: shiftLeftAbs31(num, shift)
  if un.len == num.len:
    un.add(0'u32)
  let
    n = vn.len
    m = un.len - n - 1
    base = 1'u64 shl 31
  result.q = newSeq[uint32](m + 1)
  var j = m + 1
  while j > 0:
    dec j
    var
      qhat = ((uint64(un[j + n]) shl 31) + uint64(un[j + n - 1])) div uint64(vn[n - 1])
      rhat = ((uint64(un[j + n]) shl 31) + uint64(un[j + n - 1])) mod uint64(vn[n - 1])
    if qhat >= base:
      qhat = base - 1
      rhat = ((uint64(un[j + n]) shl 31) + uint64(un[j + n - 1])) - qhat * uint64(vn[n - 1])
    if n > 1:
      while qhat * uint64(vn[n - 2]) > (rhat shl 31) + uint64(un[j + n - 2]):
        dec qhat
        rhat += uint64(vn[n - 1])
        if rhat >= base:
          break
    var
      borrow = 0'u64
      carry = 0'u64
      i = 0
    while i < n:
      let prod = qhat * uint64(vn[i]) + carry
      carry = prod shr 31
      let sub = uint64(uint32(prod) and falconWordMask) + borrow
      if uint64(un[j + i]) < sub:
        un[j + i] = uint32(uint64(un[j + i]) + base - sub)
        borrow = 1'u64
      else:
        un[j + i] = uint32(uint64(un[j + i]) - sub)
        borrow = 0'u64
      inc i
    let topSub = carry + borrow
    if uint64(un[j + n]) < topSub:
      dec qhat
      carry = 0'u64
      i = 0
      while i < n:
        let z = uint64(un[j + i]) + uint64(vn[i]) + carry
        un[j + i] = uint32(z and falconWordMask)
        carry = z shr 31
        inc i
      un[j + n] = uint32(uint64(un[j + n]) + carry)
    else:
      un[j + n] = uint32(uint64(un[j + n]) - topSub)
    result.q[j] = uint32(qhat)
  result.r = newSeq[uint32](n)
  var i = 0
  while i < n:
    result.r[i] = un[i]
    inc i
  trimAbs31(result.q)
  trimAbs31(result.r)

proc divExactSigned31(num, den: FalconSigned31): FalconSigned31 =
  if den.words.len == 0:
    raise newException(ValueError, "division by zero")
  if num.words.len == 0:
    return
  let qr = divRemAbs31(num.words, den.words)
  if qr.r.len != 0:
    raise newException(ValueError, "Falcon exact division failed")
  result.neg = num.neg xor den.neg
  result.words = qr.q
  if result.words.len == 0:
    result.neg = false

type
  FalconSigned31Mat4 = array[4, array[4, FalconSigned31]]
  FalconSigned31Matrix = seq[seq[FalconSigned31]]

proc polyAdjSmall31(a: openArray[FalconSigned31]): seq[FalconSigned31] =
  result = newSeq[FalconSigned31](a.len)
  if a.len == 0:
    return
  result[0] = a[0]
  var i = 1
  while i < a.len:
    result[i] = negSigned31(a[a.len - i])
    inc i

proc polyAddSmall31(a, b: openArray[FalconSigned31]): seq[FalconSigned31] =
  result = newSeq[FalconSigned31](a.len)
  var i = 0
  while i < a.len:
    result[i] = addSigned31(a[i], b[i])
    inc i

proc polyMulModXn1Small31(a, b: openArray[FalconSigned31]): seq[FalconSigned31] =
  let n = a.len
  result = newSeq[FalconSigned31](n)
  var i = 0
  while i < n:
    var j = 0
    while j < n:
      let term = mulSigned31(a[i], b[j])
      let k = i + j
      if k < n:
        result[k] = addSigned31(result[k], term)
      else:
        result[k - n] = subSigned31(result[k - n], term)
      inc j
    inc i

proc mulMat4FromPoly(poly: openArray[FalconSigned31]): FalconSigned31Mat4 =
  result[0][0] = poly[0]
  result[0][1] = negSigned31(poly[3])
  result[0][2] = negSigned31(poly[2])
  result[0][3] = negSigned31(poly[1])
  result[1][0] = poly[1]
  result[1][1] = poly[0]
  result[1][2] = negSigned31(poly[3])
  result[1][3] = negSigned31(poly[2])
  result[2][0] = poly[2]
  result[2][1] = poly[1]
  result[2][2] = poly[0]
  result[2][3] = negSigned31(poly[3])
  result[3][0] = poly[3]
  result[3][1] = poly[2]
  result[3][2] = poly[1]
  result[3][3] = poly[0]

proc replaceMat4Column(M: FalconSigned31Mat4, col: int,
    v: openArray[FalconSigned31]): FalconSigned31Mat4 =
  result = M
  var row = 0
  while row < 4:
    result[row][col] = v[row]
    inc row

proc det2Small31(a00, a01, a10, a11: FalconSigned31): FalconSigned31 {.inline.} =
  subSigned31(mulSigned31(a00, a11), mulSigned31(a01, a10))

proc det3Small31(a00, a01, a02, a10, a11, a12, a20, a21, a22: FalconSigned31): FalconSigned31 =
  let
    t0 = mulSigned31(a00, det2Small31(a11, a12, a21, a22))
    t1 = mulSigned31(a01, det2Small31(a10, a12, a20, a22))
    t2 = mulSigned31(a02, det2Small31(a10, a11, a20, a21))
  addSigned31(subSigned31(t0, t1), t2)

proc det4Small31(M: FalconSigned31Mat4): FalconSigned31 =
  let
    t0 = mulSigned31(M[0][0], det3Small31(
      M[1][1], M[1][2], M[1][3],
      M[2][1], M[2][2], M[2][3],
      M[3][1], M[3][2], M[3][3]))
    t1 = mulSigned31(M[0][1], det3Small31(
      M[1][0], M[1][2], M[1][3],
      M[2][0], M[2][2], M[2][3],
      M[3][0], M[3][2], M[3][3]))
    t2 = mulSigned31(M[0][2], det3Small31(
      M[1][0], M[1][1], M[1][3],
      M[2][0], M[2][1], M[2][3],
      M[3][0], M[3][1], M[3][3]))
    t3 = mulSigned31(M[0][3], det3Small31(
      M[1][0], M[1][1], M[1][2],
      M[2][0], M[2][1], M[2][2],
      M[3][0], M[3][1], M[3][2]))
  addSigned31(subSigned31(addSigned31(t0, t2), t1), negSigned31(t3))

proc mulMatrixFromPoly(poly: openArray[FalconSigned31]): FalconSigned31Matrix =
  let n = poly.len
  result = newSeq[seq[FalconSigned31]](n)
  var row = 0
  while row < n:
    result[row] = newSeq[FalconSigned31](n)
    inc row
  var col = 0
  while col < n:
    row = 0
    while row < n:
      let idx = row - col
      if idx >= 0:
        result[row][col] = poly[idx]
      else:
        result[row][col] = negSigned31(poly[idx + n])
      inc row
    inc col

proc replaceMatrixColumn(M: FalconSigned31Matrix, col: int,
    v: openArray[FalconSigned31]): FalconSigned31Matrix =
  result = newSeq[seq[FalconSigned31]](M.len)
  var row = 0
  while row < M.len:
    result[row] = newSeq[FalconSigned31](M[row].len)
    var j = 0
    while j < M[row].len:
      result[row][j] = M[row][j]
      inc j
    result[row][col] = v[row]
    inc row

proc detMatrixSigned31(M: FalconSigned31Matrix): FalconSigned31 =
  let n = M.len
  if n == 0:
    return
  if n == 1:
    return M[0][0]
  var
    A = newSeq[seq[FalconSigned31]](n)
    row = 0
    detNeg = false
    prev = signed31One()
  while row < n:
    A[row] = newSeq[FalconSigned31](n)
    var col = 0
    while col < n:
      A[row][col] = M[row][col]
      inc col
    inc row
  var k = 0
  while k + 1 < n:
    var pivot = k
    while pivot < n and A[pivot][k].words.len == 0:
      inc pivot
    if pivot >= n:
      return
    if pivot != k:
      swap(A[k], A[pivot])
      detNeg = not detNeg
    let pivotVal = A[k][k]
    row = k + 1
    while row < n:
      var col = k + 1
      while col < n:
        let num = subSigned31(
          mulSigned31(A[row][col], pivotVal),
          mulSigned31(A[row][k], A[k][col]))
        A[row][col] = divExactSigned31(num, prev)
        inc col
      A[row][k] = FalconSigned31()
      inc row
    prev = pivotVal
    inc k
  result = A[n - 1][n - 1]
  if detNeg:
    result = negSigned31(result)

proc polyBigToFp(dst: var seq[FalconFpr], poly: RnsPoly, wordOff, wordLen: int) =
  dst.setLen(poly.n)
  if wordLen == 0:
    var u = 0
    while u < poly.n:
      dst[u] = fprZero
      inc u
    return
  var u = 0
  while u < poly.n:
    let base = coeffOffset(poly, u) + wordOff
    let neg = 0'u32 - (poly.coeffs[base + wordLen - 1] shr 30)
    let xm = neg shr 1
    var
      cc = neg and 1'u32
      x = fprZero
      fsc = fprOne
      v = 0
    while v < wordLen:
      var w = (poly.coeffs[base + v] xor xm) + cc
      cc = w shr 31
      w = w and 0x7FFFFFFF'u32
      w = w - ((w shl 1) and neg)
      x = fprAdd(x, fprMul(fprOf(int64(cast[int32](w))), fsc))
      fsc = fprMul(fsc, fprPTwo31)
      inc v
    dst[u] = x
    inc u

proc polyBigToSmall(dst: var seq[int8], poly: RnsPoly, lim: int): bool =
  dst.setLen(poly.n)
  var u = 0
  while u < poly.n:
    let z = zintOneToPlain(poly.coeffs, coeffOffset(poly, u))
    if z < -lim or z > lim:
      return false
    dst[u] = int8(z)
    inc u
  true

proc polySubScaled(F: var RnsPoly, FLen: int, f: RnsPoly, fLen: int,
    k: openArray[int32], sch, scl: uint32, logn: int) =
  let n = mknSize(logn)
  var u = 0
  while u < n:
    var
      kf = -k[u]
      coeff = u
      signFlip = false
      v = 0
    while v < n:
      zintAddScaledMulSmall(F.coeffs, coeffOffset(F, coeff), FLen, f.coeffs, coeffOffset(f, v), fLen, kf, sch, scl)
      if u + v == n - 1:
        coeff = 0
        kf = -kf
        signFlip = true
      else:
        if signFlip:
          inc coeff
        else:
          inc coeff
      inc v
    inc u

proc zintRebuildCrt(poly: var RnsPoly, xLen: int, normalizeSigned: bool) =
  var tmp = newSeq[uint32](xLen)
  tmp[0] = falconPrimes[0].p
  var u = 1
  while u < xLen:
    let
      p = falconPrimes[u].p
      s = falconPrimes[u].s
      p0i = modpNinv31(p)
      R2 = modpR2(p, p0i)
    var v = 0
    while v < poly.n:
      let xOff = coeffOffset(poly, v)
      let xp = poly.coeffs[xOff + u]
      let xq = zintModSmallUnsigned(poly.coeffs, xOff, u, p, p0i, R2)
      let xr = modpMontyMul(s, modpSub(xp, xq, p), p, p0i)
      zintAddMulSmall(poly.coeffs, xOff, tmp, 0, u, xr)
      inc v
    tmp[u] = zintMulSmall(tmp, 0, u, p)
    inc u
  if normalizeSigned:
    var v = 0
    while v < poly.n:
      zintNormZero(poly.coeffs, coeffOffset(poly, v), tmp, 0, xLen)
      inc v

proc polySubScaledNtt(F: var RnsPoly, FLen: int, f: RnsPoly, fLen: int,
    k: openArray[int32], sch, scl: uint32, logn: int) =
  let
    n = mknSize(logn)
    tLen = fLen + 1
  var
    gm = newSeq[uint32](n)
    igm = newSeq[uint32](n)
    fk = initRnsPoly(n, tLen)
    t1 = newSeq[uint32](n)
    u = 0
  while u < tLen:
    let
      p = falconPrimes[u].p
      p0i = modpNinv31(p)
      R2 = modpR2(p, p0i)
      Rx = modpRx(fLen, p, p0i, R2)
    modpMkgm2(gm, igm, logn, falconPrimes[u].g, p, p0i)
    var v = 0
    while v < n:
      t1[v] = modpSet(k[v], p)
      inc v
    modpNtt2(t1, gm, logn, p, p0i)
    v = 0
    while v < n:
      fk.coeffs[v * tLen + u] = zintModSmallSigned(f.coeffs, coeffOffset(f, v), fLen, p, p0i, R2, Rx)
      inc v
    modpNtt2Ext(fk.coeffs, u, tLen, gm, logn, p, p0i)
    v = 0
    while v < n:
      let idx = v * tLen + u
      fk.coeffs[idx] = modpMontyMul(modpMontyMul(t1[v], fk.coeffs[idx], p, p0i), R2, p, p0i)
      inc v
    modpIntt2Ext(fk.coeffs, u, tLen, igm, logn, p, p0i)
    inc u
  zintRebuildCrt(fk, tLen, true)
  var coeff = 0
  while coeff < n:
    zintSubScaled(F.coeffs, coeffOffset(F, coeff), FLen, fk.coeffs, coeffOffset(fk, coeff), tLen, sch, scl)
    inc coeff

proc getRngU64(rng: var FalconShake256): uint64 =
  var tmp: array[8, byte]
  extractFalconShake256(rng, tmp)
  uint64(tmp[0]) or
    (uint64(tmp[1]) shl 8) or
    (uint64(tmp[2]) shl 16) or
    (uint64(tmp[3]) shl 24) or
    (uint64(tmp[4]) shl 32) or
    (uint64(tmp[5]) shl 40) or
    (uint64(tmp[6]) shl 48) or
    (uint64(tmp[7]) shl 56)

proc mkgauss(rng: var FalconShake256, logn: int): int =
  var
    g = 1 shl (10 - logn)
    value = 0
    u = 0
  while u < g:
    var
      r = getRngU64(rng)
      neg = uint32(r shr 63)
    r = r and (not (1'u64 shl 63))
    var
      f = uint32((r - falconGauss1024_12289[0]) shr 63)
      v = 0'u32
      k = 1
    r = getRngU64(rng)
    r = r and (not (1'u64 shl 63))
    while k < falconGauss1024_12289.len:
      let t = uint32((r - falconGauss1024_12289[k]) shr 63) xor 1'u32
      v = v or (uint32(k) and (0'u32 - (t and (f xor 1'u32))))
      f = f or t
      inc k
    v = (v xor (0'u32 - neg)) + neg
    value += int(cast[int32](v))
    inc u
  value

proc polySmallSqnorm*(f: openArray[int8], logn: int): uint32 =
  ## Paper note: Falcon keygen's small-polynomial norm bound is from the Falcon
  ## spec; this scalar path keeps the constant overflow-sentinel behavior.
  let n = mknSize(logn)
  var
    s = 0'u32
    ng = 0'u32
    u = 0
  while u < n:
    let z = int32(f[u])
    s += uint32(z * z)
    ng = ng or s
    inc u
  s or (0'u32 - (ng shr 31))

proc polySmallToFp(x: var seq[FalconFpr], f: openArray[int8], logn: int) =
  let n = mknSize(logn)
  x.setLen(n)
  var u = 0
  while u < n:
    x[u] = fprOf(int64(f[u]))
    inc u

proc polySmallMkgauss(rng: var FalconShake256, f: var seq[int8], logn: int) =
  let n = mknSize(logn)
  f.setLen(n)
  var
    mod2 = 0'u32
    u = 0
  while u < n:
    var s: int
    while true:
      s = mkgauss(rng, logn)
      if s >= -127 and s <= 127:
        if u == n - 1:
          if (mod2 xor uint32(s and 1)) == 1'u32:
            break
        else:
          mod2 = mod2 xor uint32(s and 1)
          break
    f[u] = int8(s)
    inc u

proc makeFgStep(fs, gs: RnsPoly, logn, depth: int, inNtt, outNtt: bool): tuple[f, g: RnsPoly] =
  let
    n = 1 shl logn
    hn = n shr 1
    slen = falconMaxBlSmall[depth]
    tlen = falconMaxBlSmall[depth + 1]
  result.f = initRnsPoly(hn, tlen)
  result.g = initRnsPoly(hn, tlen)
  var
    fsrc = clonePoly(fs)
    gsrc = clonePoly(gs)
    gm = newSeq[uint32](n)
    igm = newSeq[uint32](n)
    t1 = newSeq[uint32](n)
    u = 0
  while u < slen:
    let
      p = falconPrimes[u].p
      p0i = modpNinv31(p)
      R2 = modpR2(p, p0i)
    modpMkgm2(gm, igm, logn, falconPrimes[u].g, p, p0i)
    var v = 0
    while v < n:
      t1[v] = fsrc.coeffs[v * slen + u]
      inc v
    if not inNtt:
      modpNtt2(t1, gm, logn, p, p0i)
    v = 0
    while v < hn:
      let
        w0 = t1[(v shl 1) + 0]
        w1 = t1[(v shl 1) + 1]
      result.f.coeffs[v * tlen + u] = modpMontyMul(modpMontyMul(w0, w1, p, p0i), R2, p, p0i)
      inc v
    if inNtt:
      modpIntt2Ext(fsrc.coeffs, u, slen, igm, logn, p, p0i)
    v = 0
    while v < n:
      t1[v] = gsrc.coeffs[v * slen + u]
      inc v
    if not inNtt:
      modpNtt2(t1, gm, logn, p, p0i)
    v = 0
    while v < hn:
      let
        w0 = t1[(v shl 1) + 0]
        w1 = t1[(v shl 1) + 1]
      result.g.coeffs[v * tlen + u] = modpMontyMul(modpMontyMul(w0, w1, p, p0i), R2, p, p0i)
      inc v
    if inNtt:
      modpIntt2Ext(gsrc.coeffs, u, slen, igm, logn, p, p0i)
    if not outNtt:
      modpIntt2Ext(result.f.coeffs, u, tlen, igm, logn - 1, p, p0i)
      modpIntt2Ext(result.g.coeffs, u, tlen, igm, logn - 1, p, p0i)
    inc u
  zintRebuildCrt(fsrc, slen, true)
  zintRebuildCrt(gsrc, slen, true)
  if slen < tlen:
    u = slen
    while u < tlen:
      let
        p = falconPrimes[u].p
        p0i = modpNinv31(p)
        R2 = modpR2(p, p0i)
        Rx = modpRx(slen, p, p0i, R2)
      modpMkgm2(gm, igm, logn, falconPrimes[u].g, p, p0i)
      var v = 0
      while v < n:
        t1[v] = zintModSmallSigned(fsrc.coeffs, coeffOffset(fsrc, v), slen, p, p0i, R2, Rx)
        inc v
      modpNtt2(t1, gm, logn, p, p0i)
      v = 0
      while v < hn:
        let
          w0 = t1[(v shl 1) + 0]
          w1 = t1[(v shl 1) + 1]
        result.f.coeffs[v * tlen + u] = modpMontyMul(modpMontyMul(w0, w1, p, p0i), R2, p, p0i)
        inc v
      v = 0
      while v < n:
        t1[v] = zintModSmallSigned(gsrc.coeffs, coeffOffset(gsrc, v), slen, p, p0i, R2, Rx)
        inc v
      modpNtt2(t1, gm, logn, p, p0i)
      v = 0
      while v < hn:
        let
          w0 = t1[(v shl 1) + 0]
          w1 = t1[(v shl 1) + 1]
        result.g.coeffs[v * tlen + u] = modpMontyMul(modpMontyMul(w0, w1, p, p0i), R2, p, p0i)
        inc v
      if not outNtt:
        modpIntt2Ext(result.f.coeffs, u, tlen, igm, logn - 1, p, p0i)
        modpIntt2Ext(result.g.coeffs, u, tlen, igm, logn - 1, p, p0i)
      inc u

proc makeFg(f, g: openArray[int8], logn, depth: int, outNtt: bool): tuple[f, g: RnsPoly] =
  let n = mknSize(logn)
  result.f = initRnsPoly(n, 1)
  result.g = initRnsPoly(n, 1)
  let p0 = falconPrimes[0].p
  var u = 0
  while u < n:
    result.f.coeffs[u] = modpSet(int32(f[u]), p0)
    result.g.coeffs[u] = modpSet(int32(g[u]), p0)
    inc u
  if depth == 0:
    if outNtt:
      var
        gm = newSeq[uint32](n)
        igm = newSeq[uint32](n)
      let p0i = modpNinv31(p0)
      modpMkgm2(gm, igm, logn, falconPrimes[0].g, p0, p0i)
      modpNtt2(result.f.coeffs, gm, logn, p0, p0i)
      modpNtt2(result.g.coeffs, gm, logn, p0, p0i)
    return
  var current = result
  if depth == 1:
    return makeFgStep(current.f, current.g, logn, 0, false, outNtt)
  current = makeFgStep(current.f, current.g, logn, 0, false, true)
  var d = 1
  while d + 1 < depth:
    current = makeFgStep(current.f, current.g, logn - d, d, true, true)
    inc d
  makeFgStep(current.f, current.g, logn - depth + 1, depth - 1, true, outNtt)

proc solveNtruDeepest(lognTop: int, f, g: openArray[int8]): tuple[ok: bool, F, G: RnsPoly] =
  let len = falconMaxBlSmall[lognTop]
  let fg = makeFg(f, g, lognTop, lognTop, false)
  var
    fp = fg.f
    gp = fg.g
    Fp = newSeq[uint32](len)
    Gp = newSeq[uint32](len)
  zintRebuildCrt(fp, len, false)
  zintRebuildCrt(gp, len, false)
  if not zintBezout(Gp, Fp, fp.coeffs, gp.coeffs, len):
    return
  if zintMulSmall(Fp, 0, len, 12289'u32) != 0'u32 or
      zintMulSmall(Gp, 0, len, 12289'u32) != 0'u32:
    return
  result.ok = true
  result.F = initRnsPoly(1, len)
  result.G = initRnsPoly(1, len)
  copyMem(addr result.F.coeffs[0], addr Fp[0], len * sizeof(uint32))
  copyMem(addr result.G.coeffs[0], addr Gp[0], len * sizeof(uint32))

proc pow2Scale(dc: int): FalconFpr =
  var
    shift = dc
    pt = if shift < 0: fprTwo else: fprOneHalf
    outv = fprOne
  if shift < 0:
    shift = -shift
  while shift != 0:
    if (shift and 1) != 0:
      outv = fprMul(outv, pt)
    shift = shift shr 1
    pt = fprSqr(pt)
  outv

proc reduceIntermediateLogn1(ft, gt: RnsPoly, slen: int, Ft, Gt: var RnsPoly,
    llen, depth: int): tuple[ok: bool, F, G: RnsPoly] =
  var
    f0 = decodeCoeff31(ft, 0, slen)
    f1 = decodeCoeff31(ft, 1, slen)
    g0 = decodeCoeff31(gt, 0, slen)
    g1 = decodeCoeff31(gt, 1, slen)
    den = addSigned31(mulSigned31(f0, f0), mulSigned31(f1, f1))
    k = newSeq[int32](2)
    FGlen = llen
    maxBitsCurrent = 31 * llen
    minBitsFg = falconBitlength[depth].avg - 6 * falconBitlength[depth].std
    maxBitsFg = falconBitlength[depth].avg + 6 * falconBitlength[depth].std
    scaleK = maxBitsCurrent - minBitsFg
  den = addSigned31(den, mulSigned31(g0, g0))
  den = addSigned31(den, mulSigned31(g1, g1))
  if den.neg or den.words.len == 0:
    return
  while true:
    var
      F0 = decodeCoeff31(Ft, 0, FGlen)
      F1 = decodeCoeff31(Ft, 1, FGlen)
      G0 = decodeCoeff31(Gt, 0, FGlen)
      G1 = decodeCoeff31(Gt, 1, FGlen)
      h0 = addSigned31(mulSigned31(F0, f0), mulSigned31(F1, f1))
      h1 = subSigned31(mulSigned31(F1, f0), mulSigned31(F0, f1))
      denScaled = shiftLeftAbs31(den.words, scaleK)
    h0 = addSigned31(h0, mulSigned31(G0, g0))
    h0 = addSigned31(h0, mulSigned31(G1, g1))
    h1 = subSigned31(h1, mulSigned31(G0, g1))
    h1 = addSigned31(h1, mulSigned31(G1, g0))
    k[0] = roundDivSigned31(h0, denScaled)
    k[1] = roundDivSigned31(h1, denScaled)
    let
      sch = uint32(scaleK div 31)
      scl = uint32(scaleK mod 31)
    polySubScaled(Ft, FGlen, ft, slen, k, sch, scl, 1)
    polySubScaled(Gt, FGlen, gt, slen, k, sch, scl, 1)
    let newMaxBitsCurrent = scaleK + maxBitsFg + 10
    if newMaxBitsCurrent < maxBitsCurrent:
      maxBitsCurrent = newMaxBitsCurrent
      if FGlen * 31 >= maxBitsCurrent + 31:
        dec FGlen
    if scaleK <= 0:
      break
    scaleK = max(scaleK - 25, 0)
  if FGlen < slen:
    var coeff = 0
    while coeff < 2:
      let
        fOff = coeffOffset(Ft, coeff)
        gOff = coeffOffset(Gt, coeff)
        fSw = (0'u32 - (Ft.coeffs[fOff + FGlen - 1] shr 30)) shr 1
        gSw = (0'u32 - (Gt.coeffs[gOff + FGlen - 1] shr 30)) shr 1
      var v = FGlen
      while v < slen:
        Ft.coeffs[fOff + v] = fSw
        Gt.coeffs[gOff + v] = gSw
        inc v
      inc coeff
  result.ok = true
  result.F = initRnsPoly(2, slen)
  result.G = initRnsPoly(2, slen)
  var coeff = 0
  while coeff < 2:
    copyMem(addr result.F.coeffs[coeff * slen], addr Ft.coeffs[coeff * llen], slen * sizeof(uint32))
    copyMem(addr result.G.coeffs[coeff * slen], addr Gt.coeffs[coeff * llen], slen * sizeof(uint32))
    inc coeff

proc reduceIntermediateLogn2(ft, gt: RnsPoly, slen: int, Ft, Gt: var RnsPoly,
    llen, depth: int): tuple[ok: bool, F, G: RnsPoly] =
  var
    fPoly, gPoly: array[4, FalconSigned31]
    i = 0
  while i < 4:
    fPoly[i] = decodeCoeff31(ft, i, slen)
    gPoly[i] = decodeCoeff31(gt, i, slen)
    inc i
  let
    adjF = polyAdjSmall31(fPoly)
    adjG = polyAdjSmall31(gPoly)
    denPoly = polyAddSmall31(polyMulModXn1Small31(fPoly, adjF), polyMulModXn1Small31(gPoly, adjG))
    denMat = mulMat4FromPoly(denPoly)
  var
    det = det4Small31(denMat)
    detAbs = det.words
    detNeg = det.neg
    k = newSeq[int32](4)
    FGlen = llen
    maxBitsCurrent = 31 * llen
    minBitsFg = falconBitlength[depth].avg - 6 * falconBitlength[depth].std
    maxBitsFg = falconBitlength[depth].avg + 6 * falconBitlength[depth].std
    scaleK = maxBitsCurrent - minBitsFg
  if det.words.len == 0:
    return
  if detNeg:
    detAbs = det.words
  while true:
    var
      FPoly, GPoly: array[4, FalconSigned31]
      idx = 0
    while idx < 4:
      FPoly[idx] = decodeCoeff31(Ft, idx, FGlen)
      GPoly[idx] = decodeCoeff31(Gt, idx, FGlen)
      inc idx
    let
      numPoly = polyAddSmall31(polyMulModXn1Small31(FPoly, adjF), polyMulModXn1Small31(GPoly, adjG))
      denScaled = shiftLeftAbs31(detAbs, scaleK)
    idx = 0
    while idx < 4:
      var num = det4Small31(replaceMat4Column(denMat, idx, numPoly))
      if detNeg:
        num = negSigned31(num)
      k[idx] = roundDivSigned31(num, denScaled)
      inc idx
    let
      sch = uint32(scaleK div 31)
      scl = uint32(scaleK mod 31)
    polySubScaled(Ft, FGlen, ft, slen, k, sch, scl, 2)
    polySubScaled(Gt, FGlen, gt, slen, k, sch, scl, 2)
    let newMaxBitsCurrent = scaleK + maxBitsFg + 10
    if newMaxBitsCurrent < maxBitsCurrent:
      maxBitsCurrent = newMaxBitsCurrent
      if FGlen * 31 >= maxBitsCurrent + 31:
        dec FGlen
    if scaleK <= 0:
      break
    scaleK = max(scaleK - 25, 0)
  if FGlen < slen:
    var coeff = 0
    while coeff < 4:
      let
        fOff = coeffOffset(Ft, coeff)
        gOff = coeffOffset(Gt, coeff)
        fSw = (0'u32 - (Ft.coeffs[fOff + FGlen - 1] shr 30)) shr 1
        gSw = (0'u32 - (Gt.coeffs[gOff + FGlen - 1] shr 30)) shr 1
      var v = FGlen
      while v < slen:
        Ft.coeffs[fOff + v] = fSw
        Gt.coeffs[gOff + v] = gSw
        inc v
      inc coeff
  result.ok = true
  result.F = initRnsPoly(4, slen)
  result.G = initRnsPoly(4, slen)
  var coeff = 0
  while coeff < 4:
    copyMem(addr result.F.coeffs[coeff * slen], addr Ft.coeffs[coeff * llen], slen * sizeof(uint32))
    copyMem(addr result.G.coeffs[coeff * slen], addr Gt.coeffs[coeff * llen], slen * sizeof(uint32))
    inc coeff

proc reduceIntermediateExact(ft, gt: RnsPoly, slen: int, Ft, Gt: var RnsPoly,
    llen, depth, n: int): tuple[ok: bool, F, G: RnsPoly] =
  var
    fPoly = newSeq[FalconSigned31](n)
    gPoly = newSeq[FalconSigned31](n)
    logn = 0
    nCheck = 1
    i = 0
  while nCheck < n:
    nCheck = nCheck shl 1
    inc logn
  while i < n:
    fPoly[i] = decodeCoeff31(ft, i, slen)
    gPoly[i] = decodeCoeff31(gt, i, slen)
    inc i
  let
    adjF = polyAdjSmall31(fPoly)
    adjG = polyAdjSmall31(gPoly)
    denPoly = polyAddSmall31(polyMulModXn1Small31(fPoly, adjF), polyMulModXn1Small31(gPoly, adjG))
    denMat = mulMatrixFromPoly(denPoly)
  var
    det = detMatrixSigned31(denMat)
    detAbs = det.words
    detNeg = det.neg
    k = newSeq[int32](n)
    FGlen = llen
    maxBitsCurrent = 31 * llen
    minBitsFg = falconBitlength[depth].avg - 6 * falconBitlength[depth].std
    maxBitsFg = falconBitlength[depth].avg + 6 * falconBitlength[depth].std
    scaleK = maxBitsCurrent - minBitsFg
  if det.words.len == 0:
    return
  while true:
    var
      FPoly = newSeq[FalconSigned31](n)
      GPoly = newSeq[FalconSigned31](n)
      idx = 0
    while idx < n:
      FPoly[idx] = decodeCoeff31(Ft, idx, FGlen)
      GPoly[idx] = decodeCoeff31(Gt, idx, FGlen)
      inc idx
    let
      numPoly = polyAddSmall31(polyMulModXn1Small31(FPoly, adjF), polyMulModXn1Small31(GPoly, adjG))
      denScaled = shiftLeftAbs31(detAbs, scaleK)
    idx = 0
    while idx < n:
      var num = detMatrixSigned31(replaceMatrixColumn(denMat, idx, numPoly))
      if detNeg:
        num = negSigned31(num)
      try:
        k[idx] = roundDivSigned31(num, denScaled)
      except ValueError:
        when defined(falconKeygenDebugEcho):
          echo "falcon exact reducer overflow depth=", depth, " n=", n,
            " iterScale=", scaleK, " idx=", idx
        return
      inc idx
    let
      sch = uint32(scaleK div 31)
      scl = uint32(scaleK mod 31)
    polySubScaled(Ft, FGlen, ft, slen, k, sch, scl, logn)
    polySubScaled(Gt, FGlen, gt, slen, k, sch, scl, logn)
    let newMaxBitsCurrent = scaleK + maxBitsFg + 10
    if newMaxBitsCurrent < maxBitsCurrent:
      maxBitsCurrent = newMaxBitsCurrent
      if FGlen * 31 >= maxBitsCurrent + 31:
        dec FGlen
    if scaleK <= 0:
      break
    scaleK = max(scaleK - 25, 0)
  if FGlen < slen:
    var coeff = 0
    while coeff < n:
      let
        fOff = coeffOffset(Ft, coeff)
        gOff = coeffOffset(Gt, coeff)
        fSw = (0'u32 - (Ft.coeffs[fOff + FGlen - 1] shr 30)) shr 1
        gSw = (0'u32 - (Gt.coeffs[gOff + FGlen - 1] shr 30)) shr 1
      var v = FGlen
      while v < slen:
        Ft.coeffs[fOff + v] = fSw
        Gt.coeffs[gOff + v] = gSw
        inc v
      inc coeff
  result.ok = true
  result.F = initRnsPoly(n, slen)
  result.G = initRnsPoly(n, slen)
  var coeff = 0
  while coeff < n:
    copyMem(addr result.F.coeffs[coeff * slen], addr Ft.coeffs[coeff * llen], slen * sizeof(uint32))
    copyMem(addr result.G.coeffs[coeff * slen], addr Gt.coeffs[coeff * llen], slen * sizeof(uint32))
    inc coeff

proc reduceIntermediateLogn3(ft, gt: RnsPoly, slen: int, Ft, Gt: var RnsPoly,
    llen, depth: int): tuple[ok: bool, F, G: RnsPoly] =
  reduceIntermediateExact(ft, gt, slen, Ft, Gt, llen, depth, 8)

proc reduceIntermediateLogn4(ft, gt: RnsPoly, slen: int, Ft, Gt: var RnsPoly,
    llen, depth: int): tuple[ok: bool, F, G: RnsPoly] =
  reduceIntermediateExact(ft, gt, slen, Ft, Gt, llen, depth, 16)

proc solveNtruIntermediate(lognTop: int, f, g: openArray[int8],
    depth: int, Fd, Gd: RnsPoly): tuple[ok: bool, F, G: RnsPoly] =
  let
    logn = lognTop - depth
    n = 1 shl logn
    hn = n shr 1
    slen = falconMaxBlSmall[depth]
    dlen = falconMaxBlSmall[depth + 1]
    llen = falconMaxBlLarge[depth]
  var
    fg = makeFg(f, g, lognTop, depth, true)
    ft = fg.f
    gt = fg.g
    Ft = initRnsPoly(n, llen)
    Gt = initRnsPoly(n, llen)
    gm = newSeq[uint32](n)
    igm = newSeq[uint32](n)
    fx = newSeq[uint32](n)
    gx = newSeq[uint32](n)
    Fp = newSeq[uint32](hn)
    Gp = newSeq[uint32](hn)
    u = 0
  while u < llen:
    let
      p = falconPrimes[u].p
      p0i = modpNinv31(p)
      R2 = modpR2(p, p0i)
    if u == slen:
      zintRebuildCrt(ft, slen, true)
      zintRebuildCrt(gt, slen, true)
    modpMkgm2(gm, igm, logn, falconPrimes[u].g, p, p0i)
    if u < slen:
      var v = 0
      while v < n:
        fx[v] = ft.coeffs[v * slen + u]
        gx[v] = gt.coeffs[v * slen + u]
        inc v
      modpIntt2Ext(ft.coeffs, u, slen, igm, logn, p, p0i)
      modpIntt2Ext(gt.coeffs, u, slen, igm, logn, p, p0i)
    else:
      let Rx = modpRx(slen, p, p0i, R2)
      var v = 0
      while v < n:
        fx[v] = zintModSmallSigned(ft.coeffs, coeffOffset(ft, v), slen, p, p0i, R2, Rx)
        gx[v] = zintModSmallSigned(gt.coeffs, coeffOffset(gt, v), slen, p, p0i, R2, Rx)
        inc v
      modpNtt2(fx, gm, logn, p, p0i)
      modpNtt2(gx, gm, logn, p, p0i)
    let Rx = modpRx(dlen, p, p0i, R2)
    var v = 0
    while v < hn:
      Fp[v] = zintModSmallSigned(Fd.coeffs, coeffOffset(Fd, v), dlen, p, p0i, R2, Rx)
      Gp[v] = zintModSmallSigned(Gd.coeffs, coeffOffset(Gd, v), dlen, p, p0i, R2, Rx)
      inc v
    modpNtt2(Fp, gm, logn - 1, p, p0i)
    modpNtt2(Gp, gm, logn - 1, p, p0i)
    v = 0
    while v < hn:
      let
        ftA = fx[(v shl 1) + 0]
        ftB = fx[(v shl 1) + 1]
        gtA = gx[(v shl 1) + 0]
        gtB = gx[(v shl 1) + 1]
        mFp = modpMontyMul(Fp[v], R2, p, p0i)
        mGp = modpMontyMul(Gp[v], R2, p, p0i)
      Ft.coeffs[(v shl 1) * llen + u] = modpMontyMul(gtB, mFp, p, p0i)
      Ft.coeffs[((v shl 1) + 1) * llen + u] = modpMontyMul(gtA, mFp, p, p0i)
      Gt.coeffs[(v shl 1) * llen + u] = modpMontyMul(ftB, mGp, p, p0i)
      Gt.coeffs[((v shl 1) + 1) * llen + u] = modpMontyMul(ftA, mGp, p, p0i)
      inc v
    modpIntt2Ext(Ft.coeffs, u, llen, igm, logn, p, p0i)
    modpIntt2Ext(Gt.coeffs, u, llen, igm, logn, p, p0i)
    inc u
  zintRebuildCrt(Ft, llen, true)
  zintRebuildCrt(Gt, llen, true)
  if logn == 1:
    return reduceIntermediateLogn1(ft, gt, slen, Ft, Gt, llen, depth)
  if logn == 2:
    return reduceIntermediateLogn2(ft, gt, slen, Ft, Gt, llen, depth)
  if logn == 3:
    return reduceIntermediateLogn3(ft, gt, slen, Ft, Gt, llen, depth)
  if logn == 4:
    return reduceIntermediateLogn4(ft, gt, slen, Ft, Gt, llen, depth)
  var
    rt1 = newSeq[FalconFpr](n)
    rt2 = newSeq[FalconFpr](n)
    rt3 = newSeq[FalconFpr](n)
    rt4 = newSeq[FalconFpr](n)
    rt5 = newSeq[FalconFpr](n shr 1)
    k = newSeq[int32](n)
    rlen = if slen > 10: 10 else: slen
    scaleBase = 31 * (slen - rlen)
    minBitsFg = falconBitlength[depth].avg - 6 * falconBitlength[depth].std
    maxBitsFg = falconBitlength[depth].avg + 6 * falconBitlength[depth].std
  polyBigToFp(rt3, ft, slen - rlen, rlen)
  polyBigToFp(rt4, gt, slen - rlen, rlen)
  falconFft(rt3, logn)
  falconFft(rt4, logn)
  polyInvnorm2Fft(rt5, rt3, rt4, logn)
  polyAdjFft(rt3, logn)
  polyAdjFft(rt4, logn)
  var
    FGlen = llen
    maxBitsCurrent = 31 * llen
    scaleK = maxBitsCurrent - minBitsFg
    iterCount = 0
  while true:
    rlen = if FGlen > 10: 10 else: FGlen
    let scaleCurrent = 31 * (FGlen - rlen)
    polyBigToFp(rt1, Ft, FGlen - rlen, rlen)
    polyBigToFp(rt2, Gt, FGlen - rlen, rlen)
    falconFft(rt1, logn)
    falconFft(rt2, logn)
    polyMulFft(rt1, rt3, logn)
    polyMulFft(rt2, rt4, logn)
    polyAdd(rt2, rt1, logn)
    polyMulAutoadjFft(rt2, rt5, logn)
    falconIfft(rt2, logn)
    let pdc = pow2Scale(scaleK - scaleCurrent + scaleBase)
    var idx = 0
    while idx < n:
      let xv = fprMul(rt2[idx], pdc)
      if not fprLt(fprMTwo31m1, xv) or not fprLt(xv, fprPTwo31m1):
        when defined(falconKeygenDebugEcho):
          echo "falcon keygen debug depth=", depth, " iter=", iterCount,
            " idx=", idx, " scaleK=", scaleK, " FGlen=", FGlen,
            " xv=", fprToFloat(xv)
        return
      k[idx] = int32(fprRint(xv))
      inc idx
    let
      sch = uint32(scaleK div 31)
      scl = uint32(scaleK mod 31)
    if depth <= falconDepthIntFg:
      polySubScaledNtt(Ft, FGlen, ft, slen, k, sch, scl, logn)
      polySubScaledNtt(Gt, FGlen, gt, slen, k, sch, scl, logn)
    else:
      polySubScaled(Ft, FGlen, ft, slen, k, sch, scl, logn)
      polySubScaled(Gt, FGlen, gt, slen, k, sch, scl, logn)
    let newMaxBitsCurrent = scaleK + maxBitsFg + 10
    if newMaxBitsCurrent < maxBitsCurrent:
      maxBitsCurrent = newMaxBitsCurrent
      if FGlen * 31 >= maxBitsCurrent + 31:
        dec FGlen
    if scaleK <= 0:
      break
    scaleK = max(scaleK - 25, 0)
    inc iterCount
  if FGlen < slen:
    var coeff = 0
    while coeff < n:
      let
        fOff = coeffOffset(Ft, coeff)
        gOff = coeffOffset(Gt, coeff)
        fSw = (0'u32 - (Ft.coeffs[fOff + FGlen - 1] shr 30)) shr 1
        gSw = (0'u32 - (Gt.coeffs[gOff + FGlen - 1] shr 30)) shr 1
      var v = FGlen
      while v < slen:
        Ft.coeffs[fOff + v] = fSw
        Gt.coeffs[gOff + v] = gSw
        inc v
      inc coeff
  result.ok = true
  result.F = initRnsPoly(n, slen)
  result.G = initRnsPoly(n, slen)
  var coeff = 0
  while coeff < n:
    copyMem(addr result.F.coeffs[coeff * slen], addr Ft.coeffs[coeff * llen], slen * sizeof(uint32))
    copyMem(addr result.G.coeffs[coeff * slen], addr Gt.coeffs[coeff * llen], slen * sizeof(uint32))
    inc coeff

proc packSigned31(x: int64): tuple[ok: bool, word: uint32] {.inline.} =
  if x < -0x40000000'i64 or x > 0x3FFFFFFF'i64:
    return
  result.ok = true
  result.word = cast[uint32](cast[int32](x)) and falconWordMask

proc solveNtruBinaryDepth1(lognTop: int, f, g: openArray[int8],
    Fd, Gd: RnsPoly): tuple[ok: bool, F, G: RnsPoly] =
  let
    depth = 1
    logn = lognTop - depth
    n = 1 shl logn
    hn = n shr 1
    slen = falconMaxBlSmall[depth]
    dlen = falconMaxBlSmall[depth + 1]
    llen = falconMaxBlLarge[depth]
  var
    fg = makeFg(f, g, lognTop, depth, true)
    ft = fg.f
    gt = fg.g
    Ft = initRnsPoly(n, llen)
    Gt = initRnsPoly(n, llen)
    gm = newSeq[uint32](n)
    igm = newSeq[uint32](n)
    fx = newSeq[uint32](n)
    gx = newSeq[uint32](n)
    Fp = newSeq[uint32](hn)
    Gp = newSeq[uint32](hn)
    u = 0
  while u < llen:
    let
      p = falconPrimes[u].p
      p0i = modpNinv31(p)
      R2 = modpR2(p, p0i)
    if u == slen:
      zintRebuildCrt(ft, slen, true)
      zintRebuildCrt(gt, slen, true)
    modpMkgm2(gm, igm, logn, falconPrimes[u].g, p, p0i)
    if u < slen:
      var v = 0
      while v < n:
        fx[v] = ft.coeffs[v * slen + u]
        gx[v] = gt.coeffs[v * slen + u]
        inc v
      modpIntt2Ext(ft.coeffs, u, slen, igm, logn, p, p0i)
      modpIntt2Ext(gt.coeffs, u, slen, igm, logn, p, p0i)
    else:
      let Rx = modpRx(slen, p, p0i, R2)
      var v = 0
      while v < n:
        fx[v] = zintModSmallSigned(ft.coeffs, coeffOffset(ft, v), slen, p, p0i, R2, Rx)
        gx[v] = zintModSmallSigned(gt.coeffs, coeffOffset(gt, v), slen, p, p0i, R2, Rx)
        inc v
      modpNtt2(fx, gm, logn, p, p0i)
      modpNtt2(gx, gm, logn, p, p0i)
    let Rx = modpRx(dlen, p, p0i, R2)
    var v = 0
    while v < hn:
      Fp[v] = zintModSmallSigned(Fd.coeffs, coeffOffset(Fd, v), dlen, p, p0i, R2, Rx)
      Gp[v] = zintModSmallSigned(Gd.coeffs, coeffOffset(Gd, v), dlen, p, p0i, R2, Rx)
      inc v
    modpNtt2(Fp, gm, logn - 1, p, p0i)
    modpNtt2(Gp, gm, logn - 1, p, p0i)
    v = 0
    while v < hn:
      let
        ftA = fx[(v shl 1) + 0]
        ftB = fx[(v shl 1) + 1]
        gtA = gx[(v shl 1) + 0]
        gtB = gx[(v shl 1) + 1]
        mFp = modpMontyMul(Fp[v], R2, p, p0i)
        mGp = modpMontyMul(Gp[v], R2, p, p0i)
      Ft.coeffs[(v shl 1) * llen + u] = modpMontyMul(gtB, mFp, p, p0i)
      Ft.coeffs[((v shl 1) + 1) * llen + u] = modpMontyMul(gtA, mFp, p, p0i)
      Gt.coeffs[(v shl 1) * llen + u] = modpMontyMul(ftB, mGp, p, p0i)
      Gt.coeffs[((v shl 1) + 1) * llen + u] = modpMontyMul(ftA, mGp, p, p0i)
      inc v
    modpIntt2Ext(Ft.coeffs, u, llen, igm, logn, p, p0i)
    modpIntt2Ext(Gt.coeffs, u, llen, igm, logn, p, p0i)
    inc u
  zintRebuildCrt(Ft, llen, true)
  zintRebuildCrt(Gt, llen, true)

  var
    rtCandF = newSeq[FalconFpr](n)
    rtCandG = newSeq[FalconFpr](n)
    rtBaseF = newSeq[FalconFpr](n)
    rtBaseG = newSeq[FalconFpr](n)
    ratio = newSeq[FalconFpr](n)
    invnorm = newSeq[FalconFpr](hn)
  polyBigToFp(rtCandF, Ft, 0, llen)
  polyBigToFp(rtCandG, Gt, 0, llen)
  polyBigToFp(rtBaseF, ft, 0, slen)
  polyBigToFp(rtBaseG, gt, 0, slen)
  falconFft(rtCandF, logn)
  falconFft(rtCandG, logn)
  falconFft(rtBaseF, logn)
  falconFft(rtBaseG, logn)
  polyAddMuladjFft(ratio, rtCandF, rtCandG, rtBaseF, rtBaseG, logn)
  polyInvnorm2Fft(invnorm, rtBaseF, rtBaseG, logn)
  polyMulAutoadjFft(ratio, invnorm, logn)
  falconIfft(ratio, logn)
  u = 0
  while u < n:
    let z = ratio[u]
    if not fprLt(fprMTwo63m1, z) or not fprLt(z, fprPTwo63m1):
      return
    ratio[u] = fprOf(fprRint(z))
    inc u
  falconFft(ratio, logn)
  polyMulFft(rtBaseF, ratio, logn)
  polyMulFft(rtBaseG, ratio, logn)
  polySub(rtCandF, rtBaseF, logn)
  polySub(rtCandG, rtBaseG, logn)
  falconIfft(rtCandF, logn)
  falconIfft(rtCandG, logn)

  result.ok = true
  result.F = initRnsPoly(n, 1)
  result.G = initRnsPoly(n, 1)
  u = 0
  while u < n:
    let packedF = packSigned31(fprRint(rtCandF[u]))
    let packedG = packSigned31(fprRint(rtCandG[u]))
    if not packedF.ok or not packedG.ok:
      result.ok = false
      result.F.coeffs.setLen(0)
      result.G.coeffs.setLen(0)
      return
    result.F.coeffs[u] = packedF.word
    result.G.coeffs[u] = packedG.word
    inc u

proc solveNtruBinaryDepth0(logn: int, f, g: openArray[int8],
    Fd, Gd: RnsPoly): tuple[ok: bool, F, G: RnsPoly] =
  let
    n = 1 shl logn
    hn = n shr 1
    p = falconPrimes[0].p
    p0i = modpNinv31(p)
    R2 = modpR2(p, p0i)
  var
    Fp = newSeq[uint32](hn)
    Gp = newSeq[uint32](hn)
    ft = newSeq[uint32](n)
    gt = newSeq[uint32](n)
    gm = newSeq[uint32](n)
    igm = newSeq[uint32](n)
    u = 0
  modpMkgm2(gm, igm, logn, falconPrimes[0].g, p, p0i)
  while u < hn:
    Fp[u] = modpSet(zintOneToPlain(Fd.coeffs, coeffOffset(Fd, u)), p)
    Gp[u] = modpSet(zintOneToPlain(Gd.coeffs, coeffOffset(Gd, u)), p)
    inc u
  modpNtt2(Fp, gm, logn - 1, p, p0i)
  modpNtt2(Gp, gm, logn - 1, p, p0i)
  u = 0
  while u < n:
    ft[u] = modpSet(int32(f[u]), p)
    gt[u] = modpSet(int32(g[u]), p)
    inc u
  modpNtt2(ft, gm, logn, p, p0i)
  modpNtt2(gt, gm, logn, p, p0i)
  u = 0
  while u < n:
    let
      ftA = ft[u + 0]
      ftB = ft[u + 1]
      gtA = gt[u + 0]
      gtB = gt[u + 1]
      mFp = modpMontyMul(Fp[u shr 1], R2, p, p0i)
      mGp = modpMontyMul(Gp[u shr 1], R2, p, p0i)
    ft[u + 0] = modpMontyMul(gtB, mFp, p, p0i)
    ft[u + 1] = modpMontyMul(gtA, mFp, p, p0i)
    gt[u + 0] = modpMontyMul(ftB, mGp, p, p0i)
    gt[u + 1] = modpMontyMul(ftA, mGp, p, p0i)
    u += 2
  modpIntt2(ft, igm, logn, p, p0i)
  modpIntt2(gt, igm, logn, p, p0i)

  var
    Fpoly = initRnsPoly(n, 1)
    Gpoly = initRnsPoly(n, 1)
    fpoly = initRnsPoly(n, 1)
    gpoly = initRnsPoly(n, 1)
    rtCandF = newSeq[FalconFpr](n)
    rtCandG = newSeq[FalconFpr](n)
    rtBaseF = newSeq[FalconFpr](n)
    rtBaseG = newSeq[FalconFpr](n)
    ratio = newSeq[FalconFpr](n)
    invnorm = newSeq[FalconFpr](hn)
    k = newSeq[int32](n)
  u = 0
  while u < n:
    Fpoly.coeffs[u] = cast[uint32](modpNorm(ft[u], p)) and falconWordMask
    Gpoly.coeffs[u] = cast[uint32](modpNorm(gt[u], p)) and falconWordMask
    fpoly.coeffs[u] = cast[uint32](int32(f[u])) and falconWordMask
    gpoly.coeffs[u] = cast[uint32](int32(g[u])) and falconWordMask
    rtCandF[u] = fprOf(int64(modpNorm(ft[u], p)))
    rtCandG[u] = fprOf(int64(modpNorm(gt[u], p)))
    rtBaseF[u] = fprOf(int64(f[u]))
    rtBaseG[u] = fprOf(int64(g[u]))
    inc u
  falconFft(rtCandF, logn)
  falconFft(rtCandG, logn)
  falconFft(rtBaseF, logn)
  falconFft(rtBaseG, logn)
  polyAddMuladjFft(ratio, rtCandF, rtCandG, rtBaseF, rtBaseG, logn)
  polyInvnorm2Fft(invnorm, rtBaseF, rtBaseG, logn)
  polyMulAutoadjFft(ratio, invnorm, logn)
  falconIfft(ratio, logn)
  u = 0
  while u < n:
    let rounded = fprRint(ratio[u])
    if rounded < low(int32).int64 or rounded > high(int32).int64:
      return
    k[u] = int32(rounded)
    inc u
  polySubScaled(Fpoly, 1, fpoly, 1, k, 0'u32, 0'u32, logn)
  polySubScaled(Gpoly, 1, gpoly, 1, k, 0'u32, 0'u32, logn)
  result.ok = true
  result.F = Fpoly
  result.G = Gpoly

proc solveNtru(logn: int, f, g: openArray[int8], lim: int): tuple[ok: bool, F, G: seq[int8]] =
  let deepest = solveNtruDeepest(logn, f, g)
  if not deepest.ok:
    return
  var
    curF = deepest.F
    curG = deepest.G
    depth = logn
  if logn <= 2:
    while depth > 0:
      dec depth
      let step = solveNtruIntermediate(logn, f, g, depth, curF, curG)
      if not step.ok:
        return
      curF = step.F
      curG = step.G
  else:
    while depth > 2:
      dec depth
      let step = solveNtruIntermediate(logn, f, g, depth, curF, curG)
      if not step.ok:
        return
      curF = step.F
      curG = step.G
    let step1 = solveNtruBinaryDepth1(logn, f, g, curF, curG)
    if not step1.ok:
      return
    curF = step1.F
    curG = step1.G
    let step0 = solveNtruBinaryDepth0(logn, f, g, curF, curG)
    if not step0.ok:
      return
    curF = step0.F
    curG = step0.G
  result.ok = polyBigToSmall(result.F, curF, lim) and polyBigToSmall(result.G, curG, lim)
  if not result.ok:
    secureClearSeqData(result.F)
    secureClearSeqData(result.G)
    result.F.setLen(0)
    result.G.setLen(0)
    return
  let
    n = mknSize(logn)
    p = falconPrimes[0].p
    p0i = modpNinv31(p)
    r = modpMontyMul(12289'u32, 1'u32, p, p0i)
  var
    Gt = newSeq[uint32](n)
    ft = newSeq[uint32](n)
    gt = newSeq[uint32](n)
    Ft = newSeq[uint32](n)
    gm = newSeq[uint32](n)
    igm = newSeq[uint32](n)
    u = 0
  modpMkgm2(gm, igm, logn, falconPrimes[0].g, p, p0i)
  while u < n:
    Gt[u] = modpSet(int32(result.G[u]), p)
    ft[u] = modpSet(int32(f[u]), p)
    gt[u] = modpSet(int32(g[u]), p)
    Ft[u] = modpSet(int32(result.F[u]), p)
    inc u
  modpNtt2(ft, gm, logn, p, p0i)
  modpNtt2(gt, gm, logn, p, p0i)
  modpNtt2(Ft, gm, logn, p, p0i)
  modpNtt2(Gt, gm, logn, p, p0i)
  u = 0
  while u < n:
    let z = modpSub(modpMontyMul(ft[u], Gt[u], p, p0i), modpMontyMul(gt[u], Ft[u], p, p0i), p)
    if z != r:
      secureClearSeqData(result.F)
      secureClearSeqData(result.G)
      result.F.setLen(0)
      result.G.setLen(0)
      result.ok = false
      return
    inc u

proc encodePublicKey(v: FalconVariant, h: openArray[uint16]): seq[byte] =
  let p = params(v)
  result = newSeq[byte](p.publicKeyBytes)
  result[0] = byte(p.logn)
  let used = modQEncode(result.toOpenArray(1, result.high), h, p.logn)
  if used != p.publicKeyBytes - 1:
    raise newException(ValueError, "Falcon public-key encoding failed")

proc encodeSecretKey(v: FalconVariant, f, g, F: openArray[int8]): seq[byte] =
  let
    p = params(v)
    logn = p.logn
  result = newSeq[byte](p.secretKeyBytes)
  result[0] = byte(0x50 + logn)
  var u = 1
  let usedF = trimI8Encode(result.toOpenArray(u, result.high), f, logn, int(falconMaxSmallBits[logn]))
  if usedF == 0:
    raise newException(ValueError, "Falcon secret-key encoding failed for f")
  u += usedF
  let usedG = trimI8Encode(result.toOpenArray(u, result.high), g, logn, int(falconMaxSmallBits[logn]))
  if usedG == 0:
    raise newException(ValueError, "Falcon secret-key encoding failed for g")
  u += usedG
  let usedBigF = trimI8Encode(result.toOpenArray(u, result.high), F, logn, int(falconMaxLargeBits[logn]))
  if usedBigF == 0:
    raise newException(ValueError, "Falcon secret-key encoding failed for F")
  u += usedBigF
  if u != result.len:
    raise newException(ValueError, "Falcon secret-key encoding size mismatch")

proc falconKeygenFromShake*(v: FalconVariant, rng: var FalconShake256): tuple[publicKey, secretKey: seq[byte]] {.otterBench.} =
  let
    p = params(v)
    logn = p.logn
    n = mknSize(logn)
  var
    f = newSeq[int8](n)
    g = newSeq[int8](n)
    h = newSeq[uint16](n)
    F, G: seq[int8]
  while true:
    polySmallMkgauss(rng, f, logn)
    polySmallMkgauss(rng, g, logn)
    var lim = 1 shl (int(falconMaxSmallBits[logn]) - 1)
    var u = 0
    while u < n:
      if f[u] >= int8(lim) or f[u] <= int8(-lim) or g[u] >= int8(lim) or g[u] <= int8(-lim):
        lim = -1
        break
      inc u
    if lim < 0:
      continue
    let
      normf = polySmallSqnorm(f, logn)
      normg = polySmallSqnorm(g, logn)
      norm = (normf + normg) or (0'u32 - ((normf or normg) shr 31))
    if norm >= 16823'u32:
      continue
    var
      rt1 = newSeq[FalconFpr](n)
      rt2 = newSeq[FalconFpr](n)
      rt3 = newSeq[FalconFpr](n shr 1)
      bnorm = fprZero
    polySmallToFp(rt1, f, logn)
    polySmallToFp(rt2, g, logn)
    falconFft(rt1, logn)
    falconFft(rt2, logn)
    polyInvnorm2Fft(rt3, rt1, rt2, logn)
    polyAdjFft(rt1, logn)
    polyAdjFft(rt2, logn)
    polyMulconst(rt1, fprQ, logn)
    polyMulconst(rt2, fprQ, logn)
    polyMulAutoadjFft(rt1, rt3, logn)
    polyMulAutoadjFft(rt2, rt3, logn)
    falconIfft(rt1, logn)
    falconIfft(rt2, logn)
    u = 0
    when falconCompileHasSimd:
      ## Paper note: this is Tyr's applied Falcon keygen optimization: accumulate
      ## the floating norm in two `FalconFpr` lanes, then finish scalar tails.
      if useFalconSimd():
        var acc = zeroFalconSimd2()
        while u + 2 <= n:
          let
            v1 = loadFalconSimd2(rt1, u)
            v2 = loadFalconSimd2(rt2, u)
          acc = addFalconSimd2(acc,
            addFalconSimd2(mulFalconSimd2(v1, v1), mulFalconSimd2(v2, v2)))
          u = u + 2
        bnorm = sumFalconSimd2(acc)
    while u < n:
      bnorm = fprAdd(bnorm, fprSqr(rt1[u]))
      bnorm = fprAdd(bnorm, fprSqr(rt2[u]))
      inc u
    if not fprLt(bnorm, fprBnormMax):
      continue
    if not computePublic(h, f, g, logn):
      continue
    let solved = solveNtru(logn, f, g, (1 shl (int(falconMaxLargeBits[logn]) - 1)) - 1)
    if not solved.ok:
      continue
    F = solved.F
    G = solved.G
    break
  result.publicKey = encodePublicKey(v, h)
  result.secretKey = encodeSecretKey(v, f, g, F)
  secureClearSeqData(F)
  secureClearSeqData(G)

proc falconKeygenFromSeed*(v: FalconVariant, seed: openArray[byte]): tuple[publicKey, secretKey: seq[byte]] {.otterBench.} =
  var rng: FalconShake256
  initFalconShake256(rng, seed)
  falconKeygenFromShake(v, rng)

proc falconKeygenPure*(v: FalconVariant): tuple[publicKey, secretKey: seq[byte]] {.otterBench.} =
  let seed = falconRandomBytes(48)
  falconKeygenFromSeed(v, seed)

proc falconSolveNtruPure*(logn: int, f, g: openArray[int8], lim: int): tuple[ok: bool, F, G: seq[int8]] =
  solveNtru(logn, f, g, lim)
