## -------------------------------------------------------------------
## Falcon Keygen <- pure-Nim Falcon key generation and NTRU solving
## -------------------------------------------------------------------
##
##   seed -> SHAKE256 -> sample small f, g -> filters -> solve F, G -> encode
##
##   filters (cheapest first):  coefficient range -> |f|²+|g|² -> Gram-Schmidt
##                              norm -> f invertible (gives public h = g/f)
##   solve:  f·G - g·F = q, found by halving the degree down to 1, solving
##           there (Bezout), and lifting the answer back up level by level.
##
## Words used below:
##   RNS     one big number stored as its remainders modulo many small primes
##   NTT     a polynomial stored as its values at the roots of x^n + 1, so a
##           product is a pointwise product
##   31-bit  big numbers are arrays of 31-bit words, least significant first

import ./codec
import ../../helpers/secure_memory
import ./fft
import ./fpr
import ./params
when falconCompileHasSimd:
  import ./fpr_simd
import ./randomness
import ./shake
import ./vrfy
import ../../helpers/otter_support
import runePragmas

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

  FalconNttTables = object
    gm: seq[uint32]
    igm: seq[uint32]

  FalconPrimeRuntime = object
    p0i: uint32
    r2: uint32

  FalconFgViews = object
    ntt: tuple[f, g: RnsPoly]
    plain: tuple[f, g: RnsPoly]

  FalconSigned31Mat4 = array[4, array[4, FalconSigned31]]

include ./keygen_consts

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `mknSize`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
template mknSize(logn: int): int =
  1 shl logn

const
  falconWordMask = 0x7FFFFFFF'u32
  falconMaxLogn = 10

## Per-thread memoization. The tables are a pure function of (logn, primeIdx),
## so a thread-local copy is byte-identical to a shared one -- and a shared
## one would be a data race the moment two threads generated keys at once.
var
  falconNttCache {.threadvar.}: array[falconMaxLogn + 1, array[falconPrimes.len, FalconNttTables]]
  falconPrimeCache {.threadvar.}: array[falconPrimes.len, FalconPrimeRuntime]
  falconPrimeCacheReady {.threadvar.}: array[falconPrimes.len, bool]

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `initRnsPoly`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc initRnsPoly(n, stride: int): RnsPoly {.inline, role: {helper}.} =
  ## n: coefficient count. stride: 31-bit words per coefficient.
  RnsPoly(n: n, stride: stride, coeffs: newSeq[uint32](n * stride))

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `clonePoly`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc clonePoly(poly: RnsPoly): RnsPoly {.role: {helper}.} =
  ## poly: polynomial copied into fresh storage.
  result.n = poly.n
  result.stride = poly.stride
  result.coeffs = newSeq[uint32](poly.coeffs.len)
  if poly.coeffs.len > 0:
    copyMem(addr result.coeffs[0], unsafeAddr poly.coeffs[0], poly.coeffs.len * sizeof(uint32))

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `coeffOffset`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc coeffOffset(poly: RnsPoly, coeff: int): int {.inline, role: {helper}.} =
  ## poly/coeff: index of the first word of that coefficient.
  coeff * poly.stride

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `bitReverse10`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc bitReverse10(x: int): int {.role: {math}.} =
  ## x: 10-bit index, returned with its bits in reverse order.
  var
    src: int = x
    i: int = 0
  while i < 10:
    result = (result shl 1) or (src and 1)
    src = src shr 1
    i = i + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `modpSet`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc modpSet(x: int32, p: uint32): uint32 {.inline, role: {math}.} =
  ## x: small signed value, returned as its remainder 0 ..< p.
  result = cast[uint32](x)
  result += p and (0'u32 - (result shr 31))

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `modpNorm`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc modpNorm(x, p: uint32): int32 {.inline, role: {math}.} =
  ## x: remainder mod p, returned as the signed value -p/2 .. p/2.
  cast[int32](x - (p and (((x - ((p + 1'u32) shr 1)) shr 31) - 1'u32)))

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `modpNinv31`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc modpNinv31(p: uint32): uint32 {.role: {math}.} =
  ## p: odd prime. Returns -1/p mod 2^31 (Newton iteration).
  var
    y: uint32 = 2'u32 - p
  y *= 2'u32 - p * y
  y *= 2'u32 - p * y
  y *= 2'u32 - p * y
  y *= 2'u32 - p * y
  0x7FFFFFFF'u32 and (0'u32 - y)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `modpR`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc modpR(p: uint32): uint32 {.inline, role: {math}.} =
  ## p: prime. Returns 2^31 mod p (the Montgomery form of 1).
  (1'u32 shl 31) - p

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `modpAdd`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc modpAdd(a, b, p: uint32): uint32 {.inline, role: {math}.} =
  ## a/b: remainders mod p. Constant-time a + b mod p.
  result = a + b - p
  result += p and (0'u32 - (result shr 31))

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `modpSub`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc modpSub(a, b, p: uint32): uint32 {.inline, role: {math}.} =
  ## a/b: remainders mod p. Constant-time a - b mod p.
  result = a - b
  result += p and (0'u32 - (result shr 31))

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `modpMontyMul`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc modpMontyMul(a, b, p, p0i: uint32): uint32 {.inline, role: {math}.} =
  ## a/b: remainders mod p. p0i: -1/p mod 2^31. Returns a·b/2^31 mod p.
  var
    z: uint64 = uint64(a) * uint64(b)
    w: uint64 = ((z * uint64(p0i)) and 0x7FFFFFFF'u64) * uint64(p)
  result = uint32((z + w) shr 31) - p
  result += p and (0'u32 - (result shr 31))

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `modpR2`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc modpR2(p, p0i: uint32): uint32 {.role: {math}.} =
  ## p/p0i: prime and its Montgomery inverse. Returns 2^62 mod p.
  var
    z: uint32 = modpR(p)
    i: int = 0
  z = modpAdd(z, z, p)
  while i < 5:
    z = modpMontyMul(z, z, p, p0i)
    i = i + 1
  (z + (p and (0'u32 - (z and 1'u32)))) shr 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `modpRx`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc modpRx(x: int, p, p0i, R2: uint32): uint32 {.inline, role: {math}.} =
  ## x: word count. Returns 2^(31·x) mod p in Montgomery form.
  var
    e: int = x - 1
    r: uint32 = R2
    i: int = 0
  result = modpR(p)
  while (1 shl i) <= e:
    if (e and (1 shl i)) != 0:
      result = modpMontyMul(result, r, p, p0i)
    r = modpMontyMul(r, r, p, p0i)
    i = i + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `modpDiv`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc modpDiv(a, b, p, p0i, R: uint32): uint32 {.role: {math}.} =
  ## a/b: remainders mod p. Returns a/b mod p through b^(p-2), constant time.
  var
    z: uint32 = R
    z2: uint32 = 0'u32
    e: uint32 = p - 2'u32
    i: int = 30
  while i >= 0:
    z = modpMontyMul(z, z, p, p0i)
    z2 = modpMontyMul(z, b, p, p0i)
    z = z xor ((z xor z2) and (0'u32 - ((e shr i) and 1'u32)))
    i = i - 1
  z = modpMontyMul(z, 1'u32, p, p0i)
  modpMontyMul(a, z, p, p0i)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `modpMkgm2`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc modpMkgm2(gm, igm: var seq[uint32], logn: int, g, p, p0i: uint32) {.role: {math}.} =
  ## gm/igm: receive the NTT roots and their inverses (bit-reversed order).
  ## g: primitive 2048th root of unity mod p.
  var
    n: int = mknSize(logn)
    root: uint32 = modpMontyMul(g, modpR2(p, p0i), p, p0i)
    ig: uint32 = 0'u32
    shift: int = 10 - logn
    x1: uint32 = modpR(p)
    x2: uint32 = modpR(p)
    k: int = logn
    v: int = 0
    u: int = 0
  gm.setLen(n)
  igm.setLen(n)
  while k < 10:
    root = modpMontyMul(root, root, p, p0i)
    k = k + 1
  ig = modpDiv(modpR2(p, p0i), root, p, p0i, modpR(p))
  while u < n:
    v = bitReverse10(u shl shift)
    gm[v] = x1
    igm[v] = x2
    x1 = modpMontyMul(x1, root, p, p0i)
    x2 = modpMontyMul(x2, ig, p, p0i)
    u = u + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `getFalconPrimeRuntime`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc getFalconPrimeRuntime(primeIdx: int): FalconPrimeRuntime {.inline, role: {memory}.} =
  ## primeIdx: small prime; its Montgomery constants are computed once per thread.
  var
    p: uint32 = falconPrimes[primeIdx].p
  if not falconPrimeCacheReady[primeIdx]:
    falconPrimeCache[primeIdx].p0i = modpNinv31(p)
    falconPrimeCache[primeIdx].r2 = modpR2(p, falconPrimeCache[primeIdx].p0i)
    falconPrimeCacheReady[primeIdx] = true
  result = falconPrimeCache[primeIdx]

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `getFalconNttTables`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc getFalconNttTables(logn, primeIdx: int): FalconNttTables {.inline, role: {memory}.} =
  ## logn/primeIdx: NTT root tables, computed once per thread.
  var
    prime: FalconSmallPrime = falconPrimes[primeIdx]
  if falconNttCache[logn][primeIdx].gm.len != mknSize(logn):
    modpMkgm2(falconNttCache[logn][primeIdx].gm, falconNttCache[logn][primeIdx].igm,
      logn, prime.g, prime.p, getFalconPrimeRuntime(primeIdx).p0i)
  result = falconNttCache[logn][primeIdx]

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `nttButterflies`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc nttButterflies(a: var seq[uint32], off, stride, v1, ht: int,
    s, p, p0i: uint32) {.inline, role: {math}.} =
  ## One NTT group: for v in 0 ..< ht the pair (x, y) at v1 + v and
  ## v1 + ht + v becomes (x + s·y, x - s·y).
  var
    i1: int = 0
    i2: int = 0
    x: uint32 = 0'u32
    y: uint32 = 0'u32
    v: int = 0
  while v < ht:
    i1 = off + (v1 + v) * stride
    i2 = off + (v1 + ht + v) * stride
    x = a[i1]
    y = modpMontyMul(a[i2], s, p, p0i)
    a[i1] = modpAdd(x, y, p)
    a[i2] = modpSub(x, y, p)
    v = v + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `modpNtt2Ext`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc modpNtt2Ext(a: var seq[uint32], off, stride: int,
    gm: openArray[uint32], logn: int, p, p0i: uint32) {.role: {math}.} =
  ## a: n values at off, off + stride, ... turned into NTT form in place.
  var
    n: int = mknSize(logn)
    t: int = n
    m: int = 1
    ht: int = 0
    u: int = 0
    v1: int = 0
  if logn == 0:
    return
  while m < n:
    ht = t shr 1
    u = 0
    v1 = 0
    while u < m:
      nttButterflies(a, off, stride, v1, ht, gm[m + u], p, p0i)
      u = u + 1
      v1 = v1 + t
    t = ht
    m = m shl 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `modpNtt2`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc modpNtt2(a: var seq[uint32], gm: openArray[uint32], logn: int,
    p, p0i: uint32) {.inline, role: {math}.} =
  ## a: contiguous polynomial turned into NTT form in place.
  modpNtt2Ext(a, 0, 1, gm, logn, p, p0i)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `inttButterflies`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc inttButterflies(a: var seq[uint32], off, stride, v1, t: int,
    s, p, p0i: uint32) {.inline, role: {math}.} =
  ## One inverse NTT group: for v in 0 ..< t the pair (x, y) at v1 + v and
  ## v1 + t + v becomes (x + y, (x - y)·s).
  var
    i1: int = 0
    i2: int = 0
    x: uint32 = 0'u32
    y: uint32 = 0'u32
    v: int = 0
  while v < t:
    i1 = off + (v1 + v) * stride
    i2 = off + (v1 + t + v) * stride
    x = a[i1]
    y = a[i2]
    a[i1] = modpAdd(x, y, p)
    a[i2] = modpMontyMul(modpSub(x, y, p), s, p, p0i)
    v = v + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `modpIntt2Ext`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc modpIntt2Ext(a: var seq[uint32], off, stride: int,
    igm: openArray[uint32], logn: int, p, p0i: uint32) {.role: {math}.} =
  ## a: n NTT values at off, off + stride, ... turned back into coefficients.
  var
    n: int = mknSize(logn)
    t: int = 1
    m: int = n
    hm: int = 0
    dt: int = 0
    u: int = 0
    v1: int = 0
    ni: uint32 = 0'u32
    k: int = 0
  if logn == 0:
    return
  while m > 1:
    hm = m shr 1
    dt = t shl 1
    u = 0
    v1 = 0
    while u < hm:
      inttButterflies(a, off, stride, v1, t, igm[hm + u], p, p0i)
      u = u + 1
      v1 = v1 + dt
    t = dt
    m = hm
  ni = uint32(1 shl (31 - logn))
  while k < n:
    a[off + k * stride] = modpMontyMul(a[off + k * stride], ni, p, p0i)
    k = k + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `modpIntt2`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc modpIntt2(a: var seq[uint32], igm: openArray[uint32], logn: int,
    p, p0i: uint32) {.inline, role: {math}.} =
  ## a: contiguous NTT polynomial turned back into coefficients in place.
  modpIntt2Ext(a, 0, 1, igm, logn, p, p0i)

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
proc zintMulSmall(m: var seq[uint32], mOff, mLen: int, x: uint32): uint32 {.role: {math}.} =
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
proc zintModSmallUnsigned(d: openArray[uint32], dOff, dLen: int,
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
proc zintModSmallSigned(d: openArray[uint32], dOff, dLen: int,
    p, p0i, R2, Rx: uint32): uint32 {.role: {math}.} =
  ## d: signed big number (two's complement on 31-bit words). Returns d mod p.
  ## Rx: 2^(31·dLen) mod p, removed again when d is negative.
  if dLen == 0:
    return 0'u32
  result = zintModSmallUnsigned(d, dOff, dLen, p, p0i, R2)
  result = modpSub(result, Rx and (0'u32 - (d[dOff + dLen - 1] shr 30)), p)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `zintAddMulSmall`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc zintAddMulSmall(x: var seq[uint32], xOff: int, y: openArray[uint32], yOff, len: int,
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
proc zintNormZero(x: var seq[uint32], xOff: int, p: openArray[uint32], pOff, len: int) {.role: {math}.} =
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
proc zintBezout(u, v: var seq[uint32], x, y: openArray[uint32], len: int): bool {.role: {math}.} =
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
proc zintAddScaledMulSmall(x: var seq[uint32], xOff, xLen: int,
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
proc zintSubScaled(x: var seq[uint32], xOff, xLen: int,
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
proc zintOneToPlain(x: openArray[uint32], off: int): int32 {.inline, role: {math}.} =
  ## x[off]: one signed 31-bit word, returned as a normal int32.
  var
    w: uint32 = x[off]
  w = w or ((w and 0x40000000'u32) shl 1)
  cast[int32](w)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `trimAbs31`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc trimAbs31(A: var seq[uint32]) {.role: {helper}.} =
  ## A: magnitude; zero words at the top are dropped.
  while A.len > 0 and A[^1] == 0'u32:
    A.setLen(A.len - 1)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `cmpAbs31`; pitfall: fail closed and preserve canonical, constant-time comparison where secrets are involved.
proc cmpAbs31(A, B: openArray[uint32]): int {.role: {math}.} =
  ## A/B: magnitudes. Returns -1, 0 or 1 like A <=> B.
  var
    al: int = A.len
    bl: int = B.len
    i: int = 0
  while al > 0 and A[al - 1] == 0'u32:
    al = al - 1
  while bl > 0 and B[bl - 1] == 0'u32:
    bl = bl - 1
  if al < bl:
    return -1
  if al > bl:
    return 1
  i = al
  while i > 0:
    i = i - 1
    if A[i] < B[i]:
      return -1
    if A[i] > B[i]:
      return 1
  0

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `addAbs31`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc addAbs31(A, B: openArray[uint32]): seq[uint32] {.role: {math}.} =
  ## A/B: magnitudes. Returns A + B.
  var
    n: int = max(A.len, B.len)
    carry: uint32 = 0'u32
    aw: uint32 = 0'u32
    bw: uint32 = 0'u32
    z: uint64 = 0'u64
    i: int = 0
  result = newSeq[uint32](n + 1)
  while i < n:
    aw = (if i < A.len: A[i] else: 0'u32)
    bw = (if i < B.len: B[i] else: 0'u32)
    z = uint64(aw) + uint64(bw) + uint64(carry)
    result[i] = uint32(z) and falconWordMask
    carry = uint32(z shr 31)
    i = i + 1
  result[n] = carry
  trimAbs31(result)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `subAbs31`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc subAbs31(A, B: openArray[uint32]): seq[uint32] {.role: {math}.} =
  ## A/B: magnitudes with A >= B. Returns A - B.
  var
    borrow: uint32 = 0'u32
    bw: uint32 = 0'u32
    z: uint32 = 0'u32
    i: int = 0
  result = newSeq[uint32](A.len)
  while i < A.len:
    bw = (if i < B.len: B[i] else: 0'u32)
    z = A[i] - bw - borrow
    result[i] = z and falconWordMask
    borrow = z shr 31
    i = i + 1
  trimAbs31(result)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `addSigned31`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc addSigned31(a, b: FalconSigned31): FalconSigned31 {.role: {math}.} =
  ## a/b: signed big numbers. Returns a + b (zero is never negative).
  var
    c: int = 0
  if a.neg == b.neg:
    result.neg = a.neg
    result.words = addAbs31(a.words, b.words)
  else:
    c = cmpAbs31(a.words, b.words)
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

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `negSigned31`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc negSigned31(a: FalconSigned31): FalconSigned31 {.inline, role: {math}.} =
  ## a: signed big number. Returns -a.
  result = a
  if result.words.len != 0:
    result.neg = not result.neg

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `subSigned31`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc subSigned31(a, b: FalconSigned31): FalconSigned31 {.inline, role: {math}.} =
  ## a/b: signed big numbers. Returns a - b.
  addSigned31(a, negSigned31(b))

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `mulAddRow`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc mulAddRow(R: var seq[uint32], a: uint32, B: openArray[uint32], i: int)
    {.inline, role: {math}.} =
  ## R += a·B·2^(31·i); the carry runs on as far as it needs to.
  var
    carry: uint64 = 0'u64
    z: uint64 = 0'u64
    j: int = 0
    idx: int = i + B.len
  while j < B.len:
    z = uint64(R[i + j]) + uint64(a) * uint64(B[j]) + carry
    R[i + j] = uint32(z) and falconWordMask
    carry = z shr 31
    j = j + 1
  while carry != 0'u64:
    z = uint64(R[idx]) + carry
    R[idx] = uint32(z) and falconWordMask
    carry = z shr 31
    idx = idx + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `mulAbs31`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc mulAbs31(A, B: openArray[uint32]): seq[uint32] {.role: {math}.} =
  ## A/B: magnitudes. Returns A·B (schoolbook, one row per word of A).
  var
    i: int = 0
  if A.len == 0 or B.len == 0:
    return @[]
  result = newSeq[uint32](A.len + B.len)
  while i < A.len:
    mulAddRow(result, A[i], B, i)
    i = i + 1
  trimAbs31(result)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `mulSigned31`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc mulSigned31(a, b: FalconSigned31): FalconSigned31 {.role: {math}.} =
  ## a/b: signed big numbers. Returns a·b.
  result.neg = a.neg xor b.neg
  result.words = mulAbs31(a.words, b.words)
  if result.words.len == 0:
    result.neg = false

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `shiftLeftAbs31`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc shiftLeftAbs31(A: openArray[uint32], scale: int): seq[uint32] {.role: {math}.} =
  ## A: magnitude. Returns A·2^scale.
  var
    sch: int = scale div 31
    scl: int = scale mod 31
    carry: uint32 = 0'u32
    w: uint32 = 0'u32
    i: int = 0
  if A.len == 0:
    return @[]
  result = newSeq[uint32](A.len + sch + (if scl == 0: 0 else: 1))
  while i < A.len:
    w = A[i]
    result[sch + i] = ((w shl scl) and falconWordMask) or carry
    carry = (if scl == 0: 0'u32 else: w shr (31 - scl))
    i = i + 1
  if scl != 0:
    result[sch + A.len] = carry
  trimAbs31(result)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `decodeCoeff31`; pitfall: reject malformed or non-canonical input before indexed access.
proc decodeCoeff31(poly: RnsPoly, coeff, wordLen: int): FalconSigned31 {.role: {parser}.} =
  ## poly/coeff: one two's-complement coefficient of wordLen words, returned
  ## as sign + magnitude.
  var
    off: int = 0
    negMask: uint32 = 0'u32
    xm: uint32 = 0'u32
    cc: uint32 = 0'u32
    w: uint32 = 0'u32
    i: int = 0
  if wordLen <= 0:
    return
  off = coeffOffset(poly, coeff)
  negMask = 0'u32 - (poly.coeffs[off + wordLen - 1] shr 30)
  xm = negMask shr 1
  cc = negMask and 1'u32
  result.neg = negMask != 0'u32
  result.words = newSeq[uint32](wordLen)
  while i < wordLen:
    w = (poly.coeffs[off + i] xor xm) + cc
    cc = w shr 31
    result.words[i] = w and falconWordMask
    i = i + 1
  trimAbs31(result.words)
  if result.words.len == 0:
    result.neg = false

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `cloneWords31`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc cloneWords31(A: openArray[uint32]): seq[uint32] {.role: {helper}.} =
  ## A: words copied into a fresh seq.
  result = newSeq[uint32](A.len)
  if A.len > 0:
    copyMem(addr result[0], unsafeAddr A[0], A.len * sizeof(uint32))

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `bitLen31`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc bitLen31(w: uint32): int {.inline, role: {math}.} =
  ## w: word. Returns the position of its highest set bit plus one.
  var
    x: uint32 = w
  while x != 0'u32:
    result = result + 1
    x = x shr 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `divRemOneWord`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc divRemOneWord(num: openArray[uint32], d: uint32): tuple[q, r: seq[uint32]]
    {.role: {math}.} =
  ## num: magnitude. d: one-word divisor. Returns quotient and remainder.
  var
    rem: uint64 = 0'u64
    cur: uint64 = 0'u64
    i: int = num.len
  result.q = newSeq[uint32](num.len)
  while i > 0:
    i = i - 1
    cur = (rem shl 31) + uint64(num[i])
    result.q[i] = uint32(cur div uint64(d))
    rem = cur mod uint64(d)
  if rem != 0'u64:
    result.r = @[uint32(rem)]
  trimAbs31(result.q)
  trimAbs31(result.r)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `estimateQhat`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc estimateQhat(un, vn: openArray[uint32], j, n: int): uint64 {.role: {math}.} =
  ## Long division step (Knuth D3): guesses quotient word j from the top
  ## words of un and vn. The guess is never too small and at most 2 too big.
  const
    base: uint64 = 1'u64 shl 31
  var
    top: uint64 = (uint64(un[j + n]) shl 31) + uint64(un[j + n - 1])
    rhat: uint64 = top mod uint64(vn[n - 1])
    check: bool = n > 1
  result = top div uint64(vn[n - 1])
  if result >= base:
    result = base - 1
    rhat = top - result * uint64(vn[n - 1])
  while check and result * uint64(vn[n - 2]) > (rhat shl 31) + uint64(un[j + n - 2]):
    result = result - 1
    rhat = rhat + uint64(vn[n - 1])
    check = rhat < base

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `mulSubWords`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc mulSubWords(un: var seq[uint32], vn: openArray[uint32], j, n: int,
    qhat: uint64): uint64 {.role: {math}.} =
  ## Long division step (Knuth D4): un[j ..< j + n] -= qhat·vn.
  ## Returns what word j + n still has to give up.
  const
    base: uint64 = 1'u64 shl 31
  var
    borrow: uint64 = 0'u64
    carry: uint64 = 0'u64
    prod: uint64 = 0'u64
    sub: uint64 = 0'u64
    i: int = 0
  while i < n:
    prod = qhat * uint64(vn[i]) + carry
    carry = prod shr 31
    sub = uint64(uint32(prod) and falconWordMask) + borrow
    if uint64(un[j + i]) < sub:
      un[j + i] = uint32(uint64(un[j + i]) + base - sub)
      borrow = 1'u64
    else:
      un[j + i] = uint32(uint64(un[j + i]) - sub)
      borrow = 0'u64
    i = i + 1
  result = carry + borrow

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `addBackWords`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc addBackWords(un: var seq[uint32], vn: openArray[uint32], j, n: int) {.role: {math}.} =
  ## Long division step (Knuth D6): the guess was one too big, so vn is
  ## added back once to un[j ..< j + n].
  var
    carry: uint64 = 0'u64
    z: uint64 = 0'u64
    i: int = 0
  while i < n:
    z = uint64(un[j + i]) + uint64(vn[i]) + carry
    un[j + i] = uint32(z and falconWordMask)
    carry = z shr 31
    i = i + 1
  un[j + n] = uint32(uint64(un[j + n]) + carry)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `divRemAbs31`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc divRemAbs31(num, den: openArray[uint32]): tuple[q, r: seq[uint32]] {.gcsafe, role: {math}.} =
  ## num/den: magnitudes. Long division (Knuth algorithm D): den is shifted
  ## until its top word is full, then each quotient word is guessed and fixed.
  ## Note: the remainder is returned still shifted (times 2^shift).
  var
    numCmp: int = cmpAbs31(num, den)
    shift: int = 0
    vn: seq[uint32] = @[]
    un: seq[uint32] = @[]
    n: int = 0
    m: int = 0
    qhat: uint64 = 0'u64
    topSub: uint64 = 0'u64
    j: int = 0
  if den.len == 0:
    raise newException(ValueError, "division by zero")
  if numCmp < 0:
    result.q = @[]
    result.r = cloneWords31(num)
    trimAbs31(result.r)
    return
  if den.len == 1:
    return divRemOneWord(num, den[0])
  shift = 31 - bitLen31(den[^1])
  vn = (if shift == 0: cloneWords31(den) else: shiftLeftAbs31(den, shift))
  un = (if shift == 0: cloneWords31(num) else: shiftLeftAbs31(num, shift))
  if un.len == num.len:
    un.add(0'u32)
  n = vn.len
  m = un.len - n - 1
  result.q = newSeq[uint32](m + 1)
  j = m + 1
  while j > 0:
    j = j - 1
    qhat = estimateQhat(un, vn, j, n)
    topSub = mulSubWords(un, vn, j, n, qhat)
    if uint64(un[j + n]) < topSub:
      qhat = qhat - 1
      addBackWords(un, vn, j, n)
    else:
      un[j + n] = uint32(uint64(un[j + n]) - topSub)
    result.q[j] = uint32(qhat)
  result.r = un[0 ..< n]
  trimAbs31(result.q)
  trimAbs31(result.r)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `roundDivAbs31`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc roundDivAbs31(num, den: openArray[uint32]): uint32 {.role: {math}.} =
  ## num/den: magnitudes. Returns num/den rounded to nearest (ties to even),
  ## or 0x80000000 when the quotient needs more than one word.
  var
    qr: tuple[q, r: seq[uint32]] = divRemAbs31(num, den)
    q: uint32 = 0'u32
    cmp: int = 0
  if qr.q.len > 1:
    return 0x80000000'u32
  q = (if qr.q.len == 0: 0'u32 else: qr.q[0])
  cmp = cmpAbs31(addAbs31(qr.r, qr.r), den)
  if cmp > 0 or (cmp == 0 and (q and 1'u32) != 0'u32):
    return q + 1'u32
  q

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `roundDivSigned31`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc roundDivSigned31(num: FalconSigned31, den: openArray[uint32]): int32 {.role: {math}.} =
  ## num: signed big number. den: magnitude. Returns round(num/den).
  var
    q: uint32 = 0'u32
  if num.words.len == 0:
    return 0'i32
  q = roundDivAbs31(num.words, den)
  if q >= 0x80000000'u32:
    raise newException(ValueError, "Falcon exact reducer overflow")
  if num.neg:
    return -cast[int32](q)
  cast[int32](q)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `polyAdjSmall31`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyAdjSmall31(a: openArray[FalconSigned31]): seq[FalconSigned31] {.role: {math}.} =
  ## a: polynomial mod x^n + 1. Returns its adjoint a(1/x).
  var
    i: int = 1
  result = newSeq[FalconSigned31](a.len)
  if a.len == 0:
    return
  result[0] = a[0]
  while i < a.len:
    result[i] = negSigned31(a[a.len - i])
    i = i + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `polyAddSmall31`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyAddSmall31(a, b: openArray[FalconSigned31]): seq[FalconSigned31] {.role: {math}.} =
  ## a/b: polynomials. Returns a + b.
  var
    i: int = 0
  result = newSeq[FalconSigned31](a.len)
  while i < a.len:
    result[i] = addSigned31(a[i], b[i])
    i = i + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `addTermModXn1`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc addTermModXn1(R: var seq[FalconSigned31], k: int, term: FalconSigned31)
    {.inline, role: {math}.} =
  ## R: product being built. term lands on x^k; past degree n-1 it wraps
  ## around with a minus sign, because x^n = -1.
  if k < R.len:
    R[k] = addSigned31(R[k], term)
  else:
    R[k - R.len] = subSigned31(R[k - R.len], term)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `polyMulModXn1Small31`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyMulModXn1Small31(a, b: openArray[FalconSigned31]): seq[FalconSigned31] {.role: {math}.} =
  ## a/b: polynomials of n coefficients. Returns a·b mod x^n + 1.
  var
    n: int = a.len
    i: int = 0
    j: int = 0
  result = newSeq[FalconSigned31](n)
  while i < n:
    addTermModXn1(result, i + j, mulSigned31(a[i], b[j]))
    j = j + 1
    if j == n:
      j = 0
      i = i + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `mulMat4FromPoly`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc mulMat4FromPoly(poly: openArray[FalconSigned31]): FalconSigned31Mat4 {.role: {math}.} =
  ## poly: 4 coefficients. Returns the matrix of "multiply by poly mod x^4 + 1".
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

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `replaceMat4Column`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc replaceMat4Column(M: FalconSigned31Mat4, col: int,
    v: openArray[FalconSigned31]): FalconSigned31Mat4 {.role: {math}.} =
  ## M: matrix. Returns M with column col replaced by v.
  var
    row: int = 0
  result = M
  while row < 4:
    result[row][col] = v[row]
    row = row + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `det2Small31`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc det2Small31(a00, a01, a10, a11: FalconSigned31): FalconSigned31 {.inline, role: {math}.} =
  ## Determinant of [[a00 a01] [a10 a11]].
  subSigned31(mulSigned31(a00, a11), mulSigned31(a01, a10))

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `det3Small31`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc det3Small31(a00, a01, a02, a10, a11, a12, a20, a21, a22: FalconSigned31): FalconSigned31 {.role: {math}.} =
  ## Determinant of a 3x3 matrix, expanded along the first row.
  var
    t0: FalconSigned31 = mulSigned31(a00, det2Small31(a11, a12, a21, a22))
    t1: FalconSigned31 = mulSigned31(a01, det2Small31(a10, a12, a20, a22))
    t2: FalconSigned31 = mulSigned31(a02, det2Small31(a10, a11, a20, a21))
  addSigned31(subSigned31(t0, t1), t2)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `det4Small31`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc det4Small31(M: FalconSigned31Mat4): FalconSigned31 {.role: {math}.} =
  ## Determinant of a 4x4 matrix, expanded along the first row.
  var
    t0: FalconSigned31 = mulSigned31(M[0][0], det3Small31(
      M[1][1], M[1][2], M[1][3],
      M[2][1], M[2][2], M[2][3],
      M[3][1], M[3][2], M[3][3]))
    t1: FalconSigned31 = mulSigned31(M[0][1], det3Small31(
      M[1][0], M[1][2], M[1][3],
      M[2][0], M[2][2], M[2][3],
      M[3][0], M[3][2], M[3][3]))
    t2: FalconSigned31 = mulSigned31(M[0][2], det3Small31(
      M[1][0], M[1][1], M[1][3],
      M[2][0], M[2][1], M[2][3],
      M[3][0], M[3][1], M[3][3]))
    t3: FalconSigned31 = mulSigned31(M[0][3], det3Small31(
      M[1][0], M[1][1], M[1][2],
      M[2][0], M[2][1], M[2][2],
      M[3][0], M[3][1], M[3][2]))
  addSigned31(subSigned31(addSigned31(t0, t2), t1), negSigned31(t3))

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `bigCoeffToFp`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc bigCoeffToFp(poly: RnsPoly, u, wordOff, wordLen: int): FalconFpr {.role: {math}.} =
  ## poly/u: one signed big coefficient; words wordOff ..< wordOff + wordLen
  ## are read and turned into a floating-point value (0 when wordLen = 0).
  var
    base: int = 0
    neg: uint32 = 0'u32
    xm: uint32 = 0'u32
    cc: uint32 = 0'u32
    fsc: FalconFpr = fprOne
    w: uint32 = 0'u32
    v: int = 0
  result = fprZero
  if wordLen == 0:
    return
  base = coeffOffset(poly, u) + wordOff
  neg = 0'u32 - (poly.coeffs[base + wordLen - 1] shr 30)
  xm = neg shr 1
  cc = neg and 1'u32
  while v < wordLen:
    w = (poly.coeffs[base + v] xor xm) + cc
    cc = w shr 31
    w = w and 0x7FFFFFFF'u32
    w = w - ((w shl 1) and neg)
    result = fprAdd(result, fprMul(fprOf(int64(cast[int32](w))), fsc))
    fsc = fprMul(fsc, fprPTwo31)
    v = v + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `polyBigToFp`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyBigToFp(dst: var seq[FalconFpr], poly: RnsPoly, wordOff, wordLen: int) {.role: {math}.} =
  ## dst: receives every coefficient of poly as a floating-point value.
  var
    u: int = 0
  dst.setLen(poly.n)
  while u < poly.n:
    dst[u] = bigCoeffToFp(poly, u, wordOff, wordLen)
    u = u + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `polyBigToSmall`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyBigToSmall(dst: var seq[int8], poly: RnsPoly, lim: int): bool {.role: {parser}.} =
  ## dst: receives poly as small values. False when one leaves -lim .. lim.
  var
    z: int32 = 0'i32
    u: int = 0
  dst.setLen(poly.n)
  while u < poly.n:
    z = zintOneToPlain(poly.coeffs, coeffOffset(poly, u))
    if z < -lim or z > lim:
      return false
    dst[u] = int8(z)
    u = u + 1
  true

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `subScaledRow`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc subScaledRow(F: var RnsPoly, FLen: int, f: RnsPoly, fLen: int, k: int32,
    u, n: int, sch, scl: uint32) {.inline, role: {math}.} =
  ## F -= k·x^u·f·2^(31·sch + scl) mod x^n + 1: f[v] lands on F[u + v],
  ## with the sign flipped once the index wraps past x^n.
  var
    kf: int32 = -k
    coeff: int = u
    v: int = 0
  while v < n:
    zintAddScaledMulSmall(F.coeffs, coeffOffset(F, coeff), FLen,
      f.coeffs, coeffOffset(f, v), fLen, kf, sch, scl)
    if u + v == n - 1:
      coeff = 0
      kf = -kf
    else:
      coeff = coeff + 1
    v = v + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `polySubScaled`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polySubScaled(F: var RnsPoly, FLen: int, f: RnsPoly, fLen: int,
    k: openArray[int32], sch, scl: uint32, logn: int) {.role: {math}.} =
  ## F -= k·f·2^(31·sch + scl) mod x^n + 1, schoolbook product.
  var
    n: int = mknSize(logn)
    u: int = 0
  while u < n:
    subScaledRow(F, FLen, f, fLen, k[u], u, n, sch, scl)
    u = u + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `crtMergePrime`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc crtMergePrime(poly: var RnsPoly, tmp: seq[uint32], u: int) {.role: {math}.} =
  ## poly: word u (the remainder mod prime u) of every coefficient is merged
  ## into the big number held in words 0 ..< u. tmp: product of primes 0 ..< u.
  var
    p: uint32 = falconPrimes[u].p
    s: uint32 = falconPrimes[u].s
    p0i: uint32 = modpNinv31(p)
    R2: uint32 = modpR2(p, p0i)
    xOff: int = 0
    xp: uint32 = 0'u32
    xq: uint32 = 0'u32
    xr: uint32 = 0'u32
    v: int = 0
  while v < poly.n:
    xOff = coeffOffset(poly, v)
    xp = poly.coeffs[xOff + u]
    xq = zintModSmallUnsigned(poly.coeffs, xOff, u, p, p0i, R2)
    xr = modpMontyMul(s, modpSub(xp, xq, p), p, p0i)
    zintAddMulSmall(poly.coeffs, xOff, tmp, 0, u, xr)
    v = v + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `zintRebuildCrt`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc zintRebuildCrt(poly: var RnsPoly, xLen: int, normalizeSigned: bool) {.role: {math}.} =
  ## poly: every coefficient holds xLen remainders (one per small prime).
  ## They are merged into one big number (Garner's method); with
  ## normalizeSigned it is then moved into -P/2 .. P/2.
  var
    tmp: seq[uint32] = newSeq[uint32](xLen)
    u: int = 1
    v: int = 0
  tmp[0] = falconPrimes[0].p
  while u < xLen:
    crtMergePrime(poly, tmp, u)
    tmp[u] = zintMulSmall(tmp, 0, u, falconPrimes[u].p)
    u = u + 1
  while normalizeSigned and v < poly.n:
    zintNormZero(poly.coeffs, coeffOffset(poly, v), tmp, 0, xLen)
    v = v + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `mulKfOnePrime`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc mulKfOnePrime(fk: var RnsPoly, t1: var seq[uint32], f: RnsPoly, fLen: int,
    k: openArray[int32], u, logn: int) {.role: {math}.} =
  ## fk: word u of every coefficient receives k·f mod prime u (NTT product).
  ## t1: scratch of n words.
  var
    n: int = mknSize(logn)
    tLen: int = fk.stride
    prime: FalconSmallPrime = falconPrimes[u]
    runtime: FalconPrimeRuntime = getFalconPrimeRuntime(u)
    tables: FalconNttTables = getFalconNttTables(logn, u)
    Rx: uint32 = modpRx(fLen, prime.p, runtime.p0i, runtime.r2)
    idx: int = 0
    v: int = 0
  while v < n:
    t1[v] = modpSet(k[v], prime.p)
    v = v + 1
  modpNtt2(t1, tables.gm, logn, prime.p, runtime.p0i)
  v = 0
  while v < n:
    fk.coeffs[v * tLen + u] = zintModSmallSigned(f.coeffs, coeffOffset(f, v), fLen,
      prime.p, runtime.p0i, runtime.r2, Rx)
    v = v + 1
  modpNtt2Ext(fk.coeffs, u, tLen, tables.gm, logn, prime.p, runtime.p0i)
  v = 0
  while v < n:
    idx = v * tLen + u
    fk.coeffs[idx] = modpMontyMul(modpMontyMul(t1[v], fk.coeffs[idx], prime.p,
      runtime.p0i), runtime.r2, prime.p, runtime.p0i)
    v = v + 1
  modpIntt2Ext(fk.coeffs, u, tLen, tables.igm, logn, prime.p, runtime.p0i)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `polySubScaledNtt`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polySubScaledNtt(F: var RnsPoly, FLen: int, f: RnsPoly, fLen: int,
    k: openArray[int32], sch, scl: uint32, logn: int) {.role: {math}.} =
  ## F -= k·f·2^(31·sch + scl) mod x^n + 1; the product k·f is made per
  ## small prime in NTT form, then merged back into big numbers.
  var
    n: int = mknSize(logn)
    tLen: int = fLen + 1
    fk: RnsPoly = initRnsPoly(n, tLen)
    t1: seq[uint32] = newSeq[uint32](n)
    u: int = 0
    coeff: int = 0
  while u < tLen:
    mulKfOnePrime(fk, t1, f, fLen, k, u, logn)
    u = u + 1
  zintRebuildCrt(fk, tLen, true)
  while coeff < n:
    zintSubScaled(F.coeffs, coeffOffset(F, coeff), FLen, fk.coeffs, coeffOffset(fk, coeff), tLen, sch, scl)
    coeff = coeff + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `getRngU64`; pitfall: use deterministic generation only for KAT replay and system entropy in production.
proc getRngU64(rng: var FalconShake256): uint64 {.role: {dataFetcher}.} =
  ## rng: SHAKE256 reader. Returns its next 8 bytes, little-endian.
  var
    tmp: array[8, byte] = default(array[8, byte])
  extractFalconShake256(rng, tmp)
  uint64(tmp[0]) or
    (uint64(tmp[1]) shl 8) or
    (uint64(tmp[2]) shl 16) or
    (uint64(tmp[3]) shl 24) or
    (uint64(tmp[4]) shl 32) or
    (uint64(tmp[5]) shl 40) or
    (uint64(tmp[6]) shl 48) or
    (uint64(tmp[7]) shl 56)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `gaussMagnitude`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc gaussMagnitude(r: uint64, f0: uint32): uint32 {.inline, role: {math}.} =
  ## r: 63 random bits. f0: 1 when the sample is already known to be 0.
  ## Walks the whole cumulative table (constant time) and returns the first
  ## index k >= 1 whose table entry is not above r, or 0.
  var
    f: uint32 = f0
    t: uint32 = 0'u32
    k: int = 1
  while k < falconGauss1024_12289.len:
    t = uint32((r - falconGauss1024_12289[k]) shr 63) xor 1'u32
    result = result or (uint32(k) and (0'u32 - (t and (f xor 1'u32))))
    f = f or t
    k = k + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `mkgauss`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc mkgauss(rng: var FalconShake256, logn: int): int {.role: {math}.} =
  ## rng: SHAKE256 reader. Returns one Gaussian sample for degree 2^logn:
  ## the sum of 2^(10 - logn) samples from the degree-1024 table.
  var
    g: int = 1 shl (10 - logn)
    r: uint64 = 0'u64
    neg: uint32 = 0'u32
    f: uint32 = 0'u32
    v: uint32 = 0'u32
    u: int = 0
  while u < g:
    r = getRngU64(rng)
    neg = uint32(r shr 63)
    r = r and (not (1'u64 shl 63))
    f = uint32((r - falconGauss1024_12289[0]) shr 63)
    r = getRngU64(rng)
    r = r and (not (1'u64 shl 63))
    v = gaussMagnitude(r, f)
    v = (v xor (0'u32 - neg)) + neg
    result = result + int(cast[int32](v))
    u = u + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `polySmallSqnorm`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polySmallSqnorm(f: openArray[int8], logn: int): uint32 {.role: {math}.} =
  ## f: small polynomial. Returns the sum of squares, or 2^32 - 1 once it
  ## passes 2^31 (overflow sentinel, as in the Falcon spec).
  var
    n: int = mknSize(logn)
    ng: uint32 = 0'u32
    z: int32 = 0'i32
    u: int = 0
  while u < n:
    z = int32(f[u])
    result += uint32(z * z)
    ng = ng or result
    u = u + 1
  result or (0'u32 - (ng shr 31))

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `polySmallToFp`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polySmallToFp(x: var seq[FalconFpr], f: openArray[int8], logn: int) {.role: {math}.} =
  ## x: receives f as floating-point values.
  var
    n: int = mknSize(logn)
    u: int = 0
  x.setLen(n)
  while u < n:
    x[u] = fprOf(int64(f[u]))
    u = u + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `acceptGaussCoeff`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc acceptGaussCoeff(s: int, last: bool, mod2: var uint32): bool {.inline, role: {parser}.} =
  ## s: Gaussian sample. last: true for the final coefficient. mod2: parity
  ## of the coefficients kept so far. Samples outside -127 .. 127 are
  ## dropped; the last one must make the parity odd (f invertible mod 2).
  var
    parity: uint32 = mod2 xor uint32(s and 1)
  result = s >= -127 and s <= 127 and (not last or parity == 1'u32)
  if result and not last:
    mod2 = parity

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `polySmallMkgauss`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polySmallMkgauss(rng: var FalconShake256, f: var seq[int8], logn: int) {.role: {math}.} =
  ## f: receives n Gaussian coefficients with an odd sum.
  var
    n: int = mknSize(logn)
    mod2: uint32 = 0'u32
    s: int = 0
    u: int = 0
  f.setLen(n)
  while u < n:
    s = mkgauss(rng, logn)
    if acceptGaussCoeff(s, u == n - 1, mod2):
      f[u] = int8(s)
      u = u + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `halvedNttInto`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc halvedNttInto(D: var RnsPoly, t1: openArray[uint32], u, hn: int,
    prime: FalconSmallPrime, runtime: FalconPrimeRuntime) {.inline, role: {math}.} =
  ## t1: NTT form of a(x) mod prime u. Word u of D's hn coefficients
  ## receives t1[2v]·t1[2v + 1], the NTT form of a(x)·a(-x) as a
  ## polynomial in x² (half the degree).
  var
    v: int = 0
  while v < hn:
    D.coeffs[v * D.stride + u] = modpMontyMul(modpMontyMul(t1[(v shl 1) + 0],
      t1[(v shl 1) + 1], prime.p, runtime.p0i), runtime.r2, prime.p, runtime.p0i)
    v = v + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `columnInto`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc columnInto(t1: var seq[uint32], S: RnsPoly, u, slen, n: int) {.inline, role: {helper}.} =
  ## t1: receives word u (the remainder mod prime u) of S's n coefficients.
  var
    v: int = 0
  while v < n:
    t1[v] = S.coeffs[v * slen + u]
    v = v + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `reducedColumnInto`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc reducedColumnInto(t1: var seq[uint32], S: RnsPoly, slen, n: int,
    prime: FalconSmallPrime, runtime: FalconPrimeRuntime, Rx: uint32) {.inline, role: {math}.} =
  ## t1: receives every big coefficient of S (slen words) mod prime.
  var
    v: int = 0
  while v < n:
    t1[v] = zintModSmallSigned(S.coeffs, coeffOffset(S, v), slen,
      prime.p, runtime.p0i, runtime.r2, Rx)
    v = v + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `halveKnownPrime`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc halveKnownPrime(D: var RnsPoly, t1: var seq[uint32], S: var RnsPoly,
    u, slen, logn: int, inNtt: bool, prime: FalconSmallPrime,
    runtime: FalconPrimeRuntime, tables: FalconNttTables) {.role: {math}.} =
  ## D: word u receives S(x)·S(-x) mod prime u, for a prime S already has.
  ## When S was in NTT form, its column u is turned back into plain values.
  columnInto(t1, S, u, slen, mknSize(logn))
  if not inNtt:
    modpNtt2(t1, tables.gm, logn, prime.p, runtime.p0i)
  halvedNttInto(D, t1, u, mknSize(logn) shr 1, prime, runtime)
  if inNtt:
    modpIntt2Ext(S.coeffs, u, slen, tables.igm, logn, prime.p, runtime.p0i)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `halveNewPrime`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc halveNewPrime(D: var RnsPoly, t1: var seq[uint32], S: RnsPoly,
    u, slen, logn: int, prime: FalconSmallPrime, runtime: FalconPrimeRuntime,
    tables: FalconNttTables, Rx: uint32) {.role: {math}.} =
  ## D: word u receives S(x)·S(-x) mod prime u, for a prime S does not have
  ## yet (S holds plain big numbers of slen words).
  reducedColumnInto(t1, S, slen, mknSize(logn), prime, runtime, Rx)
  modpNtt2(t1, tables.gm, logn, prime.p, runtime.p0i)
  halvedNttInto(D, t1, u, mknSize(logn) shr 1, prime, runtime)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `leaveNttColumn`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc leaveNttColumn(R: var tuple[f, g: RnsPoly], u, logn: int, outNtt: bool,
    prime: FalconSmallPrime, runtime: FalconPrimeRuntime, tables: FalconNttTables)
    {.inline, role: {math}.} =
  ## R: column u is turned back into plain values unless NTT output is wanted.
  if not outNtt:
    modpIntt2Ext(R.f.coeffs, u, R.f.stride, tables.igm, logn - 1, prime.p, runtime.p0i)
    modpIntt2Ext(R.g.coeffs, u, R.g.stride, tables.igm, logn - 1, prime.p, runtime.p0i)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `halveExtraPrimes`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc halveExtraPrimes(R: var tuple[f, g: RnsPoly], fsrc, gsrc: var RnsPoly,
    t1: var seq[uint32], slen, tlen, logn: int, outNtt: bool) {.role: {math}.} =
  ## R: words slen ..< tlen are filled. fsrc/gsrc: f, g as plain residues
  ## for primes 0 ..< slen; merged here into big numbers first.
  var
    prime: FalconSmallPrime = falconPrimes[0]
    runtime: FalconPrimeRuntime = FalconPrimeRuntime()
    tables: FalconNttTables = FalconNttTables()
    Rx: uint32 = 0'u32
    u: int = slen
  zintRebuildCrt(fsrc, slen, true)
  zintRebuildCrt(gsrc, slen, true)
  while u < tlen:
    prime = falconPrimes[u]
    runtime = getFalconPrimeRuntime(u)
    tables = getFalconNttTables(logn, u)
    Rx = modpRx(slen, prime.p, runtime.p0i, runtime.r2)
    halveNewPrime(R.f, t1, fsrc, u, slen, logn, prime, runtime, tables, Rx)
    halveNewPrime(R.g, t1, gsrc, u, slen, logn, prime, runtime, tables, Rx)
    leaveNttColumn(R, u, logn, outNtt, prime, runtime, tables)
    u = u + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `makeFgStep`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc makeFgStep(fs, gs: RnsPoly, logn, depth: int, inNtt, outNtt: bool): tuple[f, g: RnsPoly] {.role: {math}.} =
  ## fs/gs: f, g at this depth (degree 2^logn, slen words per coefficient,
  ## NTT form when inNtt). Returns f(x)·f(-x) and g(x)·g(-x) as polynomials
  ## in x² (half the degree, tlen words), in NTT form when outNtt.
  ##   primes 0 ..< slen     -> taken from the residues fs/gs already hold
  ##   primes slen ..< tlen  -> computed from the rebuilt big numbers
  var
    hn: int = (1 shl logn) shr 1
    slen: int = falconMaxBlSmall[depth]
    tlen: int = falconMaxBlSmall[depth + 1]
    fsrc: RnsPoly = clonePoly(fs)
    gsrc: RnsPoly = clonePoly(gs)
    t1: seq[uint32] = newSeq[uint32](1 shl logn)
    prime: FalconSmallPrime = falconPrimes[0]
    runtime: FalconPrimeRuntime = FalconPrimeRuntime()
    tables: FalconNttTables = FalconNttTables()
    u: int = 0
  result.f = initRnsPoly(hn, tlen)
  result.g = initRnsPoly(hn, tlen)
  while u < slen:
    prime = falconPrimes[u]
    runtime = getFalconPrimeRuntime(u)
    tables = getFalconNttTables(logn, u)
    halveKnownPrime(result.f, t1, fsrc, u, slen, logn, inNtt, prime, runtime, tables)
    halveKnownPrime(result.g, t1, gsrc, u, slen, logn, inNtt, prime, runtime, tables)
    leaveNttColumn(result, u, logn, outNtt, prime, runtime, tables)
    u = u + 1
  if slen < tlen:
    halveExtraPrimes(result, fsrc, gsrc, t1, slen, tlen, logn, outNtt)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `makeFgNtt`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc makeFgNtt(f, g: openArray[int8], logn: int): tuple[f, g: RnsPoly] {.role: {math}.} =
  ## f/g: small secret pair. Returns them mod the first small prime, in NTT form.
  var
    n: int = mknSize(logn)
    p0: uint32 = falconPrimes[0].p
    runtime: FalconPrimeRuntime = getFalconPrimeRuntime(0)
    tables: FalconNttTables = getFalconNttTables(logn, 0)
    u: int = 0
  result.f = initRnsPoly(n, 1)
  result.g = initRnsPoly(n, 1)
  while u < n:
    result.f.coeffs[u] = modpSet(int32(f[u]), p0)
    result.g.coeffs[u] = modpSet(int32(g[u]), p0)
    u = u + 1
  modpNtt2(result.f.coeffs, tables.gm, logn, p0, runtime.p0i)
  modpNtt2(result.g.coeffs, tables.gm, logn, p0, runtime.p0i)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `buildPlainFgFromNtt`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc buildPlainFgFromNtt(fgNtt: tuple[f, g: RnsPoly], lognTop, depth: int): tuple[f, g: RnsPoly] {.role: {math}.} =
  ## fgNtt: f, g at this depth in NTT form. Returns them as plain big numbers.
  var
    logn: int = lognTop - depth
    slen: int = falconMaxBlSmall[depth]
    prime: FalconSmallPrime = falconPrimes[0]
    runtime: FalconPrimeRuntime = FalconPrimeRuntime()
    tables: FalconNttTables = FalconNttTables()
    u: int = 0
  result.f = clonePoly(fgNtt.f)
  result.g = clonePoly(fgNtt.g)
  while u < slen:
    prime = falconPrimes[u]
    runtime = getFalconPrimeRuntime(u)
    tables = getFalconNttTables(logn, u)
    modpIntt2Ext(result.f.coeffs, u, slen, tables.igm, logn, prime.p, runtime.p0i)
    modpIntt2Ext(result.g.coeffs, u, slen, tables.igm, logn, prime.p, runtime.p0i)
    u = u + 1
  zintRebuildCrt(result.f, slen, true)
  zintRebuildCrt(result.g, slen, true)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `buildFgViewChain`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc buildFgViewChain(f, g: openArray[int8], lognTop: int): seq[FalconFgViews] {.role: {math}.} =
  ## f/g: small secret pair. Entry d holds f, g halved d times, both in NTT
  ## form and as plain big numbers:
  ##   depth 0: degree n   depth 1: n/2   ...   depth lognTop: 1
  var
    current: tuple[f, g: RnsPoly] = (RnsPoly(), RnsPoly())
    depth: int = 1
  result = newSeq[FalconFgViews](lognTop + 1)
  result[0].ntt = makeFgNtt(f, g, lognTop)
  result[0].plain = buildPlainFgFromNtt(result[0].ntt, lognTop, 0)
  if lognTop <= 0:
    return
  current = result[0].ntt
  while depth <= lognTop:
    current = makeFgStep(current.f, current.g, lognTop - depth + 1, depth - 1, true, true)
    result[depth].ntt = current
    result[depth].plain = buildPlainFgFromNtt(current, lognTop, depth)
    depth = depth + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `deepestFgFromNttChain`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc deepestFgFromNttChain(lognTop: int,
    fgNtt: openArray[FalconFgViews]): tuple[f, g: RnsPoly] {.role: {math}.} =
  ## fgNtt: view chain. Returns f, g at degree 1 as plain big numbers.
  if lognTop <= 0:
    return makeFgStep(fgNtt[0].ntt.f, fgNtt[0].ntt.g, 1, 0, true, false)
  result = makeFgStep(fgNtt[lognTop - 1].ntt.f, fgNtt[lognTop - 1].ntt.g,
    1, lognTop - 1, true, false)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `solveNtruDeepest`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc solveNtruDeepest(lognTop: int,
    fgValue: tuple[f, g: RnsPoly]): tuple[ok: bool, F, G: RnsPoly] {.role: {math}.} =
  ## fgValue: f, g at degree 1 (plain numbers). Solves f·G - g·F = q there
  ## with Bezout: f·u - g·v = 1, then G = q·u, F = q·v.
  var
    len: int = falconMaxBlSmall[lognTop]
    fp: RnsPoly = clonePoly(fgValue.f)
    gp: RnsPoly = clonePoly(fgValue.g)
    Fp: seq[uint32] = newSeq[uint32](len)
    Gp: seq[uint32] = newSeq[uint32](len)
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

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `pow2Scale`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc pow2Scale(dc: int): FalconFpr {.role: {math}.} =
  ## dc: exponent. Returns 2^-dc as a floating-point value.
  var
    shift: int = dc
    pt: FalconFpr = (if dc < 0: fprTwo else: fprOneHalf)
  result = fprOne
  if shift < 0:
    shift = -shift
  while shift != 0:
    if (shift and 1) != 0:
      result = fprMul(result, pt)
    shift = shift shr 1
    pt = fprSqr(pt)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `shrinkFgLen`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc shrinkFgLen(FGlen, maxBitsCurrent: var int, scaleK, maxBitsFg: int)
    {.inline, role: {math}.} =
  ## After a reduction pass |F|, |G| are bounded by scaleK + maxBitsFg + 10
  ## bits; when that bound drops, F, G may lose their top word.
  var
    newMax: int = scaleK + maxBitsFg + 10
    lowered: bool = newMax < maxBitsCurrent
  if lowered:
    maxBitsCurrent = newMax
  if lowered and FGlen * 31 >= maxBitsCurrent + 31:
    FGlen = FGlen - 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `signExtendCoeff`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc signExtendCoeff(P: var RnsPoly, c, FGlen, slen: int) {.inline, role: {helper}.} =
  ## P/c: words FGlen ..< slen of the coefficient are filled with its sign,
  ## so a number of FGlen words reads the same as slen words.
  var
    o: int = coeffOffset(P, c)
    sw: uint32 = (0'u32 - (P.coeffs[o + FGlen - 1] shr 30)) shr 1
    v: int = FGlen
  while v < slen:
    P.coeffs[o + v] = sw
    v = v + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `takeReducedFg`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc takeReducedFg(Ft, Gt: var RnsPoly, coeffs, FGlen, slen, llen: int):
    tuple[ok: bool, F, G: RnsPoly] {.role: {helper}.} =
  ## Ft/Gt: reduced F, G with FGlen meaningful words of llen stored.
  ## Returns them as slen words per coefficient.
  var
    c: int = 0
  while FGlen < slen and c < coeffs:
    signExtendCoeff(Ft, c, FGlen, slen)
    signExtendCoeff(Gt, c, FGlen, slen)
    c = c + 1
  result.ok = true
  result.F = initRnsPoly(coeffs, slen)
  result.G = initRnsPoly(coeffs, slen)
  c = 0
  while c < coeffs:
    copyMem(addr result.F.coeffs[c * slen], addr Ft.coeffs[c * llen], slen * sizeof(uint32))
    copyMem(addr result.G.coeffs[c * slen], addr Gt.coeffs[c * llen], slen * sizeof(uint32))
    c = c + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `reduceIntermediateLogn1`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc reduceIntermediateLogn1(ft, gt: RnsPoly, slen: int, Ft, Gt: var RnsPoly,
    llen, depth: int): tuple[ok: bool, F, G: RnsPoly] {.role: {math}.} =
  ## Degree-2 case with exact big numbers. Repeats, with a shrinking scale:
  ##   k = round((F·adj f + G·adj g) / (f·adj f + g·adj g)),  F -= k·f,  G -= k·g
  var
    f0: FalconSigned31 = decodeCoeff31(ft, 0, slen)
    f1: FalconSigned31 = decodeCoeff31(ft, 1, slen)
    g0: FalconSigned31 = decodeCoeff31(gt, 0, slen)
    g1: FalconSigned31 = decodeCoeff31(gt, 1, slen)
    den: FalconSigned31 = addSigned31(mulSigned31(f0, f0), mulSigned31(f1, f1))
    F0: FalconSigned31 = FalconSigned31()
    F1: FalconSigned31 = FalconSigned31()
    G0: FalconSigned31 = FalconSigned31()
    G1: FalconSigned31 = FalconSigned31()
    h0: FalconSigned31 = FalconSigned31()
    h1: FalconSigned31 = FalconSigned31()
    denScaled: seq[uint32] = @[]
    k: seq[int32] = newSeq[int32](2)
    FGlen: int = llen
    maxBitsCurrent: int = 31 * llen
    minBitsFg: int = falconBitlength[depth].avg - 6 * falconBitlength[depth].std
    maxBitsFg: int = falconBitlength[depth].avg + 6 * falconBitlength[depth].std
    scaleK: int = maxBitsCurrent - minBitsFg
    done: bool = false
  den = addSigned31(den, mulSigned31(g0, g0))
  den = addSigned31(den, mulSigned31(g1, g1))
  if den.neg or den.words.len == 0:
    return
  while not done:
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
    polySubScaled(Ft, FGlen, ft, slen, k, uint32(scaleK div 31), uint32(scaleK mod 31), 1)
    polySubScaled(Gt, FGlen, gt, slen, k, uint32(scaleK div 31), uint32(scaleK mod 31), 1)
    shrinkFgLen(FGlen, maxBitsCurrent, scaleK, maxBitsFg)
    done = scaleK <= 0
    scaleK = max(scaleK - 25, 0)
  result = takeReducedFg(Ft, Gt, 2, FGlen, slen, llen)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `decodePoly4`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc decodePoly4(P: RnsPoly, wordLen: int): array[4, FalconSigned31] {.role: {parser}.} =
  ## P: 4 coefficients of wordLen words, returned as sign + magnitude.
  var
    i: int = 0
  while i < 4:
    result[i] = decodeCoeff31(P, i, wordLen)
    i = i + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `cramerK4`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc cramerK4(k: var seq[int32], denMat: FalconSigned31Mat4,
    numPoly: openArray[FalconSigned31], detNeg: bool, denScaled: openArray[uint32])
    {.role: {math}.} =
  ## k: receives the solution of denMat·k = numPoly by Cramer's rule,
  ## k[i] = round(det(denMat with column i = numPoly) / det(denMat)).
  var
    num: FalconSigned31 = FalconSigned31()
    i: int = 0
  while i < 4:
    num = det4Small31(replaceMat4Column(denMat, i, numPoly))
    if detNeg:
      num = negSigned31(num)
    k[i] = roundDivSigned31(num, denScaled)
    i = i + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `reduceIntermediateLogn2`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc reduceIntermediateLogn2(ft, gt: RnsPoly, slen: int, Ft, Gt: var RnsPoly,
    llen, depth: int): tuple[ok: bool, F, G: RnsPoly] {.role: {math}.} =
  ## Degree-4 case with exact big numbers; same steps as the degree-2 case,
  ## the division done as a 4x4 linear system.
  var
    fPoly: array[4, FalconSigned31] = decodePoly4(ft, slen)
    gPoly: array[4, FalconSigned31] = decodePoly4(gt, slen)
    adjF: seq[FalconSigned31] = polyAdjSmall31(fPoly)
    adjG: seq[FalconSigned31] = polyAdjSmall31(gPoly)
    denMat: FalconSigned31Mat4 = mulMat4FromPoly(polyAddSmall31(
      polyMulModXn1Small31(fPoly, adjF), polyMulModXn1Small31(gPoly, adjG)))
    det: FalconSigned31 = det4Small31(denMat)
    numPoly: seq[FalconSigned31] = @[]
    k: seq[int32] = newSeq[int32](4)
    FGlen: int = llen
    maxBitsCurrent: int = 31 * llen
    minBitsFg: int = falconBitlength[depth].avg - 6 * falconBitlength[depth].std
    maxBitsFg: int = falconBitlength[depth].avg + 6 * falconBitlength[depth].std
    scaleK: int = maxBitsCurrent - minBitsFg
    done: bool = false
  if det.words.len == 0:
    return
  while not done:
    numPoly = polyAddSmall31(polyMulModXn1Small31(decodePoly4(Ft, FGlen), adjF),
      polyMulModXn1Small31(decodePoly4(Gt, FGlen), adjG))
    cramerK4(k, denMat, numPoly, det.neg, shiftLeftAbs31(det.words, scaleK))
    polySubScaled(Ft, FGlen, ft, slen, k, uint32(scaleK div 31), uint32(scaleK mod 31), 2)
    polySubScaled(Gt, FGlen, gt, slen, k, uint32(scaleK div 31), uint32(scaleK mod 31), 2)
    shrinkFgLen(FGlen, maxBitsCurrent, scaleK, maxBitsFg)
    done = scaleK <= 0
    scaleK = max(scaleK - 25, 0)
  result = takeReducedFg(Ft, Gt, 4, FGlen, slen, llen)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `roundScaledK`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc roundScaledK(k: var seq[int32], rt: openArray[FalconFpr], pdc: FalconFpr): bool
    {.role: {math}.} =
  ## k: receives round(rt[i]·pdc). False as soon as one value falls outside
  ## -2^31 + 1 .. 2^31 - 1; the key candidate is then given up.
  var
    xv: FalconFpr = fprZero
    i: int = 0
  result = true
  while result and i < k.len:
    xv = fprMul(rt[i], pdc)
    result = fprLt(fprMTwo31m1, xv) and fprLt(xv, fprPTwo31m1)
    if result:
      k[i] = int32(fprRint(xv))
    i = i + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `subtractScaledFg`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc subtractScaledFg(Ft, Gt: var RnsPoly, FGlen: int, ft, gt: RnsPoly, slen: int,
    k: openArray[int32], scaleK, logn, depth: int) {.role: {math}.} =
  ## Ft -= k·ft·2^scaleK and Gt -= k·gt·2^scaleK. Shallow depths multiply
  ## in NTT form, deep ones with the schoolbook product.
  if depth <= falconDepthIntFg:
    polySubScaledNtt(Ft, FGlen, ft, slen, k, uint32(scaleK div 31), uint32(scaleK mod 31), logn)
    polySubScaledNtt(Gt, FGlen, gt, slen, k, uint32(scaleK div 31), uint32(scaleK mod 31), logn)
  else:
    polySubScaled(Ft, FGlen, ft, slen, k, uint32(scaleK div 31), uint32(scaleK mod 31), logn)
    polySubScaled(Gt, FGlen, gt, slen, k, uint32(scaleK div 31), uint32(scaleK mod 31), logn)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `reduceIntermediateFft`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc reduceIntermediateFft(ft, gt: RnsPoly, Ft, Gt: var RnsPoly,
    logn, depth: int): tuple[ok: bool, F, G: RnsPoly] {.role: {math}.} =
  ## Degree >= 8: k = round((F·adj f + G·adj g) / (f·adj f + g·adj g)) is
  ## computed in floating point on the top 10 words only, then F -= k·f,
  ## G -= k·g exactly; repeated with a shrinking scale.
  var
    n: int = 1 shl logn
    slen: int = falconMaxBlSmall[depth]
    llen: int = falconMaxBlLarge[depth]
    rt1: seq[FalconFpr] = newSeq[FalconFpr](n)
    rt2: seq[FalconFpr] = newSeq[FalconFpr](n)
    rt3: seq[FalconFpr] = newSeq[FalconFpr](n)
    rt4: seq[FalconFpr] = newSeq[FalconFpr](n)
    rt5: seq[FalconFpr] = newSeq[FalconFpr](n shr 1)
    k: seq[int32] = newSeq[int32](n)
    rlen: int = (if slen > 10: 10 else: slen)
    scaleBase: int = 31 * (slen - rlen)
    scaleCurrent: int = 0
    minBitsFg: int = falconBitlength[depth].avg - 6 * falconBitlength[depth].std
    maxBitsFg: int = falconBitlength[depth].avg + 6 * falconBitlength[depth].std
    FGlen: int = llen
    maxBitsCurrent: int = 31 * llen
    scaleK: int = maxBitsCurrent - minBitsFg
    done: bool = false
  polyBigToFp(rt3, ft, slen - rlen, rlen)
  polyBigToFp(rt4, gt, slen - rlen, rlen)
  falconFft(rt3, logn)
  falconFft(rt4, logn)
  polyInvnorm2Fft(rt5, rt3, rt4, logn)
  polyAdjFft(rt3, logn)
  polyAdjFft(rt4, logn)
  while not done:
    rlen = (if FGlen > 10: 10 else: FGlen)
    scaleCurrent = 31 * (FGlen - rlen)
    polyBigToFp(rt1, Ft, FGlen - rlen, rlen)
    polyBigToFp(rt2, Gt, FGlen - rlen, rlen)
    falconFft(rt1, logn)
    falconFft(rt2, logn)
    polyMulFft(rt1, rt3, logn)
    polyMulFft(rt2, rt4, logn)
    polyAdd(rt2, rt1, logn)
    polyMulAutoadjFft(rt2, rt5, logn)
    falconIfft(rt2, logn)
    if not roundScaledK(k, rt2, pow2Scale(scaleK - scaleCurrent + scaleBase)):
      return
    subtractScaledFg(Ft, Gt, FGlen, ft, gt, slen, k, scaleK, logn, depth)
    shrinkFgLen(FGlen, maxBitsCurrent, scaleK, maxBitsFg)
    done = scaleK <= 0
    scaleK = max(scaleK - 25, 0)
  result = takeReducedFg(Ft, Gt, n, FGlen, slen, llen)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `loadFgNtt`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc loadFgNtt(fx, gx: var seq[uint32], fgValue: FalconFgViews, u, slen, logn: int,
    prime: FalconSmallPrime, runtime: FalconPrimeRuntime, tables: FalconNttTables)
    {.role: {math}.} =
  ## fx/gx: receive f, g mod prime u in NTT form; copied for the primes the
  ## chain already holds, computed from the big numbers for the others.
  var
    n: int = 1 shl logn
    Rx: uint32 = 0'u32
  if u < slen:
    columnInto(fx, fgValue.ntt.f, u, slen, n)
    columnInto(gx, fgValue.ntt.g, u, slen, n)
    return
  Rx = modpRx(slen, prime.p, runtime.p0i, runtime.r2)
  reducedColumnInto(fx, fgValue.plain.f, slen, n, prime, runtime, Rx)
  reducedColumnInto(gx, fgValue.plain.g, slen, n, prime, runtime, Rx)
  modpNtt2(fx, tables.gm, logn, prime.p, runtime.p0i)
  modpNtt2(gx, tables.gm, logn, prime.p, runtime.p0i)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `crossMulInto`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc crossMulInto(Ft, Gt: var RnsPoly, fx, gx, Fp, Gp: openArray[uint32], u: int,
    prime: FalconSmallPrime, runtime: FalconPrimeRuntime) {.role: {math}.} =
  ## Word u of F(x) = Fd(x²)·g(-x) and G(x) = Gd(x²)·f(-x), in NTT form:
  ## the two roots ±w of one pair trade their f, g values.
  var
    llen: int = Ft.stride
    mFp: uint32 = 0'u32
    mGp: uint32 = 0'u32
    v: int = 0
  while v < Fp.len:
    mFp = modpMontyMul(Fp[v], runtime.r2, prime.p, runtime.p0i)
    mGp = modpMontyMul(Gp[v], runtime.r2, prime.p, runtime.p0i)
    Ft.coeffs[(v shl 1) * llen + u] = modpMontyMul(gx[(v shl 1) + 1], mFp, prime.p, runtime.p0i)
    Ft.coeffs[((v shl 1) + 1) * llen + u] = modpMontyMul(gx[(v shl 1) + 0], mFp, prime.p, runtime.p0i)
    Gt.coeffs[(v shl 1) * llen + u] = modpMontyMul(fx[(v shl 1) + 1], mGp, prime.p, runtime.p0i)
    Gt.coeffs[((v shl 1) + 1) * llen + u] = modpMontyMul(fx[(v shl 1) + 0], mGp, prime.p, runtime.p0i)
    v = v + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `liftFgSolution`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc liftFgSolution(lognTop: int, fgValue: FalconFgViews, depth: int,
    Fd, Gd: RnsPoly): tuple[F, G: RnsPoly] {.role: {math}.} =
  ## Fd/Gd: solution one level deeper (half the degree). Returns the
  ## unreduced solution at this depth, llen words per coefficient:
  ##   F(x) = Fd(x²)·g(-x),  G(x) = Gd(x²)·f(-x)
  ## made per small prime in NTT form, then merged into big numbers.
  var
    logn: int = lognTop - depth
    n: int = 1 shl logn
    slen: int = falconMaxBlSmall[depth]
    dlen: int = falconMaxBlSmall[depth + 1]
    llen: int = falconMaxBlLarge[depth]
    fx: seq[uint32] = newSeq[uint32](n)
    gx: seq[uint32] = newSeq[uint32](n)
    Fp: seq[uint32] = newSeq[uint32](n shr 1)
    Gp: seq[uint32] = newSeq[uint32](n shr 1)
    prime: FalconSmallPrime = falconPrimes[0]
    runtime: FalconPrimeRuntime = FalconPrimeRuntime()
    tables: FalconNttTables = FalconNttTables()
    Rx: uint32 = 0'u32
    u: int = 0
  result.F = initRnsPoly(n, llen)
  result.G = initRnsPoly(n, llen)
  while u < llen:
    prime = falconPrimes[u]
    runtime = getFalconPrimeRuntime(u)
    tables = getFalconNttTables(logn, u)
    loadFgNtt(fx, gx, fgValue, u, slen, logn, prime, runtime, tables)
    Rx = modpRx(dlen, prime.p, runtime.p0i, runtime.r2)
    reducedColumnInto(Fp, Fd, dlen, n shr 1, prime, runtime, Rx)
    reducedColumnInto(Gp, Gd, dlen, n shr 1, prime, runtime, Rx)
    modpNtt2(Fp, tables.gm, logn - 1, prime.p, runtime.p0i)
    modpNtt2(Gp, tables.gm, logn - 1, prime.p, runtime.p0i)
    crossMulInto(result.F, result.G, fx, gx, Fp, Gp, u, prime, runtime)
    modpIntt2Ext(result.F.coeffs, u, llen, tables.igm, logn, prime.p, runtime.p0i)
    modpIntt2Ext(result.G.coeffs, u, llen, tables.igm, logn, prime.p, runtime.p0i)
    u = u + 1
  zintRebuildCrt(result.F, llen, true)
  zintRebuildCrt(result.G, llen, true)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `solveNtruIntermediate`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc solveNtruIntermediate(lognTop: int,
    fgValue: FalconFgViews, depth: int,
    Fd, Gd: RnsPoly): tuple[ok: bool, F, G: RnsPoly] {.role: {math}.} =
  ## One level up: lift the deeper solution, then shrink it against f, g.
  var
    logn: int = lognTop - depth
    slen: int = falconMaxBlSmall[depth]
    llen: int = falconMaxBlLarge[depth]
    lifted: tuple[F, G: RnsPoly] = liftFgSolution(lognTop, fgValue, depth, Fd, Gd)
  case logn
  of 1:
    result = reduceIntermediateLogn1(fgValue.plain.f, fgValue.plain.g, slen,
      lifted.F, lifted.G, llen, depth)
  of 2:
    result = reduceIntermediateLogn2(fgValue.plain.f, fgValue.plain.g, slen,
      lifted.F, lifted.G, llen, depth)
  else:
    result = reduceIntermediateFft(fgValue.plain.f, fgValue.plain.g,
      lifted.F, lifted.G, logn, depth)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `packSigned31`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc packSigned31(x: int64): tuple[ok: bool, word: uint32] {.inline, role: {helper}.} =
  ## x: value that must fit a signed 31-bit word.
  if x < -0x40000000'i64 or x > 0x3FFFFFFF'i64:
    return
  result.ok = true
  result.word = cast[uint32](cast[int32](x)) and falconWordMask

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `fftReductionRatio`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc fftReductionRatio(ratio: var seq[FalconFpr], rtCandF, rtCandG, rtBaseF,
    rtBaseG, invnorm: var seq[FalconFpr], logn: int) {.role: {math}.} =
  ## ratio: receives (F·adj f + G·adj g) / (f·adj f + g·adj g) as plain
  ## values. The four inputs are left in FFT form.
  falconFft(rtCandF, logn)
  falconFft(rtCandG, logn)
  falconFft(rtBaseF, logn)
  falconFft(rtBaseG, logn)
  polyAddMuladjFft(ratio, rtCandF, rtCandG, rtBaseF, rtBaseG, logn)
  polyInvnorm2Fft(invnorm, rtBaseF, rtBaseG, logn)
  polyMulAutoadjFft(ratio, invnorm, logn)
  falconIfft(ratio, logn)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `roundRatio63`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc roundRatio63(ratio: var seq[FalconFpr]): bool {.role: {math}.} =
  ## ratio: every value rounded to an integer in place. False when one does
  ## not fit -2^63 + 1 .. 2^63 - 1.
  var
    z: FalconFpr = fprZero
    u: int = 0
  result = true
  while result and u < ratio.len:
    z = ratio[u]
    result = fprLt(fprMTwo63m1, z) and fprLt(z, fprPTwo63m1)
    if result:
      ratio[u] = fprOf(fprRint(z))
    u = u + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `packCandidates`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc packCandidates(rtF, rtG: openArray[FalconFpr]): tuple[ok: bool, F, G: RnsPoly] {.role: {helper}.} =
  ## rtF/rtG: reduced F, G as floating-point values. Returns them as one
  ## signed 31-bit word each, or ok = false when one does not fit.
  var
    pF: tuple[ok: bool, word: uint32] = (false, 0'u32)
    pG: tuple[ok: bool, word: uint32] = (false, 0'u32)
    u: int = 0
  result.ok = true
  result.F = initRnsPoly(rtF.len, 1)
  result.G = initRnsPoly(rtF.len, 1)
  while result.ok and u < rtF.len:
    pF = packSigned31(fprRint(rtF[u]))
    pG = packSigned31(fprRint(rtG[u]))
    result.ok = pF.ok and pG.ok
    result.F.coeffs[u] = pF.word
    result.G.coeffs[u] = pG.word
    u = u + 1
  if not result.ok:
    result.F.coeffs.setLen(0)
    result.G.coeffs.setLen(0)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `solveNtruBinaryDepth1`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc solveNtruBinaryDepth1(lognTop: int,
    fgValue: FalconFgViews, Fd, Gd: RnsPoly): tuple[ok: bool, F, G: RnsPoly] {.role: {math}.} =
  ## Depth 1 (half the top degree): lift, then one floating-point reduction
  ## of the whole numbers; the result fits one word per coefficient.
  var
    logn: int = lognTop - 1
    n: int = 1 shl logn
    slen: int = falconMaxBlSmall[1]
    llen: int = falconMaxBlLarge[1]
    lifted: tuple[F, G: RnsPoly] = liftFgSolution(lognTop, fgValue, 1, Fd, Gd)
    rtCandF: seq[FalconFpr] = newSeq[FalconFpr](n)
    rtCandG: seq[FalconFpr] = newSeq[FalconFpr](n)
    rtBaseF: seq[FalconFpr] = newSeq[FalconFpr](n)
    rtBaseG: seq[FalconFpr] = newSeq[FalconFpr](n)
    ratio: seq[FalconFpr] = newSeq[FalconFpr](n)
    invnorm: seq[FalconFpr] = newSeq[FalconFpr](n shr 1)
  polyBigToFp(rtCandF, lifted.F, 0, llen)
  polyBigToFp(rtCandG, lifted.G, 0, llen)
  polyBigToFp(rtBaseF, fgValue.plain.f, 0, slen)
  polyBigToFp(rtBaseG, fgValue.plain.g, 0, slen)
  fftReductionRatio(ratio, rtCandF, rtCandG, rtBaseF, rtBaseG, invnorm, logn)
  if not roundRatio63(ratio):
    return
  falconFft(ratio, logn)
  polyMulFft(rtBaseF, ratio, logn)
  polyMulFft(rtBaseG, ratio, logn)
  polySub(rtCandF, rtBaseF, logn)
  polySub(rtCandG, rtBaseG, logn)
  falconIfft(rtCandF, logn)
  falconIfft(rtCandG, logn)
  result = packCandidates(rtCandF, rtCandG)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `liftDepth0`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc liftDepth0(F0, G0: var seq[uint32], f, g: openArray[int8], Fd, Gd: RnsPoly,
    logn: int) {.role: {math}.} =
  ## F0/G0: receive F(x) = Fd(x²)·g(-x) and G(x) = Gd(x²)·f(-x) mod the
  ## first small prime, as plain values (Fd, Gd fit one word each).
  var
    n: int = 1 shl logn
    p: uint32 = falconPrimes[0].p
    runtime: FalconPrimeRuntime = getFalconPrimeRuntime(0)
    tables: FalconNttTables = getFalconNttTables(logn, 0)
    Fp: seq[uint32] = newSeq[uint32](n shr 1)
    Gp: seq[uint32] = newSeq[uint32](n shr 1)
    ftA: uint32 = 0'u32
    ftB: uint32 = 0'u32
    gtA: uint32 = 0'u32
    gtB: uint32 = 0'u32
    mFp: uint32 = 0'u32
    mGp: uint32 = 0'u32
    u: int = 0
  while u < n shr 1:
    Fp[u] = modpSet(zintOneToPlain(Fd.coeffs, coeffOffset(Fd, u)), p)
    Gp[u] = modpSet(zintOneToPlain(Gd.coeffs, coeffOffset(Gd, u)), p)
    u = u + 1
  modpNtt2(Fp, tables.gm, logn - 1, p, runtime.p0i)
  modpNtt2(Gp, tables.gm, logn - 1, p, runtime.p0i)
  u = 0
  while u < n:
    F0[u] = modpSet(int32(f[u]), p)
    G0[u] = modpSet(int32(g[u]), p)
    u = u + 1
  modpNtt2(F0, tables.gm, logn, p, runtime.p0i)
  modpNtt2(G0, tables.gm, logn, p, runtime.p0i)
  u = 0
  while u < n:
    ftA = F0[u + 0]
    ftB = F0[u + 1]
    gtA = G0[u + 0]
    gtB = G0[u + 1]
    mFp = modpMontyMul(Fp[u shr 1], runtime.r2, p, runtime.p0i)
    mGp = modpMontyMul(Gp[u shr 1], runtime.r2, p, runtime.p0i)
    F0[u + 0] = modpMontyMul(gtB, mFp, p, runtime.p0i)
    F0[u + 1] = modpMontyMul(gtA, mFp, p, runtime.p0i)
    G0[u + 0] = modpMontyMul(ftB, mGp, p, runtime.p0i)
    G0[u + 1] = modpMontyMul(ftA, mGp, p, runtime.p0i)
    u = u + 2
  modpIntt2(F0, tables.igm, logn, p, runtime.p0i)
  modpIntt2(G0, tables.igm, logn, p, runtime.p0i)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `roundRatio32`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc roundRatio32(k: var seq[int32], ratio: openArray[FalconFpr]): bool {.role: {math}.} =
  ## k: receives round(ratio[u]). False when one does not fit an int32.
  var
    rounded: int64 = 0'i64
    u: int = 0
  result = true
  while result and u < k.len:
    rounded = fprRint(ratio[u])
    result = rounded >= low(int32).int64 and rounded <= high(int32).int64
    if result:
      k[u] = int32(rounded)
    u = u + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `solveNtruBinaryDepth0`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc solveNtruBinaryDepth0(logn: int, f, g: openArray[int8],
    Fd, Gd: RnsPoly): tuple[ok: bool, F, G: RnsPoly] {.role: {math}.} =
  ## Top level: lift mod one prime (the result is small enough), then one
  ## floating-point reduction F -= k·f, G -= k·g with exact integers.
  var
    n: int = 1 shl logn
    p: uint32 = falconPrimes[0].p
    ft: seq[uint32] = newSeq[uint32](n)
    gt: seq[uint32] = newSeq[uint32](n)
    Fpoly: RnsPoly = initRnsPoly(n, 1)
    Gpoly: RnsPoly = initRnsPoly(n, 1)
    fpoly: RnsPoly = initRnsPoly(n, 1)
    gpoly: RnsPoly = initRnsPoly(n, 1)
    rtCandF: seq[FalconFpr] = newSeq[FalconFpr](n)
    rtCandG: seq[FalconFpr] = newSeq[FalconFpr](n)
    rtBaseF: seq[FalconFpr] = newSeq[FalconFpr](n)
    rtBaseG: seq[FalconFpr] = newSeq[FalconFpr](n)
    ratio: seq[FalconFpr] = newSeq[FalconFpr](n)
    invnorm: seq[FalconFpr] = newSeq[FalconFpr](n shr 1)
    k: seq[int32] = newSeq[int32](n)
    u: int = 0
  liftDepth0(ft, gt, f, g, Fd, Gd, logn)
  while u < n:
    Fpoly.coeffs[u] = cast[uint32](modpNorm(ft[u], p)) and falconWordMask
    Gpoly.coeffs[u] = cast[uint32](modpNorm(gt[u], p)) and falconWordMask
    fpoly.coeffs[u] = cast[uint32](int32(f[u])) and falconWordMask
    gpoly.coeffs[u] = cast[uint32](int32(g[u])) and falconWordMask
    rtCandF[u] = fprOf(int64(modpNorm(ft[u], p)))
    rtCandG[u] = fprOf(int64(modpNorm(gt[u], p)))
    rtBaseF[u] = fprOf(int64(f[u]))
    rtBaseG[u] = fprOf(int64(g[u]))
    u = u + 1
  fftReductionRatio(ratio, rtCandF, rtCandG, rtBaseF, rtBaseG, invnorm, logn)
  if not roundRatio32(k, ratio):
    return
  polySubScaled(Fpoly, 1, fpoly, 1, k, 0'u32, 0'u32, logn)
  polySubScaled(Gpoly, 1, gpoly, 1, k, 0'u32, 0'u32, logn)
  result.ok = true
  result.F = Fpoly
  result.G = Gpoly

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `liftStep`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc liftStep(F, G: var RnsPoly, step: tuple[ok: bool, F, G: RnsPoly]): bool
    {.inline, role: {helper}.} =
  ## F/G: replaced by the step's answer when the step worked.
  result = step.ok
  if result:
    F = step.F
    G = step.G

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `solveNtruChain`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc solveNtruChain(logn: int, f, g: openArray[int8]): tuple[ok: bool, F, G: RnsPoly] {.role: {math}.} =
  ## f/g: secret pair of degree 2^logn. Solves at degree 1, then lifts the
  ## answer back up one level at a time:
  ##   logn <= 2:  every level uses the general lift
  ##   otherwise:  general lifts down to depth 2, then depth 1, then depth 0
  var
    fgViews: seq[FalconFgViews] = buildFgViewChain(f, g, logn)
    depth: int = logn
    stop: int = (if logn <= 2: 0 else: 2)
  result = solveNtruDeepest(logn, deepestFgFromNttChain(logn, fgViews))
  while result.ok and depth > stop:
    depth = depth - 1
    result.ok = liftStep(result.F, result.G,
      solveNtruIntermediate(logn, fgViews[depth], depth, result.F, result.G))
  if result.ok and stop == 2:
    result.ok = liftStep(result.F, result.G,
      solveNtruBinaryDepth1(logn, fgViews[1], result.F, result.G))
  if result.ok and stop == 2:
    result.ok = liftStep(result.F, result.G,
      solveNtruBinaryDepth0(logn, f, g, result.F, result.G))

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `ntruEquationHolds`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc ntruEquationHolds(f, g, F, G: openArray[int8], logn: int): bool {.role: {parser}.} =
  ## f/g/F/G: candidate key. True when f·G - g·F = q mod x^n + 1, checked
  ## modulo the first small prime in NTT form.
  var
    n: int = mknSize(logn)
    p: uint32 = falconPrimes[0].p
    runtime: FalconPrimeRuntime = getFalconPrimeRuntime(0)
    tables: FalconNttTables = getFalconNttTables(logn, 0)
    r: uint32 = modpMontyMul(12289'u32, 1'u32, p, runtime.p0i)
    Gt: seq[uint32] = newSeq[uint32](n)
    ft: seq[uint32] = newSeq[uint32](n)
    gt: seq[uint32] = newSeq[uint32](n)
    Ft: seq[uint32] = newSeq[uint32](n)
    u: int = 0
  while u < n:
    Gt[u] = modpSet(int32(G[u]), p)
    ft[u] = modpSet(int32(f[u]), p)
    gt[u] = modpSet(int32(g[u]), p)
    Ft[u] = modpSet(int32(F[u]), p)
    u = u + 1
  modpNtt2(ft, tables.gm, logn, p, runtime.p0i)
  modpNtt2(gt, tables.gm, logn, p, runtime.p0i)
  modpNtt2(Ft, tables.gm, logn, p, runtime.p0i)
  modpNtt2(Gt, tables.gm, logn, p, runtime.p0i)
  result = true
  u = 0
  while result and u < n:
    result = modpSub(modpMontyMul(ft[u], Gt[u], p, runtime.p0i),
      modpMontyMul(gt[u], Ft[u], p, runtime.p0i), p) == r
    u = u + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `solveNtru`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc solveNtru(logn: int, f, g: openArray[int8], lim: int): tuple[ok: bool, F, G: seq[int8]] {.role: {math}.} =
  ## f/g: secret pair. lim: largest allowed |F|, |G|. Returns F, G with
  ## f·G - g·F = q, or ok = false (F, G wiped) when this f, g has none.
  var
    big: tuple[ok: bool, F, G: RnsPoly] = solveNtruChain(logn, f, g)
  if not big.ok:
    return
  result.ok = polyBigToSmall(result.F, big.F, lim) and polyBigToSmall(result.G, big.G, lim) and
    ntruEquationHolds(f, g, result.F, result.G, logn)
  if not result.ok:
    secureClearItems(result.F)
    secureClearItems(result.G)
    result.F.setLen(0)
    result.G.setLen(0)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `encodePublicKey`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
proc encodePublicKey(v: FalconVariant, h: openArray[uint16]): seq[byte] {.role: {helper}.} =
  ## h: public polynomial. Layout: [logn][14 bits per coefficient].
  var
    p: FalconParams = params(v)
    used: int = 0
  result = newSeq[byte](p.publicKeyBytes)
  result[0] = byte(p.logn)
  used = modQEncode(result.toOpenArray(1, result.high), h, p.logn)
  if used != p.publicKeyBytes - 1:
    raise newException(ValueError, "Falcon public-key encoding failed")

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `appendTrimmed`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc appendTrimmed(S: var seq[byte], o: var int, A: openArray[int8], logn, bits: int,
    label: string) {.role: {helper}.} =
  ## S: secret-key buffer. o: write position, moved past A. A: polynomial
  ## packed with bits bits per coefficient.
  var
    used: int = trimI8Encode(S.toOpenArray(o, S.high), A, logn, bits)
  if used == 0:
    raise newException(ValueError, "Falcon secret-key encoding failed for " & label)
  o = o + used

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `encodeSecretKey`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc encodeSecretKey(v: FalconVariant, f, g, F: openArray[int8]): seq[byte] {.role: {helper}.} =
  ## f/g/F: secret polynomials. Layout:
  ##   [0x50 + logn][f, small width][g, small width][F, large width]
  var
    p: FalconParams = params(v)
    o: int = 1
  result = newSeq[byte](p.secretKeyBytes)
  result[0] = byte(0x50 + p.logn)
  appendTrimmed(result, o, f, p.logn, int(falconMaxSmallBits[p.logn]), "f")
  appendTrimmed(result, o, g, p.logn, int(falconMaxSmallBits[p.logn]), "g")
  appendTrimmed(result, o, F, p.logn, int(falconMaxLargeBits[p.logn]), "F")
  if o != result.len:
    raise newException(ValueError, "Falcon secret-key encoding size mismatch")

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `fgSmallInRange`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc fgSmallInRange(f, g: openArray[int8], logn: int): bool {.role: {parser}.} =
  ## f/g: sampled pair. True when every coefficient fits the secret-key width.
  var
    lim: int = 1 shl (int(falconMaxSmallBits[logn]) - 1)
    u: int = 0
  result = true
  while result and u < f.len:
    result = not (f[u] >= int8(lim) or f[u] <= int8(-lim) or
      g[u] >= int8(lim) or g[u] <= int8(-lim))
    u = u + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `fgSmallNormOk`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc fgSmallNormOk(f, g: openArray[int8], logn: int): bool {.role: {parser}.} =
  ## f/g: sampled pair. True when |f|² + |g|² < 16823.
  var
    normf: uint32 = polySmallSqnorm(f, logn)
    normg: uint32 = polySmallSqnorm(g, logn)
  result = ((normf + normg) or (0'u32 - ((normf or normg) shr 31))) < 16823'u32

when falconCompileHasSimd:
  ## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `pairNormSimd`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc pairNormSimd(rt1, rt2: openArray[FalconFpr], u: var int): FalconFpr
      {.inline, role: {math}.} =
    ## rt1/rt2: vectors. Returns the sum of squares over whole pairs from
    ## u on; u is left on the first value not summed.
    ## Paper note: this is Tyr's applied Falcon keygen optimization: accumulate
    ## the floating norm in two `FalconFpr` lanes, then finish scalar tails.
    var
      acc: FalconSimd2 = zeroFalconSimd2()
      v1: FalconSimd2 = zeroFalconSimd2()
      v2: FalconSimd2 = zeroFalconSimd2()
    while u + 2 <= rt1.len:
      v1 = loadFalconSimd2(rt1, u)
      v2 = loadFalconSimd2(rt2, u)
      acc = addFalconSimd2(acc,
        addFalconSimd2(mulFalconSimd2(v1, v1), mulFalconSimd2(v2, v2)))
      u = u + 2
    result = sumFalconSimd2(acc)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `gramSchmidtNormOk`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc gramSchmidtNormOk(f, g: openArray[int8], rt1, rt2, rt3: var seq[FalconFpr],
    logn: int): bool {.role: {parser}.} =
  ## f/g: sampled pair. rt1..rt3: scratch. True when the second
  ## Gram-Schmidt vector, q·(adj f, adj g) / (f·adj f + g·adj g), is short
  ## enough for a signature to stay below the bound.
  var
    bnorm: FalconFpr = fprZero
    u: int = 0
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
  when falconCompileHasSimd:
    if useFalconSimd():
      bnorm = pairNormSimd(rt1, rt2, u)
  while u < rt1.len:
    bnorm = fprAdd(bnorm, fprSqr(rt1[u]))
    bnorm = fprAdd(bnorm, fprSqr(rt2[u]))
    u = u + 1
  result = fprLt(bnorm, fprBnormMax)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `fgCandidateOk`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc fgCandidateOk(f, g: openArray[int8], h: var seq[uint16],
    rt1, rt2, rt3: var seq[FalconFpr], logn: int): bool {.role: {parser}.} =
  ## f/g: sampled pair. h: receives the public key g/f when f is invertible.
  ## The cheapest checks run first.
  result = fgSmallInRange(f, g, logn) and fgSmallNormOk(f, g, logn) and
    gramSchmidtNormOk(f, g, rt1, rt2, rt3, logn) and computePublic(h, f, g, logn)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `falconKeygenFromShake`; pitfall: keep transcript order, domain separation, sizes, and secret wiping exact.
proc falconKeygenFromShake*(v: FalconVariant, rng: var FalconShake256): tuple[publicKey, secretKey: seq[byte]] {.otterBench, role: {orchestrator}.} =
  ## v: variant. rng: seeded SHAKE256 reader feeding the sampler.
  ##   sample f, g -> checks -> solve F, G -> (repeat until both work) -> encode
  ## Every secret working copy is wiped on the way out.
  var
    logn: int = params(v).logn
    n: int = mknSize(logn)
    f: seq[int8] = newSeq[int8](n)
    g: seq[int8] = newSeq[int8](n)
    h: seq[uint16] = newSeq[uint16](n)
    rt1: seq[FalconFpr] = newSeq[FalconFpr](n)
    rt2: seq[FalconFpr] = newSeq[FalconFpr](n)
    rt3: seq[FalconFpr] = newSeq[FalconFpr](n shr 1)
    solved: tuple[ok: bool, F, G: seq[int8]] = (false, newSeq[int8](0), newSeq[int8](0))
  defer:
    secureClearItems(f)
    secureClearItems(g)
    secureClearItems(rt1)
    secureClearItems(rt2)
    secureClearItems(rt3)
    secureClearItems(solved.F)
    secureClearItems(solved.G)
  while not solved.ok:
    polySmallMkgauss(rng, f, logn)
    polySmallMkgauss(rng, g, logn)
    if fgCandidateOk(f, g, h, rt1, rt2, rt3, logn):
      solved = solveNtru(logn, f, g, (1 shl (int(falconMaxLargeBits[logn]) - 1)) - 1)
  result.publicKey = encodePublicKey(v, h)
  result.secretKey = encodeSecretKey(v, f, g, solved.F)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `falconKeygenFromSeed`; pitfall: keep transcript order, domain separation, sizes, and secret wiping exact.
proc falconKeygenFromSeed*(v: FalconVariant, seed: openArray[byte]): tuple[publicKey, secretKey: seq[byte]] {.otterBench, role: {orchestrator}.} =
  ## The reader below is seeded with the secret seed; wipe it on the way out.
  var
    rng: FalconShake256 = default(FalconShake256)
  defer:
    secureClearPod(rng)
  initFalconShake256(rng, seed)
  result = falconKeygenFromShake(v, rng)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `falconKeygenPure`; pitfall: keep transcript order, domain separation, sizes, and secret wiping exact.
proc falconKeygenPure*(v: FalconVariant): tuple[publicKey, secretKey: seq[byte]] {.otterBench, role: {orchestrator}.} =
  ## v: variant. The 48-byte seed comes from the system and is wiped after use.
  var
    seed: seq[byte] = falconRandomBytes(48)
  defer:
    secureClearBytes(seed)
  result = falconKeygenFromSeed(v, seed)
