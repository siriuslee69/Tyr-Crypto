## -------------------------------------------------------------------
## Falcon Keygen, level 0 <- arithmetic modulo one small prime
## -------------------------------------------------------------------
##
## Keygen needs numbers far too big for one machine word. It keeps each
## one as its remainders modulo many 31-bit primes ("RNS" form) and
## computes prime by prime. This file is the per-prime toolbox:
##
##   modpAdd / modpSub / modpMontyMul   one remainder, constant time
##   modpNtt2 / modpIntt2               a whole polynomial <-> NTT form
##   getFalconNttTables / ...Runtime    per-thread caches of the constants
##   RnsPoly                            n coefficients x stride words
##
## Words used:
##   Montgomery form  x kept as x·2^31 mod p, so a product needs no division
##   NTT              a polynomial kept as its values at the roots of
##                    x^n + 1, so a product of two is a pointwise product

import runePragmas

type
  FalconSmallPrime* = object
    p*: uint32
    g*: uint32
    s*: uint32

  FalconBitlengthStats* = object
    avg*: int
    std*: int

  RnsPoly* = object
    ## n coefficients, stride 31-bit words each, stored one after another.
    n*: int
    stride*: int
    coeffs*: seq[uint32]

  FalconNttTables* = object
    gm*: seq[uint32]
    igm*: seq[uint32]

  FalconPrimeRuntime* = object
    p0i*: uint32
    r2*: uint32

include ./keygen_consts

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `mknSize`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
template mknSize*(logn: int): int =
  1 shl logn

const
  falconWordMask* = 0x7FFFFFFF'u32
  falconMaxLogn = 10

## Per-thread memoization. The tables are a pure function of (logn, primeIdx),
## so a thread-local copy is byte-identical to a shared one -- and a shared
## one would be a data race the moment two threads generated keys at once.
var
  falconNttCache {.threadvar.}: array[falconMaxLogn + 1, array[falconPrimes.len, FalconNttTables]]
  falconPrimeCache {.threadvar.}: array[falconPrimes.len, FalconPrimeRuntime]
  falconPrimeCacheReady {.threadvar.}: array[falconPrimes.len, bool]

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `initRnsPoly`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc initRnsPoly*(n, stride: int): RnsPoly {.inline, role: {helper}.} =
  ## n: coefficient count. stride: 31-bit words per coefficient.
  RnsPoly(n: n, stride: stride, coeffs: newSeq[uint32](n * stride))

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `clonePoly`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc clonePoly*(poly: RnsPoly): RnsPoly {.role: {helper}.} =
  ## poly: polynomial copied into fresh storage.
  result.n = poly.n
  result.stride = poly.stride
  result.coeffs = newSeq[uint32](poly.coeffs.len)
  if poly.coeffs.len > 0:
    copyMem(addr result.coeffs[0], unsafeAddr poly.coeffs[0], poly.coeffs.len * sizeof(uint32))

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `coeffOffset`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc coeffOffset*(poly: RnsPoly, coeff: int): int {.inline, role: {helper}.} =
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
proc modpSet*(x: int32, p: uint32): uint32 {.inline, role: {math}.} =
  ## x: small signed value, returned as its remainder 0 ..< p.
  result = cast[uint32](x)
  result += p and (0'u32 - (result shr 31))

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `modpNorm`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc modpNorm*(x, p: uint32): int32 {.inline, role: {math}.} =
  ## x: remainder mod p, returned as the signed value -p/2 .. p/2.
  cast[int32](x - (p and (((x - ((p + 1'u32) shr 1)) shr 31) - 1'u32)))

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `modpNinv31`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc modpNinv31*(p: uint32): uint32 {.role: {math}.} =
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
proc modpAdd*(a, b, p: uint32): uint32 {.inline, role: {math}.} =
  ## a/b: remainders mod p. Constant-time a + b mod p.
  result = a + b - p
  result += p and (0'u32 - (result shr 31))

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `modpSub`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc modpSub*(a, b, p: uint32): uint32 {.inline, role: {math}.} =
  ## a/b: remainders mod p. Constant-time a - b mod p.
  result = a - b
  result += p and (0'u32 - (result shr 31))

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `modpMontyMul`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc modpMontyMul*(a, b, p, p0i: uint32): uint32 {.inline, role: {math}.} =
  ## a/b: remainders mod p. p0i: -1/p mod 2^31. Returns a·b/2^31 mod p.
  var
    z: uint64 = uint64(a) * uint64(b)
    w: uint64 = ((z * uint64(p0i)) and 0x7FFFFFFF'u64) * uint64(p)
  result = uint32((z + w) shr 31) - p
  result += p and (0'u32 - (result shr 31))

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `modpR2`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc modpR2*(p, p0i: uint32): uint32 {.role: {math}.} =
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
proc modpRx*(x: int, p, p0i, R2: uint32): uint32 {.inline, role: {math}.} =
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
proc getFalconPrimeRuntime*(primeIdx: int): FalconPrimeRuntime {.inline, role: {memory}.} =
  ## primeIdx: small prime; its Montgomery constants are computed once per thread.
  var
    p: uint32 = falconPrimes[primeIdx].p
  if not falconPrimeCacheReady[primeIdx]:
    falconPrimeCache[primeIdx].p0i = modpNinv31(p)
    falconPrimeCache[primeIdx].r2 = modpR2(p, falconPrimeCache[primeIdx].p0i)
    falconPrimeCacheReady[primeIdx] = true
  result = falconPrimeCache[primeIdx]

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `getFalconNttTables`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc getFalconNttTables*(logn, primeIdx: int): FalconNttTables {.inline, role: {memory}.} =
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
proc modpNtt2Ext*(a: var seq[uint32], off, stride: int,
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
proc modpNtt2*(a: var seq[uint32], gm: openArray[uint32], logn: int,
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
proc modpIntt2Ext*(a: var seq[uint32], off, stride: int,
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
proc modpIntt2*(a: var seq[uint32], igm: openArray[uint32], logn: int,
    p, p0i: uint32) {.inline, role: {math}.} =
  ## a: contiguous NTT polynomial turned back into coefficients in place.
  modpIntt2Ext(a, 0, 1, igm, logn, p, p0i)

