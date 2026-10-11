## -------------------------------------------------------------------
## Falcon Keygen, level 2 <- polynomials of big numbers
## -------------------------------------------------------------------
##
##   RnsPoly   coefficient 0         coefficient 1         ...
##             [w0 w1 ... w(s-1)]    [w0 w1 ... w(s-1)]
##             s = stride: either s remainders (one per small prime),
##             or the s words of one big number after zintRebuildCrt
##
##   zintRebuildCrt        remainders -> big numbers (Garner's method)
##   polySubScaled(Ntt)    F -= k·f·2^shift, schoolbook or per prime
##   makeFgStep            f(x)·f(-x) as a polynomial in x²: half degree
##   buildFgViewChain      f, g at every depth, in NTT and plain form

import ./keygen_modp
import ./keygen_zint
import ./fpr
import runePragmas

type
  FalconFgViews* = object
    ntt*: tuple[f, g: RnsPoly]
    plain*: tuple[f, g: RnsPoly]

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
proc polyBigToFp*(dst: var seq[FalconFpr], poly: RnsPoly, wordOff, wordLen: int) {.role: {math}.} =
  ## dst: receives every coefficient of poly as a floating-point value.
  var
    u: int = 0
  dst.setLen(poly.n)
  while u < poly.n:
    dst[u] = bigCoeffToFp(poly, u, wordOff, wordLen)
    u = u + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `polyBigToSmall`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyBigToSmall*(dst: var seq[int8], poly: RnsPoly, lim: int): bool {.role: {parser}.} =
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
proc polySubScaled*(F: var RnsPoly, FLen: int, f: RnsPoly, fLen: int,
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
proc zintRebuildCrt*(poly: var RnsPoly, xLen: int, normalizeSigned: bool) {.role: {math}.} =
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
proc polySubScaledNtt*(F: var RnsPoly, FLen: int, f: RnsPoly, fLen: int,
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
proc columnInto*(t1: var seq[uint32], S: RnsPoly, u, slen, n: int) {.inline, role: {helper}.} =
  ## t1: receives word u (the remainder mod prime u) of S's n coefficients.
  var
    v: int = 0
  while v < n:
    t1[v] = S.coeffs[v * slen + u]
    v = v + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `reducedColumnInto`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc reducedColumnInto*(t1: var seq[uint32], S: RnsPoly, slen, n: int,
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
proc buildFgViewChain*(f, g: openArray[int8], lognTop: int): seq[FalconFgViews] {.role: {math}.} =
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
proc deepestFgFromNttChain*(lognTop: int,
    fgNtt: openArray[FalconFgViews]): tuple[f, g: RnsPoly] {.role: {math}.} =
  ## fgNtt: view chain. Returns f, g at degree 1 as plain big numbers.
  if lognTop <= 0:
    return makeFgStep(fgNtt[0].ntt.f, fgNtt[0].ntt.g, 1, 0, true, false)
  result = makeFgStep(fgNtt[lognTop - 1].ntt.f, fgNtt[lognTop - 1].ntt.g,
    1, lognTop - 1, true, false)

