## -------------------------------------------------------------------
## Falcon Keygen, level 3 <- solving the NTRU equation f·G - g·F = q
## -------------------------------------------------------------------
##
##   depth lognTop (degree 1)   Bezout on plain numbers       solveNtruDeepest
##        |  lift:   F(x) = Fd(x²)·g(-x),  G(x) = Gd(x²)·f(-x)
##        v  reduce: F -= k·f, G -= k·g until F, G are short
##   depth 2 .. lognTop - 1     solveNtruIntermediate  (exact for degree
##                              2 and 4, floating point above)
##   depth 1                    solveNtruBinaryDepth1
##   depth 0 (degree n)         solveNtruBinaryDepth0
##
## solveNtru checks the final answer modulo one prime before handing it out.

import ../../helpers/secure_memory
import ./fft
import ./fpr
import ./keygen_modp
import ./keygen_zint
import ./keygen_bigint
import ./keygen_rns
import runePragmas

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
    if not (roundDivSigned31(h0, denScaled, k[0]) and roundDivSigned31(h1, denScaled, k[1])):
      return
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
    numPoly: openArray[FalconSigned31], detNeg: bool, denScaled: openArray[uint32]): bool
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
    if not roundDivSigned31(num, denScaled, k[i]):
      return false
    i = i + 1
  result = true

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
    if not cramerK4(k, denMat, numPoly, det.neg, shiftLeftAbs31(det.words, scaleK)):
      return
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
proc solveNtru*(logn: int, f, g: openArray[int8], lim: int): tuple[ok: bool, F, G: seq[int8]] {.role: {math}.} =
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

