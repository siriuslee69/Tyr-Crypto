## -------------------------------------------------------------------
## Falcon Keygen <- pure-Nim Falcon key generation
## -------------------------------------------------------------------
##
##   seed -> SHAKE256 -> sample small f, g -> checks -> solve F, G -> encode
##
##   checks (cheapest first):  coefficient range -> |f|² + |g|² -> Gram-
##                             Schmidt norm -> f invertible (h = g/f)
##
## The levels below; each imports only levels above it in this list:
##   keygen_modp     arithmetic modulo one small prime, NTT, caches
##   keygen_zint     constant-time big numbers in 31-bit words, Bezout
##   keygen_bigint   exact signed big numbers for the two smallest levels
##   keygen_rns      polynomials of big numbers, degree halving
##   keygen_solve    the NTRU equation solver

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
import ./keygen_modp
import ./keygen_solve
import ../../helpers/otter_support
import runePragmas

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
