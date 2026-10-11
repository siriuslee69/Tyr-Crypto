## --------------------------------------------------------------------
## Falcon Sign <- expanded-key preparation and sign-tree signing in Nim
## --------------------------------------------------------------------

import ./codec
import ../../helpers/secure_memory
import ./common
import ./fft
import ./format
import ./fpr
import ./params
import ./randomness
import ./rng
import ./shake
import ./util
import ../../helpers/otter_support
import runePragmas

const
  falconSignSeedBytes* = 48

  gaussianDist: array[54, uint32] = [
    10745844'u32, 3068844'u32, 3741698'u32,
    5559083'u32, 1580863'u32, 8248194'u32,
    2260429'u32, 13669192'u32, 2736639'u32,
    708981'u32, 4421575'u32, 10046180'u32,
    169348'u32, 7122675'u32, 4136815'u32,
    30538'u32, 13063405'u32, 7650655'u32,
    4132'u32, 14505003'u32, 7826148'u32,
    417'u32, 16768101'u32, 11363290'u32,
    31'u32, 8444042'u32, 8086568'u32,
    1'u32, 12844466'u32, 265321'u32,
    0'u32, 1232676'u32, 13644283'u32,
    0'u32, 38047'u32, 9111839'u32,
    0'u32, 870'u32, 6138264'u32,
    0'u32, 14'u32, 12545723'u32,
    0'u32, 0'u32, 3104126'u32,
    0'u32, 0'u32, 28824'u32,
    0'u32, 0'u32, 198'u32,
    0'u32, 0'u32, 1'u32
  ]

type
  FalconExpandedSecret* = object
    logn*: int
    b00*: seq[FalconFpr]
    b01*: seq[FalconFpr]
    b10*: seq[FalconFpr]
    b11*: seq[FalconFpr]
    tree*: seq[FalconFpr]

  FalconSamplerContext = object
    p: FalconPrng
    sigmaMin: FalconFpr

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; signature generation algorithms for `ffLDLTreeSize`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc ffLDLTreeSize*(logn: int): int {.inline, role: {math}.} =
  ## logn: degree exponent. Returns the number of values in an LDL tree.
  (logn + 1) shl logn

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; signature generation algorithms for `copyFprRange`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc copyFprRange(A: openArray[FalconFpr], start, len: int): seq[FalconFpr] {.role: {helper}.} =
  ## A: values. Returns A[start ..< start + len] as a fresh seq.
  result = newSeq[FalconFpr](len)
  if len > 0:
    copyMem(addr result[0], unsafeAddr A[start], len * sizeof(FalconFpr))

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; signature generation algorithms for `smallintsToFpr`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc smallintsToFpr*(dst: var seq[FalconFpr], src: openArray[int8], logn: int) {.role: {math}.} =
  ## dst: receives the small coefficients src as floating-point values.
  var
    n: int = mkn(logn)
    i: int = 0
  dst.setLen(n)
  while i < n:
    dst[i] = fprOf(src[i].int64)
    i = i + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; signature generation algorithms for `ffLDLFftAt`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc ffLDLFftAt(tree: var seq[FalconFpr], treeOff: int, g00, g01, g11: openArray[FalconFpr],
    logn: int) {.role: {math}.} =
  ## tree: the LDL tree of the Gram matrix [[g00 g01] [adj g01 g11]] is
  ## written from treeOff on (FFT form):
  ##   [l10 (n values)][left subtree (d00 halves)][right subtree (d11 halves)]
  ## A leaf (n = 1) holds the matrix entry itself.
  var
    n: int = mkn(logn)
    hn: int = n shr 1
    childLen: int = 0
    d11: seq[FalconFpr] = @[]
    l10: seq[FalconFpr] = @[]
    d00Lo: seq[FalconFpr] = @[]
    d00Hi: seq[FalconFpr] = @[]
    d11Lo: seq[FalconFpr] = @[]
    d11Hi: seq[FalconFpr] = @[]
  if n == 1:
    tree[treeOff] = g00[0]
    return
  defer:
    secureClearItems(d11)
    secureClearItems(l10)
    secureClearItems(d00Lo)
    secureClearItems(d00Hi)
    secureClearItems(d11Lo)
    secureClearItems(d11Hi)
  childLen = ffLDLTreeSize(logn - 1)
  d11 = newSeq[FalconFpr](n)
  l10 = newSeq[FalconFpr](n)
  d00Lo = newSeq[FalconFpr](hn)
  d00Hi = newSeq[FalconFpr](hn)
  d11Lo = newSeq[FalconFpr](hn)
  d11Hi = newSeq[FalconFpr](hn)
  polyLDLmvFft(d11, l10, g00, g01, g11, logn)
  copyMem(addr tree[treeOff], addr l10[0], n * sizeof(FalconFpr))
  polySplitFft(d00Lo, d00Hi, g00, logn)
  polySplitFft(d11Lo, d11Hi, d11, logn)
  ffLDLFftAt(tree, treeOff + n, d00Lo, d00Hi, d00Lo, logn - 1)
  ffLDLFftAt(tree, treeOff + n + childLen, d11Lo, d11Hi, d11Lo, logn - 1)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; signature generation algorithms for `ffLDLFft`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc ffLDLFft*(tree: var seq[FalconFpr], g00, g01, g11: openArray[FalconFpr], logn: int) {.role: {math}.} =
  ## tree: receives the whole LDL tree (size ffLDLTreeSize(logn)).
  if tree.len != ffLDLTreeSize(logn):
    raise newException(ValueError, "Falcon ffLDL tree has wrong size")
  ffLDLFftAt(tree, 0, g00, g01, g11, logn)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; signature generation algorithms for `ffLDLBinaryNormalize`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc ffLDLBinaryNormalize*(tree: var seq[FalconFpr], treeOff, origLogn, logn: int) {.role: {math}.} =
  ## tree: every leaf value v becomes sqrt(v)·(1/sigma) for this degree.
  var
    n: int = mkn(logn)
  if n == 1:
    tree[treeOff] = fprMul(fprSqrt(tree[treeOff]), fprInvSigma[origLogn])
    return
  ffLDLBinaryNormalize(tree, treeOff + n, origLogn, logn - 1)
  ffLDLBinaryNormalize(tree, treeOff + n + ffLDLTreeSize(logn - 1), origLogn, logn - 1)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; signature generation algorithms for `clearExpandedSecret`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc clearExpandedSecret*(expanded: var FalconExpandedSecret) {.role: {helper}.} =
  ## expanded: every secret value is wiped and the storage emptied.
  secureClearItems(expanded.b00)
  secureClearItems(expanded.b01)
  secureClearItems(expanded.b10)
  secureClearItems(expanded.b11)
  secureClearItems(expanded.tree)
  expanded.b00.setLen(0)
  expanded.b01.setLen(0)
  expanded.b10.setLen(0)
  expanded.b11.setLen(0)
  expanded.tree.setLen(0)
  expanded.logn = 0

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; signature generation algorithms for `fprSeqIsFinite`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc fprSeqIsFinite(A: openArray[FalconFpr]): bool {.role: {parser}.} =
  ## A: values. True when none is infinite or NaN.
  var
    i: int = 0
  result = true
  while result and i < A.len:
    result = fprIsFinite(A[i])
    i = i + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; signature generation algorithms for `validateExpandedSecret`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc validateExpandedSecret*(expanded: FalconExpandedSecret, logn: int): bool {.role: {parser}.} =
  ## expanded: prepared key. True when every part has the size for logn and
  ## holds only finite values.
  var
    n: int = 0
  if logn < 1 or logn >= fprInvSigma.len:
    return false
  if expanded.logn != logn:
    return false
  n = mkn(logn)
  if expanded.b00.len != n or expanded.b01.len != n or
      expanded.b10.len != n or expanded.b11.len != n:
    return false
  if expanded.tree.len != ffLDLTreeSize(logn):
    return false
  result = fprSeqIsFinite(expanded.b00) and
    fprSeqIsFinite(expanded.b01) and
    fprSeqIsFinite(expanded.b10) and
    fprSeqIsFinite(expanded.b11) and
    fprSeqIsFinite(expanded.tree)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; signature generation algorithms for `gramEntry`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc gramEntry(a, b: openArray[FalconFpr], c, d: openArray[FalconFpr], logn: int,
    selfAdj: bool): seq[FalconFpr] {.role: {math}.} =
  ## Returns a·adj(c) + b·adj(d) in FFT form; with selfAdj, c = a and d = b
  ## and the cheaper a·adj(a) + b·adj(b) is used.
  var
    gxx: seq[FalconFpr] = copyFprRange(b, 0, b.len)
  defer:
    secureClearItems(gxx)
  result = copyFprRange(a, 0, a.len)
  if selfAdj:
    polyMulselfadjFft(result, logn)
    polyMulselfadjFft(gxx, logn)
  else:
    polyMuladjFft(result, c, logn)
    polyMuladjFft(gxx, d, logn)
  polyAdd(result, gxx, logn)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; signature generation algorithms for `expandPrivateKey`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc expandPrivateKey*(expanded: var FalconExpandedSecret, decoded: FalconDecodedSecret) {.otterBench, role: {math}.} =
  ## expanded: receives the basis B = [[g, -f] [G, -F]] in FFT form and the
  ## normalized LDL tree of its Gram matrix, ready for repeated signing.
  var
    logn: int = decoded.logn
    g00: seq[FalconFpr] = @[]
    g01: seq[FalconFpr] = @[]
    g11: seq[FalconFpr] = @[]
  defer:
    secureClearItems(g00)
    secureClearItems(g01)
    secureClearItems(g11)
  expanded.logn = logn
  smallintsToFpr(expanded.b01, decoded.f, logn)
  smallintsToFpr(expanded.b00, decoded.g, logn)
  smallintsToFpr(expanded.b11, decoded.F, logn)
  smallintsToFpr(expanded.b10, decoded.G, logn)
  falconFft(expanded.b01, logn)
  falconFft(expanded.b00, logn)
  falconFft(expanded.b11, logn)
  falconFft(expanded.b10, logn)
  polyNeg(expanded.b01, logn)
  polyNeg(expanded.b11, logn)
  g00 = gramEntry(expanded.b00, expanded.b01, expanded.b00, expanded.b01, logn, true)
  g01 = gramEntry(expanded.b00, expanded.b01, expanded.b10, expanded.b11, logn, false)
  g11 = gramEntry(expanded.b10, expanded.b11, expanded.b10, expanded.b11, logn, true)
  expanded.tree = newSeq[FalconFpr](ffLDLTreeSize(logn))
  ffLDLFft(expanded.tree, g00, g01, g11, logn)
  ffLDLBinaryNormalize(expanded.tree, 0, logn, logn)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; signature generation algorithms for `expandPrivateKey`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc expandPrivateKey*(decoded: FalconDecodedSecret): FalconExpandedSecret {.role: {math}.} =
  ## decoded: secret key polynomials. Returns the prepared signing key.
  expandPrivateKey(result, decoded)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; signature generation algorithms for `prepareSecretKey`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc prepareSecretKey*(v: FalconVariant, sk: openArray[byte]): FalconExpandedSecret {.otterBench, role: {orchestrator}.} =
  ## sk: encoded secret key. Decodes it, expands it, wipes the decoded copy.
  var
    decoded: FalconDecodedSecret = default(FalconDecodedSecret)
  if not decodeSecretKey(decoded, sk, v):
    raise newException(ValueError, "invalid Falcon secret key")
  defer:
    secureClearItems(decoded.f)
    secureClearItems(decoded.g)
    secureClearItems(decoded.F)
    secureClearItems(decoded.G)
  expandPrivateKey(result, decoded)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; signature generation algorithms for `gaussian0Sampler`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc gaussian0Sampler*(p: var FalconPrng): int {.role: {math}.} =
  ## p: sampler PRNG. Returns a half-Gaussian sample: the number of table
  ## entries (72-bit, three 24-bit words) above a fresh 72-bit random value.
  ## Every entry is compared, so the time does not depend on the result.
  var
    lo: uint64 = prngGetU64(p)
    hi: uint32 = prngGetU8(p)
    v0: uint32 = uint32(lo) and 0x00FF_FFFF'u32
    v1: uint32 = uint32(lo shr 24) and 0x00FF_FFFF'u32
    v2: uint32 = uint32(lo shr 48) or (hi shl 16)
    cc: uint32 = 0'u32
    i: int = 0
  while i < gaussianDist.len:
    cc = (v0 - gaussianDist[i + 2]) shr 31
    cc = (v1 - gaussianDist[i + 1] - cc) shr 31
    cc = (v2 - gaussianDist[i + 0] - cc) shr 31
    result = result + cc.int
    i = i + 3

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; signature generation algorithms for `berExp`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc berExp(p: var FalconPrng, x, ccs: FalconFpr): int {.role: {math}.} =
  ## p: sampler PRNG. Returns 1 with probability ccs·exp(-x), else 0.
  ## Random bytes are compared one at a time, most significant first.
  var
    s: int = int(fprTrunc(fprMul(x, fprInvLog2)))
    r: FalconFpr = fprSub(x, fprMul(fprOf(s.int64), fprLog2))
    sw: uint32 = uint32(s)
    z: uint64 = 0'u64
    i: int = 64
    w: uint32 = 0'u32
    more: bool = true
  sw = sw xor ((sw xor 63'u32) and (0'u32 - ((63'u32 - sw) shr 31)))
  s = sw.int
  z = ((fprExpmP63(r, ccs) shl 1) - 1'u64) shr s
  while more:
    i = i - 8
    w = prngGetU8(p) - uint32((z shr i) and 0xFF'u64)
    more = w == 0'u32 and i > 0
  int(w shr 31)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; signature generation algorithms for `sampler`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc sampler*(ctx: var FalconSamplerContext, mu, isigma: FalconFpr): int {.role: {math}.} =
  ## ctx: PRNG and sigma bound. Returns an integer drawn from a discrete
  ## Gaussian centred on mu with deviation 1/isigma (rejection sampling).
  var
    s: int = int(fprFloor(mu))
    r: FalconFpr = fprSub(mu, fprOf(s.int64))
    dss: FalconFpr = fprHalf(fprSqr(isigma))
    ccs: FalconFpr = fprMul(isigma, ctx.sigmaMin)
    z0: int = 0
    b: int = 0
    z: int = 0
    x: FalconFpr = fprZero
    accepted: bool = false
  while not accepted:
    z0 = gaussian0Sampler(ctx.p)
    b = int(prngGetU8(ctx.p) and 1'u32)
    z = b + ((b shl 1) - 1) * z0
    x = fprMul(fprSqr(fprSub(fprOf(z.int64), r)), dss)
    x = fprSub(x, fprMul(fprOf((z0 * z0).int64), fprInv2SqrSigma0))
    accepted = berExp(ctx.p, x, ccs) != 0
  result = s + z

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; signature generation algorithms for `ffSamplingLeaf4`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc ffSamplingLeaf4(ctx: var FalconSamplerContext, tree, t0, t1: openArray[FalconFpr]):
    tuple[z0, z1: seq[FalconFpr]] {.role: {math}.} =
  ## ffSampling for degree 4 (logn = 2), unrolled as in the reference code.
  var
    x0, x1, y0, y1, w0, w1, w2, w3, sigma: FalconFpr = default(FalconFpr)
    aRe, aIm, bRe, bIm, cRe, cIm: FalconFpr = default(FalconFpr)
    tree0: seq[FalconFpr] = copyFprRange(tree, 4, 4)
    tree1: seq[FalconFpr] = copyFprRange(tree, 8, 4)
  defer:
    secureClearItems(tree0)
    secureClearItems(tree1)
  result.z0 = newSeq[FalconFpr](4)
  result.z1 = newSeq[FalconFpr](4)

  aRe = t1[0]
  aIm = t1[2]
  bRe = t1[1]
  bIm = t1[3]
  cRe = fprAdd(aRe, bRe)
  cIm = fprAdd(aIm, bIm)
  w0 = fprHalf(cRe)
  w1 = fprHalf(cIm)
  cRe = fprSub(aRe, bRe)
  cIm = fprSub(aIm, bIm)
  w2 = fprMul(fprAdd(cRe, cIm), fprInvSqrt8)
  w3 = fprMul(fprSub(cIm, cRe), fprInvSqrt8)

  x0 = w2
  x1 = w3
  sigma = tree1[3]
  w2 = fprOf(sampler(ctx, x0, sigma).int64)
  w3 = fprOf(sampler(ctx, x1, sigma).int64)
  aRe = fprSub(x0, w2)
  aIm = fprSub(x1, w3)
  bRe = tree1[0]
  bIm = tree1[1]
  cRe = fprSub(fprMul(aRe, bRe), fprMul(aIm, bIm))
  cIm = fprAdd(fprMul(aRe, bIm), fprMul(aIm, bRe))
  x0 = fprAdd(cRe, w0)
  x1 = fprAdd(cIm, w1)
  sigma = tree1[2]
  w0 = fprOf(sampler(ctx, x0, sigma).int64)
  w1 = fprOf(sampler(ctx, x1, sigma).int64)

  aRe = w0
  aIm = w1
  bRe = w2
  bIm = w3
  cRe = fprMul(fprSub(bRe, bIm), fprInvSqrt2)
  cIm = fprMul(fprAdd(bRe, bIm), fprInvSqrt2)
  w0 = fprAdd(aRe, cRe)
  w2 = fprAdd(aIm, cIm)
  w1 = fprSub(aRe, cRe)
  w3 = fprSub(aIm, cIm)
  result.z1[0] = w0
  result.z1[2] = w2
  result.z1[1] = w1
  result.z1[3] = w3

  w0 = fprSub(t1[0], w0)
  w1 = fprSub(t1[1], w1)
  w2 = fprSub(t1[2], w2)
  w3 = fprSub(t1[3], w3)

  aRe = w0
  aIm = w2
  bRe = tree[0]
  bIm = tree[2]
  w0 = fprSub(fprMul(aRe, bRe), fprMul(aIm, bIm))
  w2 = fprAdd(fprMul(aRe, bIm), fprMul(aIm, bRe))
  aRe = w1
  aIm = w3
  bRe = tree[1]
  bIm = tree[3]
  w1 = fprSub(fprMul(aRe, bRe), fprMul(aIm, bIm))
  w3 = fprAdd(fprMul(aRe, bIm), fprMul(aIm, bRe))

  w0 = fprAdd(w0, t0[0])
  w1 = fprAdd(w1, t0[1])
  w2 = fprAdd(w2, t0[2])
  w3 = fprAdd(w3, t0[3])

  aRe = w0
  aIm = w2
  bRe = w1
  bIm = w3
  cRe = fprAdd(aRe, bRe)
  cIm = fprAdd(aIm, bIm)
  w0 = fprHalf(cRe)
  w1 = fprHalf(cIm)
  cRe = fprSub(aRe, bRe)
  cIm = fprSub(aIm, bIm)
  w2 = fprMul(fprAdd(cRe, cIm), fprInvSqrt8)
  w3 = fprMul(fprSub(cIm, cRe), fprInvSqrt8)

  x0 = w2
  x1 = w3
  sigma = tree0[3]
  y0 = fprOf(sampler(ctx, x0, sigma).int64)
  y1 = fprOf(sampler(ctx, x1, sigma).int64)
  w2 = y0
  w3 = y1
  aRe = fprSub(x0, y0)
  aIm = fprSub(x1, y1)
  bRe = tree0[0]
  bIm = tree0[1]
  cRe = fprSub(fprMul(aRe, bRe), fprMul(aIm, bIm))
  cIm = fprAdd(fprMul(aRe, bIm), fprMul(aIm, bRe))
  x0 = fprAdd(cRe, w0)
  x1 = fprAdd(cIm, w1)
  sigma = tree0[2]
  w0 = fprOf(sampler(ctx, x0, sigma).int64)
  w1 = fprOf(sampler(ctx, x1, sigma).int64)

  aRe = w0
  aIm = w1
  bRe = w2
  bIm = w3
  cRe = fprMul(fprSub(bRe, bIm), fprInvSqrt2)
  cIm = fprMul(fprAdd(bRe, bIm), fprInvSqrt2)
  result.z0[0] = fprAdd(aRe, cRe)
  result.z0[2] = fprAdd(aIm, cIm)
  result.z0[1] = fprSub(aRe, cRe)
  result.z0[3] = fprSub(aIm, cIm)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; signature generation algorithms for `ffSamplingLeaf2`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc ffSamplingLeaf2(ctx: var FalconSamplerContext, tree, t0, t1: openArray[FalconFpr]):
    tuple[z0, z1: seq[FalconFpr]] {.role: {math}.} =
  ## ffSampling for degree 2 (logn = 1), unrolled as in the reference code.
  var
    x0, x1, y0, y1, sigma: FalconFpr = default(FalconFpr)
    aRe, aIm, bRe, bIm, cRe, cIm: FalconFpr = default(FalconFpr)
  result.z0 = newSeq[FalconFpr](2)
  result.z1 = newSeq[FalconFpr](2)
  x0 = t1[0]
  x1 = t1[1]
  sigma = tree[3]
  y0 = fprOf(sampler(ctx, x0, sigma).int64)
  y1 = fprOf(sampler(ctx, x1, sigma).int64)
  result.z1[0] = y0
  result.z1[1] = y1
  aRe = fprSub(x0, y0)
  aIm = fprSub(x1, y1)
  bRe = tree[0]
  bIm = tree[1]
  cRe = fprSub(fprMul(aRe, bRe), fprMul(aIm, bIm))
  cIm = fprAdd(fprMul(aRe, bIm), fprMul(aIm, bRe))
  x0 = fprAdd(cRe, t0[0])
  x1 = fprAdd(cIm, t0[1])
  sigma = tree[2]
  result.z0[0] = fprOf(sampler(ctx, x0, sigma).int64)
  result.z0[1] = fprOf(sampler(ctx, x1, sigma).int64)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; signature generation algorithms for `ffSamplingFft`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc ffSamplingFft(ctx: var FalconSamplerContext, tree, t0, t1: openArray[FalconFpr],
    logn: int): tuple[z0, z1: seq[FalconFpr]] {.role: {math}.} =
  ## Fast Fourier sampling of (z0, z1) close to the target (t0, t1):
  ##   split t1, sample it against the right subtree -> z1
  ##   t0' = t0 + (t1 - z1)·l10, split, sample against the left subtree -> z0
  var
    n: int = 0
    hn: int = 0
    childLen: int = 0
    tree0: seq[FalconFpr] = @[]
    tree1: seq[FalconFpr] = @[]
    split0: seq[FalconFpr] = @[]
    split1: seq[FalconFpr] = @[]
    tmp: seq[FalconFpr] = @[]
    l10: seq[FalconFpr] = @[]
    merged: tuple[z0, z1: seq[FalconFpr]] = default(tuple[z0, z1: seq[FalconFpr]])
  case logn
  of 1:
    return ffSamplingLeaf2(ctx, tree, t0, t1)
  of 2:
    return ffSamplingLeaf4(ctx, tree, t0, t1)
  else:
    discard
  defer:
    secureClearItems(tree0)
    secureClearItems(tree1)
    secureClearItems(split0)
    secureClearItems(split1)
    secureClearItems(tmp)
    secureClearItems(l10)
  n = mkn(logn)
  hn = n shr 1
  childLen = ffLDLTreeSize(logn - 1)
  tree0 = copyFprRange(tree, n, childLen)
  tree1 = copyFprRange(tree, n + childLen, childLen)
  split0 = newSeq[FalconFpr](hn)
  split1 = newSeq[FalconFpr](hn)
  tmp = @t1
  l10 = copyFprRange(tree, 0, n)
  polySplitFft(split0, split1, t1, logn)
  merged = ffSamplingFft(ctx, tree1, split0, split1, logn - 1)
  result.z1 = newSeq[FalconFpr](n)
  polyMergeFft(result.z1, merged.z0, merged.z1, logn)
  secureClearItems(merged.z0)
  secureClearItems(merged.z1)

  polySub(tmp, result.z1, logn)
  polyMulFft(tmp, l10, logn)
  polyAdd(tmp, t0, logn)

  polySplitFft(split0, split1, tmp, logn)
  merged = ffSamplingFft(ctx, tree0, split0, split1, logn - 1)
  result.z0 = newSeq[FalconFpr](n)
  polyMergeFft(result.z0, merged.z0, merged.z1, logn)
  secureClearItems(merged.z0)
  secureClearItems(merged.z1)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; signature generation algorithms for `doSignTree`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc doSignTree(ctx: var FalconSamplerContext, s2: var seq[int16], expanded: FalconExpandedSecret,
    hm: openArray[uint16]): bool {.role: {math}.} =
  ## hm: hashed message point. One signing attempt: sample a lattice point
  ## close to (hm, 0), keep s2 when the signature (s1, s2) is short enough.
  var
    n: int = mkn(expanded.logn)
    t0: seq[FalconFpr] = newSeq[FalconFpr](n)
    t1: seq[FalconFpr] = newSeq[FalconFpr](n)
    tx: seq[FalconFpr] = @[]
    ty: seq[FalconFpr] = @[]
    sampled: tuple[z0, z1: seq[FalconFpr]] = default(tuple[z0, z1: seq[FalconFpr]])
    ni: FalconFpr = fprInverseOfQ
    sqn: uint32 = 0
    ng: uint32 = 0
    z: int32 = 0'i32
    i: int = 0
    s2Tmp: seq[int16] = newSeq[int16](n)
  defer:
    secureClearItems(t0)
    secureClearItems(t1)
    secureClearItems(tx)
    secureClearItems(ty)
    secureClearItems(sampled.z0)
    secureClearItems(sampled.z1)
    secureClearItems(s2Tmp)
  while i < n:
    t0[i] = fprOf(hm[i].int64)
    i = i + 1
  falconFft(t0, expanded.logn)
  t1 = @t0
  polyMulFft(t1, expanded.b01, expanded.logn)
  polyMulconst(t1, fprNeg(ni), expanded.logn)
  polyMulFft(t0, expanded.b11, expanded.logn)
  polyMulconst(t0, ni, expanded.logn)

  sampled = ffSamplingFft(ctx, expanded.tree, t0, t1, expanded.logn)
  tx = copyFprRange(sampled.z0, 0, sampled.z0.len)
  ty = copyFprRange(sampled.z1, 0, sampled.z1.len)
  t0 = copyFprRange(tx, 0, tx.len)
  t1 = copyFprRange(ty, 0, ty.len)
  polyMulFft(tx, expanded.b00, expanded.logn)
  polyMulFft(ty, expanded.b10, expanded.logn)
  polyAdd(tx, ty, expanded.logn)
  ty = copyFprRange(t0, 0, t0.len)
  polyMulFft(ty, expanded.b01, expanded.logn)
  t0 = copyFprRange(tx, 0, tx.len)
  polyMulFft(t1, expanded.b11, expanded.logn)
  polyAdd(t1, ty, expanded.logn)
  falconIfft(t0, expanded.logn)
  falconIfft(t1, expanded.logn)

  i = 0
  while i < n:
    z = hm[i].int32 - fprRint(t0[i]).int32
    sqn = sqn + uint32(z.int64 * z.int64)
    ng = ng or sqn
    s2Tmp[i] = int16(-fprRint(t1[i]))
    i = i + 1
  sqn = sqn or (0'u32 - (ng shr 31))
  if not isShortHalf(sqn, s2Tmp, expanded.logn):
    return false
  s2 = @s2Tmp
  true

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; signature generation algorithms for `signTreeRaw`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc signTreeRaw*(sig: var seq[int16], rng: var FalconShake256, expanded: FalconExpandedSecret,
    hm: openArray[uint16]) {.otterBench, role: {math}.} =
  ## sig: receives s2. Attempts repeat with fresh PRNG seeds from rng until
  ## one is short enough.
  var
    ctx: FalconSamplerContext = default(FalconSamplerContext)
    done: bool = false
  while not done:
    ctx.sigmaMin = fprSigmaMin[expanded.logn]
    prngInitFromShake(ctx.p, rng)
    done = doSignTree(ctx, sig, expanded, hm)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; signature generation algorithms for `hashNonceMessageToPointCt`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc hashNonceMessageToPointCt(dst: var seq[uint16], nonce, msg: openArray[byte], logn: int) {.role: {math}.} =
  ## dst: receives SHAKE256(nonce || msg) mapped to a polynomial mod q.
  var
    ctx: FalconShake256 = default(FalconShake256)
  initFalconShake256(ctx, nonce, msg)
  hashToPointCt(ctx, dst, logn)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; signature generation algorithms for `encodeDetachedSignature`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc encodeDetachedSignature(v: FalconVariant, nonce: openArray[byte], s2: openArray[int16]): seq[byte] {.role: {helper}.} =
  ## Layout: [0x30 + logn][nonce, 40 bytes][compressed s2]. Returns an empty
  ## seq when s2 does not fit the size limit (the caller signs again).
  var
    p: FalconParams = params(v)
    used: int = 0
  result = newSeq[byte](p.signatureBytes)
  result[0] = byte(0x30 + p.logn)
  copyBytes(result, 1, nonce)
  used = compEncode(result.toOpenArray(1 + falconNonceLen, result.high), s2, p.logn)
  if used == 0:
    result.setLen(0)
    return
  result.setLen(1 + falconNonceLen + used)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; signature generation algorithms for `falconSignPreparedDerand`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc falconSignPreparedDerand*(prepared: FalconExpandedSecret, msg, nonce, seed: openArray[byte],
    v: FalconVariant): seq[byte] {.otterBench, role: {orchestrator}.} =
  ## prepared: expanded key. nonce/seed: caller-chosen randomness, so the
  ## same inputs give the same signature.
  var
    p: FalconParams = params(v)
    hm: seq[uint16] = @[]
    sig: seq[int16] = @[]
    rng: FalconShake256 = default(FalconShake256)
  if not validateExpandedSecret(prepared, p.logn):
    raise newException(ValueError, "invalid prepared Falcon secret for variant")
  if nonce.len != falconNonceLen:
    raise newException(ValueError, "Falcon nonce must be 40 bytes")
  if seed.len != falconSignSeedBytes:
    raise newException(ValueError, "Falcon signing seed must be 48 bytes")
  defer:
    secureClearItems(hm)
    secureClearItems(sig)
    secureClearPod(rng)
  hm = newSeq[uint16](mkn(p.logn))
  hashNonceMessageToPointCt(hm, nonce, msg, p.logn)
  initFalconShake256(rng, seed)
  while result.len == 0:
    secureClearItems(sig)
    sig.setLen(0)
    signTreeRaw(sig, rng, prepared, hm)
    result = encodeDetachedSignature(v, nonce, sig)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; signature generation algorithms for `falconSignPrepared`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc falconSignPrepared*(prepared: FalconExpandedSecret, msg: openArray[byte], v: FalconVariant): seq[byte] {.otterBench, role: {orchestrator}.} =
  ## prepared: expanded key. Nonce and seed come from the system.
  var
    nonce: seq[byte] = falconRandomBytes(falconNonceLen)
    seed: seq[byte] = falconRandomBytes(falconSignSeedBytes)
  defer:
    secureClearBytes(nonce)
    secureClearBytes(seed)
  result = falconSignPreparedDerand(prepared, msg, nonce, seed, v)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; signature generation algorithms for `falconSignDerand`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc falconSignDerand*(v: FalconVariant, msg, sk, nonce, seed: openArray[byte]): seq[byte] {.otterBench, role: {orchestrator}.} =
  ## sk: encoded secret key, expanded for this one signature and wiped after.
  var
    prepared: FalconExpandedSecret = prepareSecretKey(v, sk)
  defer:
    clearExpandedSecret(prepared)
  result = falconSignPreparedDerand(prepared, msg, nonce, seed, v)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; signature generation algorithms for `falconSignPure`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc falconSignPure*(v: FalconVariant, msg, sk: openArray[byte]): seq[byte] {.otterBench, role: {orchestrator}.} =
  ## sk: encoded secret key. Signs with system randomness.
  var
    prepared: FalconExpandedSecret = prepareSecretKey(v, sk)
  defer:
    clearExpandedSecret(prepared)
  result = falconSignPrepared(prepared, msg, v)
