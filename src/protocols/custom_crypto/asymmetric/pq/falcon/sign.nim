## --------------------------------------------------------------------
## Falcon Sign <- expanded-key preparation and sign-tree signing in Nim
## --------------------------------------------------------------------

import ./codec
import ./common
import ./fft
import ./format
import ./fpr
import ./params
import ./randomness
import ./rng
import ./shake
import ./util
import ../../../../helpers/otter_support

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

proc ffLDLTreeSize*(logn: int): int {.inline.} =
  (logn + 1) shl logn

proc copyFprRange(A: openArray[FalconFpr], start, len: int): seq[FalconFpr] =
  result = newSeq[FalconFpr](len)
  if len > 0:
    copyMem(addr result[0], unsafeAddr A[start], len * sizeof(FalconFpr))

proc smallintsToFpr*(dst: var seq[FalconFpr], src: openArray[int8], logn: int) =
  let n = mkn(logn)
  dst.setLen(n)
  var i = 0
  while i < n:
    dst[i] = fprOf(src[i].int64)
    i = i + 1

proc ffLDLFftInner(tree: var seq[FalconFpr], treeOff: int, g0, g1: openArray[FalconFpr], logn: int) =
  let n = mkn(logn)
  if n == 1:
    tree[treeOff] = g0[0]
    return

  let hn = n shr 1
  var
    d11 = newSeq[FalconFpr](n)
    l10 = newSeq[FalconFpr](n)
    d00Lo = newSeq[FalconFpr](hn)
    d00Hi = newSeq[FalconFpr](hn)
    d11Lo = newSeq[FalconFpr](hn)
    d11Hi = newSeq[FalconFpr](hn)
    childLen = ffLDLTreeSize(logn - 1)
  defer:
    secureClearSeqData(d11)
    secureClearSeqData(l10)
    secureClearSeqData(d00Lo)
    secureClearSeqData(d00Hi)
    secureClearSeqData(d11Lo)
    secureClearSeqData(d11Hi)
  polyLDLmvFft(d11, l10, g0, g1, g0, logn)
  copyMem(addr tree[treeOff], addr l10[0], n * sizeof(FalconFpr))
  polySplitFft(d00Lo, d00Hi, g0, logn)
  polySplitFft(d11Lo, d11Hi, d11, logn)
  ffLDLFftInner(tree, treeOff + n, d00Lo, d00Hi, logn - 1)
  ffLDLFftInner(tree, treeOff + n + childLen, d11Lo, d11Hi, logn - 1)

proc ffLDLFft*(tree: var seq[FalconFpr], g00, g01, g11: openArray[FalconFpr], logn: int) =
  let n = mkn(logn)
  if tree.len != ffLDLTreeSize(logn):
    raise newException(ValueError, "Falcon ffLDL tree has wrong size")
  if n == 1:
    tree[0] = g00[0]
    return

  let hn = n shr 1
  var
    d11 = newSeq[FalconFpr](n)
    l10 = newSeq[FalconFpr](n)
    d00Lo = newSeq[FalconFpr](hn)
    d00Hi = newSeq[FalconFpr](hn)
    d11Lo = newSeq[FalconFpr](hn)
    d11Hi = newSeq[FalconFpr](hn)
    childLen = ffLDLTreeSize(logn - 1)
  defer:
    secureClearSeqData(d11)
    secureClearSeqData(l10)
    secureClearSeqData(d00Lo)
    secureClearSeqData(d00Hi)
    secureClearSeqData(d11Lo)
    secureClearSeqData(d11Hi)
  polyLDLmvFft(d11, l10, g00, g01, g11, logn)
  copyMem(addr tree[0], addr l10[0], n * sizeof(FalconFpr))
  polySplitFft(d00Lo, d00Hi, g00, logn)
  polySplitFft(d11Lo, d11Hi, d11, logn)
  ffLDLFftInner(tree, n, d00Lo, d00Hi, logn - 1)
  ffLDLFftInner(tree, n + childLen, d11Lo, d11Hi, logn - 1)

proc ffLDLBinaryNormalize*(tree: var seq[FalconFpr], treeOff, origLogn, logn: int) =
  let n = mkn(logn)
  if n == 1:
    tree[treeOff] = fprMul(fprSqrt(tree[treeOff]), fprInvSigma[origLogn])
    return
  ffLDLBinaryNormalize(tree, treeOff + n, origLogn, logn - 1)
  ffLDLBinaryNormalize(tree, treeOff + n + ffLDLTreeSize(logn - 1), origLogn, logn - 1)

proc clearExpandedSecret*(expanded: var FalconExpandedSecret) =
  secureClearSeqData(expanded.b00)
  secureClearSeqData(expanded.b01)
  secureClearSeqData(expanded.b10)
  secureClearSeqData(expanded.b11)
  secureClearSeqData(expanded.tree)
  expanded.b00.setLen(0)
  expanded.b01.setLen(0)
  expanded.b10.setLen(0)
  expanded.b11.setLen(0)
  expanded.tree.setLen(0)
  expanded.logn = 0

proc expandPrivateKey*(expanded: var FalconExpandedSecret, decoded: FalconDecodedSecret) {.otterBench.} =
  let logn = decoded.logn
  var
    g00, g01, g11, gxx: seq[FalconFpr]
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

  g00 = copyFprRange(expanded.b00, 0, expanded.b00.len)
  gxx = copyFprRange(expanded.b01, 0, expanded.b01.len)
  polyMulselfadjFft(g00, logn)
  polyMulselfadjFft(gxx, logn)
  polyAdd(g00, gxx, logn)

  g01 = copyFprRange(expanded.b00, 0, expanded.b00.len)
  gxx = copyFprRange(expanded.b01, 0, expanded.b01.len)
  polyMuladjFft(g01, expanded.b10, logn)
  polyMuladjFft(gxx, expanded.b11, logn)
  polyAdd(g01, gxx, logn)

  g11 = copyFprRange(expanded.b10, 0, expanded.b10.len)
  gxx = copyFprRange(expanded.b11, 0, expanded.b11.len)
  polyMulselfadjFft(g11, logn)
  polyMulselfadjFft(gxx, logn)
  polyAdd(g11, gxx, logn)

  expanded.tree = newSeq[FalconFpr](ffLDLTreeSize(logn))
  ffLDLFft(expanded.tree, g00, g01, g11, logn)
  ffLDLBinaryNormalize(expanded.tree, 0, logn, logn)

  secureClearSeqData(g00)
  secureClearSeqData(g01)
  secureClearSeqData(g11)
  secureClearSeqData(gxx)

proc expandPrivateKey*(decoded: FalconDecodedSecret): FalconExpandedSecret =
  expandPrivateKey(result, decoded)

proc prepareSecretKey*(v: FalconVariant, sk: openArray[byte]): FalconExpandedSecret {.otterBench.} =
  var decoded: FalconDecodedSecret
  if not decodeSecretKey(decoded, sk, v):
    raise newException(ValueError, "invalid Falcon secret key")
  defer:
    secureClearSeqData(decoded.f)
    secureClearSeqData(decoded.g)
    secureClearSeqData(decoded.F)
    secureClearSeqData(decoded.G)
  expandPrivateKey(result, decoded)

proc gaussian0Sampler*(p: var FalconPrng): int =
  var
    lo = prngGetU64(p)
    hi = prngGetU8(p)
    v0 = uint32(lo) and 0x00FF_FFFF'u32
    v1 = uint32(lo shr 24) and 0x00FF_FFFF'u32
    v2 = uint32(lo shr 48) or (hi shl 16)
    i: int = 0
  result = 0
  while i < gaussianDist.len:
    var
      w0 = gaussianDist[i + 2]
      w1 = gaussianDist[i + 1]
      w2 = gaussianDist[i + 0]
      cc = (v0 - w0) shr 31
    cc = (v1 - w1 - cc) shr 31
    cc = (v2 - w2 - cc) shr 31
    result = result + cc.int
    i = i + 3

proc berExp(p: var FalconPrng, x, ccs: FalconFpr): int =
  var
    s = int(fprTrunc(fprMul(x, fprInvLog2)))
    r = fprSub(x, fprMul(fprOf(s.int64), fprLog2))
    sw = uint32(s)
    z: uint64
    i: int = 64
    w: uint32 = 0
  sw = sw xor ((sw xor 63'u32) and (0'u32 - ((63'u32 - sw) shr 31)))
  s = sw.int
  z = ((fprExpmP63(r, ccs) shl 1) - 1'u64) shr s
  while true:
    i = i - 8
    w = prngGetU8(p) - uint32((z shr i) and 0xFF'u64)
    if w != 0'u32 or i <= 0:
      break
  int(w shr 31)

proc sampler*(ctx: var FalconSamplerContext, mu, isigma: FalconFpr): int =
  var
    s = int(fprFloor(mu))
    r = fprSub(mu, fprOf(s.int64))
    dss = fprHalf(fprSqr(isigma))
    ccs = fprMul(isigma, ctx.sigmaMin)
  while true:
    var
      z0 = gaussian0Sampler(ctx.p)
      b = int(prngGetU8(ctx.p) and 1'u32)
      z = b + ((b shl 1) - 1) * z0
      x = fprMul(fprSqr(fprSub(fprOf(z.int64), r)), dss)
    x = fprSub(x, fprMul(fprOf((z0 * z0).int64), fprInv2SqrSigma0))
    if berExp(ctx.p, x, ccs) != 0:
      return s + z

proc ffSamplingFft(ctx: var FalconSamplerContext, tree, t0, t1: openArray[FalconFpr],
    logn: int): tuple[z0, z1: seq[FalconFpr]] =
  if logn == 2:
    var
      x0, x1, y0, y1, w0, w1, w2, w3, sigma: FalconFpr
      aRe, aIm, bRe, bIm, cRe, cIm: FalconFpr
      tree0 = copyFprRange(tree, 4, 4)
      tree1 = copyFprRange(tree, 8, 4)
    defer:
      secureClearSeqData(tree0)
      secureClearSeqData(tree1)
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
    return
  if logn == 1:
    var
      x0, x1, y0, y1, sigma: FalconFpr
      aRe, aIm, bRe, bIm, cRe, cIm: FalconFpr
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
    return

  let
    n = mkn(logn)
    hn = n shr 1
    childLen = ffLDLTreeSize(logn - 1)
  var
    tree0 = copyFprRange(tree, n, childLen)
    tree1 = copyFprRange(tree, n + childLen, childLen)
    split0 = newSeq[FalconFpr](hn)
    split1 = newSeq[FalconFpr](hn)
    tmp = @t1
    l10 = copyFprRange(tree, 0, n)
    merged: tuple[z0, z1: seq[FalconFpr]]
  defer:
    secureClearSeqData(tree0)
    secureClearSeqData(tree1)
    secureClearSeqData(split0)
    secureClearSeqData(split1)
    secureClearSeqData(tmp)
    secureClearSeqData(l10)
  polySplitFft(split0, split1, t1, logn)
  merged = ffSamplingFft(ctx, tree1, split0, split1, logn - 1)
  result.z1 = newSeq[FalconFpr](n)
  polyMergeFft(result.z1, merged.z0, merged.z1, logn)
  secureClearSeqData(merged.z0)
  secureClearSeqData(merged.z1)

  polySub(tmp, result.z1, logn)
  polyMulFft(tmp, l10, logn)
  polyAdd(tmp, t0, logn)

  polySplitFft(split0, split1, tmp, logn)
  merged = ffSamplingFft(ctx, tree0, split0, split1, logn - 1)
  result.z0 = newSeq[FalconFpr](n)
  polyMergeFft(result.z0, merged.z0, merged.z1, logn)
  secureClearSeqData(merged.z0)
  secureClearSeqData(merged.z1)

proc doSignTree(ctx: var FalconSamplerContext, s2: var seq[int16], expanded: FalconExpandedSecret,
    hm: openArray[uint16]): bool =
  let n = mkn(expanded.logn)
  var
    t0 = newSeq[FalconFpr](n)
    t1 = newSeq[FalconFpr](n)
    tx, ty: seq[FalconFpr]
    sampled: tuple[z0, z1: seq[FalconFpr]]
    ni = fprInverseOfQ
    sqn: uint32 = 0
    ng: uint32 = 0
    i: int = 0
    s2Tmp = newSeq[int16](n)
  defer:
    secureClearSeqData(t0)
    secureClearSeqData(t1)
    secureClearSeqData(tx)
    secureClearSeqData(ty)
    secureClearSeqData(sampled.z0)
    secureClearSeqData(sampled.z1)
    secureClearSeqData(s2Tmp)
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
    let z = hm[i].int32 - fprRint(t0[i]).int32
    sqn = sqn + uint32(z.int64 * z.int64)
    ng = ng or sqn
    s2Tmp[i] = int16(-fprRint(t1[i]))
    i = i + 1
  sqn = sqn or (0'u32 - (ng shr 31))
  if not isShortHalf(sqn, s2Tmp, expanded.logn):
    return false
  s2 = @s2Tmp
  true

proc signTreeRaw*(sig: var seq[int16], rng: var FalconShake256, expanded: FalconExpandedSecret,
    hm: openArray[uint16]) {.otterBench.} =
  var ctx: FalconSamplerContext
  while true:
    ctx.sigmaMin = fprSigmaMin[expanded.logn]
    prngInitFromShake(ctx.p, rng)
    if doSignTree(ctx, sig, expanded, hm):
      return

proc hashNonceMessageToPointCt(dst: var seq[uint16], nonce, msg: openArray[byte], logn: int) =
  var ctx: FalconShake256
  initFalconShake256(ctx, nonce, msg)
  hashToPointCt(ctx, dst, logn)

proc encodeDetachedSignature(v: FalconVariant, nonce: openArray[byte], s2: openArray[int16]): seq[byte] =
  let p = params(v)
  result = newSeq[byte](p.signatureBytes)
  result[0] = byte(0x30 + p.logn)
  copyBytes(result, 1, nonce)
  let used = compEncode(result.toOpenArray(1 + falconNonceLen, result.high), s2, p.logn)
  if used == 0:
    raise newException(ValueError, "Falcon signature encoding failed")
  result.setLen(1 + falconNonceLen + used)

proc falconSignPreparedDerand*(prepared: FalconExpandedSecret, msg, nonce, seed: openArray[byte],
    v: FalconVariant): seq[byte] {.otterBench.} =
  let p = params(v)
  if prepared.logn != p.logn:
    raise newException(ValueError, "prepared Falcon secret does not match variant")
  if nonce.len != falconNonceLen:
    raise newException(ValueError, "Falcon nonce must be 40 bytes")
  if seed.len != falconSignSeedBytes:
    raise newException(ValueError, "Falcon signing seed must be 48 bytes")
  var
    hm = newSeq[uint16](mkn(p.logn))
    sig: seq[int16]
    rng: FalconShake256
  defer:
    secureClearSeqData(hm)
    secureClearSeqData(sig)
  hashNonceMessageToPointCt(hm, nonce, msg, p.logn)
  initFalconShake256(rng, seed)
  signTreeRaw(sig, rng, prepared, hm)
  result = encodeDetachedSignature(v, nonce, sig)

proc falconSignPrepared*(prepared: FalconExpandedSecret, msg: openArray[byte], v: FalconVariant): seq[byte] {.otterBench.} =
  var
    nonce = falconRandomBytes(falconNonceLen)
    seed = falconRandomBytes(falconSignSeedBytes)
  defer:
    secureClearBytes(nonce)
    secureClearBytes(seed)
  result = falconSignPreparedDerand(prepared, msg, nonce, seed, v)

proc falconSignDerand*(v: FalconVariant, msg, sk, nonce, seed: openArray[byte]): seq[byte] {.otterBench.} =
  var prepared = prepareSecretKey(v, sk)
  defer:
    clearExpandedSecret(prepared)
  result = falconSignPreparedDerand(prepared, msg, nonce, seed, v)

proc falconSignPure*(v: FalconVariant, msg, sk: openArray[byte]): seq[byte] {.otterBench.} =
  var prepared = prepareSecretKey(v, sk)
  defer:
    clearExpandedSecret(prepared)
  result = falconSignPrepared(prepared, msg, v)
