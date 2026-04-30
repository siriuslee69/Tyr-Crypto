## ----------------------------------------------------------
## Falcon FFT <- FFT and polynomial helpers for the Nim port
## ----------------------------------------------------------

import ./fpr
import ./params
import ./util
when falconCompileHasSimd:
  import ./fpr_simd

template fpcAdd(dRe, dIm, aRe, aIm, bRe, bIm: untyped) =
  block:
    let fpctRe = fprAdd(aRe, bRe)
    let fpctIm = fprAdd(aIm, bIm)
    dRe = fpctRe
    dIm = fpctIm

template fpcSub(dRe, dIm, aRe, aIm, bRe, bIm: untyped) =
  block:
    let fpctRe = fprSub(aRe, bRe)
    let fpctIm = fprSub(aIm, bIm)
    dRe = fpctRe
    dIm = fpctIm

template fpcMul(dRe, dIm, aRe, aIm, bRe, bIm: untyped) =
  block:
    let
      fpctARe = aRe
      fpctAIm = aIm
      fpctBRe = bRe
      fpctBIm = bIm
      fpctDRe = fprSub(fprMul(fpctARe, fpctBRe), fprMul(fpctAIm, fpctBIm))
      fpctDIm = fprAdd(fprMul(fpctARe, fpctBIm), fprMul(fpctAIm, fpctBRe))
    dRe = fpctDRe
    dIm = fpctDIm

template fpcDiv(dRe, dIm, aRe, aIm, bRe, bIm: untyped) =
  block:
    let
      fpctARe = aRe
      fpctAIm = aIm
      fpctBRe0 = bRe
      fpctBIm0 = bIm
      fpctM = fprInv(fprAdd(fprSqr(fpctBRe0), fprSqr(fpctBIm0)))
      fpctBRe = fprMul(fpctBRe0, fpctM)
      fpctBIm = fprMul(fprNeg(fpctBIm0), fpctM)
      fpctDRe = fprSub(fprMul(fpctARe, fpctBRe), fprMul(fpctAIm, fpctBIm))
      fpctDIm = fprAdd(fprMul(fpctARe, fpctBIm), fprMul(fpctAIm, fpctBRe))
    dRe = fpctDRe
    dIm = fpctDIm

proc falconFft*(f: var openArray[FalconFpr], logn: int) =
  let
    n = mkn(logn)
    hn = n shr 1
  var
    t = hn
    u = 1
    m = 2
  while u < logn:
    let
      ht = t shr 1
      hm = m shr 1
    var
      i1 = 0
      j1 = 0
    while i1 < hm:
      let
        j2 = j1 + ht
        sRe = fprGmTab[((m + i1) shl 1) + 0]
        sIm = fprGmTab[((m + i1) shl 1) + 1]
      var j = j1
      while j < j2:
        var
          xRe = f[j]
          xIm = f[j + hn]
          yRe = f[j + ht]
          yIm = f[j + ht + hn]
        fpcMul(yRe, yIm, yRe, yIm, sRe, sIm)
        fpcAdd(f[j], f[j + hn], xRe, xIm, yRe, yIm)
        fpcSub(f[j + ht], f[j + ht + hn], xRe, xIm, yRe, yIm)
        inc j
      inc i1
      j1 += t
    t = ht
    inc u
    m = m shl 1

proc falconIfft*(f: var openArray[FalconFpr], logn: int) =
  let
    n = mkn(logn)
    hn = n shr 1
  var
    t = 1
    m = n
    u = logn
  while u > 1:
    let
      hm = m shr 1
      dt = t shl 1
    var
      i1 = 0
      j1 = 0
    while j1 < hn:
      let
        j2 = j1 + t
        sRe = fprGmTab[((hm + i1) shl 1) + 0]
        sIm = fprNeg(fprGmTab[((hm + i1) shl 1) + 1])
      var j = j1
      while j < j2:
        var
          xRe = f[j]
          xIm = f[j + hn]
          yRe = f[j + t]
          yIm = f[j + t + hn]
        fpcAdd(f[j], f[j + hn], xRe, xIm, yRe, yIm)
        fpcSub(xRe, xIm, xRe, xIm, yRe, yIm)
        fpcMul(f[j + t], f[j + t + hn], xRe, xIm, sRe, sIm)
        inc j
      inc i1
      j1 += dt
    t = dt
    m = hm
    dec u
  if logn > 0:
    let ni = fprP2Tab[logn]
    var i = 0
    while i < n:
      f[i] = fprMul(f[i], ni)
      inc i

proc polyAdd*(a: var openArray[FalconFpr], b: openArray[FalconFpr], logn: int) =
  let n = mkn(logn)
  var u = 0
  when falconCompileHasSimd:
    if useFalconSimd():
      while u + 2 <= n:
        let av = loadFalconSimd2(a, u)
        let bv = loadFalconSimd2(b, u)
        storeFalconSimd2(addFalconSimd2(av, bv), a, u)
        u = u + 2
  while u < n:
    a[u] = fprAdd(a[u], b[u])
    inc u

proc polySub*(a: var openArray[FalconFpr], b: openArray[FalconFpr], logn: int) =
  let n = mkn(logn)
  var u = 0
  when falconCompileHasSimd:
    if useFalconSimd():
      while u + 2 <= n:
        let av = loadFalconSimd2(a, u)
        let bv = loadFalconSimd2(b, u)
        storeFalconSimd2(subFalconSimd2(av, bv), a, u)
        u = u + 2
  while u < n:
    a[u] = fprSub(a[u], b[u])
    inc u

proc polyNeg*(a: var openArray[FalconFpr], logn: int) =
  let n = mkn(logn)
  var u = 0
  while u < n:
    a[u] = fprNeg(a[u])
    inc u

proc polyAdjFft*(a: var openArray[FalconFpr], logn: int) =
  let
    n = mkn(logn)
    start = n shr 1
  var u = start
  while u < n:
    a[u] = fprNeg(a[u])
    inc u

proc polyMulFft*(a: var openArray[FalconFpr], b: openArray[FalconFpr], logn: int) =
  let
    n = mkn(logn)
    hn = n shr 1
  var u = 0
  when falconCompileHasSimd:
    if useFalconSimd():
      while u + 2 <= hn:
        let
          aRe = loadFalconSimd2(a, u)
          aIm = loadFalconSimd2(a, u + hn)
          bRe = loadFalconSimd2(b, u)
          bIm = loadFalconSimd2(b, u + hn)
          dRe = subFalconSimd2(mulFalconSimd2(aRe, bRe), mulFalconSimd2(aIm, bIm))
          dIm = addFalconSimd2(mulFalconSimd2(aRe, bIm), mulFalconSimd2(aIm, bRe))
        storeFalconSimd2(dRe, a, u)
        storeFalconSimd2(dIm, a, u + hn)
        u = u + 2
  while u < hn:
    var
      aRe = a[u]
      aIm = a[u + hn]
      bRe = b[u]
      bIm = b[u + hn]
    fpcMul(a[u], a[u + hn], aRe, aIm, bRe, bIm)
    inc u

proc polyMuladjFft*(a: var openArray[FalconFpr], b: openArray[FalconFpr], logn: int) =
  let
    n = mkn(logn)
    hn = n shr 1
  var u = 0
  when falconCompileHasSimd:
    if useFalconSimd():
      while u + 2 <= hn:
        let
          aRe = loadFalconSimd2(a, u)
          aIm = loadFalconSimd2(a, u + hn)
          bRe = loadFalconSimd2(b, u)
          bIm = loadFalconSimd2(b, u + hn)
          dRe = addFalconSimd2(mulFalconSimd2(aRe, bRe), mulFalconSimd2(aIm, bIm))
          dIm = subFalconSimd2(mulFalconSimd2(aIm, bRe), mulFalconSimd2(aRe, bIm))
        storeFalconSimd2(dRe, a, u)
        storeFalconSimd2(dIm, a, u + hn)
        u = u + 2
  while u < hn:
    var
      aRe = a[u]
      aIm = a[u + hn]
      bRe = b[u]
      bIm = fprNeg(b[u + hn])
    fpcMul(a[u], a[u + hn], aRe, aIm, bRe, bIm)
    inc u

proc polyMulselfadjFft*(a: var openArray[FalconFpr], logn: int) =
  let
    n = mkn(logn)
    hn = n shr 1
  var u = 0
  when falconCompileHasSimd:
    if useFalconSimd():
      let zv = zeroFalconSimd2()
      while u + 2 <= hn:
        let
          aRe = loadFalconSimd2(a, u)
          aIm = loadFalconSimd2(a, u + hn)
          dRe = addFalconSimd2(mulFalconSimd2(aRe, aRe), mulFalconSimd2(aIm, aIm))
        storeFalconSimd2(dRe, a, u)
        storeFalconSimd2(zv, a, u + hn)
        u = u + 2
  while u < hn:
    let
      aRe = a[u]
      aIm = a[u + hn]
    a[u] = fprAdd(fprSqr(aRe), fprSqr(aIm))
    a[u + hn] = fprZero
    inc u

proc polyMulconst*(a: var openArray[FalconFpr], x: FalconFpr, logn: int) =
  let n = mkn(logn)
  var u = 0
  when falconCompileHasSimd:
    if useFalconSimd():
      let xv = set1FalconSimd2(x)
      while u + 2 <= n:
        let av = loadFalconSimd2(a, u)
        storeFalconSimd2(mulFalconSimd2(av, xv), a, u)
        u = u + 2
  while u < n:
    a[u] = fprMul(a[u], x)
    inc u

proc polyDivFft*(a: var openArray[FalconFpr], b: openArray[FalconFpr], logn: int) =
  let
    n = mkn(logn)
    hn = n shr 1
  var u = 0
  when falconCompileHasSimd:
    if useFalconSimd():
      while u + 2 <= hn:
        let
          aRe = loadFalconSimd2(a, u)
          aIm = loadFalconSimd2(a, u + hn)
          bRe = loadFalconSimd2(b, u)
          bIm = loadFalconSimd2(b, u + hn)
          inv = divFalconSimd2(set1FalconSimd2(fprOne),
            addFalconSimd2(mulFalconSimd2(bRe, bRe), mulFalconSimd2(bIm, bIm)))
          dRe = mulFalconSimd2(addFalconSimd2(mulFalconSimd2(aRe, bRe), mulFalconSimd2(aIm, bIm)), inv)
          dIm = mulFalconSimd2(subFalconSimd2(mulFalconSimd2(aIm, bRe), mulFalconSimd2(aRe, bIm)), inv)
        storeFalconSimd2(dRe, a, u)
        storeFalconSimd2(dIm, a, u + hn)
        u = u + 2
  while u < hn:
    var
      aRe = a[u]
      aIm = a[u + hn]
      bRe = b[u]
      bIm = b[u + hn]
    fpcDiv(a[u], a[u + hn], aRe, aIm, bRe, bIm)
    inc u

proc polyInvnorm2Fft*(d: var openArray[FalconFpr], a, b: openArray[FalconFpr], logn: int) =
  let
    n = mkn(logn)
    hn = n shr 1
  var u = 0
  when falconCompileHasSimd:
    if useFalconSimd():
      while u + 2 <= hn:
        let
          aRe = loadFalconSimd2(a, u)
          aIm = loadFalconSimd2(a, u + hn)
          bRe = loadFalconSimd2(b, u)
          bIm = loadFalconSimd2(b, u + hn)
          denom = addFalconSimd2(
            addFalconSimd2(mulFalconSimd2(aRe, aRe), mulFalconSimd2(aIm, aIm)),
            addFalconSimd2(mulFalconSimd2(bRe, bRe), mulFalconSimd2(bIm, bIm))
          )
          inv = divFalconSimd2(set1FalconSimd2(fprOne), denom)
        storeFalconSimd2(inv, d, u)
        u = u + 2
  while u < hn:
    let
      aRe = a[u]
      aIm = a[u + hn]
      bRe = b[u]
      bIm = b[u + hn]
    d[u] = fprInv(
      fprAdd(
        fprAdd(fprSqr(aRe), fprSqr(aIm)),
        fprAdd(fprSqr(bRe), fprSqr(bIm))
      )
    )
    inc u

proc polyAddMuladjFft*(d: var openArray[FalconFpr], F, G, f, g: openArray[FalconFpr], logn: int) =
  let
    n = mkn(logn)
    hn = n shr 1
  var u = 0
  when falconCompileHasSimd:
    if useFalconSimd():
      while u + 2 <= hn:
        let
          FRe = loadFalconSimd2(F, u)
          FIm = loadFalconSimd2(F, u + hn)
          GRe = loadFalconSimd2(G, u)
          GIm = loadFalconSimd2(G, u + hn)
          fRe = loadFalconSimd2(f, u)
          fIm = loadFalconSimd2(f, u + hn)
          gRe = loadFalconSimd2(g, u)
          gIm = loadFalconSimd2(g, u + hn)
          aRe = addFalconSimd2(mulFalconSimd2(FRe, fRe), mulFalconSimd2(FIm, fIm))
          aIm = subFalconSimd2(mulFalconSimd2(FIm, fRe), mulFalconSimd2(FRe, fIm))
          bRe = addFalconSimd2(mulFalconSimd2(GRe, gRe), mulFalconSimd2(GIm, gIm))
          bIm = subFalconSimd2(mulFalconSimd2(GIm, gRe), mulFalconSimd2(GRe, gIm))
        storeFalconSimd2(addFalconSimd2(aRe, bRe), d, u)
        storeFalconSimd2(addFalconSimd2(aIm, bIm), d, u + hn)
        u = u + 2
  while u < hn:
    let
      FRe = F[u]
      FIm = F[u + hn]
      GRe = G[u]
      GIm = G[u + hn]
      fRe = f[u]
      fIm = f[u + hn]
      gRe = g[u]
      gIm = g[u + hn]
    var
      aRe, aIm, bRe, bIm: FalconFpr
    fpcMul(aRe, aIm, FRe, FIm, fRe, fprNeg(fIm))
    fpcMul(bRe, bIm, GRe, GIm, gRe, fprNeg(gIm))
    d[u] = fprAdd(aRe, bRe)
    d[u + hn] = fprAdd(aIm, bIm)
    inc u

proc polyMulAutoadjFft*(a: var openArray[FalconFpr], b: openArray[FalconFpr], logn: int) =
  let
    n = mkn(logn)
    hn = n shr 1
  var u = 0
  when falconCompileHasSimd:
    if useFalconSimd():
      while u + 2 <= hn:
        let
          aRe = loadFalconSimd2(a, u)
          aIm = loadFalconSimd2(a, u + hn)
          bv = loadFalconSimd2(b, u)
        storeFalconSimd2(mulFalconSimd2(aRe, bv), a, u)
        storeFalconSimd2(mulFalconSimd2(aIm, bv), a, u + hn)
        u = u + 2
  while u < hn:
    a[u] = fprMul(a[u], b[u])
    a[u + hn] = fprMul(a[u + hn], b[u])
    inc u

proc polyDivAutoadjFft*(a: var openArray[FalconFpr], b: openArray[FalconFpr], logn: int) =
  let
    n = mkn(logn)
    hn = n shr 1
  var u = 0
  when falconCompileHasSimd:
    if useFalconSimd():
      while u + 2 <= hn:
        let
          aRe = loadFalconSimd2(a, u)
          aIm = loadFalconSimd2(a, u + hn)
          inv = divFalconSimd2(set1FalconSimd2(fprOne), loadFalconSimd2(b, u))
        storeFalconSimd2(mulFalconSimd2(aRe, inv), a, u)
        storeFalconSimd2(mulFalconSimd2(aIm, inv), a, u + hn)
        u = u + 2
  while u < hn:
    let ib = fprInv(b[u])
    a[u] = fprMul(a[u], ib)
    a[u + hn] = fprMul(a[u + hn], ib)
    inc u

proc polyLDLFft*(g00: openArray[FalconFpr], g01, g11: var openArray[FalconFpr], logn: int) =
  let
    n = mkn(logn)
    hn = n shr 1
  var u = 0
  when falconCompileHasSimd:
    if useFalconSimd():
      while u + 2 <= hn:
        let
          g00Re = loadFalconSimd2(g00, u)
          g00Im = loadFalconSimd2(g00, u + hn)
          g01Re = loadFalconSimd2(g01, u)
          g01Im = loadFalconSimd2(g01, u + hn)
          g11Re = loadFalconSimd2(g11, u)
          g11Im = loadFalconSimd2(g11, u + hn)
          inv = divFalconSimd2(set1FalconSimd2(fprOne),
            addFalconSimd2(mulFalconSimd2(g00Re, g00Re), mulFalconSimd2(g00Im, g00Im)))
          muRe = mulFalconSimd2(addFalconSimd2(mulFalconSimd2(g01Re, g00Re), mulFalconSimd2(g01Im, g00Im)), inv)
          muIm = mulFalconSimd2(subFalconSimd2(mulFalconSimd2(g01Im, g00Re), mulFalconSimd2(g01Re, g00Im)), inv)
          prodRe = addFalconSimd2(mulFalconSimd2(muRe, g01Re), mulFalconSimd2(muIm, g01Im))
          prodIm = subFalconSimd2(mulFalconSimd2(muIm, g01Re), mulFalconSimd2(muRe, g01Im))
        storeFalconSimd2(subFalconSimd2(g11Re, prodRe), g11, u)
        storeFalconSimd2(subFalconSimd2(g11Im, prodIm), g11, u + hn)
        storeFalconSimd2(muRe, g01, u)
        storeFalconSimd2(negFalconSimd2(muIm), g01, u + hn)
        u = u + 2
  while u < hn:
    let
      g00Re = g00[u]
      g00Im = g00[u + hn]
      g01Re0 = g01[u]
      g01Im0 = g01[u + hn]
      g11Re = g11[u]
      g11Im = g11[u + hn]
    var
      muRe, muIm: FalconFpr
      g01Re = g01Re0
      g01Im = g01Im0
    fpcDiv(muRe, muIm, g01Re, g01Im, g00Re, g00Im)
    fpcMul(g01Re, g01Im, muRe, muIm, g01Re, fprNeg(g01Im))
    fpcSub(g11[u], g11[u + hn], g11Re, g11Im, g01Re, g01Im)
    g01[u] = muRe
    g01[u + hn] = fprNeg(muIm)
    inc u

proc polyLDLmvFft*(d11, l10: var openArray[FalconFpr], g00, g01, g11: openArray[FalconFpr], logn: int) =
  let
    n = mkn(logn)
    hn = n shr 1
  var u = 0
  when falconCompileHasSimd:
    if useFalconSimd():
      while u + 2 <= hn:
        let
          g00Re = loadFalconSimd2(g00, u)
          g00Im = loadFalconSimd2(g00, u + hn)
          g01Re = loadFalconSimd2(g01, u)
          g01Im = loadFalconSimd2(g01, u + hn)
          g11Re = loadFalconSimd2(g11, u)
          g11Im = loadFalconSimd2(g11, u + hn)
          inv = divFalconSimd2(set1FalconSimd2(fprOne),
            addFalconSimd2(mulFalconSimd2(g00Re, g00Re), mulFalconSimd2(g00Im, g00Im)))
          muRe = mulFalconSimd2(addFalconSimd2(mulFalconSimd2(g01Re, g00Re), mulFalconSimd2(g01Im, g00Im)), inv)
          muIm = mulFalconSimd2(subFalconSimd2(mulFalconSimd2(g01Im, g00Re), mulFalconSimd2(g01Re, g00Im)), inv)
          prodRe = addFalconSimd2(mulFalconSimd2(muRe, g01Re), mulFalconSimd2(muIm, g01Im))
          prodIm = subFalconSimd2(mulFalconSimd2(muIm, g01Re), mulFalconSimd2(muRe, g01Im))
        storeFalconSimd2(subFalconSimd2(g11Re, prodRe), d11, u)
        storeFalconSimd2(subFalconSimd2(g11Im, prodIm), d11, u + hn)
        storeFalconSimd2(muRe, l10, u)
        storeFalconSimd2(negFalconSimd2(muIm), l10, u + hn)
        u = u + 2
  while u < hn:
    let
      g00Re = g00[u]
      g00Im = g00[u + hn]
      g01Re0 = g01[u]
      g01Im0 = g01[u + hn]
      g11Re = g11[u]
      g11Im = g11[u + hn]
    var
      muRe, muIm: FalconFpr
      g01Re = g01Re0
      g01Im = g01Im0
    fpcDiv(muRe, muIm, g01Re, g01Im, g00Re, g00Im)
    fpcMul(g01Re, g01Im, muRe, muIm, g01Re, fprNeg(g01Im))
    fpcSub(d11[u], d11[u + hn], g11Re, g11Im, g01Re, g01Im)
    l10[u] = muRe
    l10[u + hn] = fprNeg(muIm)
    inc u

proc polySplitFft*(f0, f1: var openArray[FalconFpr], f: openArray[FalconFpr], logn: int) =
  let
    n = mkn(logn)
    hn = n shr 1
    qn = hn shr 1
  f0[0] = f[0]
  f1[0] = f[hn]
  var u = 0
  while u < qn:
    let
      aRe = f[(u shl 1) + 0]
      aIm = f[(u shl 1) + 0 + hn]
      bRe = f[(u shl 1) + 1]
      bIm = f[(u shl 1) + 1 + hn]
    var
      tRe, tIm: FalconFpr
    fpcAdd(tRe, tIm, aRe, aIm, bRe, bIm)
    f0[u] = fprHalf(tRe)
    f0[u + qn] = fprHalf(tIm)
    fpcSub(tRe, tIm, aRe, aIm, bRe, bIm)
    fpcMul(
      tRe, tIm, tRe, tIm,
      fprGmTab[((u + hn) shl 1) + 0],
      fprNeg(fprGmTab[((u + hn) shl 1) + 1])
    )
    f1[u] = fprHalf(tRe)
    f1[u + qn] = fprHalf(tIm)
    inc u

proc polyMergeFft*(f: var openArray[FalconFpr], f0, f1: openArray[FalconFpr], logn: int) =
  let
    n = mkn(logn)
    hn = n shr 1
    qn = hn shr 1
  f[0] = f0[0]
  f[hn] = f1[0]
  var u = 0
  while u < qn:
    let
      aRe = f0[u]
      aIm = f0[u + qn]
    var
      bRe, bIm, tRe, tIm: FalconFpr
    fpcMul(
      bRe, bIm, f1[u], f1[u + qn],
      fprGmTab[((u + hn) shl 1) + 0],
      fprGmTab[((u + hn) shl 1) + 1]
    )
    fpcAdd(tRe, tIm, aRe, aIm, bRe, bIm)
    f[(u shl 1) + 0] = tRe
    f[(u shl 1) + 0 + hn] = tIm
    fpcSub(tRe, tIm, aRe, aIm, bRe, bIm)
    f[(u shl 1) + 1] = tRe
    f[(u shl 1) + 1 + hn] = tIm
    inc u
