## ---------------------------------------------------------------------
## Dilithium Poly <- polynomial, vector, sampling, and packing routines
## ---------------------------------------------------------------------

import ./params
import ./arith
import ../sha3/sha3
import ../../helpers/otter_support
import std/[typetraits, volatile]

when defined(sse2) or defined(avx2):
  import simd_nexus/simd/base_operations
when defined(avx2):
  import nimsimd/avx as navx
  import nimsimd/avx2 as navx2

type
  DilithiumPoly* = object
    coeffs*: array[dilithiumN, int32]

  DilithiumPolyVecL* = object
    used*: int
    vec*: array[dilithiumMaxL, DilithiumPoly]

  DilithiumPolyVecK* = object
    used*: int
    vec*: array[dilithiumMaxK, DilithiumPoly]

  DilithiumMatrix* = object
    rows*: int
    cols*: int
    mat*: array[dilithiumMaxK, DilithiumPolyVecL]

  DilithiumPublicKeyState* = object
    rho*: array[dilithiumSeedBytes, byte]
    t1*: DilithiumPolyVecK

  DilithiumSecretKeyState* = object
    rho*: array[dilithiumSeedBytes, byte]
    tr*: array[dilithiumTrBytes, byte]
    key*: array[dilithiumSeedBytes, byte]
    t0*: DilithiumPolyVecK
    s1*: DilithiumPolyVecL
    s2*: DilithiumPolyVecK

  DilithiumSignatureState* = object
    c*: array[dilithiumMaxCtildeBytes, byte]
    cLen*: int
    z*: DilithiumPolyVecL
    h*: DilithiumPolyVecK
    ok*: bool

const
  dilithiumEtaCtBlocksEta2 = 2
  dilithiumEtaCtBlocksEta4 = 3
  dilithiumEtaCtBytesEta2 = dilithiumEtaCtBlocksEta2 * shake256RateBytes
  dilithiumEtaCtBytesEta4 = dilithiumEtaCtBlocksEta4 * shake256RateBytes

when defined(sse2) or defined(avx2):
  const
    dilithiumUniform4xInitBytes = ((768 + shake128RateBytes - 1) div shake128RateBytes) *
      shake128RateBytes
    dilithiumUniformGamma14xMaxBytes = ((640 + shake256RateBytes - 1) div shake256RateBytes) *
      shake256RateBytes
when defined(avx2):
  const
    dilithiumMontgomeryQInv = 58728449'i32

{.push boundChecks: off, overflowChecks: off.}
when defined(sse2):
  proc polyAddSimdSse(c: var DilithiumPoly, a, b: DilithiumPoly) {.inline.} =
    var
      i: int = 0
      va: i32x4
      vb: i32x4
      vr: i32x4
    i = 0
    while i + 4 <= dilithiumN:
      va = i32x4(mm_loadu_si128(cast[pointer](unsafeAddr a.coeffs[i])))
      vb = i32x4(mm_loadu_si128(cast[pointer](unsafeAddr b.coeffs[i])))
      vr = va + vb
      mm_storeu_si128(cast[pointer](unsafeAddr c.coeffs[i]), M128i(vr))
      i = i + 4
    while i < dilithiumN:
      c.coeffs[i] = a.coeffs[i] + b.coeffs[i]
      i = i + 1

  proc polySubSimdSse(c: var DilithiumPoly, a, b: DilithiumPoly) {.inline.} =
    var
      i: int = 0
      va: i32x4
      vb: i32x4
      vr: i32x4
    i = 0
    while i + 4 <= dilithiumN:
      va = i32x4(mm_loadu_si128(cast[pointer](unsafeAddr a.coeffs[i])))
      vb = i32x4(mm_loadu_si128(cast[pointer](unsafeAddr b.coeffs[i])))
      vr = va - vb
      mm_storeu_si128(cast[pointer](unsafeAddr c.coeffs[i]), M128i(vr))
      i = i + 4
    while i < dilithiumN:
      c.coeffs[i] = a.coeffs[i] - b.coeffs[i]
      i = i + 1

  proc polyShiftLSimdSse(a: var DilithiumPoly) {.inline.} =
    var
      i: int = 0
      va: i32x4
    i = 0
    while i + 4 <= dilithiumN:
      va = i32x4(mm_loadu_si128(cast[pointer](unsafeAddr a.coeffs[i])))
      va = va shl dilithiumD
      mm_storeu_si128(cast[pointer](unsafeAddr a.coeffs[i]), M128i(va))
      i = i + 4
    while i < dilithiumN:
      a.coeffs[i] = a.coeffs[i] shl dilithiumD
      i = i + 1

when defined(avx2):
  proc montgomeryReduceProdVec8Avx2(a, b: navx.M256i): navx.M256i {.inline.} =
    var
      oddA: navx.M256i
      oddB: navx.M256i
      prodEven: navx.M256i
      prodOdd: navx.M256i
      tEven: navx.M256i
      tOdd: navx.M256i
      diffEven: navx.M256i
      diffOdd: navx.M256i
      evenHigh: navx.M256i
      oddHigh: navx.M256i
      qInvVec: navx.M256i = navx.mm256_set1_epi32(dilithiumMontgomeryQInv)
      qVec: navx.M256i = navx.mm256_set1_epi32(dilithiumQ)
    prodEven = navx2.mm256_mul_epi32(a, b)
    oddA = navx2.mm256_srli_epi64(a, 32)
    oddB = navx2.mm256_srli_epi64(b, 32)
    prodOdd = navx2.mm256_mul_epi32(oddA, oddB)
    tEven = navx2.mm256_mul_epi32(prodEven, qInvVec)
    tOdd = navx2.mm256_mul_epi32(prodOdd, qInvVec)
    diffEven = navx2.mm256_sub_epi64(prodEven, navx2.mm256_mul_epi32(tEven, qVec))
    diffOdd = navx2.mm256_sub_epi64(prodOdd, navx2.mm256_mul_epi32(tOdd, qVec))
    evenHigh = navx2.mm256_srli_epi64(diffEven, 32)
    oddHigh = navx2.mm256_srli_epi64(diffOdd, 32)
    oddHigh = navx2.mm256_slli_si256(oddHigh, 4)
    result = navx2.mm256_or_si256(evenHigh, oddHigh)

  proc polyPointwiseMontgomerySimdAvx2(c: var DilithiumPoly, a, b: DilithiumPoly) {.inline, otterBench.} =
    var
      i: int = 0
      va: navx.M256i
      vb: navx.M256i
    i = 0
    while i + 8 <= dilithiumN:
      va = navx2.mm256_loadu_si256(cast[pointer](unsafeAddr a.coeffs[i]))
      vb = navx2.mm256_loadu_si256(cast[pointer](unsafeAddr b.coeffs[i]))
      navx2.mm256_storeu_si256(cast[pointer](unsafeAddr c.coeffs[i]),
        montgomeryReduceProdVec8Avx2(va, vb))
      i = i + 8
    while i < dilithiumN:
      c.coeffs[i] = montgomeryReduce(int64(a.coeffs[i]) * int64(b.coeffs[i]))
      i = i + 1

  proc polyveclPointwiseAccMontgomeryUsed4SimdAvx2(w: var DilithiumPoly, u,
      v: DilithiumPolyVecL) {.inline, otterBench.} =
    var
      i: int = 0
      acc: navx.M256i
    i = 0
    while i + 8 <= dilithiumN:
      acc = montgomeryReduceProdVec8Avx2(
        navx2.mm256_loadu_si256(cast[pointer](unsafeAddr u.vec[0].coeffs[i])),
        navx2.mm256_loadu_si256(cast[pointer](unsafeAddr v.vec[0].coeffs[i]))
      )
      acc = navx2.mm256_add_epi32(acc, montgomeryReduceProdVec8Avx2(
        navx2.mm256_loadu_si256(cast[pointer](unsafeAddr u.vec[1].coeffs[i])),
        navx2.mm256_loadu_si256(cast[pointer](unsafeAddr v.vec[1].coeffs[i]))
      ))
      acc = navx2.mm256_add_epi32(acc, montgomeryReduceProdVec8Avx2(
        navx2.mm256_loadu_si256(cast[pointer](unsafeAddr u.vec[2].coeffs[i])),
        navx2.mm256_loadu_si256(cast[pointer](unsafeAddr v.vec[2].coeffs[i]))
      ))
      acc = navx2.mm256_add_epi32(acc, montgomeryReduceProdVec8Avx2(
        navx2.mm256_loadu_si256(cast[pointer](unsafeAddr u.vec[3].coeffs[i])),
        navx2.mm256_loadu_si256(cast[pointer](unsafeAddr v.vec[3].coeffs[i]))
      ))
      navx2.mm256_storeu_si256(cast[pointer](unsafeAddr w.coeffs[i]), acc)
      i = i + 8
    while i < dilithiumN:
      w.coeffs[i] = montgomeryReduce(int64(u.vec[0].coeffs[i]) * int64(v.vec[0].coeffs[i]))
      w.coeffs[i] = w.coeffs[i] +
        montgomeryReduce(int64(u.vec[1].coeffs[i]) * int64(v.vec[1].coeffs[i]))
      w.coeffs[i] = w.coeffs[i] +
        montgomeryReduce(int64(u.vec[2].coeffs[i]) * int64(v.vec[2].coeffs[i]))
      w.coeffs[i] = w.coeffs[i] +
        montgomeryReduce(int64(u.vec[3].coeffs[i]) * int64(v.vec[3].coeffs[i]))
      i = i + 1

  proc polyveclPointwiseAccMontgomeryUsed5SimdAvx2(w: var DilithiumPoly, u,
      v: DilithiumPolyVecL) {.inline, otterBench.} =
    var
      i: int = 0
      acc: navx.M256i
    i = 0
    while i + 8 <= dilithiumN:
      acc = montgomeryReduceProdVec8Avx2(
        navx2.mm256_loadu_si256(cast[pointer](unsafeAddr u.vec[0].coeffs[i])),
        navx2.mm256_loadu_si256(cast[pointer](unsafeAddr v.vec[0].coeffs[i]))
      )
      acc = navx2.mm256_add_epi32(acc, montgomeryReduceProdVec8Avx2(
        navx2.mm256_loadu_si256(cast[pointer](unsafeAddr u.vec[1].coeffs[i])),
        navx2.mm256_loadu_si256(cast[pointer](unsafeAddr v.vec[1].coeffs[i]))
      ))
      acc = navx2.mm256_add_epi32(acc, montgomeryReduceProdVec8Avx2(
        navx2.mm256_loadu_si256(cast[pointer](unsafeAddr u.vec[2].coeffs[i])),
        navx2.mm256_loadu_si256(cast[pointer](unsafeAddr v.vec[2].coeffs[i]))
      ))
      acc = navx2.mm256_add_epi32(acc, montgomeryReduceProdVec8Avx2(
        navx2.mm256_loadu_si256(cast[pointer](unsafeAddr u.vec[3].coeffs[i])),
        navx2.mm256_loadu_si256(cast[pointer](unsafeAddr v.vec[3].coeffs[i]))
      ))
      acc = navx2.mm256_add_epi32(acc, montgomeryReduceProdVec8Avx2(
        navx2.mm256_loadu_si256(cast[pointer](unsafeAddr u.vec[4].coeffs[i])),
        navx2.mm256_loadu_si256(cast[pointer](unsafeAddr v.vec[4].coeffs[i]))
      ))
      navx2.mm256_storeu_si256(cast[pointer](unsafeAddr w.coeffs[i]), acc)
      i = i + 8
    while i < dilithiumN:
      w.coeffs[i] = montgomeryReduce(int64(u.vec[0].coeffs[i]) * int64(v.vec[0].coeffs[i]))
      w.coeffs[i] = w.coeffs[i] +
        montgomeryReduce(int64(u.vec[1].coeffs[i]) * int64(v.vec[1].coeffs[i]))
      w.coeffs[i] = w.coeffs[i] +
        montgomeryReduce(int64(u.vec[2].coeffs[i]) * int64(v.vec[2].coeffs[i]))
      w.coeffs[i] = w.coeffs[i] +
        montgomeryReduce(int64(u.vec[3].coeffs[i]) * int64(v.vec[3].coeffs[i]))
      w.coeffs[i] = w.coeffs[i] +
        montgomeryReduce(int64(u.vec[4].coeffs[i]) * int64(v.vec[4].coeffs[i]))
      i = i + 1

  proc polyveclPointwiseAccMontgomeryUsed7SimdAvx2(w: var DilithiumPoly, u,
      v: DilithiumPolyVecL) {.inline, otterBench.} =
    var
      i: int = 0
      acc: navx.M256i
    i = 0
    while i + 8 <= dilithiumN:
      acc = montgomeryReduceProdVec8Avx2(
        navx2.mm256_loadu_si256(cast[pointer](unsafeAddr u.vec[0].coeffs[i])),
        navx2.mm256_loadu_si256(cast[pointer](unsafeAddr v.vec[0].coeffs[i]))
      )
      acc = navx2.mm256_add_epi32(acc, montgomeryReduceProdVec8Avx2(
        navx2.mm256_loadu_si256(cast[pointer](unsafeAddr u.vec[1].coeffs[i])),
        navx2.mm256_loadu_si256(cast[pointer](unsafeAddr v.vec[1].coeffs[i]))
      ))
      acc = navx2.mm256_add_epi32(acc, montgomeryReduceProdVec8Avx2(
        navx2.mm256_loadu_si256(cast[pointer](unsafeAddr u.vec[2].coeffs[i])),
        navx2.mm256_loadu_si256(cast[pointer](unsafeAddr v.vec[2].coeffs[i]))
      ))
      acc = navx2.mm256_add_epi32(acc, montgomeryReduceProdVec8Avx2(
        navx2.mm256_loadu_si256(cast[pointer](unsafeAddr u.vec[3].coeffs[i])),
        navx2.mm256_loadu_si256(cast[pointer](unsafeAddr v.vec[3].coeffs[i]))
      ))
      acc = navx2.mm256_add_epi32(acc, montgomeryReduceProdVec8Avx2(
        navx2.mm256_loadu_si256(cast[pointer](unsafeAddr u.vec[4].coeffs[i])),
        navx2.mm256_loadu_si256(cast[pointer](unsafeAddr v.vec[4].coeffs[i]))
      ))
      acc = navx2.mm256_add_epi32(acc, montgomeryReduceProdVec8Avx2(
        navx2.mm256_loadu_si256(cast[pointer](unsafeAddr u.vec[5].coeffs[i])),
        navx2.mm256_loadu_si256(cast[pointer](unsafeAddr v.vec[5].coeffs[i]))
      ))
      acc = navx2.mm256_add_epi32(acc, montgomeryReduceProdVec8Avx2(
        navx2.mm256_loadu_si256(cast[pointer](unsafeAddr u.vec[6].coeffs[i])),
        navx2.mm256_loadu_si256(cast[pointer](unsafeAddr v.vec[6].coeffs[i]))
      ))
      navx2.mm256_storeu_si256(cast[pointer](unsafeAddr w.coeffs[i]), acc)
      i = i + 8
    while i < dilithiumN:
      w.coeffs[i] = montgomeryReduce(int64(u.vec[0].coeffs[i]) * int64(v.vec[0].coeffs[i]))
      w.coeffs[i] = w.coeffs[i] +
        montgomeryReduce(int64(u.vec[1].coeffs[i]) * int64(v.vec[1].coeffs[i]))
      w.coeffs[i] = w.coeffs[i] +
        montgomeryReduce(int64(u.vec[2].coeffs[i]) * int64(v.vec[2].coeffs[i]))
      w.coeffs[i] = w.coeffs[i] +
        montgomeryReduce(int64(u.vec[3].coeffs[i]) * int64(v.vec[3].coeffs[i]))
      w.coeffs[i] = w.coeffs[i] +
        montgomeryReduce(int64(u.vec[4].coeffs[i]) * int64(v.vec[4].coeffs[i]))
      w.coeffs[i] = w.coeffs[i] +
        montgomeryReduce(int64(u.vec[5].coeffs[i]) * int64(v.vec[5].coeffs[i]))
      w.coeffs[i] = w.coeffs[i] +
        montgomeryReduce(int64(u.vec[6].coeffs[i]) * int64(v.vec[6].coeffs[i]))
      i = i + 1

  proc polyveclPointwiseAccMontgomerySimdAvx2(w: var DilithiumPoly, u,
      v: DilithiumPolyVecL) {.inline, otterBench.} =
    if u.used == 4:
      polyveclPointwiseAccMontgomeryUsed4SimdAvx2(w, u, v)
      return
    if u.used == 5:
      polyveclPointwiseAccMontgomeryUsed5SimdAvx2(w, u, v)
      return
    if u.used == 7:
      polyveclPointwiseAccMontgomeryUsed7SimdAvx2(w, u, v)
      return
    var
      i: int = 0
      j: int = 0
      acc: navx.M256i
      mul: navx.M256i
    i = 0
    while i + 8 <= dilithiumN:
      acc = montgomeryReduceProdVec8Avx2(
        navx2.mm256_loadu_si256(cast[pointer](unsafeAddr u.vec[0].coeffs[i])),
        navx2.mm256_loadu_si256(cast[pointer](unsafeAddr v.vec[0].coeffs[i]))
      )
      j = 1
      while j < u.used:
        mul = montgomeryReduceProdVec8Avx2(
          navx2.mm256_loadu_si256(cast[pointer](unsafeAddr u.vec[j].coeffs[i])),
          navx2.mm256_loadu_si256(cast[pointer](unsafeAddr v.vec[j].coeffs[i]))
        )
        acc = navx2.mm256_add_epi32(acc, mul)
        j = j + 1
      navx2.mm256_storeu_si256(cast[pointer](unsafeAddr w.coeffs[i]), acc)
      i = i + 8
    while i < dilithiumN:
      w.coeffs[i] = montgomeryReduce(int64(u.vec[0].coeffs[i]) * int64(v.vec[0].coeffs[i]))
      j = 1
      while j < u.used:
        w.coeffs[i] = w.coeffs[i] +
          montgomeryReduce(int64(u.vec[j].coeffs[i]) * int64(v.vec[j].coeffs[i]))
        j = j + 1
      i = i + 1

  proc polyChkNormSimdAvx2(a: DilithiumPoly, B: int32): bool {.inline, otterBench.} =
    var
      i: int = 0
      coeffVec: navx.M256i
      signVec: navx.M256i
      absVec: navx.M256i
      cmpVec: navx.M256i
      boundVec: navx.M256i = navx.mm256_set1_epi32(B - 1)
    if B > (dilithiumQ - 1) div 8:
      return true
    i = 0
    while i + 8 <= dilithiumN:
      coeffVec = navx2.mm256_loadu_si256(cast[pointer](unsafeAddr a.coeffs[i]))
      signVec = navx2.mm256_srai_epi32(coeffVec, 31)
      absVec = navx2.mm256_add_epi32(coeffVec, coeffVec)
      absVec = navx2.mm256_and_si256(signVec, absVec)
      absVec = navx2.mm256_sub_epi32(coeffVec, absVec)
      cmpVec = navx2.mm256_cmpgt_epi32(absVec, boundVec)
      if navx2.mm256_testz_si256(cmpVec, cmpVec) == 0:
        return true
      i = i + 8
    while i < dilithiumN:
      var t: int32 = a.coeffs[i] shr 31
      t = a.coeffs[i] - (t and (2 * a.coeffs[i]))
      if t >= B:
        return true
      i = i + 1
    result = false

  proc polyAddSimdAvx2(c: var DilithiumPoly, a, b: DilithiumPoly) {.inline.} =
    var
      i: int = 0
      va: i32x8
      vb: i32x8
      vr: i32x8
    i = 0
    while i + 8 <= dilithiumN:
      va = i32x8(mm256_loadu_si256(cast[pointer](unsafeAddr a.coeffs[i])))
      vb = i32x8(mm256_loadu_si256(cast[pointer](unsafeAddr b.coeffs[i])))
      vr = va + vb
      mm256_storeu_si256(cast[pointer](unsafeAddr c.coeffs[i]), M256i(vr))
      i = i + 8
    while i < dilithiumN:
      c.coeffs[i] = a.coeffs[i] + b.coeffs[i]
      i = i + 1

  proc polySubSimdAvx2(c: var DilithiumPoly, a, b: DilithiumPoly) {.inline.} =
    var
      i: int = 0
      va: i32x8
      vb: i32x8
      vr: i32x8
    i = 0
    while i + 8 <= dilithiumN:
      va = i32x8(mm256_loadu_si256(cast[pointer](unsafeAddr a.coeffs[i])))
      vb = i32x8(mm256_loadu_si256(cast[pointer](unsafeAddr b.coeffs[i])))
      vr = va - vb
      mm256_storeu_si256(cast[pointer](unsafeAddr c.coeffs[i]), M256i(vr))
      i = i + 8
    while i < dilithiumN:
      c.coeffs[i] = a.coeffs[i] - b.coeffs[i]
      i = i + 1

  proc polyShiftLSimdAvx2(a: var DilithiumPoly) {.inline.} =
    var
      i: int = 0
      va: i32x8
    i = 0
    while i + 8 <= dilithiumN:
      va = i32x8(mm256_loadu_si256(cast[pointer](unsafeAddr a.coeffs[i])))
      va = va shl dilithiumD
      mm256_storeu_si256(cast[pointer](unsafeAddr a.coeffs[i]), M256i(va))
      i = i + 8
    while i < dilithiumN:
      a.coeffs[i] = a.coeffs[i] shl dilithiumD
      i = i + 1

{.pop.}
proc initPolyVecL*(p: DilithiumParams): DilithiumPolyVecL {.raises: [].} =
  result.used = p.l

proc initPolyVecK*(p: DilithiumParams): DilithiumPolyVecK {.raises: [].} =
  result.used = p.k

proc initMatrix*(p: DilithiumParams): DilithiumMatrix {.inline, raises: [].} =
  var
    i: int = 0
  result.rows = p.k
  result.cols = p.l
  i = 0
  {.push boundChecks: off, overflowChecks: off.}
  while i < p.k:
    result.mat[i] = initPolyVecL(p)
    i = i + 1
  {.pop.}

proc clearBytes*(A: var seq[byte]) =
  var
    i: int = 0
  i = 0
  while i < A.len:
    A[i] = 0'u8
    i = i + 1

proc clearPlainData*[T](S: var T) {.raises: [].} =
  when supportsCopyMem(T):
    zeroMem(addr S, sizeof(T))
  else:
    {.error: "clearPlainData requires supportsCopyMem(T)".}

proc clearSensitiveBytes*(A: var seq[byte]) {.raises: [].} =
  var
    i: int = 0
  while i < A.len:
    volatileStore(addr A[i], 0'u8)
    i = i + 1

proc clearSensitivePlainData*[T](S: var T) {.raises: [].} =
  when supportsCopyMem(T):
    var
      p: ptr UncheckedArray[byte] = cast[ptr UncheckedArray[byte]](addr S)
      i: int = 0
    while i < sizeof(T):
      volatileStore(addr p[i], 0'u8)
      i = i + 1
  else:
    {.error: "clearSensitivePlainData requires supportsCopyMem(T)".}

proc sliceBytes*(A: openArray[byte], o, l: int): seq[byte] =
  var
    i: int = 0
  result = newSeq[byte](l)
  i = 0
  while i < l:
    result[i] = A[o + i]
    i = i + 1

{.push boundChecks: off, overflowChecks: off.}
proc polyReduce*(a: var DilithiumPoly) {.inline, raises: [].} =
  var
    i: int = 0
  i = 0
  while i < dilithiumN:
    a.coeffs[i] = reduce32(a.coeffs[i])
    i = i + 1

proc polyCaddq*(a: var DilithiumPoly) {.inline, raises: [].} =
  var
    i: int = 0
  i = 0
  while i < dilithiumN:
    a.coeffs[i] = caddq(a.coeffs[i])
    i = i + 1

proc polyAdd*(c: var DilithiumPoly, a, b: DilithiumPoly) {.inline, raises: [].} =
  when defined(avx2):
    polyAddSimdAvx2(c, a, b)
  elif defined(sse2):
    polyAddSimdSse(c, a, b)
  else:
    var
      i: int = 0
    i = 0
    while i < dilithiumN:
      c.coeffs[i] = a.coeffs[i] + b.coeffs[i]
      i = i + 1

proc polySub*(c: var DilithiumPoly, a, b: DilithiumPoly) {.inline, raises: [].} =
  when defined(avx2):
    polySubSimdAvx2(c, a, b)
  elif defined(sse2):
    polySubSimdSse(c, a, b)
  else:
    var
      i: int = 0
    i = 0
    while i < dilithiumN:
      c.coeffs[i] = a.coeffs[i] - b.coeffs[i]
      i = i + 1

proc polyShiftL*(a: var DilithiumPoly) {.inline, raises: [].} =
  when defined(avx2):
    polyShiftLSimdAvx2(a)
  elif defined(sse2):
    polyShiftLSimdSse(a)
  else:
    var
      i: int = 0
    i = 0
    while i < dilithiumN:
      a.coeffs[i] = a.coeffs[i] shl dilithiumD
      i = i + 1

proc polyNtt*(a: var DilithiumPoly) {.inline, otterBench, raises: [].} =
  ntt(a.coeffs)

proc polyInvnttTomont*(a: var DilithiumPoly) {.inline, otterBench, raises: [].} =
  invnttTomont(a.coeffs)

proc polyPointwiseMontgomery*(c: var DilithiumPoly, a, b: DilithiumPoly) {.inline, otterBench, raises: [].} =
  when defined(avx2):
    polyPointwiseMontgomerySimdAvx2(c, a, b)
  else:
    var
      i: int = 0
    i = 0
    while i < dilithiumN:
      c.coeffs[i] = montgomeryReduce(int64(a.coeffs[i]) * int64(b.coeffs[i]))
      i = i + 1

proc polyPower2Round*(a1, a0: var DilithiumPoly, a: DilithiumPoly) {.raises: [].} =
  var
    i: int = 0
    t: tuple[a1, a0: int32]
  i = 0
  while i < dilithiumN:
    t = power2round(a.coeffs[i])
    a1.coeffs[i] = t.a1
    a0.coeffs[i] = t.a0
    i = i + 1

proc polyDecompose*(p: DilithiumParams, a1, a0: var DilithiumPoly, a: DilithiumPoly) {.raises: [].} =
  var
    i: int = 0
    t: tuple[a1, a0: int32]
  if p.gamma2 == (dilithiumQ - 1) div 32:
    i = 0
    while i < dilithiumN:
      t = decomposeGamma32(a.coeffs[i])
      a1.coeffs[i] = t.a1
      a0.coeffs[i] = t.a0
      i = i + 1
    return
  i = 0
  while i < dilithiumN:
    t = decomposeGamma88(a.coeffs[i])
    a1.coeffs[i] = t.a1
    a0.coeffs[i] = t.a0
    i = i + 1

proc polyMakeHint*(p: DilithiumParams, h: var DilithiumPoly, a0, a1: DilithiumPoly): uint32 {.raises: [].} =
  var
    i: int = 0
  i = 0
  while i < dilithiumN:
    # makeHint returns 0 or 1, so this int32 cast is exact.
    h.coeffs[i] = cast[int32](makeHint(p, a0.coeffs[i], a1.coeffs[i]))
    result = result + uint32(h.coeffs[i])
    i = i + 1

proc polyUseHint*(p: DilithiumParams, b: var DilithiumPoly, a, h: DilithiumPoly) {.raises: [].} =
  var
    i: int = 0
  if p.gamma2 == (dilithiumQ - 1) div 32:
    i = 0
    while i < dilithiumN:
      b.coeffs[i] = useHintGamma32(a.coeffs[i], uint32(h.coeffs[i]))
      i = i + 1
    return
  i = 0
  while i < dilithiumN:
    b.coeffs[i] = useHintGamma88(a.coeffs[i], uint32(h.coeffs[i]))
    i = i + 1

proc polyChkNorm*(a: DilithiumPoly, B: int32): bool {.otterBench, raises: [].} =
  when defined(avx2):
    result = polyChkNormSimdAvx2(a, B)
  else:
    var
      i: int = 0
      t: int32 = 0
    if B > (dilithiumQ - 1) div 8:
      return true
    i = 0
    while i < dilithiumN:
      t = a.coeffs[i] shr 31
      t = a.coeffs[i] - (t and (2 * a.coeffs[i]))
      if t >= B:
        return true
      i = i + 1
    result = false

proc rejUniform(dst: var array[dilithiumN, int32], offset, need: int,
    buf: openArray[byte]): int {.inline, raises: [].} =
  var
    ctr: int = 0
    pos: int = 0
    t: uint32 = 0
  ctr = 0
  pos = 0
  while ctr < need and pos + 3 <= buf.len:
    t = uint32(buf[pos])
    pos = pos + 1
    t = t or (uint32(buf[pos]) shl 8)
    pos = pos + 1
    t = t or (uint32(buf[pos]) shl 16)
    pos = pos + 1
    t = t and 0x7fffff'u32
    if t < uint32(dilithiumQ):
      # Accepted coefficients are < q, so this int32 cast is exact.
      dst[offset + ctr] = cast[int32](t)
      ctr = ctr + 1
  result = ctr

proc rejEta(p: DilithiumParams, dst: var array[dilithiumN, int32], offset, need: int,
    buf: openArray[byte]): int {.inline, raises: [].} =
  var
    ctr: int = 0
    pos: int = 0
    t0: uint32 = 0
    t1: uint32 = 0
  ctr = 0
  pos = 0
  while ctr < need and pos < buf.len:
    t0 = uint32(buf[pos] and 0x0f'u8)
    t1 = uint32(buf[pos] shr 4)
    pos = pos + 1
    if p.eta == 2:
      if t0 < 15'u32:
        t0 = t0 - ((205'u32 * t0) shr 10) * 5
        dst[offset + ctr] = 2 - cast[int32](t0)
        ctr = ctr + 1
      if t1 < 15'u32 and ctr < need:
        t1 = t1 - ((205'u32 * t1) shr 10) * 5
        dst[offset + ctr] = 2 - cast[int32](t1)
        ctr = ctr + 1
    else:
      if t0 < 9'u32:
        dst[offset + ctr] = 4 - cast[int32](t0)
        ctr = ctr + 1
      if t1 < 9'u32 and ctr < need:
        dst[offset + ctr] = 4 - cast[int32](t1)
        ctr = ctr + 1
  result = ctr

proc ctMaskLtSmall(a, b: uint32): int32 {.inline, raises: [].} =
  result = int32(((a - b) shr 31) and 1'u32)

proc ctSelectInt32(a, b, m: int32): int32 {.inline, raises: [].} =
  var
    mask: int32 = 0'i32 - m
  result = a xor ((a xor b) and mask)

proc ctSelectInt(a, b: int, m: int32): int {.inline, raises: [].} =
  var
    mask: int = 0 - int(m)
  result = a xor ((a xor b) and mask)

proc etaValueEta2(t: uint32): int32 {.inline, raises: [].} =
  var
    reduced: uint32 = 0
  reduced = t - ((205'u32 * t) shr 10) * 5'u32
  result = 2'i32 - cast[int32](reduced)

proc etaValueEta4(t: uint32): int32 {.inline, raises: [].} =
  result = 4'i32 - cast[int32](t)

proc appendEtaCt(dst: var array[dilithiumN, int32], ctr: var int,
    value: int32, accept: int32) {.inline, raises: [].} =
  var
    room: int32 = ctMaskLtSmall(uint32(ctr), uint32(dilithiumN))
    idx: int = ctSelectInt(dilithiumN - 1, ctr, room)
    take: int32 = accept and room
  dst[idx] = ctSelectInt32(dst[idx], value, take)
  ctr = ctr + int(accept)

proc fillEtaCtPrefix[INBYTES: static[int]](p: DilithiumParams, a: var DilithiumPoly,
    buf: var array[INBYTES, byte]): int {.inline, raises: [].} =
  var
    ctr: int = 0
    i: int = 0
    t0: uint32 = 0
    t1: uint32 = 0
  clearPlainData(a)
  if p.eta == 2:
    while i < INBYTES:
      t0 = uint32(buf[i] and 0x0f'u8)
      t1 = uint32(buf[i] shr 4)
      appendEtaCt(a.coeffs, ctr, etaValueEta2(t0), ctMaskLtSmall(t0, 15'u32))
      appendEtaCt(a.coeffs, ctr, etaValueEta2(t1), ctMaskLtSmall(t1, 15'u32))
      i = i + 1
  else:
    while i < INBYTES:
      t0 = uint32(buf[i] and 0x0f'u8)
      t1 = uint32(buf[i] shr 4)
      appendEtaCt(a.coeffs, ctr, etaValueEta4(t0), ctMaskLtSmall(t0, 9'u32))
      appendEtaCt(a.coeffs, ctr, etaValueEta4(t1), ctMaskLtSmall(t1, 9'u32))
      i = i + 1
  result = ctr

proc finishEtaCtPrefix[INBYTES: static[int]](p: DilithiumParams, a: var DilithiumPoly,
    S: var Sha3State, buf: var array[INBYTES, byte]) {.inline, raises: [].} =
  var
    ctr: int = 0
  ctr = fillEtaCtPrefix(p, a, buf)
  if ctr < dilithiumN:
    ## The fixed-work prefix is sized so this compatibility path should only
    ## trigger for astronomically rare SHAKE outputs; keep it for exactness.
    while ctr < dilithiumN:
      shake256SqueezeBlocksIntoUnchecked(S, buf.toOpenArray(0, shake256RateBytes - 1))
      ctr = ctr + rejEta(p, a.coeffs, ctr, dilithiumN - ctr,
        buf.toOpenArray(0, shake256RateBytes - 1))

proc initShake128NonceState(S: var Sha3State,
    seed: array[dilithiumSeedBytes, byte], nonce: uint16) {.inline, raises: [].} =
  var
    input: array[dilithiumSeedBytes + 2, byte]
    i: int = 0
  while i < dilithiumSeedBytes:
    input[i] = seed[i]
    i = i + 1
  input[dilithiumSeedBytes] = byte(nonce and 0xff'u16)
  input[dilithiumSeedBytes + 1] = byte((nonce shr 8) and 0xff'u16)
  shake128AbsorbOnce(S, input)

when defined(sse2) or defined(avx2):
  proc initShake128NonceMsg(msg: var array[dilithiumSeedBytes + 2, byte],
      seed: array[dilithiumSeedBytes, byte], nonce: uint16) {.inline, raises: [].} =
    var
      i: int = 0
    while i < dilithiumSeedBytes:
      msg[i] = seed[i]
      i = i + 1
    msg[dilithiumSeedBytes] = byte(nonce and 0xff'u16)
    msg[dilithiumSeedBytes + 1] = byte((nonce shr 8) and 0xff'u16)

proc initShake256NonceState(S: var Sha3State,
    seed: array[dilithiumCrhBytes, byte], nonce: uint16) {.inline, raises: [].} =
  var
    input: array[dilithiumCrhBytes + 2, byte]
    i: int = 0
  while i < dilithiumCrhBytes:
    input[i] = seed[i]
    i = i + 1
  input[dilithiumCrhBytes] = byte(nonce and 0xff'u16)
  input[dilithiumCrhBytes + 1] = byte((nonce shr 8) and 0xff'u16)
  shake256AbsorbOnce(S, input)

when defined(sse2) or defined(avx2):
  proc initShake256NonceMsg(msg: var array[dilithiumCrhBytes + 2, byte],
      seed: array[dilithiumCrhBytes, byte], nonce: uint16) {.inline, raises: [].} =
    var
      i: int = 0
    while i < dilithiumCrhBytes:
      msg[i] = seed[i]
      i = i + 1
    msg[dilithiumCrhBytes] = byte(nonce and 0xff'u16)
    msg[dilithiumCrhBytes + 1] = byte((nonce shr 8) and 0xff'u16)

proc polyUniformSeed(a: var DilithiumPoly,
    seed: array[dilithiumSeedBytes, byte], nonce: uint16) {.inline, raises: [].} =
  var
    S: Sha3State
    buf: array[((768 + shake128RateBytes - 1) div shake128RateBytes) * shake128RateBytes + 2, byte]
    bufLen: int = ((768 + shake128RateBytes - 1) div shake128RateBytes) * shake128RateBytes
    ctr: int = 0
    off: int = 0
    i: int = 0
  initShake128NonceState(S, seed, nonce)
  shake128SqueezeBlocksIntoUnchecked(S, buf.toOpenArray(0, bufLen - 1))
  ctr = rejUniform(a.coeffs, 0, dilithiumN, buf.toOpenArray(0, bufLen - 1))
  while ctr < dilithiumN:
    off = bufLen mod 3
    i = 0
    while i < off:
      buf[i] = buf[bufLen - off + i]
      i = i + 1
    shake128SqueezeBlocksIntoUnchecked(S, buf.toOpenArray(off, off + shake128RateBytes - 1))
    bufLen = off + shake128RateBytes
    ctr = ctr + rejUniform(a.coeffs, ctr, dilithiumN - ctr, buf.toOpenArray(0, bufLen - 1))

when defined(avx2):
  proc polyUniform4xSeed(a0, a1, a2, a3: var DilithiumPoly,
      seed: array[dilithiumSeedBytes, byte], nonce0, nonce1, nonce2,
      nonce3: uint16) {.inline, otterBench, raises: [].} =
    var
      states: array[4, Sha3State]
      msgs: array[4, array[dilithiumSeedBytes + 2, byte]]
      initBufs: array[4, array[dilithiumUniform4xInitBytes, byte]]
      extraBufs: array[4, array[shake128RateBytes, byte]]
      polys: array[4, ptr DilithiumPoly]
      ctr: array[4, int]
      lane: int = 0
    polys = [addr a0, addr a1, addr a2, addr a3]
    initShake128NonceMsg(msgs[0], seed, nonce0)
    initShake128NonceMsg(msgs[1], seed, nonce1)
    initShake128NonceMsg(msgs[2], seed, nonce2)
    initShake128NonceMsg(msgs[3], seed, nonce3)
    shake128AbsorbOnceAvx4x(states, msgs)
    shake128SqueezeBlocksAvx4x(states, initBufs)
    lane = 0
    while lane < 4:
      ctr[lane] = rejUniform(polys[lane][].coeffs, 0, dilithiumN, initBufs[lane])
      lane = lane + 1
    while ctr[0] < dilithiumN or ctr[1] < dilithiumN or ctr[2] < dilithiumN or ctr[3] < dilithiumN:
      shake128SqueezeBlocksAvx4x(states, extraBufs)
      lane = 0
      while lane < 4:
        if ctr[lane] < dilithiumN:
          ctr[lane] = ctr[lane] + rejUniform(polys[lane][].coeffs, ctr[lane],
            dilithiumN - ctr[lane], extraBufs[lane])
        lane = lane + 1

proc polyUniform*(a: var DilithiumPoly,
    seed: array[dilithiumSeedBytes, byte], nonce: uint16) {.inline, raises: [].} =
  polyUniformSeed(a, seed, nonce)

proc polyUniform*(a: var DilithiumPoly, seed: openArray[byte], nonce: uint16) =
  var
    fixedSeed: array[dilithiumSeedBytes, byte]
    i: int = 0
  if seed.len != dilithiumSeedBytes:
    raise newException(ValueError, "Dilithium rho seed must be 32 bytes")
  while i < dilithiumSeedBytes:
    fixedSeed[i] = seed[i]
    i = i + 1
  polyUniformSeed(a, fixedSeed, nonce)

proc polyUniformEtaSeed*(p: DilithiumParams, a: var DilithiumPoly,
    seed: array[dilithiumCrhBytes, byte], nonce: uint16) {.inline, raises: [].} =
  if p.eta == 2:
    var
      S: Sha3State
      buf: array[dilithiumEtaCtBytesEta2, byte]
    initShake256NonceState(S, seed, nonce)
    shake256SqueezeBlocksIntoUnchecked(S, buf.toOpenArray(0, dilithiumEtaCtBytesEta2 - 1))
    finishEtaCtPrefix(p, a, S, buf)
    clearSensitivePlainData(S)
    clearSensitivePlainData(buf)
    return
  var
    S: Sha3State
    buf: array[dilithiumEtaCtBytesEta4, byte]
  initShake256NonceState(S, seed, nonce)
  shake256SqueezeBlocksIntoUnchecked(S, buf.toOpenArray(0, dilithiumEtaCtBytesEta4 - 1))
  finishEtaCtPrefix(p, a, S, buf)
  clearSensitivePlainData(S)
  clearSensitivePlainData(buf)

proc polyUniformEta*(p: DilithiumParams, a: var DilithiumPoly,
    seed: array[dilithiumCrhBytes, byte], nonce: uint16) {.inline, raises: [].} =
  polyUniformEtaSeed(p, a, seed, nonce)

when defined(avx2):
  proc polyUniformEta4xCtSeedEta2(p: DilithiumParams, a0, a1, a2, a3: var DilithiumPoly,
      seed: array[dilithiumCrhBytes, byte], nonce0, nonce1, nonce2,
      nonce3: uint16) {.inline, otterBench, raises: [].} =
    var
      states: array[4, Sha3State]
      msgs: array[4, array[dilithiumCrhBytes + 2, byte]]
      bufs: array[4, array[dilithiumEtaCtBytesEta2, byte]]
    initShake256NonceMsg(msgs[0], seed, nonce0)
    initShake256NonceMsg(msgs[1], seed, nonce1)
    initShake256NonceMsg(msgs[2], seed, nonce2)
    initShake256NonceMsg(msgs[3], seed, nonce3)
    shake256AbsorbOnceAvx4x(states, msgs)
    shake256SqueezeBlocksAvx4x(states, bufs)
    finishEtaCtPrefix(p, a0, states[0], bufs[0])
    finishEtaCtPrefix(p, a1, states[1], bufs[1])
    finishEtaCtPrefix(p, a2, states[2], bufs[2])
    finishEtaCtPrefix(p, a3, states[3], bufs[3])
    clearSensitivePlainData(states)
    clearSensitivePlainData(bufs)
    clearSensitivePlainData(msgs)

  proc polyUniformEta4xCtSeedEta4(p: DilithiumParams, a0, a1, a2, a3: var DilithiumPoly,
      seed: array[dilithiumCrhBytes, byte], nonce0, nonce1, nonce2,
      nonce3: uint16) {.inline, otterBench, raises: [].} =
    var
      states: array[4, Sha3State]
      msgs: array[4, array[dilithiumCrhBytes + 2, byte]]
      bufs: array[4, array[dilithiumEtaCtBytesEta4, byte]]
    initShake256NonceMsg(msgs[0], seed, nonce0)
    initShake256NonceMsg(msgs[1], seed, nonce1)
    initShake256NonceMsg(msgs[2], seed, nonce2)
    initShake256NonceMsg(msgs[3], seed, nonce3)
    shake256AbsorbOnceAvx4x(states, msgs)
    shake256SqueezeBlocksAvx4x(states, bufs)
    finishEtaCtPrefix(p, a0, states[0], bufs[0])
    finishEtaCtPrefix(p, a1, states[1], bufs[1])
    finishEtaCtPrefix(p, a2, states[2], bufs[2])
    finishEtaCtPrefix(p, a3, states[3], bufs[3])
    clearSensitivePlainData(states)
    clearSensitivePlainData(bufs)
    clearSensitivePlainData(msgs)

  proc polyUniformEta4xCtSeed(p: DilithiumParams, a0, a1, a2, a3: var DilithiumPoly,
      seed: array[dilithiumCrhBytes, byte], nonce0, nonce1, nonce2,
      nonce3: uint16) {.inline, otterBench, raises: [].} =
    if p.eta == 2:
      polyUniformEta4xCtSeedEta2(p, a0, a1, a2, a3, seed, nonce0, nonce1, nonce2, nonce3)
      return
    polyUniformEta4xCtSeedEta4(p, a0, a1, a2, a3, seed, nonce0, nonce1, nonce2, nonce3)

when defined(sse2) or defined(avx2):
  proc polyUniformEta2xCtSeedEta2(p: DilithiumParams, a0, a1: var DilithiumPoly,
      seed: array[dilithiumCrhBytes, byte], nonce0, nonce1: uint16) {.inline, otterBench, raises: [].} =
    var
      msgs: array[2, array[dilithiumCrhBytes + 2, byte]]
      bufs: array[2, array[dilithiumEtaCtBytesEta2, byte]]
      ctr0: int = 0
      ctr1: int = 0
    initShake256NonceMsg(msgs[0], seed, nonce0)
    initShake256NonceMsg(msgs[1], seed, nonce1)
    shake256Sse2xInto(bufs, msgs)
    ctr0 = fillEtaCtPrefix(p, a0, bufs[0])
    ctr1 = fillEtaCtPrefix(p, a1, bufs[1])
    if ctr0 < dilithiumN:
      polyUniformEtaSeed(p, a0, seed, nonce0)
    if ctr1 < dilithiumN:
      polyUniformEtaSeed(p, a1, seed, nonce1)
    clearSensitivePlainData(bufs)
    clearSensitivePlainData(msgs)

  proc polyUniformEta2xCtSeedEta4(p: DilithiumParams, a0, a1: var DilithiumPoly,
      seed: array[dilithiumCrhBytes, byte], nonce0, nonce1: uint16) {.inline, otterBench, raises: [].} =
    var
      msgs: array[2, array[dilithiumCrhBytes + 2, byte]]
      bufs: array[2, array[dilithiumEtaCtBytesEta4, byte]]
      ctr0: int = 0
      ctr1: int = 0
    initShake256NonceMsg(msgs[0], seed, nonce0)
    initShake256NonceMsg(msgs[1], seed, nonce1)
    shake256Sse2xInto(bufs, msgs)
    ctr0 = fillEtaCtPrefix(p, a0, bufs[0])
    ctr1 = fillEtaCtPrefix(p, a1, bufs[1])
    if ctr0 < dilithiumN:
      polyUniformEtaSeed(p, a0, seed, nonce0)
    if ctr1 < dilithiumN:
      polyUniformEtaSeed(p, a1, seed, nonce1)
    clearSensitivePlainData(bufs)
    clearSensitivePlainData(msgs)

  proc polyUniformEta2xCtSeed(p: DilithiumParams, a0, a1: var DilithiumPoly,
      seed: array[dilithiumCrhBytes, byte], nonce0, nonce1: uint16) {.inline, otterBench, raises: [].} =
    if p.eta == 2:
      polyUniformEta2xCtSeedEta2(p, a0, a1, seed, nonce0, nonce1)
      return
    polyUniformEta2xCtSeedEta4(p, a0, a1, seed, nonce0, nonce1)

proc polyUniformEta*(p: DilithiumParams, a: var DilithiumPoly,
    seed: openArray[byte], nonce: uint16) =
  var
    fixedSeed: array[dilithiumCrhBytes, byte]
    i: int = 0
  if seed.len != dilithiumCrhBytes:
    raise newException(ValueError, "Dilithium eta seed must be 64 bytes")
  while i < dilithiumCrhBytes:
    fixedSeed[i] = seed[i]
    i = i + 1
  polyUniformEtaSeed(p, a, fixedSeed, nonce)
  clearSensitivePlainData(fixedSeed)

proc polyZUnpack*(p: DilithiumParams, r: var DilithiumPoly, a: openArray[byte]) {.raises: [].}

proc polyUniformGamma1Seed*(p: DilithiumParams, a: var DilithiumPoly,
    seed: array[dilithiumCrhBytes, byte], nonce: uint16) {.inline, raises: [].} =
  var
    S: Sha3State
    outLen: int = 0
    buf: array[((640 + shake256RateBytes - 1) div shake256RateBytes) * shake256RateBytes, byte]
  outLen = ((p.polyZPackedBytes + shake256RateBytes - 1) div shake256RateBytes) * shake256RateBytes
  initShake256NonceState(S, seed, nonce)
  shake256SqueezeBlocksIntoUnchecked(S, buf.toOpenArray(0, outLen - 1))
  polyZUnpack(p, a, buf.toOpenArray(0, p.polyZPackedBytes - 1))

when defined(avx2):
  proc polyUniformGamma14xSeed(p: DilithiumParams, a0, a1, a2, a3: var DilithiumPoly,
      seed: array[dilithiumCrhBytes, byte], nonce0, nonce1, nonce2,
      nonce3: uint16) {.inline, otterBench, raises: [].} =
    var
      states: array[4, Sha3State]
      msgs: array[4, array[dilithiumCrhBytes + 2, byte]]
      bufs: array[4, array[dilithiumUniformGamma14xMaxBytes, byte]]
    initShake256NonceMsg(msgs[0], seed, nonce0)
    initShake256NonceMsg(msgs[1], seed, nonce1)
    initShake256NonceMsg(msgs[2], seed, nonce2)
    initShake256NonceMsg(msgs[3], seed, nonce3)
    shake256AbsorbOnceAvx4x(states, msgs)
    shake256SqueezeBlocksAvx4x(states, bufs)
    polyZUnpack(p, a0, bufs[0].toOpenArray(0, p.polyZPackedBytes - 1))
    polyZUnpack(p, a1, bufs[1].toOpenArray(0, p.polyZPackedBytes - 1))
    polyZUnpack(p, a2, bufs[2].toOpenArray(0, p.polyZPackedBytes - 1))
    polyZUnpack(p, a3, bufs[3].toOpenArray(0, p.polyZPackedBytes - 1))

when defined(sse2) or defined(avx2):
  proc polyUniformGamma12xSeed(p: DilithiumParams, a0, a1: var DilithiumPoly,
      seed: array[dilithiumCrhBytes, byte], nonce0, nonce1: uint16) {.inline, otterBench, raises: [].} =
    var
      msgs: array[2, array[dilithiumCrhBytes + 2, byte]]
      bufs: array[2, array[dilithiumUniformGamma14xMaxBytes, byte]]
    initShake256NonceMsg(msgs[0], seed, nonce0)
    initShake256NonceMsg(msgs[1], seed, nonce1)
    shake256Sse2xInto(bufs, msgs)
    polyZUnpack(p, a0, bufs[0].toOpenArray(0, p.polyZPackedBytes - 1))
    polyZUnpack(p, a1, bufs[1].toOpenArray(0, p.polyZPackedBytes - 1))
    clearSensitivePlainData(bufs)
    clearSensitivePlainData(msgs)

proc polyUniformGamma1*(p: DilithiumParams, a: var DilithiumPoly,
    seed: array[dilithiumCrhBytes, byte], nonce: uint16) {.inline, raises: [].} =
  polyUniformGamma1Seed(p, a, seed, nonce)

proc polyUniformGamma1*(p: DilithiumParams, a: var DilithiumPoly,
    seed: openArray[byte], nonce: uint16) =
  var
    fixedSeed: array[dilithiumCrhBytes, byte]
    i: int = 0
  if seed.len != dilithiumCrhBytes:
    raise newException(ValueError, "Dilithium gamma1 seed must be 64 bytes")
  while i < dilithiumCrhBytes:
    fixedSeed[i] = seed[i]
    i = i + 1
  polyUniformGamma1Seed(p, a, fixedSeed, nonce)

proc polyChallengeSeed*(p: DilithiumParams, c: var DilithiumPoly,
    seed: openArray[byte]) {.inline, raises: [].} =
  var
    S: Sha3State
    buf: array[shake256RateBytes, byte]
    signs: uint64 = 0
    pos: int = 8
    i: int = 0
    b: uint32 = 0
  shake256AbsorbOnce(S, seed)
  shake256SqueezeBlocksIntoUnchecked(S, buf)
  i = 0
  while i < 8:
    signs = signs or (uint64(buf[i]) shl (8 * i))
    i = i + 1
  i = 0
  while i < dilithiumN:
    c.coeffs[i] = 0
    i = i + 1
  i = dilithiumN - p.tau
  while i < dilithiumN:
    while true:
      if pos >= shake256RateBytes:
        shake256SqueezeBlocksIntoUnchecked(S, buf)
        pos = 0
      b = uint32(buf[pos])
      pos = pos + 1
      if b <= uint32(i):
        break
    c.coeffs[i] = c.coeffs[int(b)]
    c.coeffs[int(b)] = 1 - 2 * cast[int32](signs and 1'u64)
    signs = signs shr 1
    i = i + 1

proc polyChallenge*(p: DilithiumParams, c: var DilithiumPoly, seed: openArray[byte]) =
  if seed.len != p.ctildeBytes:
    raise newException(ValueError, "invalid Dilithium challenge seed length")
  polyChallengeSeed(p, c, seed)

proc polyEtaPackInto(p: DilithiumParams, r: var openArray[byte],
    a: DilithiumPoly) {.inline, raises: [].} =
  var
    i: int = 0
    j: int = 0
    t: array[8, uint8]
  if p.eta == 2:
    i = 0
    while i < dilithiumN div 8:
      j = 0
      while j < 8:
        t[j] = uint8(p.eta - a.coeffs[8 * i + j])
        j = j + 1
      r[3 * i + 0] = (t[0] shr 0) or (t[1] shl 3) or (t[2] shl 6)
      r[3 * i + 1] = (t[2] shr 2) or (t[3] shl 1) or (t[4] shl 4) or (t[5] shl 7)
      r[3 * i + 2] = (t[5] shr 1) or (t[6] shl 2) or (t[7] shl 5)
      i = i + 1
    return
  i = 0
  while i < dilithiumN div 2:
    t[0] = uint8(p.eta - a.coeffs[2 * i + 0])
    t[1] = uint8(p.eta - a.coeffs[2 * i + 1])
    r[i] = t[0] or (t[1] shl 4)
    i = i + 1

proc polyEtaPack*(p: DilithiumParams, r: var openArray[byte], a: DilithiumPoly) =
  if r.len != p.polyEtaPackedBytes:
    raise newException(ValueError, "invalid Dilithium eta pack buffer length")
  polyEtaPackInto(p, r, a)

proc polyEtaPack*(p: DilithiumParams, r: var seq[byte], a: DilithiumPoly) =
  r.setLen(p.polyEtaPackedBytes)
  polyEtaPack(p, r.toOpenArray(0, r.len - 1), a)

proc polyEtaUnpackInto(p: DilithiumParams, r: var DilithiumPoly,
    a: openArray[byte]) {.inline, raises: [].} =
  var
    i: int = 0
    eta: int32 = cast[int32](p.eta)
  if p.eta == 2:
    i = 0
    while i < dilithiumN div 8:
      r.coeffs[8 * i + 0] = eta - int32((a[3 * i + 0] shr 0) and 7)
      r.coeffs[8 * i + 1] = eta - int32((a[3 * i + 0] shr 3) and 7)
      r.coeffs[8 * i + 2] = eta - int32(((a[3 * i + 0] shr 6) or (a[3 * i + 1] shl 2)) and 7)
      r.coeffs[8 * i + 3] = eta - int32((a[3 * i + 1] shr 1) and 7)
      r.coeffs[8 * i + 4] = eta - int32((a[3 * i + 1] shr 4) and 7)
      r.coeffs[8 * i + 5] = eta - int32(((a[3 * i + 1] shr 7) or (a[3 * i + 2] shl 1)) and 7)
      r.coeffs[8 * i + 6] = eta - int32((a[3 * i + 2] shr 2) and 7)
      r.coeffs[8 * i + 7] = eta - int32((a[3 * i + 2] shr 5) and 7)
      i = i + 1
    return
  i = 0
  while i < dilithiumN div 2:
    r.coeffs[2 * i + 0] = eta - int32(a[i] and 0x0f'u8)
    r.coeffs[2 * i + 1] = eta - int32(a[i] shr 4)
    i = i + 1

proc polyEtaUnpack*(p: DilithiumParams, r: var DilithiumPoly, a: openArray[byte]) {.inline, raises: [].} =
  polyEtaUnpackInto(p, r, a)

proc polyT1PackInto(r: var openArray[byte], a: DilithiumPoly) {.inline, raises: [].} =
  var
    i: int = 0
  i = 0
  while i < dilithiumN div 4:
    r[5 * i + 0] = byte(a.coeffs[4 * i + 0] shr 0)
    r[5 * i + 1] = byte((a.coeffs[4 * i + 0] shr 8) or (a.coeffs[4 * i + 1] shl 2))
    r[5 * i + 2] = byte((a.coeffs[4 * i + 1] shr 6) or (a.coeffs[4 * i + 2] shl 4))
    r[5 * i + 3] = byte((a.coeffs[4 * i + 2] shr 4) or (a.coeffs[4 * i + 3] shl 6))
    r[5 * i + 4] = byte(a.coeffs[4 * i + 3] shr 2)
    i = i + 1

proc polyT1Pack*(r: var openArray[byte], a: DilithiumPoly) =
  if r.len != 320:
    raise newException(ValueError, "invalid Dilithium t1 pack buffer length")
  polyT1PackInto(r, a)

proc polyT1Pack*(r: var seq[byte], a: DilithiumPoly) =
  r.setLen(320)
  polyT1Pack(r.toOpenArray(0, r.len - 1), a)

proc polyT1Unpack*(r: var DilithiumPoly, a: openArray[byte]) {.inline, raises: [].} =
  var
    i: int = 0
  i = 0
  while i < dilithiumN div 4:
    r.coeffs[4 * i + 0] = cast[int32]((uint32(a[5 * i + 0]) or (uint32(a[5 * i + 1]) shl 8)) and 0x3ff'u32)
    r.coeffs[4 * i + 1] = cast[int32]((uint32(a[5 * i + 1] shr 2) or (uint32(a[5 * i + 2]) shl 6)) and 0x3ff'u32)
    r.coeffs[4 * i + 2] = cast[int32]((uint32(a[5 * i + 2] shr 4) or (uint32(a[5 * i + 3]) shl 4)) and 0x3ff'u32)
    r.coeffs[4 * i + 3] = cast[int32]((uint32(a[5 * i + 3] shr 6) or (uint32(a[5 * i + 4]) shl 2)) and 0x3ff'u32)
    i = i + 1

proc polyT0PackInto(r: var openArray[byte], a: DilithiumPoly) {.inline, raises: [].} =
  var
    i: int = 0
    j: int = 0
    t: array[8, uint32]
  i = 0
  while i < dilithiumN div 8:
    j = 0
    while j < 8:
      t[j] = uint32((1 shl (dilithiumD - 1)) - a.coeffs[8 * i + j])
      j = j + 1
    r[13*i+0] = byte(t[0])
    r[13*i+1] = byte((t[0] shr 8) or (t[1] shl 5))
    r[13*i+2] = byte(t[1] shr 3)
    r[13*i+3] = byte((t[1] shr 11) or (t[2] shl 2))
    r[13*i+4] = byte((t[2] shr 6) or (t[3] shl 7))
    r[13*i+5] = byte(t[3] shr 1)
    r[13*i+6] = byte((t[3] shr 9) or (t[4] shl 4))
    r[13*i+7] = byte(t[4] shr 4)
    r[13*i+8] = byte((t[4] shr 12) or (t[5] shl 1))
    r[13*i+9] = byte((t[5] shr 7) or (t[6] shl 6))
    r[13*i+10] = byte(t[6] shr 2)
    r[13*i+11] = byte((t[6] shr 10) or (t[7] shl 3))
    r[13*i+12] = byte(t[7] shr 5)
    i = i + 1

proc polyT0Pack*(r: var openArray[byte], a: DilithiumPoly) =
  if r.len != 416:
    raise newException(ValueError, "invalid Dilithium t0 pack buffer length")
  polyT0PackInto(r, a)

proc polyT0Pack*(r: var seq[byte], a: DilithiumPoly) =
  r.setLen(416)
  polyT0Pack(r.toOpenArray(0, r.len - 1), a)

proc polyT0Unpack*(r: var DilithiumPoly, a: openArray[byte]) {.inline, raises: [].} =
  var
    i: int = 0
    j: int = 0
  i = 0
  while i < dilithiumN div 8:
    r.coeffs[8*i+0]  = cast[int32]((uint32(a[13*i+0]) or (uint32(a[13*i+1]) shl 8)) and 0x1fff'u32)
    r.coeffs[8*i+1]  = cast[int32]((uint32(a[13*i+1] shr 5) or (uint32(a[13*i+2]) shl 3) or (uint32(a[13*i+3]) shl 11)) and 0x1fff'u32)
    r.coeffs[8*i+2]  = cast[int32]((uint32(a[13*i+3] shr 2) or (uint32(a[13*i+4]) shl 6)) and 0x1fff'u32)
    r.coeffs[8*i+3]  = cast[int32]((uint32(a[13*i+4] shr 7) or (uint32(a[13*i+5]) shl 1) or (uint32(a[13*i+6]) shl 9)) and 0x1fff'u32)
    r.coeffs[8*i+4]  = cast[int32]((uint32(a[13*i+6] shr 4) or (uint32(a[13*i+7]) shl 4) or (uint32(a[13*i+8]) shl 12)) and 0x1fff'u32)
    r.coeffs[8*i+5]  = cast[int32]((uint32(a[13*i+8] shr 1) or (uint32(a[13*i+9]) shl 7)) and 0x1fff'u32)
    r.coeffs[8*i+6]  = cast[int32]((uint32(a[13*i+9] shr 6) or (uint32(a[13*i+10]) shl 2) or (uint32(a[13*i+11]) shl 10)) and 0x1fff'u32)
    r.coeffs[8*i+7]  = cast[int32]((uint32(a[13*i+11] shr 3) or (uint32(a[13*i+12]) shl 5)) and 0x1fff'u32)
    j = 0
    while j < 8:
      r.coeffs[8*i+j] = (1 shl (dilithiumD - 1)) - r.coeffs[8*i+j]
      j = j + 1
    i = i + 1

proc polyZPackInto(p: DilithiumParams, r: var openArray[byte],
    a: DilithiumPoly) {.inline, raises: [].} =
  var
    i: int = 0
    j: int = 0
    t: array[4, uint32]
  if p.gamma1 == (1 shl 17):
    i = 0
    while i < dilithiumN div 4:
      j = 0
      while j < 4:
        t[j] = uint32(p.gamma1 - a.coeffs[4 * i + j])
        j = j + 1
      r[9*i+0] = byte(t[0])
      r[9*i+1] = byte(t[0] shr 8)
      r[9*i+2] = byte((t[0] shr 16) or (t[1] shl 2))
      r[9*i+3] = byte(t[1] shr 6)
      r[9*i+4] = byte((t[1] shr 14) or (t[2] shl 4))
      r[9*i+5] = byte(t[2] shr 4)
      r[9*i+6] = byte((t[2] shr 12) or (t[3] shl 6))
      r[9*i+7] = byte(t[3] shr 2)
      r[9*i+8] = byte(t[3] shr 10)
      i = i + 1
    return
  i = 0
  while i < dilithiumN div 2:
    t[0] = uint32(p.gamma1 - a.coeffs[2 * i + 0])
    t[1] = uint32(p.gamma1 - a.coeffs[2 * i + 1])
    r[5*i+0] = byte(t[0])
    r[5*i+1] = byte(t[0] shr 8)
    r[5*i+2] = byte((t[0] shr 16) or (t[1] shl 4))
    r[5*i+3] = byte(t[1] shr 4)
    r[5*i+4] = byte(t[1] shr 12)
    i = i + 1

proc polyZPack*(p: DilithiumParams, r: var openArray[byte], a: DilithiumPoly) =
  if r.len != p.polyZPackedBytes:
    raise newException(ValueError, "invalid Dilithium z pack buffer length")
  polyZPackInto(p, r, a)

proc polyZPack*(p: DilithiumParams, r: var seq[byte], a: DilithiumPoly) =
  r.setLen(p.polyZPackedBytes)
  polyZPack(p, r.toOpenArray(0, r.len - 1), a)

proc polyZUnpack*(p: DilithiumParams, r: var DilithiumPoly, a: openArray[byte]) =
  var
    i: int = 0
    j: int = 0
  if p.gamma1 == (1 shl 17):
    i = 0
    while i < dilithiumN div 4:
      r.coeffs[4*i+0] = cast[int32]((uint32(a[9*i+0]) or (uint32(a[9*i+1]) shl 8) or (uint32(a[9*i+2]) shl 16)) and 0x3ffff'u32)
      r.coeffs[4*i+1] = cast[int32]((uint32(a[9*i+2] shr 2) or (uint32(a[9*i+3]) shl 6) or (uint32(a[9*i+4]) shl 14)) and 0x3ffff'u32)
      r.coeffs[4*i+2] = cast[int32]((uint32(a[9*i+4] shr 4) or (uint32(a[9*i+5]) shl 4) or (uint32(a[9*i+6]) shl 12)) and 0x3ffff'u32)
      r.coeffs[4*i+3] = cast[int32]((uint32(a[9*i+6] shr 6) or (uint32(a[9*i+7]) shl 2) or (uint32(a[9*i+8]) shl 10)) and 0x3ffff'u32)
      j = 0
      while j < 4:
        r.coeffs[4*i+j] = p.gamma1 - r.coeffs[4*i+j]
        j = j + 1
      i = i + 1
    return
  i = 0
  while i < dilithiumN div 2:
    r.coeffs[2*i+0] = cast[int32]((uint32(a[5*i+0]) or (uint32(a[5*i+1]) shl 8) or (uint32(a[5*i+2]) shl 16)) and 0xfffff'u32)
    r.coeffs[2*i+1] = cast[int32](uint32(a[5*i+2] shr 4) or (uint32(a[5*i+3]) shl 4) or (uint32(a[5*i+4]) shl 12))
    r.coeffs[2*i+0] = p.gamma1 - r.coeffs[2*i+0]
    r.coeffs[2*i+1] = p.gamma1 - r.coeffs[2*i+1]
    i = i + 1

proc polyW1PackInto*(p: DilithiumParams, r: var openArray[byte],
    a: DilithiumPoly) {.inline, raises: [].} =
  var
    i: int = 0
  if p.gamma2 == (dilithiumQ - 1) div 88:
    i = 0
    while i < dilithiumN div 4:
      r[3*i+0] = byte(a.coeffs[4*i+0] or (a.coeffs[4*i+1] shl 6))
      r[3*i+1] = byte((a.coeffs[4*i+1] shr 2) or (a.coeffs[4*i+2] shl 4))
      r[3*i+2] = byte((a.coeffs[4*i+2] shr 4) or (a.coeffs[4*i+3] shl 2))
      i = i + 1
    return
  i = 0
  while i < dilithiumN div 2:
    r[i] = byte(a.coeffs[2*i+0] or (a.coeffs[2*i+1] shl 4))
    i = i + 1

proc polyW1Pack*(p: DilithiumParams, r: var openArray[byte], a: DilithiumPoly) =
  if r.len != p.polyW1PackedBytes:
    raise newException(ValueError, "invalid Dilithium w1 pack buffer length")
  polyW1PackInto(p, r, a)

proc polyW1Pack*(p: DilithiumParams, r: var seq[byte], a: DilithiumPoly) =
  r.setLen(p.polyW1PackedBytes)
  polyW1Pack(p, r.toOpenArray(0, r.len - 1), a)

proc polyveclUniformEta*(p: DilithiumParams, v: var DilithiumPolyVecL,
    seed: array[dilithiumCrhBytes, byte], nonce: uint16) {.inline, raises: [].} =
  var
    i: int = 0
    nn: uint16 = nonce
  when defined(avx2):
    var
      tmp: DilithiumPoly
    if p.l == 4:
      polyUniformEta4xCtSeed(p, v.vec[0], v.vec[1], v.vec[2], v.vec[3],
        seed, nn, nn + 1'u16, nn + 2'u16, nn + 3'u16)
      return
    if p.l == 5:
      polyUniformEta4xCtSeed(p, v.vec[0], v.vec[1], v.vec[2], v.vec[3],
        seed, nn, nn + 1'u16, nn + 2'u16, nn + 3'u16)
      polyUniformEtaSeed(p, v.vec[4], seed, nn + 4'u16)
      return
    if p.l == 7:
      polyUniformEta4xCtSeed(p, v.vec[0], v.vec[1], v.vec[2], v.vec[3],
        seed, nn, nn + 1'u16, nn + 2'u16, nn + 3'u16)
      polyUniformEta4xCtSeed(p, v.vec[4], v.vec[5], v.vec[6], tmp,
        seed, nn + 4'u16, nn + 5'u16, nn + 6'u16, 0'u16)
      clearSensitivePlainData(tmp)
      return
  while i < p.l:
    polyUniformEta(p, v.vec[i], seed, nn)
    nn = nn + 1'u16
    i = i + 1

proc polyveclUniformEta*(p: DilithiumParams, v: var DilithiumPolyVecL,
    seed: openArray[byte], nonce: uint16) =
  var
    fixedSeed: array[dilithiumCrhBytes, byte]
    i: int = 0
  if seed.len != dilithiumCrhBytes:
    raise newException(ValueError, "Dilithium eta seed must be 64 bytes")
  while i < dilithiumCrhBytes:
    fixedSeed[i] = seed[i]
    i = i + 1
  polyveclUniformEta(p, v, fixedSeed, nonce)
  clearSensitivePlainData(fixedSeed)

proc polyveclUniformGamma1BaseNonce*(p: DilithiumParams, v: var DilithiumPolyVecL,
    seed: array[dilithiumCrhBytes, byte], baseNonce: uint16) {.inline, otterBench, raises: [].} =
  var
    i: int = 0
    nonceNow: uint16 = baseNonce
  when defined(avx2):
    if p.l == 4:
      polyUniformGamma14xSeed(p, v.vec[0], v.vec[1], v.vec[2], v.vec[3],
        seed, nonceNow, nonceNow + 1'u16, nonceNow + 2'u16, nonceNow + 3'u16)
      return
    if p.l == 5:
      polyUniformGamma14xSeed(p, v.vec[0], v.vec[1], v.vec[2], v.vec[3],
        seed, nonceNow, nonceNow + 1'u16, nonceNow + 2'u16, nonceNow + 3'u16)
      polyUniformGamma1Seed(p, v.vec[4], seed, nonceNow + 4'u16)
      return
    if p.l == 7:
      polyUniformGamma14xSeed(p, v.vec[0], v.vec[1], v.vec[2], v.vec[3],
        seed, nonceNow, nonceNow + 1'u16, nonceNow + 2'u16, nonceNow + 3'u16)
      polyUniformGamma12xSeed(p, v.vec[4], v.vec[5], seed, nonceNow + 4'u16, nonceNow + 5'u16)
      polyUniformGamma1Seed(p, v.vec[6], seed, nonceNow + 6'u16)
      return
  while i < p.l:
    polyUniformGamma1Seed(p, v.vec[i], seed, nonceNow)
    nonceNow = nonceNow + 1'u16
    i = i + 1

proc polyveclUniformGamma1*(p: DilithiumParams, v: var DilithiumPolyVecL,
    seed: array[dilithiumCrhBytes, byte], nonce: uint16) {.inline, raises: [].} =
  polyveclUniformGamma1BaseNonce(p, v, seed, uint16(p.l * int(nonce)))

proc polyveclUniformGamma1*(p: DilithiumParams, v: var DilithiumPolyVecL,
    seed: openArray[byte], nonce: uint16) =
  var
    fixedSeed: array[dilithiumCrhBytes, byte]
    i: int = 0
  if seed.len != dilithiumCrhBytes:
    raise newException(ValueError, "Dilithium gamma1 seed must be 64 bytes")
  while i < dilithiumCrhBytes:
    fixedSeed[i] = seed[i]
    i = i + 1
  polyveclUniformGamma1(p, v, fixedSeed, nonce)

proc polyveclReduce*(v: var DilithiumPolyVecL) {.inline, raises: [].} =
  for i in 0 ..< v.used:
    polyReduce(v.vec[i])

proc polyveclAdd*(w: var DilithiumPolyVecL, u, v: DilithiumPolyVecL) {.inline, raises: [].} =
  for i in 0 ..< w.used:
    polyAdd(w.vec[i], u.vec[i], v.vec[i])

proc polyveclNtt*(v: var DilithiumPolyVecL) {.inline, raises: [].} =
  for i in 0 ..< v.used:
    polyNtt(v.vec[i])

proc polyveclInvnttTomont*(v: var DilithiumPolyVecL) {.inline, raises: [].} =
  for i in 0 ..< v.used:
    polyInvnttTomont(v.vec[i])

proc polyveclPointwisePolyMontgomery*(r: var DilithiumPolyVecL, a: DilithiumPoly,
    v: DilithiumPolyVecL) {.inline, raises: [].} =
  for i in 0 ..< r.used:
    polyPointwiseMontgomery(r.vec[i], a, v.vec[i])

proc polyveclPointwiseAccMontgomery*(w: var DilithiumPoly, u, v: DilithiumPolyVecL) {.inline, otterBench, raises: [].} =
  when defined(avx2):
    polyveclPointwiseAccMontgomerySimdAvx2(w, u, v)
  else:
    var
      t: DilithiumPoly
      i: int = 1
    polyPointwiseMontgomery(w, u.vec[0], v.vec[0])
    while i < u.used:
      polyPointwiseMontgomery(t, u.vec[i], v.vec[i])
      polyAdd(w, w, t)
      i = i + 1

proc polyveclChkNorm*(v: DilithiumPolyVecL, B: int32): bool {.inline, raises: [].} =
  for i in 0 ..< v.used:
    if polyChkNorm(v.vec[i], B):
      return true
  result = false

proc polyveckUniformEta*(p: DilithiumParams, v: var DilithiumPolyVecK,
    seed: array[dilithiumCrhBytes, byte], nonce: uint16) {.inline, raises: [].} =
  var
    i: int = 0
    nn: uint16 = nonce
  when defined(avx2):
    if p.k == 4:
      polyUniformEta4xCtSeed(p, v.vec[0], v.vec[1], v.vec[2], v.vec[3],
        seed, nn, nn + 1'u16, nn + 2'u16, nn + 3'u16)
      return
    if p.k == 6:
      polyUniformEta4xCtSeed(p, v.vec[0], v.vec[1], v.vec[2], v.vec[3],
        seed, nn, nn + 1'u16, nn + 2'u16, nn + 3'u16)
      polyUniformEta2xCtSeed(p, v.vec[4], v.vec[5], seed, nn + 4'u16, nn + 5'u16)
      return
    if p.k == 8:
      polyUniformEta4xCtSeed(p, v.vec[0], v.vec[1], v.vec[2], v.vec[3],
        seed, nn, nn + 1'u16, nn + 2'u16, nn + 3'u16)
      polyUniformEta4xCtSeed(p, v.vec[4], v.vec[5], v.vec[6], v.vec[7],
        seed, nn + 4'u16, nn + 5'u16, nn + 6'u16, nn + 7'u16)
      return
  while i < p.k:
    polyUniformEta(p, v.vec[i], seed, nn)
    nn = nn + 1'u16
    i = i + 1

proc polyveckUniformEta*(p: DilithiumParams, v: var DilithiumPolyVecK,
    seed: openArray[byte], nonce: uint16) =
  var
    fixedSeed: array[dilithiumCrhBytes, byte]
    i: int = 0
  if seed.len != dilithiumCrhBytes:
    raise newException(ValueError, "Dilithium eta seed must be 64 bytes")
  while i < dilithiumCrhBytes:
    fixedSeed[i] = seed[i]
    i = i + 1
  polyveckUniformEta(p, v, fixedSeed, nonce)
  clearSensitivePlainData(fixedSeed)

proc polyveckReduce*(v: var DilithiumPolyVecK) {.inline, raises: [].} =
  for i in 0 ..< v.used:
    polyReduce(v.vec[i])

proc polyveckCaddq*(v: var DilithiumPolyVecK) {.inline, raises: [].} =
  for i in 0 ..< v.used:
    polyCaddq(v.vec[i])

proc polyveckAdd*(w: var DilithiumPolyVecK, u, v: DilithiumPolyVecK) {.inline, raises: [].} =
  for i in 0 ..< w.used:
    polyAdd(w.vec[i], u.vec[i], v.vec[i])

proc polyveckSub*(w: var DilithiumPolyVecK, u, v: DilithiumPolyVecK) {.inline, raises: [].} =
  for i in 0 ..< w.used:
    polySub(w.vec[i], u.vec[i], v.vec[i])

proc polyveckShiftl*(v: var DilithiumPolyVecK) {.inline, raises: [].} =
  for i in 0 ..< v.used:
    polyShiftL(v.vec[i])

proc polyveckNtt*(v: var DilithiumPolyVecK) {.inline, raises: [].} =
  for i in 0 ..< v.used:
    polyNtt(v.vec[i])

proc polyveckInvnttTomont*(v: var DilithiumPolyVecK) {.inline, raises: [].} =
  for i in 0 ..< v.used:
    polyInvnttTomont(v.vec[i])

proc polyveckPointwisePolyMontgomery*(r: var DilithiumPolyVecK, a: DilithiumPoly,
    v: DilithiumPolyVecK) {.inline, raises: [].} =
  for i in 0 ..< r.used:
    polyPointwiseMontgomery(r.vec[i], a, v.vec[i])

proc polyveckChkNorm*(v: DilithiumPolyVecK, B: int32): bool {.inline, raises: [].} =
  for i in 0 ..< v.used:
    if polyChkNorm(v.vec[i], B):
      return true
  result = false

proc polyveckPower2Round*(v1, v0: var DilithiumPolyVecK, v: DilithiumPolyVecK) {.inline, raises: [].} =
  for i in 0 ..< v.used:
    polyPower2Round(v1.vec[i], v0.vec[i], v.vec[i])

proc polyveckDecompose*(p: DilithiumParams, v1, v0: var DilithiumPolyVecK,
    v: DilithiumPolyVecK) {.inline, otterBench, raises: [].} =
  for i in 0 ..< v.used:
    polyDecompose(p, v1.vec[i], v0.vec[i], v.vec[i])

proc polyveckMakeHint*(p: DilithiumParams, h: var DilithiumPolyVecK,
    v0, v1: DilithiumPolyVecK): uint32 {.inline, otterBench, raises: [].} =
  for i in 0 ..< h.used:
    result = result + polyMakeHint(p, h.vec[i], v0.vec[i], v1.vec[i])

proc polyveckUseHint*(p: DilithiumParams, w: var DilithiumPolyVecK,
    v, h: DilithiumPolyVecK) {.inline, otterBench, raises: [].} =
  for i in 0 ..< w.used:
    polyUseHint(p, w.vec[i], v.vec[i], h.vec[i])

proc polyveckPackW1*(p: DilithiumParams, r: var openArray[byte], w1: DilithiumPolyVecK) {.inline, otterBench, raises: [].} =
  for i in 0 ..< p.k:
    polyW1PackInto(p, r.toOpenArray(i * p.polyW1PackedBytes,
      (i + 1) * p.polyW1PackedBytes - 1), w1.vec[i])

proc polyveckPackW1*(p: DilithiumParams, r: var seq[byte], w1: DilithiumPolyVecK) =
  r.setLen(p.k * p.polyW1PackedBytes)
  polyveckPackW1(p, r.toOpenArray(0, r.len - 1), w1)

proc polyvecMatrixExpandRowInto*(p: DilithiumParams, row: var DilithiumPolyVecL,
    rho: array[dilithiumSeedBytes, byte], rowIndex: int) {.inline, otterBench, raises: [].} =
  var
    j: int = 0
  row = initPolyVecL(p)
  when defined(avx2):
    var
      baseNonce: uint16 = uint16(rowIndex shl 8)
      tmp: DilithiumPoly
    if p.l == 4:
      polyUniform4xSeed(row.vec[0], row.vec[1], row.vec[2], row.vec[3],
        rho, baseNonce, baseNonce + 1'u16, baseNonce + 2'u16, baseNonce + 3'u16)
      return
    if p.l == 5:
      polyUniform4xSeed(row.vec[0], row.vec[1], row.vec[2], row.vec[3],
        rho, baseNonce, baseNonce + 1'u16, baseNonce + 2'u16, baseNonce + 3'u16)
      polyUniform(row.vec[4], rho, baseNonce + 4'u16)
      return
    if p.l == 7:
      polyUniform4xSeed(row.vec[0], row.vec[1], row.vec[2], row.vec[3],
        rho, baseNonce, baseNonce + 1'u16, baseNonce + 2'u16, baseNonce + 3'u16)
      polyUniform4xSeed(row.vec[4], row.vec[5], row.vec[6], tmp,
        rho, baseNonce + 4'u16, baseNonce + 5'u16, baseNonce + 6'u16, 0'u16)
      return
  while j < p.l:
    polyUniform(row.vec[j], rho, uint16((rowIndex shl 8) + j))
    j = j + 1

proc polyvecMatrixExpand*(p: DilithiumParams,
    rho: array[dilithiumSeedBytes, byte]): DilithiumMatrix {.inline, otterBench, raises: [].} =
  result = initMatrix(p)
  if p.k == 4:
    polyvecMatrixExpandRowInto(p, result.mat[0], rho, 0)
    polyvecMatrixExpandRowInto(p, result.mat[1], rho, 1)
    polyvecMatrixExpandRowInto(p, result.mat[2], rho, 2)
    polyvecMatrixExpandRowInto(p, result.mat[3], rho, 3)
    return
  if p.k == 6:
    polyvecMatrixExpandRowInto(p, result.mat[0], rho, 0)
    polyvecMatrixExpandRowInto(p, result.mat[1], rho, 1)
    polyvecMatrixExpandRowInto(p, result.mat[2], rho, 2)
    polyvecMatrixExpandRowInto(p, result.mat[3], rho, 3)
    polyvecMatrixExpandRowInto(p, result.mat[4], rho, 4)
    polyvecMatrixExpandRowInto(p, result.mat[5], rho, 5)
    return
  if p.k == 8:
    polyvecMatrixExpandRowInto(p, result.mat[0], rho, 0)
    polyvecMatrixExpandRowInto(p, result.mat[1], rho, 1)
    polyvecMatrixExpandRowInto(p, result.mat[2], rho, 2)
    polyvecMatrixExpandRowInto(p, result.mat[3], rho, 3)
    polyvecMatrixExpandRowInto(p, result.mat[4], rho, 4)
    polyvecMatrixExpandRowInto(p, result.mat[5], rho, 5)
    polyvecMatrixExpandRowInto(p, result.mat[6], rho, 6)
    polyvecMatrixExpandRowInto(p, result.mat[7], rho, 7)
    return
  for i in 0 ..< p.k:
    polyvecMatrixExpandRowInto(p, result.mat[i], rho, i)

proc polyvecMatrixExpand*(p: DilithiumParams, rho: openArray[byte]): DilithiumMatrix =
  var
    fixedRho: array[dilithiumSeedBytes, byte]
    i: int = 0
  if rho.len != dilithiumSeedBytes:
    raise newException(ValueError, "Dilithium rho seed must be 32 bytes")
  while i < dilithiumSeedBytes:
    fixedRho[i] = rho[i]
    i = i + 1
  result = polyvecMatrixExpand(p, fixedRho)

proc polyvecMatrixPointwiseMontgomery*(p: DilithiumParams, t: var DilithiumPolyVecK,
    mat: DilithiumMatrix, v: DilithiumPolyVecL) {.inline, otterBench, raises: [].} =
  if p.k == 4:
    polyveclPointwiseAccMontgomery(t.vec[0], mat.mat[0], v)
    polyveclPointwiseAccMontgomery(t.vec[1], mat.mat[1], v)
    polyveclPointwiseAccMontgomery(t.vec[2], mat.mat[2], v)
    polyveclPointwiseAccMontgomery(t.vec[3], mat.mat[3], v)
    return
  if p.k == 6:
    polyveclPointwiseAccMontgomery(t.vec[0], mat.mat[0], v)
    polyveclPointwiseAccMontgomery(t.vec[1], mat.mat[1], v)
    polyveclPointwiseAccMontgomery(t.vec[2], mat.mat[2], v)
    polyveclPointwiseAccMontgomery(t.vec[3], mat.mat[3], v)
    polyveclPointwiseAccMontgomery(t.vec[4], mat.mat[4], v)
    polyveclPointwiseAccMontgomery(t.vec[5], mat.mat[5], v)
    return
  if p.k == 8:
    polyveclPointwiseAccMontgomery(t.vec[0], mat.mat[0], v)
    polyveclPointwiseAccMontgomery(t.vec[1], mat.mat[1], v)
    polyveclPointwiseAccMontgomery(t.vec[2], mat.mat[2], v)
    polyveclPointwiseAccMontgomery(t.vec[3], mat.mat[3], v)
    polyveclPointwiseAccMontgomery(t.vec[4], mat.mat[4], v)
    polyveclPointwiseAccMontgomery(t.vec[5], mat.mat[5], v)
    polyveclPointwiseAccMontgomery(t.vec[6], mat.mat[6], v)
    polyveclPointwiseAccMontgomery(t.vec[7], mat.mat[7], v)
    return
  for i in 0 ..< p.k:
    polyveclPointwiseAccMontgomery(t.vec[i], mat.mat[i], v)

proc packPkIntoUnchecked(p: DilithiumParams, dst: var openArray[byte], rho: openArray[byte],
    t1: DilithiumPolyVecK) {.raises: [].} =
  var
    i: int = 0
  i = 0
  while i < dilithiumSeedBytes:
    dst[i] = rho[i]
    i = i + 1
  i = 0
  while i < p.k:
    polyT1PackInto(dst.toOpenArray(dilithiumSeedBytes + i * p.polyT1PackedBytes,
      dilithiumSeedBytes + (i + 1) * p.polyT1PackedBytes - 1), t1.vec[i])
    i = i + 1

proc packPkInto*(p: DilithiumParams, dst: var openArray[byte], rho: openArray[byte],
    t1: DilithiumPolyVecK) =
  if dst.len != p.publicKeyBytes:
    raise newException(ValueError, "invalid Dilithium public key buffer length")
  packPkIntoUnchecked(p, dst, rho, t1)

proc packPk*(p: DilithiumParams, rho: openArray[byte], t1: DilithiumPolyVecK): seq[byte] {.raises: [].} =
  result = newSeq[byte](p.publicKeyBytes)
  packPkIntoUnchecked(p, result, rho, t1)

proc unpackPk*(p: DilithiumParams, pk: openArray[byte]): DilithiumPublicKeyState {.raises: [].} =
  var
    i: int = 0
  result.t1 = initPolyVecK(p)
  i = 0
  while i < dilithiumSeedBytes:
    result.rho[i] = pk[i]
    i = i + 1
  for i in 0 ..< p.k:
    polyT1Unpack(result.t1.vec[i],
      pk.toOpenArray(dilithiumSeedBytes + i * p.polyT1PackedBytes,
        dilithiumSeedBytes + (i + 1) * p.polyT1PackedBytes - 1))

proc packSkIntoUnchecked(p: DilithiumParams, dst: var openArray[byte], rho, tr, key: openArray[byte],
    t0: DilithiumPolyVecK, s1: DilithiumPolyVecL, s2: DilithiumPolyVecK) {.raises: [].} =
  var
    o: int = 0
    i: int = 0
  i = 0
  while i < dilithiumSeedBytes:
    dst[o + i] = rho[i]
    i = i + 1
  o = o + dilithiumSeedBytes
  i = 0
  while i < dilithiumSeedBytes:
    dst[o + i] = key[i]
    i = i + 1
  o = o + dilithiumSeedBytes
  i = 0
  while i < dilithiumTrBytes:
    dst[o + i] = tr[i]
    i = i + 1
  o = o + dilithiumTrBytes
  i = 0
  while i < p.l:
    polyEtaPackInto(p, dst.toOpenArray(o, o + p.polyEtaPackedBytes - 1), s1.vec[i])
    o = o + p.polyEtaPackedBytes
    i = i + 1
  i = 0
  while i < p.k:
    polyEtaPackInto(p, dst.toOpenArray(o, o + p.polyEtaPackedBytes - 1), s2.vec[i])
    o = o + p.polyEtaPackedBytes
    i = i + 1
  i = 0
  while i < p.k:
    polyT0PackInto(dst.toOpenArray(o, o + p.polyT0PackedBytes - 1), t0.vec[i])
    o = o + p.polyT0PackedBytes
    i = i + 1

proc packSkInto*(p: DilithiumParams, dst: var openArray[byte], rho, tr, key: openArray[byte],
    t0: DilithiumPolyVecK, s1: DilithiumPolyVecL, s2: DilithiumPolyVecK) =
  if dst.len != p.secretKeyBytes:
    raise newException(ValueError, "invalid Dilithium secret key buffer length")
  packSkIntoUnchecked(p, dst, rho, tr, key, t0, s1, s2)

proc packSk*(p: DilithiumParams, rho, tr, key: openArray[byte], t0: DilithiumPolyVecK,
    s1: DilithiumPolyVecL, s2: DilithiumPolyVecK): seq[byte] {.raises: [].} =
  result = newSeq[byte](p.secretKeyBytes)
  packSkIntoUnchecked(p, result, rho, tr, key, t0, s1, s2)

proc unpackSk*(p: DilithiumParams, sk: openArray[byte]): DilithiumSecretKeyState {.raises: [].} =
  var
    o: int = 0
    i: int = 0
  result.s1 = initPolyVecL(p)
  result.s2 = initPolyVecK(p)
  result.t0 = initPolyVecK(p)
  i = 0
  while i < dilithiumSeedBytes:
    result.rho[i] = sk[o + i]
    i = i + 1
  o = o + dilithiumSeedBytes
  i = 0
  while i < dilithiumSeedBytes:
    result.key[i] = sk[o + i]
    i = i + 1
  o = o + dilithiumSeedBytes
  i = 0
  while i < dilithiumTrBytes:
    result.tr[i] = sk[o + i]
    i = i + 1
  o = o + dilithiumTrBytes
  for i in 0 ..< p.l:
    polyEtaUnpackInto(p, result.s1.vec[i], sk.toOpenArray(o, o + p.polyEtaPackedBytes - 1))
    o = o + p.polyEtaPackedBytes
  for i in 0 ..< p.k:
    polyEtaUnpackInto(p, result.s2.vec[i], sk.toOpenArray(o, o + p.polyEtaPackedBytes - 1))
    o = o + p.polyEtaPackedBytes
  for i in 0 ..< p.k:
    polyT0Unpack(result.t0.vec[i], sk.toOpenArray(o, o + p.polyT0PackedBytes - 1))
    o = o + p.polyT0PackedBytes

proc packSigIntoUnchecked(p: DilithiumParams, dst: var openArray[byte], c: openArray[byte],
    z: DilithiumPolyVecL, h: DilithiumPolyVecK) {.raises: [].} =
  var
    o: int = 0
    k: int = 0
    i: int = 0
    j: int = 0
  i = 0
  while i < p.ctildeBytes:
    dst[i] = c[i]
    i = i + 1
  o = p.ctildeBytes
  i = 0
  while i < p.l:
    polyZPackInto(p, dst.toOpenArray(o, o + p.polyZPackedBytes - 1), z.vec[i])
    o = o + p.polyZPackedBytes
    i = i + 1
  i = 0
  while i < p.omega + p.k:
    dst[o + i] = 0
    i = i + 1
  k = 0
  i = 0
  while i < p.k:
    j = 0
    while j < dilithiumN:
      if h.vec[i].coeffs[j] != 0:
        dst[o + k] = byte(j)
        k = k + 1
      j = j + 1
    dst[o + p.omega + i] = byte(k)
    i = i + 1

proc packSigInto*(p: DilithiumParams, dst: var openArray[byte], c: openArray[byte],
    z: DilithiumPolyVecL, h: DilithiumPolyVecK) =
  if dst.len != p.signatureBytes:
    raise newException(ValueError, "invalid Dilithium signature buffer length")
  packSigIntoUnchecked(p, dst, c, z, h)

proc packSig*(p: DilithiumParams, c: openArray[byte], z: DilithiumPolyVecL,
    h: DilithiumPolyVecK): seq[byte] {.raises: [].} =
  result = newSeq[byte](p.signatureBytes)
  packSigIntoUnchecked(p, result, c, z, h)

proc unpackSig*(p: DilithiumParams, sig: openArray[byte]): DilithiumSignatureState {.raises: [].} =
  var
    o: int = p.ctildeBytes + p.l * p.polyZPackedBytes
    k: int = 0
    i: int = 0
  if sig.len != p.signatureBytes:
    result.ok = false
    return
  result.cLen = p.ctildeBytes
  result.z = initPolyVecL(p)
  result.h = initPolyVecK(p)
  i = 0
  while i < p.ctildeBytes:
    result.c[i] = sig[i]
    i = i + 1
  for i in 0 ..< p.l:
    polyZUnpack(p, result.z.vec[i],
      sig.toOpenArray(p.ctildeBytes + i * p.polyZPackedBytes,
        p.ctildeBytes + (i + 1) * p.polyZPackedBytes - 1))
  for i in 0 ..< p.k:
    for j in 0 ..< dilithiumN:
      result.h.vec[i].coeffs[j] = 0
    if int(sig[o + p.omega + i]) < k or int(sig[o + p.omega + i]) > p.omega:
      result.ok = false
      return
    for j in k ..< int(sig[o + p.omega + i]):
      if j > k and sig[o + j] <= sig[o + j - 1]:
        result.ok = false
        return
      result.h.vec[i].coeffs[int(sig[o + j])] = 1
    k = int(sig[o + p.omega + i])
  for j in k ..< p.omega:
    if sig[o + j] != 0:
      result.ok = false
      return
  result.ok = true
{.pop.}
