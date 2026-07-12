## ---------------------------------------------------------------------
## Dilithium Poly <- polynomial, vector, sampling, and packing routines
## ---------------------------------------------------------------------

import ./params
import ./arith
import ../../../sha3
import ../../../../helpers/otter_support
import std/[typetraits, volatile]

when defined(sse2) or defined(avx2) or defined(neon) or defined(arm64) or defined(aarch64):
  import simd_nexus/simd/base_operations
when defined(neon) or defined(arm64) or defined(aarch64):
  import simd_nexus/simd/generic_i32
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

when defined(sse2) or defined(avx2) or defined(neon) or defined(arm64) or defined(aarch64):
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
  ## Paper note: these public coefficient-lane add/sub/shift helpers follow the
  ## SIMD arithmetic direction in `2021-0986_neon_ntt_dilithium_kyber_saber.pdf`
  ## and `2022-0112_kyber_dilithium_speed_memory_cortex_m4.pdf`, while keeping
  ## the reference Dilithium polynomial operations unchanged.
  ## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyAddSimdSse`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
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

  ## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polySubSimdSse`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
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

  ## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyShiftLSimdSse`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
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

when defined(neon) or defined(arm64) or defined(aarch64):
  ## Paper note: ARM128 lanes are the local portable NEON version of the public
  ## polynomial arithmetic batching discussed in `2021-0986_neon_ntt_dilithium_kyber_saber.pdf`.
  ## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyAddSimdNeon`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
  proc polyAddSimdNeon(c: var DilithiumPoly, a, b: DilithiumPoly) {.inline.} =
    var
      i: int = 0
      va: uint32x4
      vb: uint32x4
    i = 0
    while i + 4 <= dilithiumN:
      va = loadI32x4At[uint32x4](a.coeffs, i)
      vb = loadI32x4At[uint32x4](b.coeffs, i)
      storeI32x4At[uint32x4](va + vb, c.coeffs, i)
      i = i + 4
    while i < dilithiumN:
      c.coeffs[i] = a.coeffs[i] + b.coeffs[i]
      i = i + 1

  ## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polySubSimdNeon`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
  proc polySubSimdNeon(c: var DilithiumPoly, a, b: DilithiumPoly) {.inline.} =
    var
      i: int = 0
      va: uint32x4
      vb: uint32x4
    i = 0
    while i + 4 <= dilithiumN:
      va = loadI32x4At[uint32x4](a.coeffs, i)
      vb = loadI32x4At[uint32x4](b.coeffs, i)
      storeI32x4At[uint32x4](va - vb, c.coeffs, i)
      i = i + 4
    while i < dilithiumN:
      c.coeffs[i] = a.coeffs[i] - b.coeffs[i]
      i = i + 1

  ## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyShiftLSimdNeon`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
  proc polyShiftLSimdNeon(a: var DilithiumPoly) {.inline.} =
    var
      i: int = 0
      va: uint32x4
    i = 0
    while i + 4 <= dilithiumN:
      va = loadI32x4At[uint32x4](a.coeffs, i)
      storeI32x4At[uint32x4](va shl dilithiumD, a.coeffs, i)
      i = i + 4
    while i < dilithiumN:
      a.coeffs[i] = a.coeffs[i] shl dilithiumD
      i = i + 1

when defined(avx2):
  ## Paper note: the eight-lane Montgomery product is the AVX2-side companion to
  ## the vectorized NTT/reduction style in `2018-0039_vectorized_ntt_implementations.pdf`.
  ## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `montgomeryReduceProdVec8Avx2`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
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

  ## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyPointwiseMontgomerySimdAvx2`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
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

  ## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyveclPointwiseAccMontgomeryUsed4SimdAvx2`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
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

  ## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyveclPointwiseAccMontgomeryUsed5SimdAvx2`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
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

  ## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyveclPointwiseAccMontgomeryUsed7SimdAvx2`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
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

  ## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyveclPointwiseAccMontgomerySimdAvx2`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
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

  ## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyChkNormSimdAvx2`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
  proc polyChkNormSimdAvx2(a: DilithiumPoly, B: int32): bool {.inline, otterBench.} =
    var
      i: int = 0
      bad: int32 = 0
      coeffVec: navx.M256i
      signVec: navx.M256i
      absVec: navx.M256i
      cmpVec: navx.M256i
      badVec: navx.M256i = navx.mm256_setzero_si256()
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
      # Accumulate branch-free: a per-block branch on secret-derived
      # coefficients would leak which block exceeds the bound.
      badVec = navx2.mm256_or_si256(badVec, cmpVec)
      i = i + 8
    while i < dilithiumN:
      var t: int32 = a.coeffs[i] shr 31
      t = a.coeffs[i] - (t and (2 * a.coeffs[i]))
      bad = bad or ((B - 1 - t) shr 31)
      i = i + 1
    result = navx2.mm256_testz_si256(badVec, badVec) == 0 or bad != 0

  ## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyAddSimdAvx2`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
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

  ## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polySubSimdAvx2`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
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

  ## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyShiftLSimdAvx2`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
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
## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `initPolyVecL`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc initPolyVecL*(p: DilithiumParams): DilithiumPolyVecL {.raises: [].} =
  result.used = p.l

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `initPolyVecK`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc initPolyVecK*(p: DilithiumParams): DilithiumPolyVecK {.raises: [].} =
  result.used = p.k

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `initMatrix`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `clearBytes`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc clearBytes*(A: var seq[byte]) =
  var
    i: int = 0
  i = 0
  while i < A.len:
    A[i] = 0'u8
    i = i + 1

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `clearPlainData`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc clearPlainData*[T](S: var T) {.raises: [].} =
  when supportsCopyMem(T):
    zeroMem(addr S, sizeof(T))
  else:
    {.error: "clearPlainData requires supportsCopyMem(T)".}

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `clearSensitiveBytes`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc clearSensitiveBytes*(A: var seq[byte]) {.raises: [].} =
  var
    i: int = 0
  while i < A.len:
    volatileStore(addr A[i], 0'u8)
    i = i + 1

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `clearSensitivePlainData`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `sliceBytes`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc sliceBytes*(A: openArray[byte], o, l: int): seq[byte] =
  var
    i: int = 0
  result = newSeq[byte](l)
  i = 0
  while i < l:
    result[i] = A[o + i]
    i = i + 1

{.push boundChecks: off, overflowChecks: off.}
## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyReduce`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyReduce*(a: var DilithiumPoly) {.inline, raises: [].} =
  var
    i: int = 0
  i = 0
  while i < dilithiumN:
    a.coeffs[i] = reduce32(a.coeffs[i])
    i = i + 1

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyCaddq`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyCaddq*(a: var DilithiumPoly) {.inline, raises: [].} =
  var
    i: int = 0
  i = 0
  while i < dilithiumN:
    a.coeffs[i] = caddq(a.coeffs[i])
    i = i + 1

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyAdd`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyAdd*(c: var DilithiumPoly, a, b: DilithiumPoly) {.inline, raises: [].} =
  ## Paper note: this dispatch is where Tyr differs from clean reference code by
  ## selecting fixed public SIMD coefficient lanes when the target supports them.
  when defined(avx2):
    polyAddSimdAvx2(c, a, b)
  elif defined(sse2):
    polyAddSimdSse(c, a, b)
  elif defined(neon) or defined(arm64) or defined(aarch64):
    polyAddSimdNeon(c, a, b)
  else:
    var
      i: int = 0
    i = 0
    while i < dilithiumN:
      c.coeffs[i] = a.coeffs[i] + b.coeffs[i]
      i = i + 1

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polySub`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polySub*(c: var DilithiumPoly, a, b: DilithiumPoly) {.inline, raises: [].} =
  ## Paper note: subtraction uses the same backend split as addition, so the
  ## arithmetic is reference-compatible but packed per target ISA.
  when defined(avx2):
    polySubSimdAvx2(c, a, b)
  elif defined(sse2):
    polySubSimdSse(c, a, b)
  elif defined(neon) or defined(arm64) or defined(aarch64):
    polySubSimdNeon(c, a, b)
  else:
    var
      i: int = 0
    i = 0
    while i < dilithiumN:
      c.coeffs[i] = a.coeffs[i] - b.coeffs[i]
      i = i + 1

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyShiftL`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyShiftL*(a: var DilithiumPoly) {.inline, raises: [].} =
  when defined(avx2):
    polyShiftLSimdAvx2(a)
  elif defined(sse2):
    polyShiftLSimdSse(a)
  elif defined(neon) or defined(arm64) or defined(aarch64):
    polyShiftLSimdNeon(a)
  else:
    var
      i: int = 0
    i = 0
    while i < dilithiumN:
      a.coeffs[i] = a.coeffs[i] shl dilithiumD
      i = i + 1

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyNtt`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyNtt*(a: var DilithiumPoly) {.inline, otterBench, raises: [].} =
  ntt(a.coeffs)

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyInvnttTomont`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyInvnttTomont*(a: var DilithiumPoly) {.inline, otterBench, raises: [].} =
  invnttTomont(a.coeffs)

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyPointwiseMontgomery`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyPointwiseMontgomery*(c: var DilithiumPoly, a, b: DilithiumPoly) {.inline, otterBench, raises: [].} =
  ## Paper note: the AVX2 branch packs eight independent Montgomery products,
  ## matching the lane-level multiplication/reduction strategy from the AVX2 NTT paper.
  when defined(avx2):
    polyPointwiseMontgomerySimdAvx2(c, a, b)
  else:
    var
      i: int = 0
    i = 0
    while i < dilithiumN:
      c.coeffs[i] = montgomeryReduce(int64(a.coeffs[i]) * int64(b.coeffs[i]))
      i = i + 1

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyPower2Round`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyDecompose`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyMakeHint`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyMakeHint*(p: DilithiumParams, h: var DilithiumPoly, a0, a1: DilithiumPoly): uint32 {.raises: [].} =
  var
    i: int = 0
  i = 0
  while i < dilithiumN:
    # makeHint returns 0 or 1, so this int32 cast is exact.
    h.coeffs[i] = cast[int32](makeHint(p, a0.coeffs[i], a1.coeffs[i]))
    result = result + uint32(h.coeffs[i])
    i = i + 1

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyUseHint`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyChkNorm`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyChkNorm*(a: DilithiumPoly, B: int32): bool {.otterBench, raises: [].} =
  when defined(avx2):
    result = polyChkNormSimdAvx2(a, B)
  else:
    var
      i: int = 0
      t: int32 = 0
      bad: int32 = 0
    if B > (dilithiumQ - 1) div 8:
      return true
    i = 0
    while i < dilithiumN:
      t = a.coeffs[i] shr 31
      t = a.coeffs[i] - (t and (2 * a.coeffs[i]))
      # Sign bit of B-1-t is set exactly when t >= B; accumulate branch-free
      # since the coefficients are secret-derived during signing.
      bad = bad or ((B - 1 - t) shr 31)
      i = i + 1
    result = bad != 0

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `rejUniform`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `rejEta`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `ctMaskLtSmall`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc ctMaskLtSmall(a, b: uint32): int32 {.inline, raises: [].} =
  result = int32(((a - b) shr 31) and 1'u32)

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `ctSelectInt32`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc ctSelectInt32(a, b, m: int32): int32 {.inline, raises: [].} =
  var
    mask: int32 = 0'i32 - m
  result = a xor ((a xor b) and mask)

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `ctSelectInt`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc ctSelectInt(a, b: int, m: int32): int {.inline, raises: [].} =
  var
    mask: int = 0 - int(m)
  result = a xor ((a xor b) and mask)

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `etaValueEta2`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc etaValueEta2(t: uint32): int32 {.inline, raises: [].} =
  var
    reduced: uint32 = 0
  reduced = t - ((205'u32 * t) shr 10) * 5'u32
  result = 2'i32 - cast[int32](reduced)

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `etaValueEta4`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc etaValueEta4(t: uint32): int32 {.inline, raises: [].} =
  result = 4'i32 - cast[int32](t)

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `appendEtaCt`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc appendEtaCt(dst: var array[dilithiumN, int32], ctr: var int,
    value: int32, accept: int32) {.inline, raises: [].} =
  ## Paper note: `2024-1149_dilithium_sampling_implementation_analysis.pdf` and
  ## `2025-0214_dilithium_rejection_sampling_side_channel.pdf` motivate keeping
  ## the eta prefix path fixed-work and using masked stores instead of branching
  ## on rejected nibbles.
  var
    room: int32 = ctMaskLtSmall(uint32(ctr), uint32(dilithiumN))
    idx: int = ctSelectInt(dilithiumN - 1, ctr, room)
    take: int32 = accept and room
  dst[idx] = ctSelectInt32(dst[idx], value, take)
  ctr = ctr + int(accept)

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `fillEtaCtPrefix`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `finishEtaCtPrefix`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc finishEtaCtPrefix[INBYTES: static[int]](p: DilithiumParams, a: var DilithiumPoly,
    S: var Sha3State, buf: var array[INBYTES, byte]) {.inline, raises: [].} =
  ## Paper note: this completes the fixed-work eta prefix and only falls back to
  ## scalar rejection sampling after the public fixed budget is exhausted.
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

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `initShake128NonceState`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

when defined(sse2) or defined(avx2) or defined(neon) or defined(arm64) or defined(aarch64):
  ## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `initShake128NonceMsg`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc initShake128NonceMsg(msg: var array[dilithiumSeedBytes + 2, byte],
      seed: array[dilithiumSeedBytes, byte], nonce: uint16) {.inline, raises: [].} =
    var
      i: int = 0
    while i < dilithiumSeedBytes:
      msg[i] = seed[i]
      i = i + 1
    msg[dilithiumSeedBytes] = byte(nonce and 0xff'u16)
    msg[dilithiumSeedBytes + 1] = byte((nonce shr 8) and 0xff'u16)

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `initShake256NonceState`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

when defined(sse2) or defined(avx2) or defined(neon) or defined(arm64) or defined(aarch64):
  ## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `initShake256NonceMsg`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc initShake256NonceMsg(msg: var array[dilithiumCrhBytes + 2, byte],
      seed: array[dilithiumCrhBytes, byte], nonce: uint16) {.inline, raises: [].} =
    var
      i: int = 0
    while i < dilithiumCrhBytes:
      msg[i] = seed[i]
      i = i + 1
    msg[dilithiumCrhBytes] = byte(nonce and 0xff'u16)
    msg[dilithiumCrhBytes + 1] = byte((nonce shr 8) and 0xff'u16)

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyUniformSeed`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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
  ## Paper note: four-way SHAKE128 expansion is a performance batching of public
  ## matrix/nonces, in the same family as vectorized Dilithium implementations;
  ## each lane still runs the reference rejection sampler for exact output.
  ## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyUniform4xSeed`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

when defined(sse2) or defined(avx2) or defined(neon) or defined(arm64) or defined(aarch64):
  ## Paper note: this 2-lane SHAKE path is the scalar-compatible fallback for
  ## targets without AVX2 4x Keccak, preserving the same per-lane nonce schedule.
  ## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyUniform2xSeed`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc polyUniform2xSeed(a0, a1: var DilithiumPoly,
      seed: array[dilithiumSeedBytes, byte], nonce0, nonce1: uint16) {.inline, otterBench, raises: [].} =
    var
      states: array[2, Sha3State]
      msgs: array[2, array[dilithiumSeedBytes + 2, byte]]
      initBufs: array[2, array[dilithiumUniform4xInitBytes, byte]]
      extraBufs: array[2, array[shake128RateBytes, byte]]
      polys: array[2, ptr DilithiumPoly]
      ctr: array[2, int]
      lane: int = 0
    polys = [addr a0, addr a1]
    initShake128NonceMsg(msgs[0], seed, nonce0)
    initShake128NonceMsg(msgs[1], seed, nonce1)
    shake128AbsorbOnceSse2x(states, msgs)
    shake128SqueezeBlocksSse2x(states, initBufs)
    lane = 0
    while lane < 2:
      ctr[lane] = rejUniform(polys[lane][].coeffs, 0, dilithiumN, initBufs[lane])
      lane = lane + 1
    while ctr[0] < dilithiumN or ctr[1] < dilithiumN:
      shake128SqueezeBlocksSse2x(states, extraBufs)
      lane = 0
      while lane < 2:
        if ctr[lane] < dilithiumN:
          ctr[lane] = ctr[lane] + rejUniform(polys[lane][].coeffs, ctr[lane],
            dilithiumN - ctr[lane], extraBufs[lane])
        lane = lane + 1
    clearSensitivePlainData(states)
    clearSensitivePlainData(msgs)
    clearSensitivePlainData(initBufs)
    clearSensitivePlainData(extraBufs)

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyUniform`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyUniform*(a: var DilithiumPoly,
    seed: array[dilithiumSeedBytes, byte], nonce: uint16) {.inline, raises: [].} =
  polyUniformSeed(a, seed, nonce)

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyUniform`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyUniformEtaSeed`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyUniformEta`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyUniformEta*(p: DilithiumParams, a: var DilithiumPoly,
    seed: array[dilithiumCrhBytes, byte], nonce: uint16) {.inline, raises: [].} =
  polyUniformEtaSeed(p, a, seed, nonce)

when defined(avx2):
  ## Paper note: the 4x eta functions combine AVX2 SHAKE batching with the
  ## fixed-work eta prefix above; they are not the variable-work reference loop.
  ## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyUniformEta4xCtSeedEta2`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

  ## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyUniformEta4xCtSeedEta4`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

  ## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyUniformEta4xCtSeed`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc polyUniformEta4xCtSeed(p: DilithiumParams, a0, a1, a2, a3: var DilithiumPoly,
      seed: array[dilithiumCrhBytes, byte], nonce0, nonce1, nonce2,
      nonce3: uint16) {.inline, otterBench, raises: [].} =
    if p.eta == 2:
      polyUniformEta4xCtSeedEta2(p, a0, a1, a2, a3, seed, nonce0, nonce1, nonce2, nonce3)
      return
    polyUniformEta4xCtSeedEta4(p, a0, a1, a2, a3, seed, nonce0, nonce1, nonce2, nonce3)

when defined(sse2) or defined(avx2) or defined(neon) or defined(arm64) or defined(aarch64):
  ## Paper note: the 2x eta functions use the same masked fixed-prefix fill for
  ## SSE2/NEON-class targets, then fall back per lane only if the fixed prefix
  ## did not produce enough accepted coefficients.
  ## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyUniformEta2xCtSeedEta2`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

  ## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyUniformEta2xCtSeedEta4`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

  ## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyUniformEta2xCtSeed`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc polyUniformEta2xCtSeed(p: DilithiumParams, a0, a1: var DilithiumPoly,
      seed: array[dilithiumCrhBytes, byte], nonce0, nonce1: uint16) {.inline, otterBench, raises: [].} =
    if p.eta == 2:
      polyUniformEta2xCtSeedEta2(p, a0, a1, seed, nonce0, nonce1)
      return
    polyUniformEta2xCtSeedEta4(p, a0, a1, seed, nonce0, nonce1)

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyUniformEta`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyZUnpack`; pitfall: reject malformed or non-canonical input before indexed access.
proc polyZUnpack*(p: DilithiumParams, r: var DilithiumPoly, a: openArray[byte]) {.raises: [].}

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyUniformGamma1Seed`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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
  ## Paper note: gamma1 sampling is batched only at the SHAKE/output-unpack layer,
  ## a performance optimization that preserves the CRYSTALS-Dilithium distribution.
  ## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyUniformGamma14xSeed`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

when defined(sse2) or defined(avx2) or defined(neon) or defined(arm64) or defined(aarch64):
  ## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyUniformGamma12xSeed`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyUniformGamma1`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyUniformGamma1*(p: DilithiumParams, a: var DilithiumPoly,
    seed: array[dilithiumCrhBytes, byte], nonce: uint16) {.inline, raises: [].} =
  polyUniformGamma1Seed(p, a, seed, nonce)

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyUniformGamma1`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyChallengeSeed`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyChallenge`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyChallenge*(p: DilithiumParams, c: var DilithiumPoly, seed: openArray[byte]) =
  if seed.len != p.ctildeBytes:
    raise newException(ValueError, "invalid Dilithium challenge seed length")
  polyChallengeSeed(p, c, seed)

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyEtaPackInto`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
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

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyEtaPack`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
proc polyEtaPack*(p: DilithiumParams, r: var openArray[byte], a: DilithiumPoly) =
  if r.len != p.polyEtaPackedBytes:
    raise newException(ValueError, "invalid Dilithium eta pack buffer length")
  polyEtaPackInto(p, r, a)

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyEtaPack`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
proc polyEtaPack*(p: DilithiumParams, r: var seq[byte], a: DilithiumPoly) =
  r.setLen(p.polyEtaPackedBytes)
  polyEtaPack(p, r.toOpenArray(0, r.len - 1), a)

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyEtaUnpackInto`; pitfall: reject malformed or non-canonical input before indexed access.
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

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyEtaUnpack`; pitfall: reject malformed or non-canonical input before indexed access.
proc polyEtaUnpack*(p: DilithiumParams, r: var DilithiumPoly, a: openArray[byte]) {.inline, raises: [].} =
  polyEtaUnpackInto(p, r, a)

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyT1PackInto`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
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

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyT1Pack`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
proc polyT1Pack*(r: var openArray[byte], a: DilithiumPoly) =
  if r.len != 320:
    raise newException(ValueError, "invalid Dilithium t1 pack buffer length")
  polyT1PackInto(r, a)

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyT1Pack`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
proc polyT1Pack*(r: var seq[byte], a: DilithiumPoly) =
  r.setLen(320)
  polyT1Pack(r.toOpenArray(0, r.len - 1), a)

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyT1Unpack`; pitfall: reject malformed or non-canonical input before indexed access.
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

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyT0PackInto`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
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

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyT0Pack`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
proc polyT0Pack*(r: var openArray[byte], a: DilithiumPoly) =
  if r.len != 416:
    raise newException(ValueError, "invalid Dilithium t0 pack buffer length")
  polyT0PackInto(r, a)

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyT0Pack`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
proc polyT0Pack*(r: var seq[byte], a: DilithiumPoly) =
  r.setLen(416)
  polyT0Pack(r.toOpenArray(0, r.len - 1), a)

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyT0Unpack`; pitfall: reject malformed or non-canonical input before indexed access.
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

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyZPackInto`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
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

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyZPack`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
proc polyZPack*(p: DilithiumParams, r: var openArray[byte], a: DilithiumPoly) =
  if r.len != p.polyZPackedBytes:
    raise newException(ValueError, "invalid Dilithium z pack buffer length")
  polyZPackInto(p, r, a)

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyZPack`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
proc polyZPack*(p: DilithiumParams, r: var seq[byte], a: DilithiumPoly) =
  r.setLen(p.polyZPackedBytes)
  polyZPack(p, r.toOpenArray(0, r.len - 1), a)

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyZUnpack`; pitfall: reject malformed or non-canonical input before indexed access.
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

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyW1PackInto`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
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

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyW1Pack`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
proc polyW1Pack*(p: DilithiumParams, r: var openArray[byte], a: DilithiumPoly) =
  if r.len != p.polyW1PackedBytes:
    raise newException(ValueError, "invalid Dilithium w1 pack buffer length")
  polyW1PackInto(p, r, a)

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyW1Pack`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
proc polyW1Pack*(p: DilithiumParams, r: var seq[byte], a: DilithiumPoly) =
  r.setLen(p.polyW1PackedBytes)
  polyW1Pack(p, r.toOpenArray(0, r.len - 1), a)

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyveclUniformEta`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyveclUniformEta*(p: DilithiumParams, v: var DilithiumPolyVecL,
    seed: array[dilithiumCrhBytes, byte], nonce: uint16) {.inline, raises: [].} =
  ## Paper note: vector secrets consume the fixed-work 4x/2x eta samplers above,
  ## so the side-channel hardening applies at the vector entry point too.
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
  when defined(sse2) or defined(neon) or defined(arm64) or defined(aarch64):
    if p.l == 4:
      polyUniformEta2xCtSeed(p, v.vec[0], v.vec[1], seed, nn, nn + 1'u16)
      polyUniformEta2xCtSeed(p, v.vec[2], v.vec[3], seed, nn + 2'u16, nn + 3'u16)
      return
    if p.l == 5:
      polyUniformEta2xCtSeed(p, v.vec[0], v.vec[1], seed, nn, nn + 1'u16)
      polyUniformEta2xCtSeed(p, v.vec[2], v.vec[3], seed, nn + 2'u16, nn + 3'u16)
      polyUniformEtaSeed(p, v.vec[4], seed, nn + 4'u16)
      return
    if p.l == 7:
      polyUniformEta2xCtSeed(p, v.vec[0], v.vec[1], seed, nn, nn + 1'u16)
      polyUniformEta2xCtSeed(p, v.vec[2], v.vec[3], seed, nn + 2'u16, nn + 3'u16)
      polyUniformEta2xCtSeed(p, v.vec[4], v.vec[5], seed, nn + 4'u16, nn + 5'u16)
      polyUniformEtaSeed(p, v.vec[6], seed, nn + 6'u16)
      return
  while i < p.l:
    polyUniformEta(p, v.vec[i], seed, nn)
    nn = nn + 1'u16
    i = i + 1

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyveclUniformEta`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyveclUniformGamma1BaseNonce`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyveclUniformGamma1BaseNonce*(p: DilithiumParams, v: var DilithiumPolyVecL,
    seed: array[dilithiumCrhBytes, byte], baseNonce: uint16) {.inline, otterBench, raises: [].} =
  ## Paper note: this selects the batched gamma1 SHAKE paths for public nonce
  ## groups, reducing sponge setup overhead without changing rejection behavior.
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
  when defined(sse2) or defined(neon) or defined(arm64) or defined(aarch64):
    if p.l == 4:
      polyUniformGamma12xSeed(p, v.vec[0], v.vec[1], seed, nonceNow, nonceNow + 1'u16)
      polyUniformGamma12xSeed(p, v.vec[2], v.vec[3], seed, nonceNow + 2'u16, nonceNow + 3'u16)
      return
    if p.l == 5:
      polyUniformGamma12xSeed(p, v.vec[0], v.vec[1], seed, nonceNow, nonceNow + 1'u16)
      polyUniformGamma12xSeed(p, v.vec[2], v.vec[3], seed, nonceNow + 2'u16, nonceNow + 3'u16)
      polyUniformGamma1Seed(p, v.vec[4], seed, nonceNow + 4'u16)
      return
    if p.l == 7:
      polyUniformGamma12xSeed(p, v.vec[0], v.vec[1], seed, nonceNow, nonceNow + 1'u16)
      polyUniformGamma12xSeed(p, v.vec[2], v.vec[3], seed, nonceNow + 2'u16, nonceNow + 3'u16)
      polyUniformGamma12xSeed(p, v.vec[4], v.vec[5], seed, nonceNow + 4'u16, nonceNow + 5'u16)
      polyUniformGamma1Seed(p, v.vec[6], seed, nonceNow + 6'u16)
      return
  while i < p.l:
    polyUniformGamma1Seed(p, v.vec[i], seed, nonceNow)
    nonceNow = nonceNow + 1'u16
    i = i + 1

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyveclUniformGamma1`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyveclUniformGamma1*(p: DilithiumParams, v: var DilithiumPolyVecL,
    seed: array[dilithiumCrhBytes, byte], nonce: uint16) {.inline, raises: [].} =
  polyveclUniformGamma1BaseNonce(p, v, seed, uint16(p.l * int(nonce)))

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyveclUniformGamma1`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyveclReduce`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyveclReduce*(v: var DilithiumPolyVecL) {.inline, raises: [].} =
  for i in 0 ..< v.used:
    polyReduce(v.vec[i])

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyveclAdd`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyveclAdd*(w: var DilithiumPolyVecL, u, v: DilithiumPolyVecL) {.inline, raises: [].} =
  for i in 0 ..< w.used:
    polyAdd(w.vec[i], u.vec[i], v.vec[i])

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyveclNtt`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyveclNtt*(v: var DilithiumPolyVecL) {.inline, raises: [].} =
  for i in 0 ..< v.used:
    polyNtt(v.vec[i])

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyveclInvnttTomont`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyveclInvnttTomont*(v: var DilithiumPolyVecL) {.inline, raises: [].} =
  for i in 0 ..< v.used:
    polyInvnttTomont(v.vec[i])

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyveclPointwisePolyMontgomery`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyveclPointwisePolyMontgomery*(r: var DilithiumPolyVecL, a: DilithiumPoly,
    v: DilithiumPolyVecL) {.inline, raises: [].} =
  for i in 0 ..< r.used:
    polyPointwiseMontgomery(r.vec[i], a, v.vec[i])

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyveclPointwiseAccMontgomery`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyveclPointwiseAccMontgomery*(w: var DilithiumPoly, u, v: DilithiumPolyVecL) {.inline, otterBench, raises: [].} =
  ## Paper note: the AVX2 branch fuses vector pointwise products and accumulation
  ## in fixed public coefficient lanes, following the vectorized NTT implementation style.
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

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyveclChkNorm`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyveclChkNorm*(v: DilithiumPolyVecL, B: int32): bool {.inline, raises: [].} =
  var bad: bool = false
  for i in 0 ..< v.used:
    if polyChkNorm(v.vec[i], B):
      bad = true
  result = bad

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyveckUniformEta`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyveckUniformEta*(p: DilithiumParams, v: var DilithiumPolyVecK,
    seed: array[dilithiumCrhBytes, byte], nonce: uint16) {.inline, raises: [].} =
  ## Paper note: K-vector eta sampling reuses the same fixed-prefix batched
  ## samplers, keeping secret-vector generation aligned with the leakage papers.
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
  when defined(sse2) or defined(neon) or defined(arm64) or defined(aarch64):
    if p.k == 4:
      polyUniformEta2xCtSeed(p, v.vec[0], v.vec[1], seed, nn, nn + 1'u16)
      polyUniformEta2xCtSeed(p, v.vec[2], v.vec[3], seed, nn + 2'u16, nn + 3'u16)
      return
    if p.k == 6:
      polyUniformEta2xCtSeed(p, v.vec[0], v.vec[1], seed, nn, nn + 1'u16)
      polyUniformEta2xCtSeed(p, v.vec[2], v.vec[3], seed, nn + 2'u16, nn + 3'u16)
      polyUniformEta2xCtSeed(p, v.vec[4], v.vec[5], seed, nn + 4'u16, nn + 5'u16)
      return
    if p.k == 8:
      polyUniformEta2xCtSeed(p, v.vec[0], v.vec[1], seed, nn, nn + 1'u16)
      polyUniformEta2xCtSeed(p, v.vec[2], v.vec[3], seed, nn + 2'u16, nn + 3'u16)
      polyUniformEta2xCtSeed(p, v.vec[4], v.vec[5], seed, nn + 4'u16, nn + 5'u16)
      polyUniformEta2xCtSeed(p, v.vec[6], v.vec[7], seed, nn + 6'u16, nn + 7'u16)
      return
  while i < p.k:
    polyUniformEta(p, v.vec[i], seed, nn)
    nn = nn + 1'u16
    i = i + 1

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyveckUniformEta`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyveckReduce`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyveckReduce*(v: var DilithiumPolyVecK) {.inline, raises: [].} =
  for i in 0 ..< v.used:
    polyReduce(v.vec[i])

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyveckCaddq`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyveckCaddq*(v: var DilithiumPolyVecK) {.inline, raises: [].} =
  for i in 0 ..< v.used:
    polyCaddq(v.vec[i])

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyveckAdd`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyveckAdd*(w: var DilithiumPolyVecK, u, v: DilithiumPolyVecK) {.inline, raises: [].} =
  for i in 0 ..< w.used:
    polyAdd(w.vec[i], u.vec[i], v.vec[i])

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyveckSub`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyveckSub*(w: var DilithiumPolyVecK, u, v: DilithiumPolyVecK) {.inline, raises: [].} =
  for i in 0 ..< w.used:
    polySub(w.vec[i], u.vec[i], v.vec[i])

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyveckShiftl`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyveckShiftl*(v: var DilithiumPolyVecK) {.inline, raises: [].} =
  for i in 0 ..< v.used:
    polyShiftL(v.vec[i])

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyveckNtt`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyveckNtt*(v: var DilithiumPolyVecK) {.inline, raises: [].} =
  for i in 0 ..< v.used:
    polyNtt(v.vec[i])

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyveckInvnttTomont`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyveckInvnttTomont*(v: var DilithiumPolyVecK) {.inline, raises: [].} =
  for i in 0 ..< v.used:
    polyInvnttTomont(v.vec[i])

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyveckPointwisePolyMontgomery`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyveckPointwisePolyMontgomery*(r: var DilithiumPolyVecK, a: DilithiumPoly,
    v: DilithiumPolyVecK) {.inline, raises: [].} =
  for i in 0 ..< r.used:
    polyPointwiseMontgomery(r.vec[i], a, v.vec[i])

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyveckChkNorm`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyveckChkNorm*(v: DilithiumPolyVecK, B: int32): bool {.inline, raises: [].} =
  var bad: bool = false
  for i in 0 ..< v.used:
    if polyChkNorm(v.vec[i], B):
      bad = true
  result = bad

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyveckPower2Round`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyveckPower2Round*(v1, v0: var DilithiumPolyVecK, v: DilithiumPolyVecK) {.inline, raises: [].} =
  for i in 0 ..< v.used:
    polyPower2Round(v1.vec[i], v0.vec[i], v.vec[i])

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyveckDecompose`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyveckDecompose*(p: DilithiumParams, v1, v0: var DilithiumPolyVecK,
    v: DilithiumPolyVecK) {.inline, otterBench, raises: [].} =
  for i in 0 ..< v.used:
    polyDecompose(p, v1.vec[i], v0.vec[i], v.vec[i])

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyveckMakeHint`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyveckMakeHint*(p: DilithiumParams, h: var DilithiumPolyVecK,
    v0, v1: DilithiumPolyVecK): uint32 {.inline, otterBench, raises: [].} =
  for i in 0 ..< h.used:
    result = result + polyMakeHint(p, h.vec[i], v0.vec[i], v1.vec[i])

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyveckUseHint`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyveckUseHint*(p: DilithiumParams, w: var DilithiumPolyVecK,
    v, h: DilithiumPolyVecK) {.inline, otterBench, raises: [].} =
  for i in 0 ..< w.used:
    polyUseHint(p, w.vec[i], v.vec[i], h.vec[i])

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyveckPackW1`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
proc polyveckPackW1*(p: DilithiumParams, r: var openArray[byte], w1: DilithiumPolyVecK) {.inline, otterBench, raises: [].} =
  for i in 0 ..< p.k:
    polyW1PackInto(p, r.toOpenArray(i * p.polyW1PackedBytes,
      (i + 1) * p.polyW1PackedBytes - 1), w1.vec[i])

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyveckPackW1`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
proc polyveckPackW1*(p: DilithiumParams, r: var seq[byte], w1: DilithiumPolyVecK) =
  r.setLen(p.k * p.polyW1PackedBytes)
  polyveckPackW1(p, r.toOpenArray(0, r.len - 1), w1)

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyvecMatrixExpandRowInto`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyvecMatrixExpandRowInto*(p: DilithiumParams, row: var DilithiumPolyVecL,
    rho: array[dilithiumSeedBytes, byte], rowIndex: int) {.inline, otterBench, raises: [].} =
  ## Paper note: matrix rows use 4x/2x public SHAKE expansion here; this is the
  ## concrete matrix-expansion difference from a clean one-polynomial-at-a-time reference.
  var
    j: int = 0
    baseNonce: uint16 = uint16(rowIndex shl 8)
  row = initPolyVecL(p)
  when defined(avx2):
    var
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
  when defined(sse2) or defined(neon) or defined(arm64) or defined(aarch64):
    if p.l == 4:
      polyUniform2xSeed(row.vec[0], row.vec[1], rho, baseNonce, baseNonce + 1'u16)
      polyUniform2xSeed(row.vec[2], row.vec[3], rho, baseNonce + 2'u16, baseNonce + 3'u16)
      return
    if p.l == 5:
      polyUniform2xSeed(row.vec[0], row.vec[1], rho, baseNonce, baseNonce + 1'u16)
      polyUniform2xSeed(row.vec[2], row.vec[3], rho, baseNonce + 2'u16, baseNonce + 3'u16)
      polyUniform(row.vec[4], rho, baseNonce + 4'u16)
      return
    if p.l == 7:
      polyUniform2xSeed(row.vec[0], row.vec[1], rho, baseNonce, baseNonce + 1'u16)
      polyUniform2xSeed(row.vec[2], row.vec[3], rho, baseNonce + 2'u16, baseNonce + 3'u16)
      polyUniform2xSeed(row.vec[4], row.vec[5], rho, baseNonce + 4'u16, baseNonce + 5'u16)
      polyUniform(row.vec[6], rho, baseNonce + 6'u16)
      return
  while j < p.l:
    polyUniform(row.vec[j], rho, uint16((rowIndex shl 8) + j))
    j = j + 1

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyvecMatrixExpand`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyvecMatrixExpand`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `polyvecMatrixPointwiseMontgomery`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `packPkIntoUnchecked`; pitfall: fail closed and preserve canonical, constant-time comparison where secrets are involved.
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

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `packPkInto`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
proc packPkInto*(p: DilithiumParams, dst: var openArray[byte], rho: openArray[byte],
    t1: DilithiumPolyVecK) =
  if dst.len != p.publicKeyBytes:
    raise newException(ValueError, "invalid Dilithium public key buffer length")
  packPkIntoUnchecked(p, dst, rho, t1)

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `packPk`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
proc packPk*(p: DilithiumParams, rho: openArray[byte], t1: DilithiumPolyVecK): seq[byte] {.raises: [].} =
  result = newSeq[byte](p.publicKeyBytes)
  packPkIntoUnchecked(p, result, rho, t1)

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `unpackPk`; pitfall: reject malformed or non-canonical input before indexed access.
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

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `packSkIntoUnchecked`; pitfall: fail closed and preserve canonical, constant-time comparison where secrets are involved.
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

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `packSkInto`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
proc packSkInto*(p: DilithiumParams, dst: var openArray[byte], rho, tr, key: openArray[byte],
    t0: DilithiumPolyVecK, s1: DilithiumPolyVecL, s2: DilithiumPolyVecK) =
  if dst.len != p.secretKeyBytes:
    raise newException(ValueError, "invalid Dilithium secret key buffer length")
  packSkIntoUnchecked(p, dst, rho, tr, key, t0, s1, s2)

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `packSk`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
proc packSk*(p: DilithiumParams, rho, tr, key: openArray[byte], t0: DilithiumPolyVecK,
    s1: DilithiumPolyVecL, s2: DilithiumPolyVecK): seq[byte] {.raises: [].} =
  result = newSeq[byte](p.secretKeyBytes)
  packSkIntoUnchecked(p, result, rho, tr, key, t0, s1, s2)

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `unpackSk`; pitfall: reject malformed or non-canonical input before indexed access.
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

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `packSigIntoUnchecked`; pitfall: fail closed and preserve canonical, constant-time comparison where secrets are involved.
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

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `packSigInto`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
proc packSigInto*(p: DilithiumParams, dst: var openArray[byte], c: openArray[byte],
    z: DilithiumPolyVecL, h: DilithiumPolyVecK) =
  if dst.len != p.signatureBytes:
    raise newException(ValueError, "invalid Dilithium signature buffer length")
  packSigIntoUnchecked(p, dst, c, z, h)

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `packSig`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
proc packSig*(p: DilithiumParams, c: openArray[byte], z: DilithiumPolyVecL,
    h: DilithiumPolyVecK): seq[byte] {.raises: [].} =
  result = newSeq[byte](p.signatureBytes)
  packSigIntoUnchecked(p, result, c, z, h)

## Reference: [FIPS-204] sections 6-7 and algorithms 1-33; polynomial arithmetic and internal algorithm steps for `unpackSig`; pitfall: reject malformed or non-canonical input before indexed access.
proc unpackSig*(p: DilithiumParams, sig: openArray[byte]): DilithiumSignatureState {.raises: [].} =
  ## Reference: FIPS 204 algorithm 27, `HintBitUnpack`, steps 4-8. The
  ## per-polynomial indices must be strictly increasing and unused slots
  ## must be zero. In particular, keep `current <= previous` as rejection:
  ## changing it to `<` recreates the non-canonical-signature CVE class
  ## described by CVE-2026-24850 / GHSA-5x2r-hc65-25f9.
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
