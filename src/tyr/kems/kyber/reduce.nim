## ---------------------------------------------------------
## Kyber Reduce <- Montgomery and Barrett reduction helpers
## ---------------------------------------------------------

import ./params

when defined(avx2):
  import nimsimd/sse2 as nsse2
  import nimsimd/avx as navx
  import nimsimd/avx2 as navx2

{.push boundChecks: off.}

const
  kyberMont* = -1044'i16 ## 2^16 mod q
  kyberQInv* = -3327'i16 ## q^-1 mod 2^16
  kyberBarrettV = int32(((1 shl 26) + kyberQ div 2) div kyberQ)

## Reference: [KYBER-R3-20210804] version 3.02 sections 1.3 and 4, algorithms 1-9; finite-field, ring, and transform arithmetic for `montgomeryReduce`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc montgomeryReduce*(a: int32): int16 {.inline.} =
  ## Compute the Montgomery reduction of `a`.
  var
    t: int16 = 0
    m: int32 = 0
  m = int32(cast[int16](a)) * int32(kyberQInv)
  t = cast[int16](m)
  result = int16((a - int32(t) * kyberQ) shr 16)

## Reference: [KYBER-R3-20210804] version 3.02 sections 1.3 and 4, algorithms 1-9; finite-field, ring, and transform arithmetic for `barrettReduce`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc barrettReduce*(a: int16): int16 {.inline.} =
  ## Compute the centered Barrett reduction of `a`.
  var
    t: int16 = 0
  t = int16((kyberBarrettV * int32(a) + (1 shl 25)) shr 26)
  t = t * int16(kyberQ)
  result = a - t

when defined(avx2):
  ## Paper note: these AVX2 reduction helpers vectorize the same Montgomery and
  ## Barrett formulas used by Kyber, in the implementation style discussed in
  ## `2022-0112_kyber_dilithium_speed_memory_cortex_m4.pdf` and the AVX2 NTT
  ## paper `2018-0039_vectorized_ntt_implementations.pdf`.
  ## Reference: [KYBER-R3-20210804] version 3.02 sections 1.3 and 4, algorithms 1-9; finite-field, ring, and transform arithmetic for `low16ToI32x8`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc low16ToI32x8(v: navx.M256i): navx.M256i {.inline.} =
    result = navx2.mm256_slli_epi32(v, 16)
    result = navx2.mm256_srai_epi32(result, 16)

  ## Reference: [KYBER-R3-20210804] version 3.02 sections 1.3 and 4, algorithms 1-9; finite-field, ring, and transform arithmetic for `loadI16x8AsI32x8`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc loadI16x8AsI32x8*(p: ptr int16): navx.M256i {.inline.} =
    var
      lanes: nsse2.M128i = nsse2.mm_loadu_si128(cast[pointer](p))
    result = navx2.mm256_cvtepi16_epi32(lanes)

  ## Reference: [KYBER-R3-20210804] version 3.02 sections 1.3 and 4, algorithms 1-9; finite-field, ring, and transform arithmetic for `packStoreI32x8ToI16x8`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
  proc packStoreI32x8ToI16x8*(p: ptr int16, v: navx.M256i) {.inline.} =
    var
      lo: nsse2.M128i = navx.mm256_castsi256_si128(v)
      hi: nsse2.M128i = navx2.mm256_extracti128_si256(v, 1)
      packed: nsse2.M128i = nsse2.mm_packs_epi32(lo, hi)
    nsse2.mm_storeu_si128(cast[pointer](p), packed)

  ## Reference: [KYBER-R3-20210804] version 3.02 sections 1.3 and 4, algorithms 1-9; finite-field, ring, and transform arithmetic for `montgomeryReduceVec8`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc montgomeryReduceVec8*(a: navx.M256i): navx.M256i {.inline.} =
    var
      qInvVec: navx.M256i = navx.mm256_set1_epi32(int32(kyberQInv))
      qVec: navx.M256i = navx.mm256_set1_epi32(int32(kyberQ))
      t: navx.M256i = navx2.mm256_mullo_epi32(low16ToI32x8(a), qInvVec)
    t = low16ToI32x8(t)
    result = navx2.mm256_sub_epi32(a, navx2.mm256_mullo_epi32(t, qVec))
    result = navx2.mm256_srai_epi32(result, 16)

  ## Reference: [KYBER-R3-20210804] version 3.02 sections 1.3 and 4, algorithms 1-9; finite-field, ring, and transform arithmetic for `barrettReduceVec8`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc barrettReduceVec8*(a: navx.M256i): navx.M256i {.inline.} =
    var
      vVec: navx.M256i = navx.mm256_set1_epi32(kyberBarrettV)
      halfVec: navx.M256i = navx.mm256_set1_epi32(1 shl 25)
      qVec: navx.M256i = navx.mm256_set1_epi32(int32(kyberQ))
      t: navx.M256i = navx2.mm256_mullo_epi32(vVec, a)
    t = navx2.mm256_add_epi32(t, halfVec)
    t = navx2.mm256_srai_epi32(t, 26)
    result = navx2.mm256_sub_epi32(a, navx2.mm256_mullo_epi32(t, qVec))

  ## Reference: [KYBER-R3-20210804] version 3.02 sections 1.3 and 4, algorithms 1-9; finite-field, ring, and transform arithmetic for `montgomeryMulChunk8`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc montgomeryMulChunk8*(dst, src: ptr int16, factor: int16) {.inline.} =
    var
      srcVec: navx.M256i = loadI16x8AsI32x8(src)
      factorVec: navx.M256i = navx.mm256_set1_epi32(int32(factor))
      product: navx.M256i = navx2.mm256_mullo_epi32(srcVec, factorVec)
      reduced: navx.M256i = montgomeryReduceVec8(product)
    packStoreI32x8ToI16x8(dst, reduced)

  ## Reference: [KYBER-R3-20210804] version 3.02 sections 1.3 and 4, algorithms 1-9; finite-field, ring, and transform arithmetic for `barrettReduceChunk8`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc barrettReduceChunk8*(dst: ptr int16) {.inline.} =
    var
      srcVec: navx.M256i = loadI16x8AsI32x8(dst)
      reduced: navx.M256i = barrettReduceVec8(srcVec)
    packStoreI32x8ToI16x8(dst, reduced)

{.pop.}
