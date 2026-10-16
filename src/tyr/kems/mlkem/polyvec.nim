## ------------------------------------------------------
## ML-KEM PolyVec <- vector serialization and arithmetic
## ------------------------------------------------------

import ./params
import ./types
import ./poly
import ./ntt
import ./reduce

when defined(sse2) or defined(avx2):
  import nimsimd/sse2 as nsse2
when defined(avx2):
  import nimsimd/avx as navx
  import nimsimd/avx2 as navx2
when defined(neon) or defined(arm64) or defined(aarch64):
  import nimsimd/neon

{.push boundChecks: off.}

type
  ## Cached twiddle-scaled odd coefficients for one NTT-domain polynomial.
  ## Paper note: the cache is the local Nim analogue of the mul-cache style used
  ## in optimized ML-KEM implementations; see
  ## `2021-0986_neon_ntt_dilithium_kyber_saber.pdf` and
  ## `2018-0039_vectorized_ntt_implementations.pdf`.
  PolyMulCache* = array[mlkemN div 2, int16]
  ## Cached twiddle-scaled odd coefficients for one ML-KEM vector.
  PolyVecMulCache* = array[mlkemMaxK, PolyMulCache]

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; polynomial arithmetic and internal algorithm steps for `storeBaseMulAccReducedChunk4`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc storeBaseMulAccReducedChunk4(dst: ptr int16, evenTerms, oddTerms: array[4, int32]) {.inline.} =
  var
    dstData = cast[ptr UncheckedArray[int16]](dst)
    lane: int = 0
  lane = 0
  while lane < 4:
    dstData[2 * lane + 0] = montgomeryReduce(evenTerms[lane])
    dstData[2 * lane + 1] = montgomeryReduce(oddTerms[lane])
    lane = lane + 1

when defined(sse2):
  ## Paper note: this SSE2 path fuses cached twiddle terms with pairwise
  ## multiply-add lanes, differing from clean PQClean by avoiding repeated
  ## odd-coefficient twiddle multiplication in the hot polyvec accumulator.
  ## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; polynomial arithmetic and internal algorithm steps for `baseMulCachedTermsChunk4Sse2`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
  proc baseMulCachedTermsChunk4Sse2(aPtr, bPtr, cachePtr: ptr int16,
      acc0, acc1: var array[4, int32]) {.inline.} =
    var
      aData = cast[ptr UncheckedArray[int16]](aPtr)
      bData = cast[ptr UncheckedArray[int16]](bPtr)
      cacheData = cast[ptr UncheckedArray[int16]](cachePtr)
      evenTerms: array[8, int16] = default(array[8, int16])
      oddTerms: array[8, int16] = default(array[8, int16])
      evenVec: nsse2.M128i = default(nsse2.M128i)
      oddVec: nsse2.M128i = default(nsse2.M128i)
      aVec: nsse2.M128i = default(nsse2.M128i)
      tmp0: array[4, int32] = default(array[4, int32])
      tmp1: array[4, int32] = default(array[4, int32])
      lane: int = 0
    lane = 0
    while lane < 4:
      evenTerms[2 * lane + 0] = bData[2 * lane + 0]
      evenTerms[2 * lane + 1] = cacheData[lane]
      oddTerms[2 * lane + 0] = bData[2 * lane + 1]
      oddTerms[2 * lane + 1] = bData[2 * lane + 0]
      lane = lane + 1
    aVec = nsse2.mm_loadu_si128(cast[pointer](aPtr))
    evenVec = nsse2.mm_loadu_si128(cast[pointer](unsafeAddr evenTerms[0]))
    oddVec = nsse2.mm_loadu_si128(cast[pointer](unsafeAddr oddTerms[0]))
    nsse2.mm_storeu_si128(cast[pointer](unsafeAddr tmp0[0]), nsse2.mm_madd_epi16(aVec, evenVec))
    nsse2.mm_storeu_si128(cast[pointer](unsafeAddr tmp1[0]), nsse2.mm_madd_epi16(aVec, oddVec))
    lane = 0
    while lane < 4:
      acc0[lane] = acc0[lane] + tmp0[lane]
      acc1[lane] = acc1[lane] + tmp1[lane]
      lane = lane + 1

when defined(neon) or defined(arm64) or defined(aarch64):
  type
    NeonI16x4 {.importc: "int16x4_t", header: "arm_neon.h".} = object
    NeonI16x8 {.importc: "int16x8_t", header: "arm_neon.h".} = object

  ## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; polynomial arithmetic and internal algorithm steps for `vld1q_s16`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  func vld1q_s16(p: pointer): NeonI16x8 {.importc, header: "arm_neon.h".}
  ## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; polynomial arithmetic and internal algorithm steps for `vget_low_s16`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  func vget_low_s16(a: NeonI16x8): NeonI16x4 {.importc, header: "arm_neon.h".}
  ## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; polynomial arithmetic and internal algorithm steps for `vget_high_s16`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  func vget_high_s16(a: NeonI16x8): NeonI16x4 {.importc, header: "arm_neon.h".}
  ## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; polynomial arithmetic and internal algorithm steps for `vmull_s16`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  func vmull_s16(a, b: NeonI16x4): int32x4 {.importc, header: "arm_neon.h".}

  ## Paper note: NEON uses signed widening multiplies for the same cached
  ## base-multiply accumulator idea documented for ARM in
  ## `2021-0986_neon_ntt_dilithium_kyber_saber.pdf`.
  ## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; polynomial arithmetic and internal algorithm steps for `maddPairwiseChunk4Neon`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
  proc maddPairwiseChunk4Neon(aVec, bVec: NeonI16x8, acc: var array[4, int32]) {.inline.} =
    var
      lo: int32x4 = vmull_s16(vget_low_s16(aVec), vget_low_s16(bVec))
      hi: int32x4 = vmull_s16(vget_high_s16(aVec), vget_high_s16(bVec))
      loLanes: array[4, int32] = default(array[4, int32])
      hiLanes: array[4, int32] = default(array[4, int32])
    vst1q_s32(cast[pointer](unsafeAddr loLanes[0]), lo)
    vst1q_s32(cast[pointer](unsafeAddr hiLanes[0]), hi)
    acc[0] = acc[0] + loLanes[0] + loLanes[1]
    acc[1] = acc[1] + loLanes[2] + loLanes[3]
    acc[2] = acc[2] + hiLanes[0] + hiLanes[1]
    acc[3] = acc[3] + hiLanes[2] + hiLanes[3]

  ## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; polynomial arithmetic and internal algorithm steps for `baseMulCachedTermsChunk4Neon`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
  proc baseMulCachedTermsChunk4Neon(aPtr, bPtr, cachePtr: ptr int16,
      acc0, acc1: var array[4, int32]) {.inline.} =
    var
      bData = cast[ptr UncheckedArray[int16]](bPtr)
      cacheData = cast[ptr UncheckedArray[int16]](cachePtr)
      evenTerms: array[8, int16] = default(array[8, int16])
      oddTerms: array[8, int16] = default(array[8, int16])
      aVec: NeonI16x8 = default(NeonI16x8)
      evenVec: NeonI16x8 = default(NeonI16x8)
      oddVec: NeonI16x8 = default(NeonI16x8)
      lane: int = 0
    lane = 0
    while lane < 4:
      evenTerms[2 * lane + 0] = bData[2 * lane + 0]
      evenTerms[2 * lane + 1] = cacheData[lane]
      oddTerms[2 * lane + 0] = bData[2 * lane + 1]
      oddTerms[2 * lane + 1] = bData[2 * lane + 0]
      lane = lane + 1
    aVec = vld1q_s16(cast[pointer](aPtr))
    evenVec = vld1q_s16(cast[pointer](unsafeAddr evenTerms[0]))
    oddVec = vld1q_s16(cast[pointer](unsafeAddr oddTerms[0]))
    maddPairwiseChunk4Neon(aVec, evenVec, acc0)
    maddPairwiseChunk4Neon(aVec, oddVec, acc1)

when defined(avx2):
  ## Paper note: AVX2 packs four NTT base multiplications into one cached
  ## multiply-add chunk; this is the vectorized-NTT/mulcache idea applied at
  ## Tyr's Nim polyvec boundary instead of copying the upstream C layout.
  ## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; polynomial arithmetic and internal algorithm steps for `baseMulCachedTermsChunk8`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc baseMulCachedTermsChunk8(aPtr, bPtr, cachePtr: ptr int16, acc0, acc1: var navx.M256i) {.inline.} =
    var
      aVec: navx.M256i = navx2.mm256_loadu_si256(cast[pointer](aPtr))
      bVec: navx.M256i = navx2.mm256_loadu_si256(cast[pointer](bPtr))
      cacheVec: navx.M256i = loadI16x8AsI32x8(cachePtr)
      evenMask: navx.M256i = navx.mm256_set1_epi32(0x0000ffff'i32)
      evenCacheVec: navx.M256i = default(navx.M256i)
      oddEvenVec: navx.M256i = default(navx.M256i)
    evenCacheVec = navx2.mm256_and_si256(bVec, evenMask)
    evenCacheVec = navx2.mm256_or_si256(evenCacheVec, navx2.mm256_slli_epi32(cacheVec, 16))
    oddEvenVec = navx2.mm256_or_si256(navx2.mm256_srli_epi32(bVec, 16),
      navx2.mm256_slli_epi32(bVec, 16))
    acc0 = navx2.mm256_add_epi32(acc0, navx2.mm256_madd_epi16(aVec, evenCacheVec))
    acc1 = navx2.mm256_add_epi32(acc1, navx2.mm256_madd_epi16(aVec, oddEvenVec))

  ## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; polynomial arithmetic and internal algorithm steps for `storeBaseMulAccReducedChunk8`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc storeBaseMulAccReducedChunk8(dstLo, dstHi: ptr int16, evenTerms, oddTerms: navx.M256i) {.inline.} =
    var
      evenReduced: navx.M256i = montgomeryReduceVec8(evenTerms)
      oddReduced: navx.M256i = montgomeryReduceVec8(oddTerms)
      evenLo: nsse2.M128i = navx.mm256_castsi256_si128(evenReduced)
      evenHi: nsse2.M128i = navx2.mm256_extracti128_si256(evenReduced, 1)
      oddLo: nsse2.M128i = navx.mm256_castsi256_si128(oddReduced)
      oddHi: nsse2.M128i = navx2.mm256_extracti128_si256(oddReduced, 1)
      packedEvenLo: nsse2.M128i = nsse2.mm_packs_epi32(evenLo, evenLo)
      packedOddLo: nsse2.M128i = nsse2.mm_packs_epi32(oddLo, oddLo)
      packedEvenHi: nsse2.M128i = nsse2.mm_packs_epi32(evenHi, evenHi)
      packedOddHi: nsse2.M128i = nsse2.mm_packs_epi32(oddHi, oddHi)
      interleavedLo: nsse2.M128i = nsse2.mm_unpacklo_epi16(packedEvenLo, packedOddLo)
      interleavedHi: nsse2.M128i = nsse2.mm_unpacklo_epi16(packedEvenHi, packedOddHi)
    nsse2.mm_storeu_si128(cast[pointer](dstLo), interleavedLo)
    nsse2.mm_storeu_si128(cast[pointer](dstHi), interleavedHi)

## Reference: [FIPS-203] algorithm 4 ByteEncode_11 with Compress_11; packing rules for `compress11Block`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
proc compress11Block(dst: var openArray[byte], o: int, P: Poly, c: int) {.inline.} =
  ## dst/o: output and byte offset. P/c: polynomial and first of 8 coefficients.
  ##   8 numbers x 11 bits = 88 bits = 11 bytes
  var
    t8 {.noinit.}: array[8, uint16]
    k: int = 0
    u: int32 = 0
    d0: uint64 = 0
  while k < 8:
    u = int32(P.coeffs[c + k])
    u = u + ((u shr 15) and mlkemQ)
    d0 = ((uint64(u) shl 11) + 1664'u64) * 645084'u64
    t8[k] = uint16((d0 shr 31) and 0x7ff'u64)
    k = k + 1
  dst[o + 0] = byte(t8[0] shr 0)
  dst[o + 1] = byte((t8[0] shr 8) or (t8[1] shl 3))
  dst[o + 2] = byte((t8[1] shr 5) or (t8[2] shl 6))
  dst[o + 3] = byte(t8[2] shr 2)
  dst[o + 4] = byte((t8[2] shr 10) or (t8[3] shl 1))
  dst[o + 5] = byte((t8[3] shr 7) or (t8[4] shl 4))
  dst[o + 6] = byte((t8[4] shr 4) or (t8[5] shl 7))
  dst[o + 7] = byte(t8[5] shr 1)
  dst[o + 8] = byte((t8[5] shr 9) or (t8[6] shl 2))
  dst[o + 9] = byte((t8[6] shr 6) or (t8[7] shl 5))
  dst[o + 10] = byte(t8[7] shr 3)

## Reference: [FIPS-203] algorithm 4 ByteEncode_10 with Compress_10; packing rules for `compress10Block`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
proc compress10Block(dst: var openArray[byte], o: int, P: Poly, c: int) {.inline.} =
  ## dst/o: output and byte offset. P/c: polynomial and first of 4 coefficients.
  ##   4 numbers x 10 bits = 40 bits = 5 bytes
  var
    t4 {.noinit.}: array[4, uint16]
    k: int = 0
    u: int32 = 0
    d0: uint64 = 0
  while k < 4:
    u = int32(P.coeffs[c + k])
    u = u + ((u shr 15) and mlkemQ)
    d0 = ((uint64(u) shl 10) + 1665'u64) * 1290167'u64
    t4[k] = uint16((d0 shr 32) and 0x3ff'u64)
    k = k + 1
  dst[o + 0] = byte(t4[0] shr 0)
  dst[o + 1] = byte((t4[0] shr 8) or (t4[1] shl 2))
  dst[o + 2] = byte((t4[1] shr 6) or (t4[2] shl 4))
  dst[o + 3] = byte((t4[2] shr 4) or (t4[3] shl 6))
  dst[o + 4] = byte(t4[3] shr 2)

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; polynomial arithmetic and internal algorithm steps for `polyvecCompressInto`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyvecCompressInto*(dst: var openArray[byte], p: MlKemParams, a: PolyVec) =
  ## Compress and serialize a ML-KEM polynomial vector into a caller-provided buffer.
  ##   11 bits per number (ML-KEM-1024) or 10 bits (512 / 768)
  var
    i: int = 0
    j: int = 0
  if dst.len != p.polyVecCompressedBytes:
    raise newException(ValueError, "invalid ML-KEM compressed polyvec length")
  if p.polyVecCompressedBytes == p.k * 352:
    while i < p.k:
      j = 0
      while j < mlkemN div 8:
        compress11Block(dst, i * 352 + j * 11, a.vec[i], 8 * j)
        j = j + 1
      i = i + 1
    return
  if p.polyVecCompressedBytes == p.k * 320:
    while i < p.k:
      j = 0
      while j < mlkemN div 4:
        compress10Block(dst, i * 320 + j * 5, a.vec[i], 4 * j)
        j = j + 1
      i = i + 1
    return
  raise newException(ValueError, "unsupported ML-KEM polyvec compression size")

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; polynomial arithmetic and internal algorithm steps for `polyvecCompress`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyvecCompress*(p: MlKemParams, a: PolyVec): seq[byte] =
  ## Compress and serialize a ML-KEM polynomial vector.
  result = newSeq[byte](p.polyVecCompressedBytes)
  polyvecCompressInto(result, p, a)

## Reference: [FIPS-203] algorithm 6 ByteDecode_11 with Decompress_11; unpacking rules for `decompress11Block`; pitfall: reject malformed or non-canonical input before indexed access.
proc decompress11Block(P: var Poly, c: int, A: openArray[byte], o: int) {.inline.} =
  ## P/c: polynomial and first of 8 coefficients. A/o: input and byte offset.
  ##   11 bytes -> 8 numbers of 11 bits -> each * q / 2^11, rounded
  var
    t8 {.noinit.}: array[8, uint16]
    k: int = 0
  t8[0] = (uint16(A[o + 0]) shr 0) or (uint16(A[o + 1]) shl 8)
  t8[1] = (uint16(A[o + 1]) shr 3) or (uint16(A[o + 2]) shl 5)
  t8[2] = (uint16(A[o + 2]) shr 6) or (uint16(A[o + 3]) shl 2) or (uint16(A[o + 4]) shl 10)
  t8[3] = (uint16(A[o + 4]) shr 1) or (uint16(A[o + 5]) shl 7)
  t8[4] = (uint16(A[o + 5]) shr 4) or (uint16(A[o + 6]) shl 4)
  t8[5] = (uint16(A[o + 6]) shr 7) or (uint16(A[o + 7]) shl 1) or (uint16(A[o + 8]) shl 9)
  t8[6] = (uint16(A[o + 8]) shr 2) or (uint16(A[o + 9]) shl 6)
  t8[7] = (uint16(A[o + 9]) shr 5) or (uint16(A[o + 10]) shl 3)
  while k < 8:
    P.coeffs[c + k] = int16(((uint32(t8[k] and 0x7ff'u16) * uint32(mlkemQ)) + 1024'u32) shr 11)
    k = k + 1

## Reference: [FIPS-203] algorithm 6 ByteDecode_10 with Decompress_10; unpacking rules for `decompress10Block`; pitfall: reject malformed or non-canonical input before indexed access.
proc decompress10Block(P: var Poly, c: int, A: openArray[byte], o: int) {.inline.} =
  ## P/c: polynomial and first of 4 coefficients. A/o: input and byte offset.
  ##   5 bytes -> 4 numbers of 10 bits -> each * q / 2^10, rounded
  var
    t4 {.noinit.}: array[4, uint16]
    k: int = 0
  t4[0] = (uint16(A[o + 0]) shr 0) or (uint16(A[o + 1]) shl 8)
  t4[1] = (uint16(A[o + 1]) shr 2) or (uint16(A[o + 2]) shl 6)
  t4[2] = (uint16(A[o + 2]) shr 4) or (uint16(A[o + 3]) shl 4)
  t4[3] = (uint16(A[o + 3]) shr 6) or (uint16(A[o + 4]) shl 2)
  while k < 4:
    P.coeffs[c + k] = int16(((uint32(t4[k] and 0x3ff'u16) * uint32(mlkemQ)) + 512'u32) shr 10)
    k = k + 1

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; polynomial arithmetic and internal algorithm steps for `polyvecDecompressInto`; pitfall: reject malformed or non-canonical input before indexed access.
proc polyvecDecompressInto*(r: var PolyVec, p: MlKemParams, A: openArray[byte]) =
  ## Decompress and deserialize a ML-KEM polynomial vector into a caller-provided vector.
  ##   11 bits per number (ML-KEM-1024) or 10 bits (512 / 768)
  var
    i: int = 0
    j: int = 0
  if A.len != p.polyVecCompressedBytes:
    raise newException(ValueError, "invalid ML-KEM compressed polyvec length")
  if p.polyVecCompressedBytes == p.k * 352:
    while i < p.k:
      j = 0
      while j < mlkemN div 8:
        decompress11Block(r.vec[i], 8 * j, A, i * 352 + j * 11)
        j = j + 1
      i = i + 1
    return
  if p.polyVecCompressedBytes == p.k * 320:
    while i < p.k:
      j = 0
      while j < mlkemN div 4:
        decompress10Block(r.vec[i], 4 * j, A, i * 320 + j * 5)
        j = j + 1
      i = i + 1
    return
  raise newException(ValueError, "unsupported ML-KEM polyvec compression size")

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; polynomial arithmetic and internal algorithm steps for `polyvecDecompress`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyvecDecompress*(p: MlKemParams, A: openArray[byte]): PolyVec =
  ## Decompress and deserialize a ML-KEM polynomial vector.
  polyvecDecompressInto(result, p, A)

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; polynomial arithmetic and internal algorithm steps for `polyvecToBytesInto`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyvecToBytesInto*(dst: var openArray[byte], p: MlKemParams, a: PolyVec) {.inline.} =
  ## Serialize a ML-KEM polynomial vector into a caller-provided buffer.
  var
    i: int = 0
    o: int = 0
  if dst.len != p.k * mlkemPolyBytes:
    raise newException(ValueError, "invalid ML-KEM polyvec byte length")
  case p.k
  of 2:
    polyToBytesInto(dst.toOpenArray(0, mlkemPolyBytes - 1), a.vec[0])
    polyToBytesInto(dst.toOpenArray(mlkemPolyBytes, 2 * mlkemPolyBytes - 1), a.vec[1])
  of 3:
    polyToBytesInto(dst.toOpenArray(0, mlkemPolyBytes - 1), a.vec[0])
    polyToBytesInto(dst.toOpenArray(mlkemPolyBytes, 2 * mlkemPolyBytes - 1), a.vec[1])
    polyToBytesInto(dst.toOpenArray(2 * mlkemPolyBytes, 3 * mlkemPolyBytes - 1), a.vec[2])
  of 4:
    polyToBytesInto(dst.toOpenArray(0, mlkemPolyBytes - 1), a.vec[0])
    polyToBytesInto(dst.toOpenArray(mlkemPolyBytes, 2 * mlkemPolyBytes - 1), a.vec[1])
    polyToBytesInto(dst.toOpenArray(2 * mlkemPolyBytes, 3 * mlkemPolyBytes - 1), a.vec[2])
    polyToBytesInto(dst.toOpenArray(3 * mlkemPolyBytes, 4 * mlkemPolyBytes - 1), a.vec[3])
  else:
    i = 0
    while i < p.k:
      o = i * mlkemPolyBytes
      polyToBytesInto(dst.toOpenArray(o, o + mlkemPolyBytes - 1), a.vec[i])
      i = i + 1

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; polynomial arithmetic and internal algorithm steps for `polyvecToBytes`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyvecToBytes*(p: MlKemParams, a: PolyVec): seq[byte] =
  ## Serialize a ML-KEM polynomial vector.
  result = newSeq[byte](p.k * mlkemPolyBytes)
  polyvecToBytesInto(result, p, a)

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; polynomial arithmetic and internal algorithm steps for `polyvecFromBytesInto`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyvecFromBytesInto*(r: var PolyVec, p: MlKemParams, A: openArray[byte]) {.inline.} =
  ## Deserialize a ML-KEM polynomial vector into a caller-provided vector.
  var
    i: int = 0
    o: int = 0
  if A.len != p.k * mlkemPolyBytes:
    raise newException(ValueError, "invalid ML-KEM polyvec byte length")
  case p.k
  of 2:
    polyFromBytesInto(r.vec[0], A.toOpenArray(0, mlkemPolyBytes - 1))
    polyFromBytesInto(r.vec[1], A.toOpenArray(mlkemPolyBytes, 2 * mlkemPolyBytes - 1))
  of 3:
    polyFromBytesInto(r.vec[0], A.toOpenArray(0, mlkemPolyBytes - 1))
    polyFromBytesInto(r.vec[1], A.toOpenArray(mlkemPolyBytes, 2 * mlkemPolyBytes - 1))
    polyFromBytesInto(r.vec[2], A.toOpenArray(2 * mlkemPolyBytes, 3 * mlkemPolyBytes - 1))
  of 4:
    polyFromBytesInto(r.vec[0], A.toOpenArray(0, mlkemPolyBytes - 1))
    polyFromBytesInto(r.vec[1], A.toOpenArray(mlkemPolyBytes, 2 * mlkemPolyBytes - 1))
    polyFromBytesInto(r.vec[2], A.toOpenArray(2 * mlkemPolyBytes, 3 * mlkemPolyBytes - 1))
    polyFromBytesInto(r.vec[3], A.toOpenArray(3 * mlkemPolyBytes, 4 * mlkemPolyBytes - 1))
  else:
    i = 0
    while i < p.k:
      o = i * mlkemPolyBytes
      polyFromBytesInto(r.vec[i], A.toOpenArray(o, o + mlkemPolyBytes - 1))
      i = i + 1

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; polynomial arithmetic and internal algorithm steps for `polyvecFromBytes`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyvecFromBytes*(p: MlKemParams, A: openArray[byte]): PolyVec =
  ## Deserialize a ML-KEM polynomial vector.
  polyvecFromBytesInto(result, p, A)

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; polynomial arithmetic and internal algorithm steps for `polyvecNtt`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyvecNtt*(p: MlKemParams, r: var PolyVec) {.inline.} =
  ## Apply forward NTT to each vector element.
  case p.k
  of 2:
    polyNtt(r.vec[0])
    polyNtt(r.vec[1])
  of 3:
    polyNtt(r.vec[0])
    polyNtt(r.vec[1])
    polyNtt(r.vec[2])
  of 4:
    polyNtt(r.vec[0])
    polyNtt(r.vec[1])
    polyNtt(r.vec[2])
    polyNtt(r.vec[3])
  else:
    var
      i: int = 0
    while i < p.k:
      polyNtt(r.vec[i])
      i = i + 1

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; polynomial arithmetic and internal algorithm steps for `polyvecInvNttToMont`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyvecInvNttToMont*(p: MlKemParams, r: var PolyVec) {.inline.} =
  ## Apply inverse NTT to each vector element.
  case p.k
  of 2:
    polyInvNttToMont(r.vec[0])
    polyInvNttToMont(r.vec[1])
  of 3:
    polyInvNttToMont(r.vec[0])
    polyInvNttToMont(r.vec[1])
    polyInvNttToMont(r.vec[2])
  of 4:
    polyInvNttToMont(r.vec[0])
    polyInvNttToMont(r.vec[1])
    polyInvNttToMont(r.vec[2])
    polyInvNttToMont(r.vec[3])
  else:
    var
      i: int = 0
    while i < p.k:
      polyInvNttToMont(r.vec[i])
      i = i + 1

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; polynomial arithmetic and internal algorithm steps for `polyvecBaseMulAccMontgomery`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyvecBaseMulAccMontgomery*(p: MlKemParams, r: var Poly, a, b: PolyVec) {.inline.} =
  ## Multiply and accumulate two ML-KEM polynomial vectors.
  var
    i: int = 1
    t {.noinit.}: Poly
  polyBaseMulMontgomery(r, a.vec[0], b.vec[0])
  i = 1
  while i < p.k:
    polyBaseMulMontgomery(t, a.vec[i], b.vec[i])
    polyAdd(r, r, t)
    i = i + 1
  polyReduce(r)

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; polynomial arithmetic and internal algorithm steps for `polyMulCacheCompute`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyMulCacheCompute*(x: var PolyMulCache, a: Poly) {.inline.} =
  ## Precompute the twiddle-scaled odd coefficients used in NTT base multiplication.
  var
    i: int = 0
  i = 0
  while i < mlkemN div 4:
    x[2 * i + 0] = montgomeryReduce(int32(a.coeffs[4 * i + 1]) * int32(zetas[64 + i]))
    x[2 * i + 1] = montgomeryReduce(int32(a.coeffs[4 * i + 3]) * int32(-zetas[64 + i]))
    i = i + 1

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; polynomial arithmetic and internal algorithm steps for `polyvecMulCacheCompute`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyvecMulCacheCompute*(p: MlKemParams, x: var PolyVecMulCache, a: PolyVec) {.inline.} =
  ## Precompute twiddle-scaled odd coefficients for a ML-KEM polynomial vector.
  case p.k
  of 2:
    polyMulCacheCompute(x[0], a.vec[0])
    polyMulCacheCompute(x[1], a.vec[1])
  of 3:
    polyMulCacheCompute(x[0], a.vec[0])
    polyMulCacheCompute(x[1], a.vec[1])
    polyMulCacheCompute(x[2], a.vec[2])
  of 4:
    polyMulCacheCompute(x[0], a.vec[0])
    polyMulCacheCompute(x[1], a.vec[1])
    polyMulCacheCompute(x[2], a.vec[2])
    polyMulCacheCompute(x[3], a.vec[3])
  else:
    var
      i: int = 0
    while i < p.k:
      polyMulCacheCompute(x[i], a.vec[i])
      i = i + 1

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; polynomial arithmetic and internal algorithm steps for `polyvecBaseMulAccMontgomeryCached`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyvecBaseMulAccMontgomeryCached*(p: MlKemParams, r: var Poly, a, b: PolyVec,
    bCache: var PolyVecMulCache) {.inline.} =
  ## Multiply and accumulate two ML-KEM polynomial vectors using a cached second operand.
  ## Paper note: this differs from the clean reference accumulator by consuming
  ## `PolyVecMulCache` across fixed public `k` cases, then reducing once.
  var
    i: int = 0
    t0: int32 = 0
    t1: int32 = 0
  when defined(avx2):
    var
      acc0: navx.M256i = default(navx.M256i)
      acc1: navx.M256i = default(navx.M256i)
  i = 0
  case p.k
  of 2:
    when defined(avx2):
      while i + 8 <= mlkemN div 2:
        acc0 = navx2.mm256_setzero_si256()
        acc1 = navx2.mm256_setzero_si256()
        baseMulCachedTermsChunk8(unsafeAddr a.vec[0].coeffs[2 * i], unsafeAddr b.vec[0].coeffs[2 * i],
          unsafeAddr bCache[0][i], acc0, acc1)
        baseMulCachedTermsChunk8(unsafeAddr a.vec[1].coeffs[2 * i], unsafeAddr b.vec[1].coeffs[2 * i],
          unsafeAddr bCache[1][i], acc0, acc1)
        storeBaseMulAccReducedChunk8(unsafeAddr r.coeffs[2 * i], unsafeAddr r.coeffs[2 * i + 8], acc0, acc1)
        i = i + 8
    when defined(sse2):
      while i + 4 <= mlkemN div 2:
        var
          acc0x4: array[4, int32] = default(array[4, int32])
          acc1x4: array[4, int32] = default(array[4, int32])
        baseMulCachedTermsChunk4Sse2(unsafeAddr a.vec[0].coeffs[2 * i], unsafeAddr b.vec[0].coeffs[2 * i],
          unsafeAddr bCache[0][i], acc0x4, acc1x4)
        baseMulCachedTermsChunk4Sse2(unsafeAddr a.vec[1].coeffs[2 * i], unsafeAddr b.vec[1].coeffs[2 * i],
          unsafeAddr bCache[1][i], acc0x4, acc1x4)
        storeBaseMulAccReducedChunk4(unsafeAddr r.coeffs[2 * i], acc0x4, acc1x4)
        i = i + 4
    when defined(neon) or defined(arm64) or defined(aarch64):
      while i + 4 <= mlkemN div 2:
        var
          acc0x4: array[4, int32] = default(array[4, int32])
          acc1x4: array[4, int32] = default(array[4, int32])
        baseMulCachedTermsChunk4Neon(unsafeAddr a.vec[0].coeffs[2 * i], unsafeAddr b.vec[0].coeffs[2 * i],
          unsafeAddr bCache[0][i], acc0x4, acc1x4)
        baseMulCachedTermsChunk4Neon(unsafeAddr a.vec[1].coeffs[2 * i], unsafeAddr b.vec[1].coeffs[2 * i],
          unsafeAddr bCache[1][i], acc0x4, acc1x4)
        storeBaseMulAccReducedChunk4(unsafeAddr r.coeffs[2 * i], acc0x4, acc1x4)
        i = i + 4
    while i < mlkemN div 2:
      t0 =
        int32(a.vec[0].coeffs[2 * i + 1]) * int32(bCache[0][i]) +
        int32(a.vec[0].coeffs[2 * i + 0]) * int32(b.vec[0].coeffs[2 * i + 0]) +
        int32(a.vec[1].coeffs[2 * i + 1]) * int32(bCache[1][i]) +
        int32(a.vec[1].coeffs[2 * i + 0]) * int32(b.vec[1].coeffs[2 * i + 0])
      t1 =
        int32(a.vec[0].coeffs[2 * i + 0]) * int32(b.vec[0].coeffs[2 * i + 1]) +
        int32(a.vec[0].coeffs[2 * i + 1]) * int32(b.vec[0].coeffs[2 * i + 0]) +
        int32(a.vec[1].coeffs[2 * i + 0]) * int32(b.vec[1].coeffs[2 * i + 1]) +
        int32(a.vec[1].coeffs[2 * i + 1]) * int32(b.vec[1].coeffs[2 * i + 0])
      r.coeffs[2 * i + 0] = montgomeryReduce(t0)
      r.coeffs[2 * i + 1] = montgomeryReduce(t1)
      i = i + 1
  of 3:
    when defined(avx2):
      while i + 8 <= mlkemN div 2:
        acc0 = navx2.mm256_setzero_si256()
        acc1 = navx2.mm256_setzero_si256()
        baseMulCachedTermsChunk8(unsafeAddr a.vec[0].coeffs[2 * i], unsafeAddr b.vec[0].coeffs[2 * i],
          unsafeAddr bCache[0][i], acc0, acc1)
        baseMulCachedTermsChunk8(unsafeAddr a.vec[1].coeffs[2 * i], unsafeAddr b.vec[1].coeffs[2 * i],
          unsafeAddr bCache[1][i], acc0, acc1)
        baseMulCachedTermsChunk8(unsafeAddr a.vec[2].coeffs[2 * i], unsafeAddr b.vec[2].coeffs[2 * i],
          unsafeAddr bCache[2][i], acc0, acc1)
        storeBaseMulAccReducedChunk8(unsafeAddr r.coeffs[2 * i], unsafeAddr r.coeffs[2 * i + 8], acc0, acc1)
        i = i + 8
    when defined(sse2):
      while i + 4 <= mlkemN div 2:
        var
          acc0x4: array[4, int32] = default(array[4, int32])
          acc1x4: array[4, int32] = default(array[4, int32])
        baseMulCachedTermsChunk4Sse2(unsafeAddr a.vec[0].coeffs[2 * i], unsafeAddr b.vec[0].coeffs[2 * i],
          unsafeAddr bCache[0][i], acc0x4, acc1x4)
        baseMulCachedTermsChunk4Sse2(unsafeAddr a.vec[1].coeffs[2 * i], unsafeAddr b.vec[1].coeffs[2 * i],
          unsafeAddr bCache[1][i], acc0x4, acc1x4)
        baseMulCachedTermsChunk4Sse2(unsafeAddr a.vec[2].coeffs[2 * i], unsafeAddr b.vec[2].coeffs[2 * i],
          unsafeAddr bCache[2][i], acc0x4, acc1x4)
        storeBaseMulAccReducedChunk4(unsafeAddr r.coeffs[2 * i], acc0x4, acc1x4)
        i = i + 4
    when defined(neon) or defined(arm64) or defined(aarch64):
      while i + 4 <= mlkemN div 2:
        var
          acc0x4: array[4, int32] = default(array[4, int32])
          acc1x4: array[4, int32] = default(array[4, int32])
        baseMulCachedTermsChunk4Neon(unsafeAddr a.vec[0].coeffs[2 * i], unsafeAddr b.vec[0].coeffs[2 * i],
          unsafeAddr bCache[0][i], acc0x4, acc1x4)
        baseMulCachedTermsChunk4Neon(unsafeAddr a.vec[1].coeffs[2 * i], unsafeAddr b.vec[1].coeffs[2 * i],
          unsafeAddr bCache[1][i], acc0x4, acc1x4)
        baseMulCachedTermsChunk4Neon(unsafeAddr a.vec[2].coeffs[2 * i], unsafeAddr b.vec[2].coeffs[2 * i],
          unsafeAddr bCache[2][i], acc0x4, acc1x4)
        storeBaseMulAccReducedChunk4(unsafeAddr r.coeffs[2 * i], acc0x4, acc1x4)
        i = i + 4
    while i < mlkemN div 2:
      t0 =
        int32(a.vec[0].coeffs[2 * i + 1]) * int32(bCache[0][i]) +
        int32(a.vec[0].coeffs[2 * i + 0]) * int32(b.vec[0].coeffs[2 * i + 0]) +
        int32(a.vec[1].coeffs[2 * i + 1]) * int32(bCache[1][i]) +
        int32(a.vec[1].coeffs[2 * i + 0]) * int32(b.vec[1].coeffs[2 * i + 0]) +
        int32(a.vec[2].coeffs[2 * i + 1]) * int32(bCache[2][i]) +
        int32(a.vec[2].coeffs[2 * i + 0]) * int32(b.vec[2].coeffs[2 * i + 0])
      t1 =
        int32(a.vec[0].coeffs[2 * i + 0]) * int32(b.vec[0].coeffs[2 * i + 1]) +
        int32(a.vec[0].coeffs[2 * i + 1]) * int32(b.vec[0].coeffs[2 * i + 0]) +
        int32(a.vec[1].coeffs[2 * i + 0]) * int32(b.vec[1].coeffs[2 * i + 1]) +
        int32(a.vec[1].coeffs[2 * i + 1]) * int32(b.vec[1].coeffs[2 * i + 0]) +
        int32(a.vec[2].coeffs[2 * i + 0]) * int32(b.vec[2].coeffs[2 * i + 1]) +
        int32(a.vec[2].coeffs[2 * i + 1]) * int32(b.vec[2].coeffs[2 * i + 0])
      r.coeffs[2 * i + 0] = montgomeryReduce(t0)
      r.coeffs[2 * i + 1] = montgomeryReduce(t1)
      i = i + 1
  of 4:
    when defined(avx2):
      while i + 8 <= mlkemN div 2:
        acc0 = navx2.mm256_setzero_si256()
        acc1 = navx2.mm256_setzero_si256()
        baseMulCachedTermsChunk8(unsafeAddr a.vec[0].coeffs[2 * i], unsafeAddr b.vec[0].coeffs[2 * i],
          unsafeAddr bCache[0][i], acc0, acc1)
        baseMulCachedTermsChunk8(unsafeAddr a.vec[1].coeffs[2 * i], unsafeAddr b.vec[1].coeffs[2 * i],
          unsafeAddr bCache[1][i], acc0, acc1)
        baseMulCachedTermsChunk8(unsafeAddr a.vec[2].coeffs[2 * i], unsafeAddr b.vec[2].coeffs[2 * i],
          unsafeAddr bCache[2][i], acc0, acc1)
        baseMulCachedTermsChunk8(unsafeAddr a.vec[3].coeffs[2 * i], unsafeAddr b.vec[3].coeffs[2 * i],
          unsafeAddr bCache[3][i], acc0, acc1)
        storeBaseMulAccReducedChunk8(unsafeAddr r.coeffs[2 * i], unsafeAddr r.coeffs[2 * i + 8], acc0, acc1)
        i = i + 8
    when defined(sse2):
      while i + 4 <= mlkemN div 2:
        var
          acc0x4: array[4, int32] = default(array[4, int32])
          acc1x4: array[4, int32] = default(array[4, int32])
        baseMulCachedTermsChunk4Sse2(unsafeAddr a.vec[0].coeffs[2 * i], unsafeAddr b.vec[0].coeffs[2 * i],
          unsafeAddr bCache[0][i], acc0x4, acc1x4)
        baseMulCachedTermsChunk4Sse2(unsafeAddr a.vec[1].coeffs[2 * i], unsafeAddr b.vec[1].coeffs[2 * i],
          unsafeAddr bCache[1][i], acc0x4, acc1x4)
        baseMulCachedTermsChunk4Sse2(unsafeAddr a.vec[2].coeffs[2 * i], unsafeAddr b.vec[2].coeffs[2 * i],
          unsafeAddr bCache[2][i], acc0x4, acc1x4)
        baseMulCachedTermsChunk4Sse2(unsafeAddr a.vec[3].coeffs[2 * i], unsafeAddr b.vec[3].coeffs[2 * i],
          unsafeAddr bCache[3][i], acc0x4, acc1x4)
        storeBaseMulAccReducedChunk4(unsafeAddr r.coeffs[2 * i], acc0x4, acc1x4)
        i = i + 4
    when defined(neon) or defined(arm64) or defined(aarch64):
      while i + 4 <= mlkemN div 2:
        var
          acc0x4: array[4, int32] = default(array[4, int32])
          acc1x4: array[4, int32] = default(array[4, int32])
        baseMulCachedTermsChunk4Neon(unsafeAddr a.vec[0].coeffs[2 * i], unsafeAddr b.vec[0].coeffs[2 * i],
          unsafeAddr bCache[0][i], acc0x4, acc1x4)
        baseMulCachedTermsChunk4Neon(unsafeAddr a.vec[1].coeffs[2 * i], unsafeAddr b.vec[1].coeffs[2 * i],
          unsafeAddr bCache[1][i], acc0x4, acc1x4)
        baseMulCachedTermsChunk4Neon(unsafeAddr a.vec[2].coeffs[2 * i], unsafeAddr b.vec[2].coeffs[2 * i],
          unsafeAddr bCache[2][i], acc0x4, acc1x4)
        baseMulCachedTermsChunk4Neon(unsafeAddr a.vec[3].coeffs[2 * i], unsafeAddr b.vec[3].coeffs[2 * i],
          unsafeAddr bCache[3][i], acc0x4, acc1x4)
        storeBaseMulAccReducedChunk4(unsafeAddr r.coeffs[2 * i], acc0x4, acc1x4)
        i = i + 4
    while i < mlkemN div 2:
      t0 =
        int32(a.vec[0].coeffs[2 * i + 1]) * int32(bCache[0][i]) +
        int32(a.vec[0].coeffs[2 * i + 0]) * int32(b.vec[0].coeffs[2 * i + 0]) +
        int32(a.vec[1].coeffs[2 * i + 1]) * int32(bCache[1][i]) +
        int32(a.vec[1].coeffs[2 * i + 0]) * int32(b.vec[1].coeffs[2 * i + 0]) +
        int32(a.vec[2].coeffs[2 * i + 1]) * int32(bCache[2][i]) +
        int32(a.vec[2].coeffs[2 * i + 0]) * int32(b.vec[2].coeffs[2 * i + 0]) +
        int32(a.vec[3].coeffs[2 * i + 1]) * int32(bCache[3][i]) +
        int32(a.vec[3].coeffs[2 * i + 0]) * int32(b.vec[3].coeffs[2 * i + 0])
      t1 =
        int32(a.vec[0].coeffs[2 * i + 0]) * int32(b.vec[0].coeffs[2 * i + 1]) +
        int32(a.vec[0].coeffs[2 * i + 1]) * int32(b.vec[0].coeffs[2 * i + 0]) +
        int32(a.vec[1].coeffs[2 * i + 0]) * int32(b.vec[1].coeffs[2 * i + 1]) +
        int32(a.vec[1].coeffs[2 * i + 1]) * int32(b.vec[1].coeffs[2 * i + 0]) +
        int32(a.vec[2].coeffs[2 * i + 0]) * int32(b.vec[2].coeffs[2 * i + 1]) +
        int32(a.vec[2].coeffs[2 * i + 1]) * int32(b.vec[2].coeffs[2 * i + 0]) +
        int32(a.vec[3].coeffs[2 * i + 0]) * int32(b.vec[3].coeffs[2 * i + 1]) +
        int32(a.vec[3].coeffs[2 * i + 1]) * int32(b.vec[3].coeffs[2 * i + 0])
      r.coeffs[2 * i + 0] = montgomeryReduce(t0)
      r.coeffs[2 * i + 1] = montgomeryReduce(t1)
      i = i + 1
  else:
    var
      k: int = 0
    while i < mlkemN div 2:
      t0 = 0
      t1 = 0
      k = 0
      while k < p.k:
        t0 = t0 + int32(a.vec[k].coeffs[2 * i + 1]) * int32(bCache[k][i])
        t0 = t0 + int32(a.vec[k].coeffs[2 * i + 0]) * int32(b.vec[k].coeffs[2 * i + 0])
        t1 = t1 + int32(a.vec[k].coeffs[2 * i + 0]) * int32(b.vec[k].coeffs[2 * i + 1])
        t1 = t1 + int32(a.vec[k].coeffs[2 * i + 1]) * int32(b.vec[k].coeffs[2 * i + 0])
        k = k + 1
      r.coeffs[2 * i + 0] = montgomeryReduce(t0)
      r.coeffs[2 * i + 1] = montgomeryReduce(t1)
      i = i + 1
  polyReduce(r)

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; polynomial arithmetic and internal algorithm steps for `polyvecReduce`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyvecReduce*(p: MlKemParams, r: var PolyVec) {.inline.} =
  ## Apply Barrett reduction to all coefficients of all vector elements.
  case p.k
  of 2:
    polyReduce(r.vec[0])
    polyReduce(r.vec[1])
  of 3:
    polyReduce(r.vec[0])
    polyReduce(r.vec[1])
    polyReduce(r.vec[2])
  of 4:
    polyReduce(r.vec[0])
    polyReduce(r.vec[1])
    polyReduce(r.vec[2])
    polyReduce(r.vec[3])
  else:
    var
      i: int = 0
    while i < p.k:
      polyReduce(r.vec[i])
      i = i + 1

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; polynomial arithmetic and internal algorithm steps for `polyvecAdd`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyvecAdd*(p: MlKemParams, r: var PolyVec, a, b: PolyVec) {.inline.} =
  ## Add two ML-KEM polynomial vectors.
  case p.k
  of 2:
    polyAdd(r.vec[0], a.vec[0], b.vec[0])
    polyAdd(r.vec[1], a.vec[1], b.vec[1])
  of 3:
    polyAdd(r.vec[0], a.vec[0], b.vec[0])
    polyAdd(r.vec[1], a.vec[1], b.vec[1])
    polyAdd(r.vec[2], a.vec[2], b.vec[2])
  of 4:
    polyAdd(r.vec[0], a.vec[0], b.vec[0])
    polyAdd(r.vec[1], a.vec[1], b.vec[1])
    polyAdd(r.vec[2], a.vec[2], b.vec[2])
    polyAdd(r.vec[3], a.vec[3], b.vec[3])
  else:
    var
      i: int = 0
    while i < p.k:
      polyAdd(r.vec[i], a.vec[i], b.vec[i])
      i = i + 1

{.pop.}
