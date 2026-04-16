## ------------------------------------------------------
## Kyber PolyVec <- vector serialization and arithmetic
## ------------------------------------------------------

import ./params
import ./types
import ./poly
import ./ntt
import ./reduce

{.push boundChecks: off.}

type
  ## Cached twiddle-scaled odd coefficients for one NTT-domain polynomial.
  PolyMulCache* = array[kyberN div 2, int16]
  ## Cached twiddle-scaled odd coefficients for one Kyber vector.
  PolyVecMulCache* = array[kyberMaxK, PolyMulCache]

proc polyvecCompressInto*(dst: var openArray[byte], p: KyberParams, a: PolyVec) =
  ## Compress and serialize a Kyber polynomial vector into a caller-provided buffer.
  var
    i: int = 0
    j: int = 0
    k: int = 0
    o: int = 0
    d0: uint64 = 0
    t8 {.noinit.}: array[8, uint16]
    t4 {.noinit.}: array[4, uint16]
    u: int32 = 0
  if dst.len != p.polyVecCompressedBytes:
    raise newException(ValueError, "invalid Kyber compressed polyvec length")
  if p.polyVecCompressedBytes == p.k * 352:
    i = 0
    while i < p.k:
      j = 0
      while j < kyberN div 8:
        k = 0
        while k < 8:
          u = int32(a.vec[i].coeffs[8 * j + k])
          u = u + ((u shr 15) and kyberQ)
          d0 = uint64(u)
          d0 = d0 shl 11
          d0 = d0 + 1664'u64
          d0 = d0 * 645084'u64
          d0 = d0 shr 31
          t8[k] = uint16(d0 and 0x7ff'u64)
          k = k + 1
        o = i * (kyberN div 8) * 11 + j * 11
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
        j = j + 1
      i = i + 1
    return

  if p.polyVecCompressedBytes == p.k * 320:
    i = 0
    while i < p.k:
      j = 0
      while j < kyberN div 4:
        k = 0
        while k < 4:
          u = int32(a.vec[i].coeffs[4 * j + k])
          u = u + ((u shr 15) and kyberQ)
          d0 = uint64(u)
          d0 = d0 shl 10
          d0 = d0 + 1665'u64
          d0 = d0 * 1290167'u64
          d0 = d0 shr 32
          t4[k] = uint16(d0 and 0x3ff'u64)
          k = k + 1
        o = i * (kyberN div 4) * 5 + j * 5
        dst[o + 0] = byte(t4[0] shr 0)
        dst[o + 1] = byte((t4[0] shr 8) or (t4[1] shl 2))
        dst[o + 2] = byte((t4[1] shr 6) or (t4[2] shl 4))
        dst[o + 3] = byte((t4[2] shr 4) or (t4[3] shl 6))
        dst[o + 4] = byte(t4[3] shr 2)
        j = j + 1
      i = i + 1
    return

  raise newException(ValueError, "unsupported Kyber polyvec compression size")

proc polyvecCompress*(p: KyberParams, a: PolyVec): seq[byte] =
  ## Compress and serialize a Kyber polynomial vector.
  result = newSeq[byte](p.polyVecCompressedBytes)
  polyvecCompressInto(result, p, a)

proc polyvecDecompressInto*(r: var PolyVec, p: KyberParams, A: openArray[byte]) =
  ## Decompress and deserialize a Kyber polynomial vector into a caller-provided vector.
  var
    i: int = 0
    j: int = 0
    k: int = 0
    o: int = 0
    t8 {.noinit.}: array[8, uint16]
    t4 {.noinit.}: array[4, uint16]
  if A.len != p.polyVecCompressedBytes:
    raise newException(ValueError, "invalid Kyber compressed polyvec length")
  if p.polyVecCompressedBytes == p.k * 352:
    i = 0
    while i < p.k:
      j = 0
      while j < kyberN div 8:
        o = i * (kyberN div 8) * 11 + j * 11
        t8[0] = (uint16(A[o + 0]) shr 0) or (uint16(A[o + 1]) shl 8)
        t8[1] = (uint16(A[o + 1]) shr 3) or (uint16(A[o + 2]) shl 5)
        t8[2] = (uint16(A[o + 2]) shr 6) or (uint16(A[o + 3]) shl 2) or (uint16(A[o + 4]) shl 10)
        t8[3] = (uint16(A[o + 4]) shr 1) or (uint16(A[o + 5]) shl 7)
        t8[4] = (uint16(A[o + 5]) shr 4) or (uint16(A[o + 6]) shl 4)
        t8[5] = (uint16(A[o + 6]) shr 7) or (uint16(A[o + 7]) shl 1) or (uint16(A[o + 8]) shl 9)
        t8[6] = (uint16(A[o + 8]) shr 2) or (uint16(A[o + 9]) shl 6)
        t8[7] = (uint16(A[o + 9]) shr 5) or (uint16(A[o + 10]) shl 3)
        k = 0
        while k < 8:
          r.vec[i].coeffs[8 * j + k] =
            int16(((uint32(t8[k] and 0x7ff'u16) * uint32(kyberQ)) + 1024'u32) shr 11)
          k = k + 1
        j = j + 1
      i = i + 1
    return

  if p.polyVecCompressedBytes == p.k * 320:
    i = 0
    while i < p.k:
      j = 0
      while j < kyberN div 4:
        o = i * (kyberN div 4) * 5 + j * 5
        t4[0] = (uint16(A[o + 0]) shr 0) or (uint16(A[o + 1]) shl 8)
        t4[1] = (uint16(A[o + 1]) shr 2) or (uint16(A[o + 2]) shl 6)
        t4[2] = (uint16(A[o + 2]) shr 4) or (uint16(A[o + 3]) shl 4)
        t4[3] = (uint16(A[o + 3]) shr 6) or (uint16(A[o + 4]) shl 2)
        k = 0
        while k < 4:
          r.vec[i].coeffs[4 * j + k] =
            int16(((uint32(t4[k] and 0x3ff'u16) * uint32(kyberQ)) + 512'u32) shr 10)
          k = k + 1
        j = j + 1
      i = i + 1
    return

  raise newException(ValueError, "unsupported Kyber polyvec compression size")

proc polyvecDecompress*(p: KyberParams, A: openArray[byte]): PolyVec =
  ## Decompress and deserialize a Kyber polynomial vector.
  polyvecDecompressInto(result, p, A)

proc polyvecToBytesInto*(dst: var openArray[byte], p: KyberParams, a: PolyVec) {.inline.} =
  ## Serialize a Kyber polynomial vector into a caller-provided buffer.
  var
    i: int = 0
    o: int = 0
  if dst.len != p.k * kyberPolyBytes:
    raise newException(ValueError, "invalid Kyber polyvec byte length")
  case p.k
  of 2:
    polyToBytesInto(dst.toOpenArray(0, kyberPolyBytes - 1), a.vec[0])
    polyToBytesInto(dst.toOpenArray(kyberPolyBytes, 2 * kyberPolyBytes - 1), a.vec[1])
  of 3:
    polyToBytesInto(dst.toOpenArray(0, kyberPolyBytes - 1), a.vec[0])
    polyToBytesInto(dst.toOpenArray(kyberPolyBytes, 2 * kyberPolyBytes - 1), a.vec[1])
    polyToBytesInto(dst.toOpenArray(2 * kyberPolyBytes, 3 * kyberPolyBytes - 1), a.vec[2])
  of 4:
    polyToBytesInto(dst.toOpenArray(0, kyberPolyBytes - 1), a.vec[0])
    polyToBytesInto(dst.toOpenArray(kyberPolyBytes, 2 * kyberPolyBytes - 1), a.vec[1])
    polyToBytesInto(dst.toOpenArray(2 * kyberPolyBytes, 3 * kyberPolyBytes - 1), a.vec[2])
    polyToBytesInto(dst.toOpenArray(3 * kyberPolyBytes, 4 * kyberPolyBytes - 1), a.vec[3])
  else:
    i = 0
    while i < p.k:
      o = i * kyberPolyBytes
      polyToBytesInto(dst.toOpenArray(o, o + kyberPolyBytes - 1), a.vec[i])
      i = i + 1

proc polyvecToBytes*(p: KyberParams, a: PolyVec): seq[byte] =
  ## Serialize a Kyber polynomial vector.
  result = newSeq[byte](p.k * kyberPolyBytes)
  polyvecToBytesInto(result, p, a)

proc polyvecFromBytesInto*(r: var PolyVec, p: KyberParams, A: openArray[byte]) {.inline.} =
  ## Deserialize a Kyber polynomial vector into a caller-provided vector.
  var
    i: int = 0
    o: int = 0
  if A.len != p.k * kyberPolyBytes:
    raise newException(ValueError, "invalid Kyber polyvec byte length")
  case p.k
  of 2:
    polyFromBytesInto(r.vec[0], A.toOpenArray(0, kyberPolyBytes - 1))
    polyFromBytesInto(r.vec[1], A.toOpenArray(kyberPolyBytes, 2 * kyberPolyBytes - 1))
  of 3:
    polyFromBytesInto(r.vec[0], A.toOpenArray(0, kyberPolyBytes - 1))
    polyFromBytesInto(r.vec[1], A.toOpenArray(kyberPolyBytes, 2 * kyberPolyBytes - 1))
    polyFromBytesInto(r.vec[2], A.toOpenArray(2 * kyberPolyBytes, 3 * kyberPolyBytes - 1))
  of 4:
    polyFromBytesInto(r.vec[0], A.toOpenArray(0, kyberPolyBytes - 1))
    polyFromBytesInto(r.vec[1], A.toOpenArray(kyberPolyBytes, 2 * kyberPolyBytes - 1))
    polyFromBytesInto(r.vec[2], A.toOpenArray(2 * kyberPolyBytes, 3 * kyberPolyBytes - 1))
    polyFromBytesInto(r.vec[3], A.toOpenArray(3 * kyberPolyBytes, 4 * kyberPolyBytes - 1))
  else:
    i = 0
    while i < p.k:
      o = i * kyberPolyBytes
      polyFromBytesInto(r.vec[i], A.toOpenArray(o, o + kyberPolyBytes - 1))
      i = i + 1

proc polyvecFromBytes*(p: KyberParams, A: openArray[byte]): PolyVec =
  ## Deserialize a Kyber polynomial vector.
  polyvecFromBytesInto(result, p, A)

proc polyvecNtt*(p: KyberParams, r: var PolyVec) {.inline.} =
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

proc polyvecInvNttToMont*(p: KyberParams, r: var PolyVec) {.inline.} =
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

proc polyvecBaseMulAccMontgomery*(p: KyberParams, r: var Poly, a, b: PolyVec) {.inline.} =
  ## Multiply and accumulate two Kyber polynomial vectors.
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

proc polyMulCacheCompute*(x: var PolyMulCache, a: Poly) {.inline.} =
  ## Precompute the twiddle-scaled odd coefficients used in NTT base multiplication.
  var
    i: int = 0
  i = 0
  while i < kyberN div 4:
    x[2 * i + 0] = montgomeryReduce(int32(a.coeffs[4 * i + 1]) * int32(zetas[64 + i]))
    x[2 * i + 1] = montgomeryReduce(int32(a.coeffs[4 * i + 3]) * int32(-zetas[64 + i]))
    i = i + 1

proc polyvecMulCacheCompute*(p: KyberParams, x: var PolyVecMulCache, a: PolyVec) {.inline.} =
  ## Precompute twiddle-scaled odd coefficients for a Kyber polynomial vector.
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

proc polyvecBaseMulAccMontgomeryCached*(p: KyberParams, r: var Poly, a, b: PolyVec,
    bCache: var PolyVecMulCache) {.inline.} =
  ## Multiply and accumulate two Kyber polynomial vectors using a cached second operand.
  var
    i: int = 0
    t0: int32 = 0
    t1: int32 = 0
  i = 0
  case p.k
  of 2:
    while i < kyberN div 2:
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
    while i < kyberN div 2:
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
    while i < kyberN div 2:
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
    while i < kyberN div 2:
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

proc polyvecReduce*(p: KyberParams, r: var PolyVec) {.inline.} =
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

proc polyvecAdd*(p: KyberParams, r: var PolyVec, a, b: PolyVec) {.inline.} =
  ## Add two Kyber polynomial vectors.
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
