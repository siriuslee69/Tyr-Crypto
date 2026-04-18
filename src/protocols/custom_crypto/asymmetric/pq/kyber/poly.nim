## ------------------------------------------------------
## Kyber Poly <- polynomial serialization and arithmetic
## ------------------------------------------------------

import ./params
import ./types
import ./reduce
import ./ntt
import ./cbd
import ./symmetric
import ./verify

when defined(sse2) or defined(avx2):
  import simd_nexus/simd/base_operations

{.push boundChecks: off.}

when defined(sse2):
  proc polyAddSimdSse(r: var Poly, a, b: Poly) =
    var
      i: int = 0
      va: i16x8
      vb: i16x8
      vr: i16x8
    i = 0
    while i + 8 <= kyberN:
      va = i16x8(mm_loadu_si128(cast[pointer](unsafeAddr a.coeffs[i])))
      vb = i16x8(mm_loadu_si128(cast[pointer](unsafeAddr b.coeffs[i])))
      vr = va + vb
      mm_storeu_si128(cast[pointer](unsafeAddr r.coeffs[i]), M128i(vr))
      i = i + 8
    while i < kyberN:
      r.coeffs[i] = a.coeffs[i] + b.coeffs[i]
      i = i + 1

  proc polySubSimdSse(r: var Poly, a, b: Poly) =
    var
      i: int = 0
      va: i16x8
      vb: i16x8
      vr: i16x8
    i = 0
    while i + 8 <= kyberN:
      va = i16x8(mm_loadu_si128(cast[pointer](unsafeAddr a.coeffs[i])))
      vb = i16x8(mm_loadu_si128(cast[pointer](unsafeAddr b.coeffs[i])))
      vr = va - vb
      mm_storeu_si128(cast[pointer](unsafeAddr r.coeffs[i]), M128i(vr))
      i = i + 8
    while i < kyberN:
      r.coeffs[i] = a.coeffs[i] - b.coeffs[i]
      i = i + 1

when defined(avx2):
  proc polyAddSimdAvx2(r: var Poly, a, b: Poly) =
    var
      i: int = 0
      va: i16x16
      vb: i16x16
      vr: i16x16
    i = 0
    while i + 16 <= kyberN:
      va = i16x16(mm256_loadu_si256(cast[pointer](unsafeAddr a.coeffs[i])))
      vb = i16x16(mm256_loadu_si256(cast[pointer](unsafeAddr b.coeffs[i])))
      vr = va + vb
      mm256_storeu_si256(cast[pointer](unsafeAddr r.coeffs[i]), M256i(vr))
      i = i + 16
    while i < kyberN:
      r.coeffs[i] = a.coeffs[i] + b.coeffs[i]
      i = i + 1

  proc polySubSimdAvx2(r: var Poly, a, b: Poly) =
    var
      i: int = 0
      va: i16x16
      vb: i16x16
      vr: i16x16
    i = 0
    while i + 16 <= kyberN:
      va = i16x16(mm256_loadu_si256(cast[pointer](unsafeAddr a.coeffs[i])))
      vb = i16x16(mm256_loadu_si256(cast[pointer](unsafeAddr b.coeffs[i])))
      vr = va - vb
      mm256_storeu_si256(cast[pointer](unsafeAddr r.coeffs[i]), M256i(vr))
      i = i + 16
    while i < kyberN:
      r.coeffs[i] = a.coeffs[i] - b.coeffs[i]
      i = i + 1

proc polyReduce*(r: var Poly) {.inline.}

proc polyCompressInto*(dst: var openArray[byte], p: KyberParams, a: Poly) =
  ## Compress and serialize one Kyber polynomial into a caller-provided buffer.
  var
    i: int = 0
    j: int = 0
    u: int32 = 0
    d0: uint32 = 0
    t8 {.noinit.}: array[8, byte]
  if dst.len != p.polyCompressedBytes:
    raise newException(ValueError, "invalid Kyber compressed polynomial length")
  if p.polyCompressedBytes == 128:
    i = 0
    while i < kyberN div 8:
      j = 0
      while j < 8:
        u = int32(a.coeffs[8 * i + j])
        u = u + ((u shr 15) and kyberQ)
        d0 = uint32(u shl 4)
        d0 = d0 + 1665'u32
        d0 = d0 * 80635'u32
        d0 = d0 shr 28
        t8[j] = byte(d0 and 0x0f'u32)
        j = j + 1
      dst[4 * i + 0] = t8[0] or (t8[1] shl 4)
      dst[4 * i + 1] = t8[2] or (t8[3] shl 4)
      dst[4 * i + 2] = t8[4] or (t8[5] shl 4)
      dst[4 * i + 3] = t8[6] or (t8[7] shl 4)
      i = i + 1
    return

  if p.polyCompressedBytes == 160:
    i = 0
    while i < kyberN div 8:
      j = 0
      while j < 8:
        u = int32(a.coeffs[8 * i + j])
        u = u + ((u shr 15) and kyberQ)
        d0 = uint32(u shl 5)
        d0 = d0 + 1664'u32
        d0 = d0 * 40318'u32
        d0 = d0 shr 27
        t8[j] = byte(d0 and 0x1f'u32)
        j = j + 1
      dst[5 * i + 0] = (t8[0] shr 0) or (t8[1] shl 5)
      dst[5 * i + 1] = (t8[1] shr 3) or (t8[2] shl 2) or (t8[3] shl 7)
      dst[5 * i + 2] = (t8[3] shr 1) or (t8[4] shl 4)
      dst[5 * i + 3] = (t8[4] shr 4) or (t8[5] shl 1) or (t8[6] shl 6)
      dst[5 * i + 4] = (t8[6] shr 2) or (t8[7] shl 3)
      i = i + 1
    return

  raise newException(ValueError, "unsupported Kyber polynomial compression size")

proc polyCompress*(p: KyberParams, a: Poly): seq[byte] =
  ## Compress and serialize one Kyber polynomial.
  result = newSeq[byte](p.polyCompressedBytes)
  polyCompressInto(result, p, a)

proc polyDecompressInto*(r: var Poly, p: KyberParams, A: openArray[byte]) =
  ## Decompress and deserialize one Kyber polynomial into a caller-provided polynomial.
  var
    i: int = 0
    j: int = 0
    t8 {.noinit.}: array[8, uint16]
  if A.len != p.polyCompressedBytes:
    raise newException(ValueError, "invalid Kyber compressed polynomial length")
  if p.polyCompressedBytes == 128:
    i = 0
    while i < kyberN div 2:
      r.coeffs[2 * i + 0] = int16((((uint16(A[i]) and 0x0f'u16) * uint16(kyberQ)) + 8'u16) shr 4)
      r.coeffs[2 * i + 1] = int16((((uint16(A[i]) shr 4) * uint16(kyberQ)) + 8'u16) shr 4)
      i = i + 1
    return

  if p.polyCompressedBytes == 160:
    i = 0
    while i < kyberN div 8:
      t8[0] = (uint16(A[5 * i + 0]) shr 0)
      t8[1] = (uint16(A[5 * i + 0]) shr 5) or (uint16(A[5 * i + 1]) shl 3)
      t8[2] = (uint16(A[5 * i + 1]) shr 2)
      t8[3] = (uint16(A[5 * i + 1]) shr 7) or (uint16(A[5 * i + 2]) shl 1)
      t8[4] = (uint16(A[5 * i + 2]) shr 4) or (uint16(A[5 * i + 3]) shl 4)
      t8[5] = (uint16(A[5 * i + 3]) shr 1)
      t8[6] = (uint16(A[5 * i + 3]) shr 6) or (uint16(A[5 * i + 4]) shl 2)
      t8[7] = (uint16(A[5 * i + 4]) shr 3)
      j = 0
      while j < 8:
        r.coeffs[8 * i + j] =
          int16(((uint32(t8[j] and 0x1f'u16) * uint32(kyberQ)) + 16'u32) shr 5)
        j = j + 1
      i = i + 1
    return

  raise newException(ValueError, "unsupported Kyber polynomial compression size")

proc polyDecompress*(p: KyberParams, A: openArray[byte]): Poly =
  ## Decompress and deserialize one Kyber polynomial.
  polyDecompressInto(result, p, A)

proc polyToBytesInto*(dst: var openArray[byte], a: Poly) =
  ## Serialize one Kyber polynomial into a caller-provided buffer.
  var
    i: int = 0
    t0: uint16 = 0
    t1: uint16 = 0
  if dst.len != kyberPolyBytes:
    raise newException(ValueError, "invalid Kyber polynomial byte length")
  i = 0
  while i < kyberN div 2:
    t0 = uint16(a.coeffs[2 * i])
    t0 = t0 + (uint16(a.coeffs[2 * i] shr 15) and uint16(kyberQ))
    t1 = uint16(a.coeffs[2 * i + 1])
    t1 = t1 + (uint16(a.coeffs[2 * i + 1] shr 15) and uint16(kyberQ))
    dst[3 * i + 0] = byte(t0 shr 0)
    dst[3 * i + 1] = byte((t0 shr 8) or (t1 shl 4))
    dst[3 * i + 2] = byte(t1 shr 4)
    i = i + 1

proc polyToBytes*(a: Poly): seq[byte] =
  ## Serialize one Kyber polynomial.
  result = newSeq[byte](kyberPolyBytes)
  polyToBytesInto(result, a)

proc polyFromBytesInto*(r: var Poly, A: openArray[byte]) =
  ## Deserialize one Kyber polynomial into a caller-provided polynomial.
  var
    i: int = 0
  if A.len != kyberPolyBytes:
    raise newException(ValueError, "invalid Kyber polynomial byte length")
  i = 0
  while i < kyberN div 2:
    r.coeffs[2 * i] =
      int16((uint16(A[3 * i + 0]) or (uint16(A[3 * i + 1]) shl 8)) and 0x0fff'u16)
    r.coeffs[2 * i + 1] =
      int16(((uint16(A[3 * i + 1]) shr 4) or (uint16(A[3 * i + 2]) shl 4)) and 0x0fff'u16)
    i = i + 1

proc polyFromBytes*(A: openArray[byte]): Poly =
  ## Deserialize one Kyber polynomial.
  polyFromBytesInto(result, A)

proc polyFromMsg*(r: var Poly, A: openArray[byte]) =
  ## Convert a 32-byte message into a Kyber polynomial.
  var
    i: int = 0
    j: int = 0
    v: int16 = int16((kyberQ + 1) div 2)
  if A.len != kyberSymBytes:
    raise newException(ValueError, "Kyber message must be 32 bytes")
  i = 0
  while i < kyberN div 8:
    j = 0
    while j < 8:
      r.coeffs[8 * i + j] = 0'i16
      cmovInt16(r.coeffs[8 * i + j], v, uint16((A[i] shr j) and 1'u8))
      j = j + 1
    i = i + 1

proc polyFromMsg*(A: openArray[byte]): Poly =
  ## Convert a 32-byte message into a Kyber polynomial.
  polyFromMsg(result, A)

proc polyToMsgInto*(dst: var openArray[byte], a: Poly) =
  ## Convert a Kyber polynomial back into a 32-byte message into a caller-provided buffer.
  var
    i: int = 0
    j: int = 0
    t: uint32 = 0
  if dst.len != kyberSymBytes:
    raise newException(ValueError, "Kyber message output must be 32 bytes")
  i = 0
  while i < kyberN div 8:
    dst[i] = 0'u8
    j = 0
    while j < 8:
      t = cast[uint32](int32(a.coeffs[8 * i + j]))
      t = t shl 1
      t = t + 1665'u32
      t = t * 80635'u32
      t = t shr 28
      t = t and 1'u32
      dst[i] = dst[i] or byte(t shl j)
      j = j + 1
    i = i + 1

proc polyToMsg*(a: Poly): seq[byte] =
  ## Convert a Kyber polynomial back into a 32-byte message.
  result = newSeq[byte](kyberSymBytes)
  polyToMsgInto(result, a)

proc polyGetNoiseEta1Into*(p: KyberParams, r: var Poly, seed: openArray[byte], nonce: byte) =
  ## Deterministically sample an eta1-noise polynomial into a caller-owned polynomial.
  var
    bufLen: int = 0
    buf {.noinit.}: array[3 * kyberN div 4, byte]
  bufLen = p.eta1 * kyberN div 4
  prfInto(buf.toOpenArray(0, bufLen - 1), seed, nonce)
  polyCbdEta1Into(p, r, buf.toOpenArray(0, bufLen - 1))

proc polyGetNoiseEta1*(p: KyberParams, seed: openArray[byte], nonce: byte): Poly =
  ## Deterministically sample an eta1-noise polynomial.
  polyGetNoiseEta1Into(p, result, seed, nonce)

proc polyGetNoiseEta2Into*(p: KyberParams, r: var Poly, seed: openArray[byte], nonce: byte) =
  ## Deterministically sample an eta2-noise polynomial into a caller-owned polynomial.
  var
    bufLen: int = 0
    buf {.noinit.}: array[2 * kyberN div 4, byte]
  bufLen = p.eta2 * kyberN div 4
  prfInto(buf.toOpenArray(0, bufLen - 1), seed, nonce)
  polyCbdEta2Into(p, r, buf.toOpenArray(0, bufLen - 1))

proc polyGetNoiseEta2*(p: KyberParams, seed: openArray[byte], nonce: byte): Poly =
  ## Deterministically sample an eta2-noise polynomial.
  polyGetNoiseEta2Into(p, result, seed, nonce)

proc polyNtt*(r: var Poly) {.inline.} =
  ## Apply the forward NTT to one polynomial.
  ntt(r.coeffs)
  polyReduce(r)

proc polyInvNttToMont*(r: var Poly) {.inline.} =
  ## Apply the inverse NTT to one polynomial.
  invNtt(r.coeffs)

proc polyBaseMulMontgomery*(r: var Poly, a, b: Poly) {.inline.} =
  ## Multiply two NTT-domain polynomials coefficient pairs at a time.
  var
    i: int = 0
    pa {.noinit.}: array[2, int16]
    pb {.noinit.}: array[2, int16]
    pr {.noinit.}: array[2, int16]
  i = 0
  while i < kyberN div 4:
    pa[0] = a.coeffs[4 * i + 0]
    pa[1] = a.coeffs[4 * i + 1]
    pb[0] = b.coeffs[4 * i + 0]
    pb[1] = b.coeffs[4 * i + 1]
    baseMul(pr, pa, pb, zetas[64 + i])
    r.coeffs[4 * i + 0] = pr[0]
    r.coeffs[4 * i + 1] = pr[1]

    pa[0] = a.coeffs[4 * i + 2]
    pa[1] = a.coeffs[4 * i + 3]
    pb[0] = b.coeffs[4 * i + 2]
    pb[1] = b.coeffs[4 * i + 3]
    baseMul(pr, pa, pb, -zetas[64 + i])
    r.coeffs[4 * i + 2] = pr[0]
    r.coeffs[4 * i + 3] = pr[1]
    i = i + 1

proc polyToMont*(r: var Poly) {.inline.} =
  ## Convert polynomial coefficients into Montgomery form.
  var
    i: int = 0
  const f = int16((1'u64 shl 32) mod uint64(kyberQ))
  when defined(avx2):
    i = 0
    while i + 8 <= kyberN:
      montgomeryMulChunk8(unsafeAddr r.coeffs[i], unsafeAddr r.coeffs[i], f)
      i = i + 8
    while i < kyberN:
      r.coeffs[i] = montgomeryReduce(int32(r.coeffs[i]) * int32(f))
      i = i + 1
  else:
    i = 0
    while i < kyberN:
      r.coeffs[i] = montgomeryReduce(int32(r.coeffs[i]) * int32(f))
      i = i + 1

proc polyReduce*(r: var Poly) {.inline.} =
  ## Apply Barrett reduction to all coefficients.
  var
    i: int = 0
  when defined(avx2):
    i = 0
    while i + 8 <= kyberN:
      barrettReduceChunk8(unsafeAddr r.coeffs[i])
      i = i + 8
    while i < kyberN:
      r.coeffs[i] = barrettReduce(r.coeffs[i])
      i = i + 1
  else:
    i = 0
    while i < kyberN:
      r.coeffs[i] = barrettReduce(r.coeffs[i])
      i = i + 1

proc polyAdd*(r: var Poly, a, b: Poly) {.inline.} =
  ## Add two polynomials without immediate modular reduction.
  when defined(avx2):
    polyAddSimdAvx2(r, a, b)
  elif defined(sse2):
    polyAddSimdSse(r, a, b)
  else:
    var
      i: int = 0
    i = 0
    while i < kyberN:
      r.coeffs[i] = a.coeffs[i] + b.coeffs[i]
      i = i + 1

proc polySub*(r: var Poly, a, b: Poly) {.inline.} =
  ## Subtract two polynomials without immediate modular reduction.
  when defined(avx2):
    polySubSimdAvx2(r, a, b)
  elif defined(sse2):
    polySubSimdSse(r, a, b)
  else:
    var
      i: int = 0
    i = 0
    while i < kyberN:
      r.coeffs[i] = a.coeffs[i] - b.coeffs[i]
      i = i + 1

{.pop.}
