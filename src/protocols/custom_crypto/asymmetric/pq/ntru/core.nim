## ----------------------------------------------------------
## NTRU Core <- pure-Nim NTRU arithmetic, OWC-CPA, and KEM code
## ----------------------------------------------------------

import std/volatile

import ./params
import ../common/pq_rng
import ../../../sha3
import ../kyber/verify
import ../../../../helpers/otter_support

when defined(sse2) or defined(avx2) or defined(neon) or defined(arm64) or defined(aarch64):
  import simd_nexus/simd/base_operations
when defined(neon) or defined(arm64) or defined(aarch64):
  import simd_nexus/simd/generic_i16

{.push boundChecks: off.}

type
  ## One NTRU polynomial. The active prefix length is selected by NtruParams.n.
  NtruPoly* = object
    coeffs*: array[ntruMaxN, uint16]

proc secureClearPoly(a: var NtruPoly) {.raises: [].} =
  ## Volatile zeroization for secret polynomial scratch (cannot be elided).
  var
    i: int = 0
  while i < ntruMaxN:
    volatileStore(addr a.coeffs[i], 0'u16)
    i = i + 1

proc q(p: NtruParams): uint16 {.inline.} =
  result = uint16(1 shl p.logQ)

proc qMask(p: NtruParams): uint16 {.inline.} =
  result = uint16((1 shl p.logQ) - 1)

proc modQ(p: NtruParams, x: uint16): uint16 {.inline.} =
  result = x and qMask(p)

proc u16Add(a, b: uint16): uint16 {.inline.} =
  result = uint16((uint32(a) + uint32(b)) and 0xffff'u32)

proc u16Sub(a, b: uint16): uint16 {.inline.} =
  result = uint16((uint32(a) + 0x10000'u32 - uint32(b)) and 0xffff'u32)

proc u16Mul(a, b: uint16): uint16 {.inline.} =
  result = uint16((uint32(a) * uint32(b)) and 0xffff'u32)

proc u16Neg(a: uint16): uint16 {.inline.} =
  result = uint16((0x10000'u32 - uint32(a)) and 0xffff'u32)

proc i64ToU16(a: int64): uint16 {.inline.} =
  result = uint16(cast[uint64](a) and 0xffff'u64)

proc load16Le(A: openArray[byte], o: int): uint16 {.inline.} =
  var
    t: uint16 = 0
  t = uint16(A[o]) or uint16(uint16(A[o + 1]) shl 8)
  result = t

proc copyBytes(dst: var openArray[byte], o: int, src: openArray[byte]) =
  var
    i: int = 0
  i = 0
  while i < src.len:
    dst[o + i] = src[i]
    i = i + 1

proc nonzeroToOne(t: uint32): int {.inline.} =
  var
    x: uint64 = 0
  x = (0x100000000'u64 - uint64(t)) and 0xffffffff'u64
  result = int((x shr 31) and 1'u64)

proc mod3(a: uint16): uint16 =
  var
    r: uint16 = 0
  r = (a shr 8) + (a and 0xff'u16)
  r = (r shr 4) + (r and 0x0f'u16)
  r = (r shr 2) + (r and 0x03'u16)
  r = (r shr 2) + (r and 0x03'u16)
  r = ((r shr 2) + r) and 0x03'u16
  result = (r + ((r + 1'u16) shr 2)) and 0x03'u16

proc mod3Small(a: uint8): uint8 =
  var
    r: uint16 = 0
  r = (uint16(a) shr 4) + (uint16(a) and 0x0f'u16)
  r = (r shr 2) + (r and 0x03'u16)
  r = (r shr 2) + (r and 0x03'u16)
  r = ((r shr 2) + r) and 0x03'u16
  result = byte((r + ((r + 1'u16) shr 2)) and 0x03'u16)

proc bothNegativeMask(x, y: int16): int16 {.inline.} =
  var
    b: uint16 = 0
  b = (cast[uint16](x) and cast[uint16](y)) shr 15
  result = int16(0 - int(b))

proc int32Minmax(a, b: var int32) =
  var
    ab: int32 = 0
    c: int32 = 0
    cu: uint32 = 0
  ab = b xor a
  cu = uint32((uint64(cast[uint32](b)) + 0x100000000'u64 -
    uint64(cast[uint32](a))) and 0xffffffff'u64)
  c = cast[int32](cu)
  c = c xor (ab and (c xor b))
  c = int32(0 - int((cast[uint32](c) shr 31) and 1'u32))
  c = c and ab
  a = a xor c
  b = b xor c

proc negativeMaskInt32(x: int32): int32 {.inline.} =
  var
    b: uint32 = 0
  b = (cast[uint32](x) shr 31) and 1'u32
  result = int32(0 - int(b))

proc sortInt32Fixed(A: var openArray[int32]) {.otterBench.} =
  var
    pass: int = 0
    j: int = 0
  pass = 0
  while pass < A.len:
    j = pass and 1
    while j + 1 < A.len:
      int32Minmax(A[j], A[j + 1])
      j = j + 2
    pass = pass + 1

proc clearNtruPolyActive(r: var NtruPoly, p: NtruParams) {.inline.} =
  var
    i: int = 0
  i = 0
  while i < p.n:
    r.coeffs[i] = 0
    i = i + 1

proc packBits(dst: var openArray[byte], V: openArray[uint16], bits, count: int,
    mask: uint16) =
  var
    acc: uint32 = 0
    accBits: int = 0
    outIdx: int = 0
    i: int = 0
  outIdx = 0
  while outIdx < dst.len:
    dst[outIdx] = 0'u8
    outIdx = outIdx + 1
  outIdx = 0
  i = 0
  while i < count:
    acc = acc or ((uint32(V[i] and mask)) shl accBits)
    accBits = accBits + bits
    while accBits >= 8:
      dst[outIdx] = byte(acc and 0xff'u32)
      outIdx = outIdx + 1
      acc = acc shr 8
      accBits = accBits - 8
    i = i + 1
  if accBits > 0 and outIdx < dst.len:
    dst[outIdx] = byte(acc and 0xff'u32)

proc unpackBits(V: var openArray[uint16], src: openArray[byte], bits, count: int) =
  var
    mask: uint32 = 0
    acc: uint32 = 0
    accBits: int = 0
    inIdx: int = 0
    i: int = 0
  mask = (1'u32 shl bits) - 1'u32
  i = 0
  while i < count:
    while accBits < bits:
      acc = acc or (uint32(src[inIdx]) shl accBits)
      inIdx = inIdx + 1
      accBits = accBits + 8
    V[i] = uint16(acc and mask)
    acc = acc shr bits
    accBits = accBits - bits
    i = i + 1

proc polyMod3Phi*(r: var NtruPoly, p: NtruParams)

proc polyS3ToBytes*(dst: var openArray[byte], p: NtruParams, a: NtruPoly) =
  var
    i: int = 0
    j: int = 0
    c: byte = 0
  i = 0
  while i < p.packDeg div 5:
    c = byte(a.coeffs[5 * i + 4] and 255'u16)
    c = byte((3 * uint16(c) + a.coeffs[5 * i + 3]) and 255'u16)
    c = byte((3 * uint16(c) + a.coeffs[5 * i + 2]) and 255'u16)
    c = byte((3 * uint16(c) + a.coeffs[5 * i + 1]) and 255'u16)
    c = byte((3 * uint16(c) + a.coeffs[5 * i + 0]) and 255'u16)
    dst[i] = c
    i = i + 1
  if 5 * i < p.packDeg:
    c = 0'u8
    j = p.packDeg - (5 * i) - 1
    while j >= 0:
      c = byte((3 * uint16(c) + a.coeffs[5 * i + j]) and 255'u16)
      j = j - 1
    dst[i] = c

proc polyS3FromBytes*(r: var NtruPoly, p: NtruParams, src: openArray[byte]) =
  var
    i: int = 0
    j: int = 0
    c: byte = 0
  i = 0
  while i < p.packDeg div 5:
    c = src[i]
    r.coeffs[5 * i + 0] = uint16(c)
    r.coeffs[5 * i + 1] = uint16(uint32(c) * 171'u32 shr 9)
    r.coeffs[5 * i + 2] = uint16(uint32(c) * 57'u32 shr 9)
    r.coeffs[5 * i + 3] = uint16(uint32(c) * 19'u32 shr 9)
    r.coeffs[5 * i + 4] = uint16(uint32(c) * 203'u32 shr 14)
    i = i + 1
  if 5 * i < p.packDeg:
    c = src[i]
    j = 0
    while (5 * i + j) < p.packDeg:
      r.coeffs[5 * i + j] = uint16(c)
      c = byte(uint32(c) * 171'u32 shr 9)
      j = j + 1
  r.coeffs[p.n - 1] = 0
  polyMod3Phi(r, p)

proc polySqToBytes*(dst: var openArray[byte], p: NtruParams, a: NtruPoly) =
  var
    T: array[ntruMaxN, uint16]
    i: int = 0
  i = 0
  while i < p.packDeg:
    T[i] = modQ(p, a.coeffs[i])
    i = i + 1
  packBits(dst, T, p.logQ, p.packDeg, qMask(p))

proc polySqFromBytes*(r: var NtruPoly, p: NtruParams, src: openArray[byte]) =
  unpackBits(r.coeffs, src, p.logQ, p.packDeg)
  r.coeffs[p.n - 1] = 0

proc polyRqSumZeroToBytes*(dst: var openArray[byte], p: NtruParams, a: NtruPoly) =
  polySqToBytes(dst, p, a)

proc polyRqSumZeroFromBytes*(r: var NtruPoly, p: NtruParams, src: openArray[byte]) =
  var
    i: int = 0
  polySqFromBytes(r, p, src)
  r.coeffs[p.n - 1] = 0
  i = 0
  while i < p.packDeg:
    r.coeffs[p.n - 1] = u16Sub(r.coeffs[p.n - 1], r.coeffs[i])
    i = i + 1

proc polyZ3ToZq*(r: var NtruPoly, p: NtruParams) =
  var
    i: int = 0
  i = 0
  while i < p.n:
    r.coeffs[i] = r.coeffs[i] or (u16Neg(r.coeffs[i] shr 1) and qMask(p))
    i = i + 1

proc polyTrinaryZqToZ3*(r: var NtruPoly, p: NtruParams) =
  var
    i: int = 0
  i = 0
  while i < p.n:
    r.coeffs[i] = modQ(p, r.coeffs[i])
    r.coeffs[i] = 3'u16 and (r.coeffs[i] xor (r.coeffs[i] shr (p.logQ - 1)))
    i = i + 1

proc polyMod3Phi*(r: var NtruPoly, p: NtruParams) =
  var
    i: int = 0
  i = 0
  while i < p.n:
    r.coeffs[i] = mod3(u16Add(r.coeffs[i], uint16(2'u32 * uint32(r.coeffs[p.n - 1]))))
    i = i + 1

proc polyModQPhi*(r: var NtruPoly, p: NtruParams) =
  var
    i: int = 0
  i = 0
  while i < p.n:
    r.coeffs[i] = u16Sub(r.coeffs[i], r.coeffs[p.n - 1])
    i = i + 1

proc polyRqToS3*(r: var NtruPoly, p: NtruParams, a: NtruPoly) =
  var
    i: int = 0
    flag: uint16 = 0
  i = 0
  while i < p.n:
    r.coeffs[i] = modQ(p, a.coeffs[i])
    flag = r.coeffs[i] shr (p.logQ - 1)
    r.coeffs[i] = u16Add(r.coeffs[i], uint16(uint32(flag) shl (1 - (p.logQ and 1))))
    i = i + 1
  polyMod3Phi(r, p)

when defined(sse2):
  proc reduceCyclicSse(r: var NtruPoly, p: NtruParams,
      C: array[2 * ntruMaxN, uint16]) =
    var
      i: int = 0
      a: i16x8
      b: i16x8
      v: i16x8
    i = 0
    while i + 8 <= p.n:
      a = i16x8(mm_loadu_si128(cast[pointer](unsafeAddr C[i])))
      b = i16x8(mm_loadu_si128(cast[pointer](unsafeAddr C[p.n + i])))
      v = a + b
      mm_storeu_si128(cast[pointer](unsafeAddr r.coeffs[i]), M128i(v))
      i = i + 8
    while i < p.n:
      r.coeffs[i] = u16Add(C[i], C[p.n + i])
      i = i + 1

when defined(avx2):
  proc reduceCyclicAvx2(r: var NtruPoly, p: NtruParams,
      C: array[2 * ntruMaxN, uint16]) =
    var
      i: int = 0
      a: i16x16
      b: i16x16
      v: i16x16
    i = 0
    while i + 16 <= p.n:
      a = i16x16(mm256_loadu_si256(cast[pointer](unsafeAddr C[i])))
      b = i16x16(mm256_loadu_si256(cast[pointer](unsafeAddr C[p.n + i])))
      v = a + b
      mm256_storeu_si256(cast[pointer](unsafeAddr r.coeffs[i]), M256i(v))
      i = i + 16
    while i < p.n:
      r.coeffs[i] = u16Add(C[i], C[p.n + i])
      i = i + 1

when defined(sse2) and not defined(avx2):
  proc polyRqMulSse2(r: var NtruPoly, p: NtruParams,
      a, b: NtruPoly) {.inline.} =
    ## Multiply eight cyclic-ring coefficients per fixed public step.
    var
      i: int = 0
      j: int = 0
      k: int = 0
      av: i16x8
      bv: i16x8
      rv: i16x8
    clearNtruPolyActive(r, p)
    i = 0
    while i < p.n:
      av = i16x8(mm_set1_epi16(a.coeffs[i]))
      j = 0
      k = i
      while k + 8 <= p.n:
        bv = i16x8(mm_loadu_si128(cast[pointer](unsafeAddr b.coeffs[j])))
        rv = i16x8(mm_loadu_si128(cast[pointer](unsafeAddr r.coeffs[k])))
        rv = rv + i16x8(mm_mullo_epi16(av.M128i, bv.M128i))
        mm_storeu_si128(cast[pointer](unsafeAddr r.coeffs[k]), rv.M128i)
        j = j + 8
        k = k + 8
      while k < p.n:
        r.coeffs[k] = u16Add(r.coeffs[k], u16Mul(a.coeffs[i], b.coeffs[j]))
        j = j + 1
        k = k + 1
      k = 0
      while j + 8 <= p.n:
        bv = i16x8(mm_loadu_si128(cast[pointer](unsafeAddr b.coeffs[j])))
        rv = i16x8(mm_loadu_si128(cast[pointer](unsafeAddr r.coeffs[k])))
        rv = rv + i16x8(mm_mullo_epi16(av.M128i, bv.M128i))
        mm_storeu_si128(cast[pointer](unsafeAddr r.coeffs[k]), rv.M128i)
        j = j + 8
        k = k + 8
      while j < p.n:
        r.coeffs[k] = u16Add(r.coeffs[k], u16Mul(a.coeffs[i], b.coeffs[j]))
        j = j + 1
        k = k + 1
      i = i + 1

when defined(neon) or defined(arm64) or defined(aarch64):
  proc reduceCyclicNeon(r: var NtruPoly, p: NtruParams,
      C: array[2 * ntruMaxN, uint16]) =
    var
      i: int = 0
      a: uint16x8
      b: uint16x8
    i = 0
    while i + 8 <= p.n:
      a = loadI16x8At[uint16x8](C, i)
      b = loadI16x8At[uint16x8](C, p.n + i)
      storeI16x8At[uint16x8](a + b, r.coeffs, i)
      i = i + 8
    while i < p.n:
      r.coeffs[i] = u16Add(C[i], C[p.n + i])
      i = i + 1

proc polyRqMulTmp(r: var NtruPoly, p: NtruParams, a, b: NtruPoly) {.inline.} =
  var
    C: array[2 * ntruMaxN, uint16]
    i: int = 0
    j: int = 0
    prod: uint16 = 0
  i = 0
  while i < 2 * p.n:
    C[i] = 0
    i = i + 1
  i = 0
  while i < p.n:
    j = 0
    while j < p.n:
      prod = u16Mul(a.coeffs[i], b.coeffs[j])
      C[i + j] = u16Add(C[i + j], prod)
      j = j + 1
    i = i + 1
  when defined(avx2):
    reduceCyclicAvx2(r, p, C)
  elif defined(sse2):
    reduceCyclicSse(r, p, C)
  elif defined(neon) or defined(arm64) or defined(aarch64):
    reduceCyclicNeon(r, p, C)
  else:
    i = 0
    while i < p.n:
      r.coeffs[i] = u16Add(C[i], C[p.n + i])
      i = i + 1

proc polyRqMulRows(r: var NtruPoly, p: NtruParams, a, b: NtruPoly) {.inline.} =
  var
    i: int = 0
    j: int = 0
    k: int = 0
    ai: uint16 = 0
    prod: uint16 = 0
  clearNtruPolyActive(r, p)
  i = 0
  while i < p.n:
    ai = a.coeffs[i]
    j = 0
    k = i
    while k < p.n:
      prod = u16Mul(ai, b.coeffs[j])
      r.coeffs[k] = u16Add(r.coeffs[k], prod)
      j = j + 1
      k = k + 1
    k = 0
    while j < p.n:
      prod = u16Mul(ai, b.coeffs[j])
      r.coeffs[k] = u16Add(r.coeffs[k], prod)
      j = j + 1
      k = k + 1
    i = i + 1

proc polyRqMulCoeff(r: var NtruPoly, p: NtruParams, a, b: NtruPoly) {.inline.} =
  var
    k: int = 0
    i: int = 0
    j: int = 0
    acc: uint16 = 0
  k = 0
  while k < p.n:
    acc = 0
    i = 0
    j = k
    while i <= k:
      acc = u16Add(acc, u16Mul(a.coeffs[i], b.coeffs[j]))
      i = i + 1
      j = j - 1
    i = k + 1
    j = p.n - 1
    while i < p.n:
      acc = u16Add(acc, u16Mul(a.coeffs[i], b.coeffs[j]))
      i = i + 1
      j = j - 1
    r.coeffs[k] = acc
    k = k + 1

proc polyRqMulRowsUnroll4(r: var NtruPoly, p: NtruParams, a, b: NtruPoly) {.inline.} =
  var
    i: int = 0
    j: int = 0
    k: int = 0
    ai: uint16 = 0
  clearNtruPolyActive(r, p)
  i = 0
  while i < p.n:
    ai = a.coeffs[i]
    j = 0
    k = i
    while k + 4 <= p.n:
      r.coeffs[k] = u16Add(r.coeffs[k], u16Mul(ai, b.coeffs[j]))
      r.coeffs[k + 1] = u16Add(r.coeffs[k + 1], u16Mul(ai, b.coeffs[j + 1]))
      r.coeffs[k + 2] = u16Add(r.coeffs[k + 2], u16Mul(ai, b.coeffs[j + 2]))
      r.coeffs[k + 3] = u16Add(r.coeffs[k + 3], u16Mul(ai, b.coeffs[j + 3]))
      j = j + 4
      k = k + 4
    while k < p.n:
      r.coeffs[k] = u16Add(r.coeffs[k], u16Mul(ai, b.coeffs[j]))
      j = j + 1
      k = k + 1
    k = 0
    while j + 4 <= p.n:
      r.coeffs[k] = u16Add(r.coeffs[k], u16Mul(ai, b.coeffs[j]))
      r.coeffs[k + 1] = u16Add(r.coeffs[k + 1], u16Mul(ai, b.coeffs[j + 1]))
      r.coeffs[k + 2] = u16Add(r.coeffs[k + 2], u16Mul(ai, b.coeffs[j + 2]))
      r.coeffs[k + 3] = u16Add(r.coeffs[k + 3], u16Mul(ai, b.coeffs[j + 3]))
      j = j + 4
      k = k + 4
    while j < p.n:
      r.coeffs[k] = u16Add(r.coeffs[k], u16Mul(ai, b.coeffs[j]))
      j = j + 1
      k = k + 1
    i = i + 1

when defined(avx2):
  proc polyRqMulAvx2(r: var NtruPoly, p: NtruParams,
      a, b: NtruPoly) {.inline.} =
    ## Multiply 16 cyclic-ring coefficients per fixed public step.
    var
      i: int = 0
      j: int = 0
      k: int = 0
      av: i16x16
      bv: i16x16
      rv: i16x16
    clearNtruPolyActive(r, p)
    i = 0
    while i < p.n:
      av = i16x16(mm256_set1_epi16(a.coeffs[i]))
      j = 0
      k = i
      while k + 16 <= p.n:
        bv = i16x16(mm256_loadu_si256(cast[pointer](unsafeAddr b.coeffs[j])))
        rv = i16x16(mm256_loadu_si256(cast[pointer](unsafeAddr r.coeffs[k])))
        rv = rv + i16x16(mm256_mullo_epi16(av.M256i, bv.M256i))
        mm256_storeu_si256(cast[pointer](unsafeAddr r.coeffs[k]), rv.M256i)
        j = j + 16
        k = k + 16
      while k < p.n:
        r.coeffs[k] = u16Add(r.coeffs[k], u16Mul(a.coeffs[i], b.coeffs[j]))
        j = j + 1
        k = k + 1
      k = 0
      while j + 16 <= p.n:
        bv = i16x16(mm256_loadu_si256(cast[pointer](unsafeAddr b.coeffs[j])))
        rv = i16x16(mm256_loadu_si256(cast[pointer](unsafeAddr r.coeffs[k])))
        rv = rv + i16x16(mm256_mullo_epi16(av.M256i, bv.M256i))
        mm256_storeu_si256(cast[pointer](unsafeAddr r.coeffs[k]), rv.M256i)
        j = j + 16
        k = k + 16
      while j < p.n:
        r.coeffs[k] = u16Add(r.coeffs[k], u16Mul(a.coeffs[i], b.coeffs[j]))
        j = j + 1
        k = k + 1
      i = i + 1

when defined(neon) or defined(arm64) or defined(aarch64):
  proc polyRqMulNeon(r: var NtruPoly, p: NtruParams,
      a, b: NtruPoly) {.inline.} =
    ## Multiply eight cyclic-ring coefficients per fixed public step.
    var
      i: int = 0
      j: int = 0
      k: int = 0
      av: uint16x8
      bv: uint16x8
      rv: uint16x8
    clearNtruPolyActive(r, p)
    i = 0
    while i < p.n:
      av = vmovq_n_u16(a.coeffs[i])
      j = 0
      k = i
      while k + 8 <= p.n:
        bv = loadI16x8At[uint16x8](b.coeffs, j)
        rv = loadI16x8At[uint16x8](r.coeffs, k)
        storeI16x8At[uint16x8](rv + mulLoI16[uint16x8](av, bv), r.coeffs, k)
        j = j + 8
        k = k + 8
      while k < p.n:
        r.coeffs[k] = u16Add(r.coeffs[k], u16Mul(a.coeffs[i], b.coeffs[j]))
        j = j + 1
        k = k + 1
      k = 0
      while j + 8 <= p.n:
        bv = loadI16x8At[uint16x8](b.coeffs, j)
        rv = loadI16x8At[uint16x8](r.coeffs, k)
        storeI16x8At[uint16x8](rv + mulLoI16[uint16x8](av, bv), r.coeffs, k)
        j = j + 8
        k = k + 8
      while j < p.n:
        r.coeffs[k] = u16Add(r.coeffs[k], u16Mul(a.coeffs[i], b.coeffs[j]))
        j = j + 1
        k = k + 1
      i = i + 1

const
  ntruToomPadMax = ((ntruMaxN + 3) div 4) * 4
  ntruToomChunkMax = ntruToomPadMax div 4
  ntruToomResMax = 2 * ntruToomChunkMax - 1
  ntruToomInfPoint = 99
  ntruToomK2PadMax = ((ntruMaxN + 31) div 32) * 32
  ntruToomK2BaseMax = ntruToomK2PadMax div 16
  ntruToomK2ChunkMax = ntruToomK2PadMax div 4
  ntruToomK2EvalMax = 9 * ntruToomK2BaseMax
  ntruToomK2ProdMax = 18 * ntruToomK2BaseMax

type
  NtruToomEval = array[ntruToomChunkMax, int64]
  NtruToomProd = array[ntruToomResMax, int64]
  NtruToomProducts = array[7, NtruToomProd]
  NtruToomWide = array[2 * ntruToomPadMax, int64]
  NtruToomK2Padded = array[ntruToomK2PadMax, uint16]
  NtruToomK2Eval = array[ntruToomK2EvalMax, uint16]
  NtruToomK2Prod = array[ntruToomK2ProdMax, uint16]
  NtruToomK2Products = array[7, NtruToomK2Prod]
  NtruToomK2Chunk = array[2 * ntruToomK2ChunkMax, uint16]
  NtruToomK2Tmp = array[4 * ntruToomK2BaseMax, uint16]
  NtruToomK2Wide = array[2 * ntruToomK2PadMax, uint16]

proc ntruToomLen(p: NtruParams): int {.inline.} =
  result = ((p.n + 3) div 4) * 4

proc ntruToomK2Len(p: NtruParams): int {.inline.} =
  result = ((p.n + 31) div 32) * 32

proc u16MulSmall(a: uint16, b: int): uint16 {.inline.} =
  result = uint16((uint32(a) * uint32(b)) and 0xffff'u32)

proc u16FromI64(a: int64): uint16 {.inline.} =
  result = uint16(cast[uint64](a) and 0xffff'u64)

proc cShrI64ToU16(a: int64, s: int): uint16 {.inline.} =
  var
    t: uint64 = 0
  t = cast[uint64](a) and 0xffffffff'u64
  result = uint16((t shr s) and 0xffff'u64)

proc ntruToomCoeffAt(A: NtruPoly, p: NtruParams, i: int): int64 {.inline.} =
  if i < p.n:
    result = int64(A.coeffs[i])
  else:
    result = 0

proc evalNtruToomPoint(E: var NtruToomEval, p: NtruParams, A: NtruPoly,
    point, m: int) {.inline.} =
  var
    i: int = 0
    a0: int64 = 0
    a1: int64 = 0
    a2: int64 = 0
    a3: int64 = 0
  i = 0
  while i < m:
    a0 = ntruToomCoeffAt(A, p, i)
    a1 = ntruToomCoeffAt(A, p, m + i)
    a2 = ntruToomCoeffAt(A, p, 2 * m + i)
    a3 = ntruToomCoeffAt(A, p, 3 * m + i)
    case point
    of 0:
      E[i] = a0
    of 1:
      E[i] = a0 + a1 + a2 + a3
    of -1:
      E[i] = a0 - a1 + a2 - a3
    of 2:
      E[i] = a0 + 2 * a1 + 4 * a2 + 8 * a3
    of -2:
      E[i] = a0 - 2 * a1 + 4 * a2 - 8 * a3
    of 3:
      E[i] = a0 + 3 * a1 + 9 * a2 + 27 * a3
    else:
      E[i] = a3
    i = i + 1

proc mulNtruToomEvals(R: var NtruToomProd, A, B: NtruToomEval, m: int) {.inline.} =
  var
    i: int = 0
    j: int = 0
    n: int = 0
  n = 2 * m - 1
  i = 0
  while i < n:
    R[i] = 0
    i = i + 1
  i = 0
  while i < m:
    j = 0
    while j < m:
      R[i + j] = R[i + j] + A[i] * B[j]
      j = j + 1
    i = i + 1

proc mulNtruToomPoint(R: var NtruToomProd, p: NtruParams, a, b: NtruPoly,
    point, m: int) {.inline.} =
  var
    A: NtruToomEval
    B: NtruToomEval
  evalNtruToomPoint(A, p, a, point, m)
  evalNtruToomPoint(B, p, b, point, m)
  mulNtruToomEvals(R, A, B, m)

proc interpolateNtruToom(C: var NtruToomWide, W: NtruToomProducts, l, m: int) {.inline.} =
  var
    i: int = 0
    n: int = 0
    w0: int64 = 0
    w1: int64 = 0
    wm1: int64 = 0
    w2: int64 = 0
    wm2: int64 = 0
    w3: int64 = 0
    winf: int64 = 0
    c0: int64 = 0
    c1: int64 = 0
    c2: int64 = 0
    c3: int64 = 0
    c4: int64 = 0
    c5: int64 = 0
    c6: int64 = 0
  n = 2 * m - 1
  i = 0
  while i < 2 * l:
    C[i] = 0
    i = i + 1
  i = 0
  while i < n:
    w0 = W[0][i]
    w1 = W[1][i]
    wm1 = W[2][i]
    w2 = W[3][i]
    wm2 = W[4][i]
    w3 = W[5][i]
    winf = W[6][i]
    c0 = w0
    c1 = (-40 * w0 + 120 * w1 - 60 * wm1 - 30 * w2 + 6 * wm2 +
      4 * w3 - 1440 * winf) div 120
    c2 = (-30 * w0 + 16 * w1 + 16 * wm1 - w2 - wm2 + 96 * winf) div 24
    c3 = (10 * w0 - 14 * w1 - wm1 + 7 * w2 - wm2 - w3 +
      360 * winf) div 24
    c4 = (6 * w0 - 4 * w1 - 4 * wm1 + w2 + wm2 - 120 * winf) div 24
    c5 = (-10 * w0 + 10 * w1 + 5 * wm1 - 5 * w2 - wm2 + w3 -
      360 * winf) div 120
    c6 = winf
    C[i] = C[i] + c0
    C[m + i] = C[m + i] + c1
    C[2 * m + i] = C[2 * m + i] + c2
    C[3 * m + i] = C[3 * m + i] + c3
    C[4 * m + i] = C[4 * m + i] + c4
    C[5 * m + i] = C[5 * m + i] + c5
    C[6 * m + i] = C[6 * m + i] + c6
    i = i + 1

proc polyRqMulToom4(r: var NtruPoly, p: NtruParams, a, b: NtruPoly) {.inline.} =
  var
    W: NtruToomProducts
    C: NtruToomWide
    l: int = 0
    m: int = 0
    i: int = 0
  l = ntruToomLen(p)
  m = l div 4
  mulNtruToomPoint(W[0], p, a, b, 0, m)
  mulNtruToomPoint(W[1], p, a, b, 1, m)
  mulNtruToomPoint(W[2], p, a, b, -1, m)
  mulNtruToomPoint(W[3], p, a, b, 2, m)
  mulNtruToomPoint(W[4], p, a, b, -2, m)
  mulNtruToomPoint(W[5], p, a, b, 3, m)
  mulNtruToomPoint(W[6], p, a, b, ntruToomInfPoint, m)
  interpolateNtruToom(C, W, l, m)
  i = 0
  while i < p.n:
    r.coeffs[i] = i64ToU16(C[i] + C[p.n + i])
    i = i + 1

proc k2x2Eval(E: var NtruToomK2Eval, k: int) {.inline.} =
  var
    i: int = 0
  i = 0
  while i < 4 * k:
    E[4 * k + i] = E[i]
    i = i + 1
  i = 0
  while i < k:
    E[4 * k + i] = u16Add(E[4 * k + i], E[1 * k + i])
    E[5 * k + i] = u16Add(E[5 * k + i], E[3 * k + i])
    E[6 * k + i] = u16Add(E[6 * k + i], E[0 * k + i])
    E[7 * k + i] = u16Add(E[7 * k + i], E[2 * k + i])
    E[8 * k + i] = u16Add(E[5 * k + i], E[6 * k + i])
    i = i + 1

proc evalNtruToomK2Point(E: var NtruToomK2Eval, A: NtruToomK2Padded,
    point, m, k: int) {.inline.} =
  var
    i: int = 0
    a0: uint16 = 0
    a1: uint16 = 0
    a2: uint16 = 0
    a3: uint16 = 0
  i = 0
  while i < m:
    a0 = A[i]
    a1 = A[m + i]
    a2 = A[2 * m + i]
    a3 = A[3 * m + i]
    case point
    of 0:
      E[i] = a0
    of 1:
      E[i] = u16Add(u16Add(a0, a1), u16Add(a2, a3))
    of -1:
      E[i] = u16Sub(u16Add(a0, a2), u16Add(a1, a3))
    of 2:
      E[i] = u16Add(u16Add(a0, u16MulSmall(a1, 2)),
        u16Add(u16MulSmall(a2, 4), u16MulSmall(a3, 8)))
    of -2:
      E[i] = u16Sub(u16Add(a0, u16MulSmall(a2, 4)),
        u16Add(u16MulSmall(a1, 2), u16MulSmall(a3, 8)))
    of 3:
      E[i] = u16Add(u16Add(a0, u16MulSmall(a1, 3)),
        u16Add(u16MulSmall(a2, 9), u16MulSmall(a3, 27)))
    else:
      E[i] = a3
    i = i + 1
  k2x2Eval(E, k)

proc schoolbookKxK(R: var NtruToomK2Prod, rOff: int, A: NtruToomK2Eval,
    aOff: int, B: NtruToomK2Eval, bOff, k: int) {.inline.} =
  var
    i: int = 0
    j: int = 0
  j = 0
  while j < k:
    R[rOff + j] = u16Mul(A[aOff], B[bOff + j])
    j = j + 1
  i = 1
  while i < k:
    j = 0
    while j < k - 1:
      R[rOff + i + j] = u16Add(R[rOff + i + j],
        u16Mul(A[aOff + i], B[bOff + j]))
      j = j + 1
    R[rOff + i + k - 1] = u16Mul(A[aOff + i], B[bOff + k - 1])
    i = i + 1
  R[rOff + 2 * k - 1] = 0

proc toomK2BaseMul(R: var NtruToomK2Prod, A, B: NtruToomK2Eval,
    k: int) {.inline.} =
  var
    i: int = 0
  i = 0
  while i < 9:
    schoolbookKxK(R, i * 2 * k, A, i * k, B, i * k, k)
    i = i + 1

proc toomK2PointMul(R: var NtruToomK2Prod, A, B: NtruToomK2Padded,
    point, m, k: int) {.inline.} =
  var
    AE: NtruToomK2Eval
    BE: NtruToomK2Eval
  evalNtruToomK2Point(AE, A, point, m, k)
  evalNtruToomK2Point(BE, B, point, m, k)
  toomK2BaseMul(R, AE, BE, k)

proc k2x2Interpolate(R: var NtruToomK2Chunk, A: NtruToomK2Prod,
    k: int) {.inline.} =
  var
    tmp: NtruToomK2Tmp
    i: int = 0
  i = 0
  while i < 2 * k:
    R[0 * k + i] = A[0 * k + i]
    R[2 * k + i] = A[2 * k + i]
    i = i + 1
  i = 0
  while i < 2 * k:
    R[1 * k + i] = u16Add(R[1 * k + i],
      u16Sub(u16Sub(A[8 * k + i], A[0 * k + i]), A[2 * k + i]))
    i = i + 1
  i = 0
  while i < 2 * k:
    R[4 * k + i] = A[4 * k + i]
    R[6 * k + i] = A[6 * k + i]
    i = i + 1
  i = 0
  while i < 2 * k:
    R[5 * k + i] = u16Add(R[5 * k + i],
      u16Sub(u16Sub(A[14 * k + i], A[4 * k + i]), A[6 * k + i]))
    i = i + 1
  i = 0
  while i < 2 * k:
    tmp[0 * k + i] = A[12 * k + i]
    tmp[2 * k + i] = A[10 * k + i]
    i = i + 1
  i = 0
  while i < 2 * k:
    tmp[1 * k + i] = u16Add(tmp[1 * k + i],
      u16Sub(u16Sub(A[16 * k + i], A[12 * k + i]), A[10 * k + i]))
    i = i + 1
  i = 0
  while i < 4 * k:
    tmp[i] = u16Sub(u16Sub(tmp[i], R[i]), R[4 * k + i])
    i = i + 1
  i = 0
  while i < 4 * k:
    R[2 * k + i] = u16Add(R[2 * k + i], tmp[i])
    i = i + 1

proc copyK2ChunkToWide(C: var NtruToomK2Wide, o: int, A: NtruToomK2Chunk,
    n: int) {.inline.} =
  var
    i: int = 0
  i = 0
  while i < n:
    C[o + i] = A[i]
    i = i + 1

proc interpolateNtruToomK2(C: var NtruToomK2Wide, W: NtruToomK2Products,
    m, k: int) {.inline.} =
  const
    inv3: uint16 = 43691
    inv5: uint16 = 52429
  var
    c0: NtruToomK2Chunk
    p1: NtruToomK2Chunk
    pm1: NtruToomK2Chunk
    p2: NtruToomK2Chunk
    pm2: NtruToomK2Chunk
    c6: NtruToomK2Chunk
    i: int = 0
    n: int = 0
    v0: uint16 = 0
    v1: uint16 = 0
    v2: uint16 = 0
  n = 2 * m
  k2x2Interpolate(c0, W[0], k)
  k2x2Interpolate(p1, W[1], k)
  k2x2Interpolate(pm1, W[2], k)
  k2x2Interpolate(p2, W[3], k)
  k2x2Interpolate(pm2, W[4], k)
  k2x2Interpolate(c6, W[6], k)
  copyK2ChunkToWide(C, 0, c0, n)
  copyK2ChunkToWide(C, 6 * m, c6, n)
  i = 0
  while i < n:
    v0 = cShrI64ToU16(int64(p1[i]) + int64(pm1[i]), 1)
    v0 = u16Sub(u16Sub(v0, C[i]), C[6 * m + i])
    v1 = cShrI64ToU16(int64(p2[i]) + int64(pm2[i]) -
      2 * int64(C[i]) - 128 * int64(C[6 * m + i]), 3)
    C[4 * m + i] = u16Mul(inv3, u16Sub(v1, v0))
    C[2 * m + i] = u16Sub(v0, C[4 * m + i])
    p1[i] = cShrI64ToU16(int64(p1[i]) - int64(pm1[i]), 1)
    i = i + 1
  k2x2Interpolate(pm1, W[5], k)
  i = 0
  while i < n:
    v0 = p1[i]
    v1 = u16Mul(inv3,
      u16Sub(cShrI64ToU16(int64(p2[i]) - int64(pm2[i]), 2), v0))
    v2 = u16Mul(inv3, u16FromI64(int64(pm1[i]) - int64(C[i]) -
      9 * (int64(C[2 * m + i]) + 9 * (int64(C[4 * m + i]) +
      9 * int64(C[6 * m + i])))))
    v2 = cShrI64ToU16(int64(v2) - int64(v0), 3)
    v2 = u16Sub(v2, v1)
    pm1[i] = u16Mul(inv5, v2)
    p2[i] = u16Sub(v1, v2)
    p1[i] = u16Sub(u16Sub(v0, p2[i]), pm1[i])
    i = i + 1
  i = 0
  while i < n:
    C[1 * m + i] = u16Add(C[1 * m + i], p1[i])
    C[3 * m + i] = u16Add(C[3 * m + i], p2[i])
    C[5 * m + i] = u16Add(C[5 * m + i], pm1[i])
    i = i + 1

proc polyRqMulToom4K2(r: var NtruPoly, p: NtruParams, a, b: NtruPoly) {.inline.} =
  var
    A: NtruToomK2Padded
    B: NtruToomK2Padded
    W: NtruToomK2Products
    C: NtruToomK2Wide
    l: int = 0
    m: int = 0
    k: int = 0
    i: int = 0
  l = ntruToomK2Len(p)
  m = l div 4
  k = l div 16
  i = 0
  while i < p.n:
    A[i] = a.coeffs[i]
    B[i] = b.coeffs[i]
    i = i + 1
  while i < l:
    A[i] = 0
    B[i] = 0
    i = i + 1
  toomK2PointMul(W[0], A, B, 0, m, k)
  toomK2PointMul(W[1], A, B, 1, m, k)
  toomK2PointMul(W[2], A, B, -1, m, k)
  toomK2PointMul(W[3], A, B, 2, m, k)
  toomK2PointMul(W[4], A, B, -2, m, k)
  toomK2PointMul(W[5], A, B, 3, m, k)
  toomK2PointMul(W[6], A, B, ntruToomInfPoint, m, k)
  interpolateNtruToomK2(C, W, m, k)
  i = 0
  while i < p.n:
    r.coeffs[i] = u16Add(C[i], C[p.n + i])
    i = i + 1

proc polyRqMul*(r: var NtruPoly, p: NtruParams, a, b: NtruPoly) {.otterBench.} =
  when defined(ntruMulTmp):
    polyRqMulTmp(r, p, a, b)
  elif defined(ntruMulRows):
    polyRqMulRows(r, p, a, b)
  elif defined(ntruMulRowsUnroll4):
    polyRqMulRowsUnroll4(r, p, a, b)
  elif defined(ntruMulToom4K2):
    polyRqMulToom4K2(r, p, a, b)
  elif defined(ntruMulToom4):
    polyRqMulToom4(r, p, a, b)
  elif defined(ntruMulCoeff):
    polyRqMulCoeff(r, p, a, b)
  elif defined(avx2):
    polyRqMulAvx2(r, p, a, b)
  elif defined(sse2):
    polyRqMulSse2(r, p, a, b)
  elif defined(neon) or defined(arm64) or defined(aarch64):
    polyRqMulNeon(r, p, a, b)
  else:
    polyRqMulToom4K2(r, p, a, b)

proc polySqMul*(r: var NtruPoly, p: NtruParams, a, b: NtruPoly) {.otterBench.} =
  polyRqMul(r, p, a, b)
  polyModQPhi(r, p)

proc polyS3Mul*(r: var NtruPoly, p: NtruParams, a, b: NtruPoly) {.otterBench.} =
  var
    i: int = 0
  polyRqMul(r, p, a, b)
  i = 0
  while i < p.n:
    r.coeffs[i] = modQ(p, r.coeffs[i])
    i = i + 1
  polyMod3Phi(r, p)

proc polyR2Inv*(r: var NtruPoly, p: NtruParams, a: NtruPoly) {.otterBench.} =
  var
    f: NtruPoly
    g: NtruPoly
    v: NtruPoly
    w: NtruPoly
    i: int = 0
    loop: int = 0
    delta: int16 = 1
    sign: uint16 = 0
    swap: int16 = 0
    t: uint16 = 0
    mask: uint16 = 0
  w.coeffs[0] = 1
  i = 0
  while i < p.n:
    f.coeffs[i] = 1
    i = i + 1
  i = 0
  while i < p.n - 1:
    g.coeffs[p.n - 2 - i] = (a.coeffs[i] xor a.coeffs[p.n - 1]) and 1'u16
    i = i + 1
  g.coeffs[p.n - 1] = 0
  loop = 0
  while loop < 2 * (p.n - 1) - 1:
    i = p.n - 1
    while i > 0:
      v.coeffs[i] = v.coeffs[i - 1]
      i = i - 1
    v.coeffs[0] = 0
    sign = g.coeffs[0] and f.coeffs[0]
    swap = bothNegativeMask(int16(-int(delta)), int16(-int(g.coeffs[0])))
    delta = int16(int32(delta) xor (int32(swap) and (int32(delta) xor -int32(delta))))
    delta = int16(int32(delta) + 1)
    mask = cast[uint16](swap)
    i = 0
    while i < p.n:
      t = mask and (f.coeffs[i] xor g.coeffs[i])
      f.coeffs[i] = f.coeffs[i] xor t
      g.coeffs[i] = g.coeffs[i] xor t
      t = mask and (v.coeffs[i] xor w.coeffs[i])
      v.coeffs[i] = v.coeffs[i] xor t
      w.coeffs[i] = w.coeffs[i] xor t
      i = i + 1
    i = 0
    while i < p.n:
      g.coeffs[i] = g.coeffs[i] xor (sign and f.coeffs[i])
      w.coeffs[i] = w.coeffs[i] xor (sign and v.coeffs[i])
      i = i + 1
    i = 0
    while i < p.n - 1:
      g.coeffs[i] = g.coeffs[i + 1]
      i = i + 1
    g.coeffs[p.n - 1] = 0
    loop = loop + 1
  i = 0
  while i < p.n - 1:
    r.coeffs[i] = v.coeffs[p.n - 2 - i]
    i = i + 1
  r.coeffs[p.n - 1] = 0

proc polyS3Inv*(r: var NtruPoly, p: NtruParams, a: NtruPoly) {.otterBench.} =
  var
    f: NtruPoly
    g: NtruPoly
    v: NtruPoly
    w: NtruPoly
    i: int = 0
    loop: int = 0
    delta: int16 = 1
    sign: uint16 = 0
    swap: int16 = 0
    t: uint16 = 0
    mask: uint16 = 0
  w.coeffs[0] = 1
  i = 0
  while i < p.n:
    f.coeffs[i] = 1
    i = i + 1
  i = 0
  while i < p.n - 1:
    g.coeffs[p.n - 2 - i] = uint16(mod3Small(byte((a.coeffs[i] and 3'u16) +
      2'u16 * (a.coeffs[p.n - 1] and 3'u16))))
    i = i + 1
  g.coeffs[p.n - 1] = 0
  loop = 0
  while loop < 2 * (p.n - 1) - 1:
    i = p.n - 1
    while i > 0:
      v.coeffs[i] = v.coeffs[i - 1]
      i = i - 1
    v.coeffs[0] = 0
    sign = uint16(mod3Small(byte(2'u16 * g.coeffs[0] * f.coeffs[0])))
    swap = bothNegativeMask(int16(-int(delta)), int16(-int(g.coeffs[0])))
    delta = int16(int32(delta) xor (int32(swap) and (int32(delta) xor -int32(delta))))
    delta = int16(int32(delta) + 1)
    mask = cast[uint16](swap)
    i = 0
    while i < p.n:
      t = mask and (f.coeffs[i] xor g.coeffs[i])
      f.coeffs[i] = f.coeffs[i] xor t
      g.coeffs[i] = g.coeffs[i] xor t
      t = mask and (v.coeffs[i] xor w.coeffs[i])
      v.coeffs[i] = v.coeffs[i] xor t
      w.coeffs[i] = w.coeffs[i] xor t
      i = i + 1
    i = 0
    while i < p.n:
      g.coeffs[i] = uint16(mod3Small(byte(g.coeffs[i] + sign * f.coeffs[i])))
      w.coeffs[i] = uint16(mod3Small(byte(w.coeffs[i] + sign * v.coeffs[i])))
      i = i + 1
    i = 0
    while i < p.n - 1:
      g.coeffs[i] = g.coeffs[i + 1]
      i = i + 1
    g.coeffs[p.n - 1] = 0
    loop = loop + 1
  sign = f.coeffs[0]
  i = 0
  while i < p.n - 1:
    r.coeffs[i] = uint16(mod3Small(byte(sign * v.coeffs[p.n - 2 - i])))
    i = i + 1
  r.coeffs[p.n - 1] = 0

proc polyRqInv*(r: var NtruPoly, p: NtruParams, a: NtruPoly) {.otterBench.} =
  var
    ai2: NtruPoly
    b: NtruPoly
    c: NtruPoly
    s: NtruPoly
    i: int = 0
    iter: int = 0
  polyR2Inv(ai2, p, a)
  i = 0
  while i < p.n:
    b.coeffs[i] = u16Neg(a.coeffs[i])
    r.coeffs[i] = ai2.coeffs[i]
    i = i + 1
  iter = 0
  while iter < 4:
    polyRqMul(c, p, r, b)
    c.coeffs[0] = u16Add(c.coeffs[0], 2)
    polyRqMul(s, p, c, r)
    r = s
    iter = iter + 1

proc polyLift*(r: var NtruPoly, p: NtruParams, a: NtruPoly) {.otterBench.} =
  var
    b: NtruPoly
    i: int = 0
    t: uint16 = 0
    zj: uint16 = 0
  if p.hps:
    i = 0
    while i < p.n:
      r.coeffs[i] = a.coeffs[i]
      i = i + 1
    polyZ3ToZq(r, p)
    return
  t = uint16(3 - (p.n mod 3))
  b.coeffs[0] = uint16(uint32(a.coeffs[0]) * uint32(2 - t) +
    uint32(a.coeffs[2]) * uint32(t))
  b.coeffs[1] = uint16(uint32(a.coeffs[1]) * uint32(2 - t))
  b.coeffs[2] = uint16(uint32(a.coeffs[2]) * uint32(2 - t))
  zj = 0
  i = 3
  while i < p.n:
    b.coeffs[0] = u16Add(b.coeffs[0], uint16(uint32(a.coeffs[i]) * uint32(zj + 2 * t)))
    b.coeffs[1] = u16Add(b.coeffs[1], uint16(uint32(a.coeffs[i]) * uint32(zj + t)))
    b.coeffs[2] = u16Add(b.coeffs[2], uint16(uint32(a.coeffs[i]) * uint32(zj)))
    zj = uint16((zj + t) mod 3)
    i = i + 1
  b.coeffs[1] = u16Add(b.coeffs[1], uint16(uint32(a.coeffs[0]) * uint32(zj + t)))
  b.coeffs[2] = u16Add(b.coeffs[2], uint16(uint32(a.coeffs[0]) * uint32(zj)))
  b.coeffs[2] = u16Add(b.coeffs[2], uint16(uint32(a.coeffs[1]) * uint32(zj + t)))
  i = 3
  while i < p.n:
    b.coeffs[i] = u16Add(b.coeffs[i - 3],
      uint16(2'u32 * uint32(a.coeffs[i] + a.coeffs[i - 1] + a.coeffs[i - 2])))
    i = i + 1
  polyMod3Phi(b, p)
  polyZ3ToZq(b, p)
  r.coeffs[0] = u16Neg(b.coeffs[0])
  i = 0
  while i < p.n - 1:
    r.coeffs[i + 1] = u16Sub(b.coeffs[i], b.coeffs[i + 1])
    i = i + 1

proc sampleIid(r: var NtruPoly, p: NtruParams, U: openArray[byte]) {.otterBench.} =
  var
    i: int = 0
  i = 0
  while i < p.n - 1:
    r.coeffs[i] = mod3(uint16(U[i]))
    i = i + 1
  r.coeffs[p.n - 1] = 0

proc sampleFixedTypeSort(r: var NtruPoly, p: NtruParams,
    U: openArray[byte]) {.inline.} =
  var
    S: seq[int32] = @[]
    i: int = 0
    x: uint32 = 0
  S = newSeq[int32](p.n - 1)
  i = 0
  while i < (p.n - 1) div 4:
    x = (uint32(U[15 * i + 0]) shl 2) or (uint32(U[15 * i + 1]) shl 10) or
      (uint32(U[15 * i + 2]) shl 18) or (uint32(U[15 * i + 3]) shl 26)
    S[4 * i + 0] = cast[int32](x)
    x = ((uint32(U[15 * i + 3]) and 0xc0'u32) shr 4) or
      (uint32(U[15 * i + 4]) shl 4) or (uint32(U[15 * i + 5]) shl 12) or
      (uint32(U[15 * i + 6]) shl 20) or (uint32(U[15 * i + 7]) shl 28)
    S[4 * i + 1] = cast[int32](x)
    x = ((uint32(U[15 * i + 7]) and 0xf0'u32) shr 2) or
      (uint32(U[15 * i + 8]) shl 6) or (uint32(U[15 * i + 9]) shl 14) or
      (uint32(U[15 * i + 10]) shl 22) or (uint32(U[15 * i + 11]) shl 30)
    S[4 * i + 2] = cast[int32](x)
    x = (uint32(U[15 * i + 11]) and 0xfc'u32) or
      (uint32(U[15 * i + 12]) shl 8) or (uint32(U[15 * i + 13]) shl 16) or
      (uint32(U[15 * i + 14]) shl 24)
    S[4 * i + 3] = cast[int32](x)
    i = i + 1
  i = 0
  while i < p.weight div 2:
    S[i] = S[i] or 1
    i = i + 1
  while i < p.weight:
    S[i] = S[i] or 2
    i = i + 1
  sortInt32Fixed(S)
  i = 0
  while i < p.n - 1:
    r.coeffs[i] = uint16(S[i] and 3)
    i = i + 1

proc sampleFixedType(r: var NtruPoly, p: NtruParams, U: openArray[byte]) {.otterBench.} =
  ## The fixed sorting network is data-oblivious. The removed ISO rejection
  ## sampler had secret-dependent work and could read beyond its input.
  sampleFixedTypeSort(r, p, U)
  r.coeffs[p.n - 1] = 0

proc sampleIidPlus(r: var NtruPoly, p: NtruParams, U: openArray[byte]) {.otterBench.} =
  var
    i: int = 0
    s: uint16 = 0
  sampleIid(r, p, U)
  i = 0
  while i < p.n - 1:
    r.coeffs[i] = r.coeffs[i] or u16Neg(r.coeffs[i] shr 1)
    i = i + 1
  i = 0
  while i < p.n - 1:
    s = u16Add(s, u16Mul(r.coeffs[i + 1], r.coeffs[i]))
    i = i + 1
  s = 1'u16 or u16Neg(s shr 15)
  i = 0
  while i < p.n:
    r.coeffs[i] = u16Mul(s, r.coeffs[i])
    i = i + 2
  i = 0
  while i < p.n:
    r.coeffs[i] = 3'u16 and (r.coeffs[i] xor (r.coeffs[i] shr 15))
    i = i + 1

proc sampleFg(f, g: var NtruPoly, p: NtruParams, U: openArray[byte]) {.otterBench.} =
  if p.hps:
    sampleIid(f, p, U.toOpenArray(0, p.sampleIidBytes - 1))
    sampleFixedType(g, p, U.toOpenArray(p.sampleIidBytes, p.sampleFgBytes - 1))
  else:
    sampleIidPlus(f, p, U.toOpenArray(0, p.sampleIidBytes - 1))
    sampleIidPlus(g, p, U.toOpenArray(p.sampleIidBytes, p.sampleFgBytes - 1))

proc sampleRm(r, m: var NtruPoly, p: NtruParams, U: openArray[byte]) {.otterBench.} =
  if p.hps:
    sampleIid(r, p, U.toOpenArray(0, p.sampleIidBytes - 1))
    sampleFixedType(m, p, U.toOpenArray(p.sampleIidBytes, p.sampleRmBytes - 1))
  else:
    sampleIid(r, p, U.toOpenArray(0, p.sampleIidBytes - 1))
    sampleIid(m, p, U.toOpenArray(p.sampleIidBytes, p.sampleRmBytes - 1))

proc owcpaCheckCiphertext(p: NtruParams, ciphertext: openArray[byte]): int =
  var
    t: uint16 = 0
    used: int = 0
  used = (p.logQ * p.packDeg) and 7
  t = uint16(ciphertext[p.ciphertextBytes - 1])
  t = t and uint16(0xff'u16 shl (8 - used))
  result = nonzeroToOne(uint32(t))

proc owcpaCheckR(p: NtruParams, r: NtruPoly): int =
  var
    i: int = 0
    t: uint32 = 0
    c: uint16 = 0
  i = 0
  while i < p.n - 1:
    c = r.coeffs[i]
    t = t or uint32((c + 1'u16) and uint16(int(q(p)) - 4))
    t = t or uint32((c + 2'u16) and 4'u16)
    i = i + 1
  t = t or uint32(r.coeffs[p.n - 1])
  result = nonzeroToOne(t)

proc owcpaCheckM(p: NtruParams, m: NtruPoly): int =
  var
    i: int = 0
    t: uint32 = 0
    ps: uint16 = 0
    ms: uint16 = 0
  i = 0
  while i < p.n:
    ps = ps + (m.coeffs[i] and 1'u16)
    ms = ms + (m.coeffs[i] and 2'u16)
    i = i + 1
  t = t or uint32(ps xor (ms shr 1))
  t = t or uint32(ms xor uint16(p.weight))
  result = nonzeroToOne(t)

proc owcpaKeypair*(pk, sk: var openArray[byte], p: NtruParams, seed: openArray[byte]) {.otterBench.} =
  ## Generate an NTRU OWC-CPA keypair.
  var
    f: NtruPoly
    g: NtruPoly
    invfMod3: NtruPoly
    gf: NtruPoly
    invgf: NtruPoly
    tmp: NtruPoly
    invh: NtruPoly
    h: NtruPoly
    i: int = 0
  sampleFg(f, g, p, seed)
  polyS3Inv(invfMod3, p, f)
  polyS3ToBytes(sk.toOpenArray(0, p.packTrinaryBytes - 1), p, f)
  polyS3ToBytes(sk.toOpenArray(p.packTrinaryBytes, 2 * p.packTrinaryBytes - 1), p, invfMod3)
  polyZ3ToZq(f, p)
  polyZ3ToZq(g, p)
  if p.hps:
    i = 0
    while i < p.n:
      g.coeffs[i] = uint16(3'u32 * uint32(g.coeffs[i]))
      i = i + 1
  else:
    i = p.n - 1
    while i > 0:
      g.coeffs[i] = uint16(3'u32 * uint32(u16Sub(g.coeffs[i - 1], g.coeffs[i])))
      i = i - 1
    g.coeffs[0] = u16Neg(uint16(3'u32 * uint32(g.coeffs[0])))
  polyRqMul(gf, p, g, f)
  polyRqInv(invgf, p, gf)
  polyRqMul(tmp, p, invgf, f)
  polySqMul(invh, p, tmp, f)
  polySqToBytes(sk.toOpenArray(2 * p.packTrinaryBytes,
    2 * p.packTrinaryBytes + p.owcpaPublicKeyBytes - 1), p, invh)
  polyRqMul(tmp, p, invgf, g)
  polyRqMul(h, p, tmp, g)
  polyRqSumZeroToBytes(pk, p, h)
  secureClearPoly(f)
  secureClearPoly(g)
  secureClearPoly(invfMod3)
  secureClearPoly(gf)
  secureClearPoly(invgf)
  secureClearPoly(tmp)
  secureClearPoly(invh)

proc owcpaEnc*(c: var openArray[byte], p: NtruParams, r, m: NtruPoly,
    pk: openArray[byte]) {.otterBench.} =
  ## Encrypt one NTRU OWC-CPA message.
  var
    h: NtruPoly
    liftm: NtruPoly
    ct: NtruPoly
    i: int = 0
  polyRqSumZeroFromBytes(h, p, pk)
  polyRqMul(ct, p, r, h)
  polyLift(liftm, p, m)
  i = 0
  while i < p.n:
    ct.coeffs[i] = u16Add(ct.coeffs[i], liftm.coeffs[i])
    i = i + 1
  polyRqSumZeroToBytes(c, p, ct)
  secureClearPoly(liftm)

proc owcpaDec*(rm: var openArray[byte], p: NtruParams, ciphertext,
    secretkey: openArray[byte]): int {.otterBench.} =
  ## Decrypt and validate one NTRU OWC-CPA ciphertext.
  var
    c: NtruPoly
    f: NtruPoly
    cf: NtruPoly
    mf: NtruPoly
    finv3: NtruPoly
    m: NtruPoly
    liftm: NtruPoly
    invh: NtruPoly
    r: NtruPoly
    b: NtruPoly
    i: int = 0
  polyRqSumZeroFromBytes(c, p, ciphertext)
  polyS3FromBytes(f, p, secretkey.toOpenArray(0, p.packTrinaryBytes - 1))
  polyZ3ToZq(f, p)
  polyRqMul(cf, p, c, f)
  polyRqToS3(mf, p, cf)
  polyS3FromBytes(finv3, p, secretkey.toOpenArray(p.packTrinaryBytes,
    2 * p.packTrinaryBytes - 1))
  polyS3Mul(m, p, mf, finv3)
  polyS3ToBytes(rm.toOpenArray(p.packTrinaryBytes, p.owcpaMsgBytes - 1), p, m)
  result = owcpaCheckCiphertext(p, ciphertext)
  if p.hps:
    result = result or owcpaCheckM(p, m)
  polyLift(liftm, p, m)
  i = 0
  while i < p.n:
    b.coeffs[i] = u16Sub(c.coeffs[i], liftm.coeffs[i])
    i = i + 1
  polySqFromBytes(invh, p, secretkey.toOpenArray(2 * p.packTrinaryBytes,
    2 * p.packTrinaryBytes + p.owcpaPublicKeyBytes - 1))
  polySqMul(r, p, b, invh)
  result = result or owcpaCheckR(p, r)
  polyTrinaryZqToZ3(r, p)
  polyS3ToBytes(rm.toOpenArray(0, p.packTrinaryBytes - 1), p, r)
  secureClearPoly(f)
  secureClearPoly(finv3)
  secureClearPoly(invh)
  secureClearPoly(m)
  secureClearPoly(r)
  secureClearPoly(cf)
  secureClearPoly(mf)
  secureClearPoly(b)
  secureClearPoly(liftm)

proc ntruKemKeypairInto*(pk, sk: var openArray[byte], p: NtruParams,
    R: var PqRandomContext) {.otterBench.} =
  ## Generate an NTRU KEM keypair.
  var
    seed: seq[byte] = @[]
    prf: seq[byte] = @[]
  seed = pqRandomBytes(R, p.sampleFgBytes)
  owcpaKeypair(pk, sk.toOpenArray(0, p.owcpaSecretKeyBytes - 1), p, seed)
  prf = pqRandomBytes(R, ntruPrfKeyBytes)
  copyBytes(sk, p.owcpaSecretKeyBytes, prf)
  secureClearBytes(seed)
  secureClearBytes(prf)

proc ntruKemEncInto*(ciphertext, sharedSecret: var openArray[byte],
    pk: openArray[byte], p: NtruParams, R: var PqRandomContext) {.otterBench.} =
  ## Encapsulate with pure-Nim NTRU.
  var
    r: NtruPoly
    m: NtruPoly
    rm: seq[byte] = @[]
    rmSeed: seq[byte] = @[]
  rm = newSeq[byte](p.owcpaMsgBytes)
  rmSeed = pqRandomBytes(R, p.sampleRmBytes)
  sampleRm(r, m, p, rmSeed)
  polyS3ToBytes(rm.toOpenArray(0, p.packTrinaryBytes - 1), p, r)
  polyS3ToBytes(rm.toOpenArray(p.packTrinaryBytes, p.owcpaMsgBytes - 1), p, m)
  sha3_256Into(sharedSecret, rm)
  polyZ3ToZq(r, p)
  owcpaEnc(ciphertext, p, r, m, pk)
  secureClearPoly(r)
  secureClearPoly(m)
  secureClearBytes(rm)
  secureClearBytes(rmSeed)

proc ntruKemDecInto*(sharedSecret: var openArray[byte], sk, ciphertext: openArray[byte],
    p: NtruParams) {.otterBench.} =
  ## Decapsulate with pure-Nim NTRU.
  var
    fail: int = 0
    rm: seq[byte] = @[]
    buf: seq[byte] = @[]
  rm = newSeq[byte](p.owcpaMsgBytes)
  buf = newSeq[byte](ntruPrfKeyBytes + p.ciphertextBytes)
  fail = owcpaDec(rm, p, ciphertext, sk)
  sha3_256Into(sharedSecret, rm)
  copyBytes(buf, 0, sk.toOpenArray(p.owcpaSecretKeyBytes,
    p.owcpaSecretKeyBytes + ntruPrfKeyBytes - 1))
  copyBytes(buf, ntruPrfKeyBytes, ciphertext)
  sha3_256Into(rm.toOpenArray(0, ntruSharedSecretBytes - 1), buf)
  cmovBytes(sharedSecret, rm.toOpenArray(0, ntruSharedSecretBytes - 1), uint8(fail))
  secureClearBytes(rm)
  secureClearBytes(buf)

{.pop.}
