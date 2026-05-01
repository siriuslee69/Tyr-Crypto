## -------------------------------------------------------------
## SABER Core <- pure-Nim SABER arithmetic, IND-CPA, and KEM code
## -------------------------------------------------------------

import ./params
import ../common/pq_rng
import ../../../sha3
import ../kyber/verify
import ../../../../helpers/otter_support

when defined(saberMulNttScalar):
  import std/volatile

when defined(sse2) or defined(avx2) or defined(neon) or defined(arm64) or defined(aarch64):
  import simd_nexus/simd/base_operations
when defined(neon) or defined(arm64) or defined(aarch64):
  import simd_nexus/simd/generic_i16

{.push boundChecks: off.}

type
  ## One SABER polynomial in R_q / R_p.
  SaberPoly* = object
    coeffs*: array[saberN, uint16]

  ## SABER uses at most L=4; parameter sets select the active prefix.
  SaberPolyVec* = array[4, SaberPoly]
  SaberMatrix* = array[4, SaberPolyVec]

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

proc u16Shl(a: uint16, b: int): uint16 {.inline.} =
  result = uint16((uint32(a) shl b) and 0xffff'u32)

proc u16MulSmall(a: uint16, b: int): uint16 {.inline.} =
  result = uint16((uint32(a) * uint32(b)) and 0xffff'u32)

proc cSarDiffU16(a, b: uint16, shift: int): uint16 {.inline.} =
  var
    t: int32 = 0
  t = int32(uint32(a)) - int32(uint32(b))
  result = uint16(cast[uint32](t shr shift) and 0xffff'u32)

proc cMulShiftU16(a: int64, m: uint16, shift: int): uint16 {.inline.} =
  var
    x: uint64 = 0
    y: uint64 = 0
  x = uint64(cast[uint32](int32(a)))
  y = (x * uint64(m)) and 0xffffffff'u64
  result = uint16((y shr shift) and 0xffff'u64)

proc clearPoly(S: var SaberPoly) =
  var
    i: int = 0
  i = 0
  while i < saberN:
    S.coeffs[i] = 0
    i = i + 1

proc storeSaberReduced(c: var SaberPoly, i: int, v: uint16, accumulate: bool) {.inline.} =
  if accumulate:
    c.coeffs[i] = u16Add(c.coeffs[i], v)
  else:
    c.coeffs[i] = v

proc copyBytes(dst: var openArray[byte], o: int, src: openArray[byte]) =
  var
    i: int = 0
  i = 0
  while i < src.len:
    dst[o + i] = src[i]
    i = i + 1

proc loadLe(A: openArray[byte], o, n: int): uint64 =
  var
    i: int = 0
  result = 0
  i = 0
  while i < n:
    result = result or (uint64(A[o + i]) shl (8 * i))
    i = i + 1

proc packBits(dst: var openArray[byte], V: openArray[uint16], bits, count: int) =
  var
    mask: uint32 = 0
    acc: uint32 = 0
    accBits: int = 0
    outIdx: int = 0
    i: int = 0
  mask = (1'u32 shl bits) - 1'u32
  while outIdx < dst.len:
    dst[outIdx] = 0'u8
    outIdx = outIdx + 1
  outIdx = 0
  i = 0
  while i < count:
    acc = acc or ((uint32(V[i]) and mask) shl accBits)
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

proc polq2bs(dst: var openArray[byte], a: SaberPoly) =
  packBits(dst, a.coeffs, saberEq, saberN)

proc bs2polq(r: var SaberPoly, src: openArray[byte]) =
  unpackBits(r.coeffs, src, saberEq, saberN)

proc polp2bs(dst: var openArray[byte], a: SaberPoly) =
  packBits(dst, a.coeffs, saberEp, saberN)

proc bs2polp(r: var SaberPoly, src: openArray[byte]) =
  unpackBits(r.coeffs, src, saberEp, saberN)

proc polt2bs(dst: var openArray[byte], p: SaberParams, a: SaberPoly) =
  packBits(dst, a.coeffs, p.et, saberN)

proc bs2polt(r: var SaberPoly, p: SaberParams, src: openArray[byte]) =
  unpackBits(r.coeffs, src, p.et, saberN)

proc polvecq2bs(dst: var openArray[byte], p: SaberParams, V: SaberPolyVec) =
  var
    i: int = 0
    o: int = 0
  i = 0
  while i < p.l:
    o = i * saberPolyBytes
    polq2bs(dst.toOpenArray(o, o + saberPolyBytes - 1), V[i])
    i = i + 1

proc bs2polvecq(V: var SaberPolyVec, p: SaberParams, src: openArray[byte]) =
  var
    i: int = 0
    o: int = 0
  i = 0
  while i < p.l:
    o = i * saberPolyBytes
    bs2polq(V[i], src.toOpenArray(o, o + saberPolyBytes - 1))
    i = i + 1

proc polvecp2bs(dst: var openArray[byte], p: SaberParams, V: SaberPolyVec) =
  var
    i: int = 0
    o: int = 0
  i = 0
  while i < p.l:
    o = i * saberPolyCompressedBytes
    polp2bs(dst.toOpenArray(o, o + saberPolyCompressedBytes - 1), V[i])
    i = i + 1

proc bs2polvecp(V: var SaberPolyVec, p: SaberParams, src: openArray[byte]) =
  var
    i: int = 0
    o: int = 0
  i = 0
  while i < p.l:
    o = i * saberPolyCompressedBytes
    bs2polp(V[i], src.toOpenArray(o, o + saberPolyCompressedBytes - 1))
    i = i + 1

proc bs2polmsg(r: var SaberPoly, src: openArray[byte]) =
  var
    i: int = 0
    j: int = 0
  j = 0
  while j < saberKeyBytes:
    i = 0
    while i < 8:
      r.coeffs[j * 8 + i] = uint16((src[j] shr i) and 1'u8)
      i = i + 1
    j = j + 1

proc polmsg2bs(dst: var openArray[byte], a: SaberPoly) =
  var
    i: int = 0
    j: int = 0
  j = 0
  while j < saberKeyBytes:
    dst[j] = 0'u8
    i = 0
    while i < 8:
      dst[j] = dst[j] or byte((a.coeffs[j * 8 + i] and 1'u16) shl i)
      i = i + 1
    j = j + 1

proc cbd(r: var SaberPoly, p: SaberParams, buf: openArray[byte]) {.otterBench.} =
  var
    i: int = 0
    j: int = 0
    t: uint64 = 0
    d: uint64 = 0
    a0: uint64 = 0
    a1: uint64 = 0
    a2: uint64 = 0
    a3: uint64 = 0
    b0: uint64 = 0
    b1: uint64 = 0
    b2: uint64 = 0
    b3: uint64 = 0
  i = 0
  while i < saberN div 4:
    d = 0
    case p.mu
    of 10:
      t = loadLe(buf, 5 * i, 5)
      j = 0
      while j < 5:
        d = d + ((t shr j) and 0x0842108421'u64)
        j = j + 1
      a0 = d and 0x1f'u64
      b0 = (d shr 5) and 0x1f'u64
      a1 = (d shr 10) and 0x1f'u64
      b1 = (d shr 15) and 0x1f'u64
      a2 = (d shr 20) and 0x1f'u64
      b2 = (d shr 25) and 0x1f'u64
      a3 = (d shr 30) and 0x1f'u64
      b3 = d shr 35
    of 8:
      t = loadLe(buf, 4 * i, 4)
      j = 0
      while j < 4:
        d = d + ((t shr j) and 0x11111111'u64)
        j = j + 1
      a0 = d and 0x0f'u64
      b0 = (d shr 4) and 0x0f'u64
      a1 = (d shr 8) and 0x0f'u64
      b1 = (d shr 12) and 0x0f'u64
      a2 = (d shr 16) and 0x0f'u64
      b2 = (d shr 20) and 0x0f'u64
      a3 = (d shr 24) and 0x0f'u64
      b3 = d shr 28
    of 6:
      t = loadLe(buf, 3 * i, 3)
      j = 0
      while j < 3:
        d = d + ((t shr j) and 0x249249'u64)
        j = j + 1
      a0 = d and 0x07'u64
      b0 = (d shr 3) and 0x07'u64
      a1 = (d shr 6) and 0x07'u64
      b1 = (d shr 9) and 0x07'u64
      a2 = (d shr 12) and 0x07'u64
      b2 = (d shr 15) and 0x07'u64
      a3 = (d shr 18) and 0x07'u64
      b3 = d shr 21
    else:
      raise newException(ValueError, "unsupported SABER noise width")
    r.coeffs[4 * i + 0] = u16Sub(uint16(a0), uint16(b0))
    r.coeffs[4 * i + 1] = u16Sub(uint16(a1), uint16(b1))
    r.coeffs[4 * i + 2] = u16Sub(uint16(a2), uint16(b2))
    r.coeffs[4 * i + 3] = u16Sub(uint16(a3), uint16(b3))
    i = i + 1

when defined(sse2):
  proc reduceNegacyclicSse(c: var SaberPoly, C: array[2 * saberN, uint16],
      accumulate: bool) =
    var
      i: int = 0
      a: i16x8
      b: i16x8
      r: i16x8
      old: i16x8
    i = 0
    while i + 8 <= saberN:
      a = i16x8(mm_loadu_si128(cast[pointer](unsafeAddr C[i])))
      b = i16x8(mm_loadu_si128(cast[pointer](unsafeAddr C[saberN + i])))
      r = a - b
      if accumulate:
        old = i16x8(mm_loadu_si128(cast[pointer](unsafeAddr c.coeffs[i])))
        r = old + r
      mm_storeu_si128(cast[pointer](unsafeAddr c.coeffs[i]), M128i(r))
      i = i + 8

when defined(avx2):
  proc reduceNegacyclicAvx2(c: var SaberPoly, C: array[2 * saberN, uint16],
      accumulate: bool) =
    var
      i: int = 0
      a: i16x16
      b: i16x16
      r: i16x16
      old: i16x16
    i = 0
    while i + 16 <= saberN:
      a = i16x16(mm256_loadu_si256(cast[pointer](unsafeAddr C[i])))
      b = i16x16(mm256_loadu_si256(cast[pointer](unsafeAddr C[saberN + i])))
      r = a - b
      if accumulate:
        old = i16x16(mm256_loadu_si256(cast[pointer](unsafeAddr c.coeffs[i])))
        r = old + r
      mm256_storeu_si256(cast[pointer](unsafeAddr c.coeffs[i]), M256i(r))
      i = i + 16

when defined(neon) or defined(arm64) or defined(aarch64):
  proc reduceNegacyclicNeon(c: var SaberPoly, C: array[2 * saberN, uint16],
      accumulate: bool) =
    var
      i: int = 0
      a: uint16x8
      b: uint16x8
      r: uint16x8
      old: uint16x8
    i = 0
    while i + 8 <= saberN:
      a = loadI16x8At[uint16x8](C, i)
      b = loadI16x8At[uint16x8](C, saberN + i)
      r = a - b
      if accumulate:
        old = loadI16x8At[uint16x8](c.coeffs, i)
        r = old + r
      storeI16x8At[uint16x8](r, c.coeffs, i)
      i = i + 8

proc polyMulIntoTmp(c: var SaberPoly, a, b: SaberPoly, accumulate: bool) {.inline.} =
  var
    C: array[2 * saberN, uint16]
    i: int = 0
    j: int = 0
    prod: uint16 = 0
  i = 0
  while i < 2 * saberN:
    C[i] = 0
    i = i + 1
  i = 0
  while i < saberN:
    j = 0
    while j < saberN:
      prod = u16Mul(a.coeffs[i], b.coeffs[j])
      C[i + j] = u16Add(C[i + j], prod)
      j = j + 1
    i = i + 1
  when defined(avx2):
    reduceNegacyclicAvx2(c, C, accumulate)
  elif defined(sse2):
    reduceNegacyclicSse(c, C, accumulate)
  elif defined(neon) or defined(arm64) or defined(aarch64):
    reduceNegacyclicNeon(c, C, accumulate)
  else:
    var
      red: uint16 = 0
    i = 0
    while i < saberN:
      red = u16Sub(C[i], C[i + saberN])
      if accumulate:
        c.coeffs[i] = u16Add(c.coeffs[i], red)
      else:
        c.coeffs[i] = red
      i = i + 1

proc polyMulIntoRows(c: var SaberPoly, a, b: SaberPoly, accumulate: bool) {.inline.} =
  var
    i: int = 0
    j: int = 0
    k: int = 0
    ai: uint16 = 0
  if not accumulate:
    clearPoly(c)
  i = 0
  while i < saberN:
    ai = a.coeffs[i]
    j = 0
    k = i
    while k < saberN:
      c.coeffs[k] = u16Add(c.coeffs[k], u16Mul(ai, b.coeffs[j]))
      j = j + 1
      k = k + 1
    k = 0
    while j < saberN:
      c.coeffs[k] = u16Sub(c.coeffs[k], u16Mul(ai, b.coeffs[j]))
      j = j + 1
      k = k + 1
    i = i + 1

proc polyMulIntoRowsUnroll4(c: var SaberPoly, a, b: SaberPoly, accumulate: bool) {.inline.} =
  var
    i: int = 0
    j: int = 0
    k: int = 0
    ai: uint16 = 0
  if not accumulate:
    clearPoly(c)
  i = 0
  while i < saberN:
    ai = a.coeffs[i]
    j = 0
    k = i
    while k + 4 <= saberN:
      c.coeffs[k] = u16Add(c.coeffs[k], u16Mul(ai, b.coeffs[j]))
      c.coeffs[k + 1] = u16Add(c.coeffs[k + 1], u16Mul(ai, b.coeffs[j + 1]))
      c.coeffs[k + 2] = u16Add(c.coeffs[k + 2], u16Mul(ai, b.coeffs[j + 2]))
      c.coeffs[k + 3] = u16Add(c.coeffs[k + 3], u16Mul(ai, b.coeffs[j + 3]))
      j = j + 4
      k = k + 4
    while k < saberN:
      c.coeffs[k] = u16Add(c.coeffs[k], u16Mul(ai, b.coeffs[j]))
      j = j + 1
      k = k + 1
    k = 0
    while j + 4 <= saberN:
      c.coeffs[k] = u16Sub(c.coeffs[k], u16Mul(ai, b.coeffs[j]))
      c.coeffs[k + 1] = u16Sub(c.coeffs[k + 1], u16Mul(ai, b.coeffs[j + 1]))
      c.coeffs[k + 2] = u16Sub(c.coeffs[k + 2], u16Mul(ai, b.coeffs[j + 2]))
      c.coeffs[k + 3] = u16Sub(c.coeffs[k + 3], u16Mul(ai, b.coeffs[j + 3]))
      j = j + 4
      k = k + 4
    while j < saberN:
      c.coeffs[k] = u16Sub(c.coeffs[k], u16Mul(ai, b.coeffs[j]))
      j = j + 1
      k = k + 1
    i = i + 1

proc polyMulIntoCoeff(c: var SaberPoly, a, b: SaberPoly, accumulate: bool) {.inline.} =
  var
    k: int = 0
    i: int = 0
    j: int = 0
    acc: uint16 = 0
  k = 0
  while k < saberN:
    acc = 0
    i = 0
    j = k
    while i <= k:
      acc = u16Add(acc, u16Mul(a.coeffs[i], b.coeffs[j]))
      i = i + 1
      j = j - 1
    i = k + 1
    j = saberN - 1
    while i < saberN:
      acc = u16Sub(acc, u16Mul(a.coeffs[i], b.coeffs[j]))
      i = i + 1
      j = j - 1
    storeSaberReduced(c, k, acc, accumulate)
    k = k + 1

when defined(saberMulNttScalar):
  type
    SaberNttPoly = array[saberN, int32]

  const
    saberNttQ1 = 12289'i32
    saberNttQ2 = 40961'i32
    saberNttQ1Recip = 349496'u64
    saberNttQ2Recip = 104855'u64
    saberNttInvP1ModP2 = 5853'i32
    saberNttProduct = 503369729'i64
    saberNttHalfProduct = 251684864'i64
    saberNttInvNQ1 = 12241'i32
    saberNttInvNQ2 = 40801'i32

  func makeSaberNttPowers(modulus, root: int): array[saberN, int32] =
    var
      x: int = 1
      i: int = 0
    i = 0
    while i < saberN:
      result[i] = int32(x)
      x = (x * root) mod modulus
      i = i + 1

  const
    saberNttOmegaQ1 = makeSaberNttPowers(12289, 8340)
    saberNttInvOmegaQ1 = makeSaberNttPowers(12289, 1696)
    saberNttTwistQ1 = makeSaberNttPowers(12289, 3400)
    saberNttInvTwistQ1 = makeSaberNttPowers(12289, 2859)
    saberNttOmegaQ2 = makeSaberNttPowers(40961, 36043)
    saberNttInvOmegaQ2 = makeSaberNttPowers(40961, 9170)
    saberNttTwistQ2 = makeSaberNttPowers(40961, 8603)
    saberNttInvTwistQ2 = makeSaberNttPowers(40961, 39585)

  proc subQIfNeeded(a, q: int32): int32 {.inline.} =
    var
      t: int32 = 0
      mask: uint32 = 0
    t = a - q
    mask = 0'u32 - ((cast[uint32](t) shr 31) and 1'u32)
    result = t + cast[int32](uint32(q) and mask)

  proc addMod(a, b, q: int32): int32 {.inline.} =
    result = subQIfNeeded(a + b, q)

  proc subMod(a, b, q: int32): int32 {.inline.} =
    var
      t: int32 = 0
      mask: uint32 = 0
    t = a - b
    mask = 0'u32 - ((cast[uint32](t) shr 31) and 1'u32)
    result = t + cast[int32](uint32(q) and mask)

  proc mulMod(a, b, q: int32, recip: uint64): int32 {.inline.} =
    var
      x: uint64 = 0
      approx: uint64 = 0
      r: int32 = 0
    x = uint64(cast[uint32](a)) * uint64(cast[uint32](b))
    approx = (x * recip) shr 32
    r = int32(int64(x) - int64(approx) * int64(q))
    r = subQIfNeeded(r, q)
    r = subQIfNeeded(r, q)
    r = subQIfNeeded(r, q)
    result = subQIfNeeded(r, q)

  proc reduceU16Mod(a: uint16, q: int32): int32 {.inline.} =
    var
      r: int32 = 0
      i: int = 0
    r = int32(a)
    i = 0
    while i < 6:
      r = subQIfNeeded(r, q)
      i = i + 1
    result = r

  proc reduceSigned16Mod(a: uint16, q: int32): int32 {.inline.} =
    var
      r: int32 = 0
      i: int = 0
    r = int32(cast[int16](a)) + 3'i32 * q
    i = 0
    while i < 6:
      r = subQIfNeeded(r, q)
      i = i + 1
    result = r

  proc bitReverse(a: var SaberNttPoly) {.inline.} =
    var
      i: int = 1
      j: int = 0
      bit: int = 0
      tmp: int32 = 0
    i = 1
    while i < saberN:
      bit = saberN shr 1
      while (j and bit) != 0:
        j = j xor bit
        bit = bit shr 1
      j = j xor bit
      if i < j:
        tmp = a[i]
        a[i] = a[j]
        a[j] = tmp
      i = i + 1

  proc cyclicNtt(a: var SaberNttPoly, powers: openArray[int32], q: int32,
      recip: uint64) {.inline.} =
    var
      length: int = 2
      half: int = 0
      base: int = 0
      j: int = 0
      w: int32 = 0
      wLen: int32 = 0
      u: int32 = 0
      v: int32 = 0
    bitReverse(a)
    length = 2
    while length <= saberN:
      half = length shr 1
      wLen = powers[saberN div length]
      base = 0
      while base < saberN:
        w = 1
        j = 0
        while j < half:
          u = a[base + j]
          v = mulMod(a[base + j + half], w, q, recip)
          a[base + j] = addMod(u, v, q)
          a[base + j + half] = subMod(u, v, q)
          w = mulMod(w, wLen, q, recip)
          j = j + 1
        base = base + length
      length = length shl 1

  proc cyclicInvNtt(a: var SaberNttPoly, invPowers: openArray[int32],
      q: int32, recip: uint64, invN: int32) {.inline.} =
    var
      i: int = 0
    cyclicNtt(a, invPowers, q, recip)
    i = 0
    while i < saberN:
      a[i] = mulMod(a[i], invN, q, recip)
      i = i + 1

  proc loadTwistedPositive(r: var SaberNttPoly, a: SaberPoly,
      twist: openArray[int32], q: int32, recip: uint64) {.inline.} =
    var
      i: int = 0
    i = 0
    while i < saberN:
      r[i] = mulMod(reduceU16Mod(a.coeffs[i], q), twist[i], q, recip)
      i = i + 1

  proc loadTwistedSigned(r: var SaberNttPoly, a: SaberPoly,
      twist: openArray[int32], q: int32, recip: uint64) {.inline.} =
    var
      i: int = 0
    i = 0
    while i < saberN:
      r[i] = mulMod(reduceSigned16Mod(a.coeffs[i], q), twist[i], q, recip)
      i = i + 1

  proc pointwiseMul(r: var SaberNttPoly, b: SaberNttPoly, q: int32,
      recip: uint64) {.inline.} =
    var
      i: int = 0
    i = 0
    while i < saberN:
      r[i] = mulMod(r[i], b[i], q, recip)
      i = i + 1

  proc untwist(r: var SaberNttPoly, invTwist: openArray[int32],
      q: int32, recip: uint64) {.inline.} =
    var
      i: int = 0
    i = 0
    while i < saberN:
      r[i] = mulMod(r[i], invTwist[i], q, recip)
      i = i + 1

  proc crtToU16(r1, r2: int32): uint16 {.inline.} =
    var
      diff: int32 = 0
      k: int32 = 0
      x: int64 = 0
      centered: int64 = 0
      sign: uint64 = 0
      mask: uint64 = 0
    diff = subMod(r2, r1, saberNttQ2)
    k = mulMod(diff, saberNttInvP1ModP2, saberNttQ2, saberNttQ2Recip)
    x = int64(r1) + int64(saberNttQ1) * int64(k)
    sign = (cast[uint64](saberNttHalfProduct - x) shr 63) and 1'u64
    mask = 0'u64 - sign
    centered = x - int64(uint64(saberNttProduct) and mask)
    result = uint16(cast[uint64](centered) and 0xffff'u64)

  proc secureClearNttPoly(a: var SaberNttPoly) {.raises: [].} =
    var
      i: int = 0
      p: ptr UncheckedArray[int32]
    p = cast[ptr UncheckedArray[int32]](addr a[0])
    i = 0
    while i < saberN:
      volatileStore(addr p[i], 0'i32)
      i = i + 1

  proc polyMulIntoNttSmallB(c: var SaberPoly, a, b: SaberPoly,
      accumulate: bool) {.inline.} =
    var
      x: SaberNttPoly
      y: SaberNttPoly
      r1: SaberNttPoly
      i: int = 0
      coeff: uint16 = 0
    loadTwistedPositive(x, a, saberNttTwistQ1, saberNttQ1, saberNttQ1Recip)
    loadTwistedSigned(y, b, saberNttTwistQ1, saberNttQ1, saberNttQ1Recip)
    cyclicNtt(x, saberNttOmegaQ1, saberNttQ1, saberNttQ1Recip)
    cyclicNtt(y, saberNttOmegaQ1, saberNttQ1, saberNttQ1Recip)
    pointwiseMul(x, y, saberNttQ1, saberNttQ1Recip)
    cyclicInvNtt(x, saberNttInvOmegaQ1, saberNttQ1, saberNttQ1Recip,
      saberNttInvNQ1)
    untwist(x, saberNttInvTwistQ1, saberNttQ1, saberNttQ1Recip)
    i = 0
    while i < saberN:
      r1[i] = x[i]
      i = i + 1

    loadTwistedPositive(x, a, saberNttTwistQ2, saberNttQ2, saberNttQ2Recip)
    loadTwistedSigned(y, b, saberNttTwistQ2, saberNttQ2, saberNttQ2Recip)
    cyclicNtt(x, saberNttOmegaQ2, saberNttQ2, saberNttQ2Recip)
    cyclicNtt(y, saberNttOmegaQ2, saberNttQ2, saberNttQ2Recip)
    pointwiseMul(x, y, saberNttQ2, saberNttQ2Recip)
    cyclicInvNtt(x, saberNttInvOmegaQ2, saberNttQ2, saberNttQ2Recip,
      saberNttInvNQ2)
    untwist(x, saberNttInvTwistQ2, saberNttQ2, saberNttQ2Recip)

    i = 0
    while i < saberN:
      coeff = crtToU16(r1[i], x[i])
      storeSaberReduced(c, i, coeff, accumulate)
      i = i + 1
    secureClearNttPoly(x)
    secureClearNttPoly(y)
    secureClearNttPoly(r1)

const
  saberToomChunk = saberN div 4
  saberToomRes = 2 * saberToomChunk - 1
  saberToomInfPoint = 99

type
  SaberToomEval = array[saberToomChunk, int64]
  SaberToomProd = array[saberToomRes, int64]
  SaberToomProducts = array[7, SaberToomProd]
  SaberToomWide = array[2 * saberN, int64]

proc evalSaberToomPoint(E: var SaberToomEval, A: SaberPoly, point: int) {.inline.} =
  var
    i: int = 0
    a0: int64 = 0
    a1: int64 = 0
    a2: int64 = 0
    a3: int64 = 0
  i = 0
  while i < saberToomChunk:
    a0 = int64(A.coeffs[i])
    a1 = int64(A.coeffs[saberToomChunk + i])
    a2 = int64(A.coeffs[2 * saberToomChunk + i])
    a3 = int64(A.coeffs[3 * saberToomChunk + i])
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

proc mulSaberToomEvals(R: var SaberToomProd, A, B: SaberToomEval) {.inline.} =
  var
    i: int = 0
    j: int = 0
  i = 0
  while i < saberToomRes:
    R[i] = 0
    i = i + 1
  i = 0
  while i < saberToomChunk:
    j = 0
    while j < saberToomChunk:
      R[i + j] = R[i + j] + A[i] * B[j]
      j = j + 1
    i = i + 1

proc mulSaberToomPoint(R: var SaberToomProd, a, b: SaberPoly, point: int) {.inline.} =
  var
    A: SaberToomEval
    B: SaberToomEval
  evalSaberToomPoint(A, a, point)
  evalSaberToomPoint(B, b, point)
  mulSaberToomEvals(R, A, B)

proc interpolateSaberToom(C: var SaberToomWide, W: SaberToomProducts) {.inline.} =
  var
    i: int = 0
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
  i = 0
  while i < 2 * saberN:
    C[i] = 0
    i = i + 1
  i = 0
  while i < saberToomRes:
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
    C[saberToomChunk + i] = C[saberToomChunk + i] + c1
    C[2 * saberToomChunk + i] = C[2 * saberToomChunk + i] + c2
    C[3 * saberToomChunk + i] = C[3 * saberToomChunk + i] + c3
    C[4 * saberToomChunk + i] = C[4 * saberToomChunk + i] + c4
    C[5 * saberToomChunk + i] = C[5 * saberToomChunk + i] + c5
    C[6 * saberToomChunk + i] = C[6 * saberToomChunk + i] + c6
    i = i + 1

proc polyMulIntoToom4(c: var SaberPoly, a, b: SaberPoly, accumulate: bool) {.inline.} =
  var
    W: SaberToomProducts
    C: SaberToomWide
    i: int = 0
    red: uint16 = 0
  mulSaberToomPoint(W[0], a, b, 0)
  mulSaberToomPoint(W[1], a, b, 1)
  mulSaberToomPoint(W[2], a, b, -1)
  mulSaberToomPoint(W[3], a, b, 2)
  mulSaberToomPoint(W[4], a, b, -2)
  mulSaberToomPoint(W[5], a, b, 3)
  mulSaberToomPoint(W[6], a, b, saberToomInfPoint)
  interpolateSaberToom(C, W)
  i = 0
  while i < saberN:
    red = i64ToU16(C[i] - C[saberN + i])
    storeSaberReduced(c, i, red, accumulate)
    i = i + 1

type
  SaberKaratsuba64 = array[64, uint16]
  SaberKaratsuba127 = array[127, uint16]
  SaberToomModWide = array[2 * saberN, uint16]
  SaberToom4ModEval = object
    w1: SaberKaratsuba64
    w2: SaberKaratsuba64
    w3: SaberKaratsuba64
    w4: SaberKaratsuba64
    w5: SaberKaratsuba64
    w6: SaberKaratsuba64
    w7: SaberKaratsuba64

proc karatsuba64Mod(R: var SaberKaratsuba127, A, B: SaberKaratsuba64) {.inline.} =
  var
    d01: array[31, uint16]
    d0123: array[31, uint16]
    d23: array[31, uint16]
    resultD01: array[63, uint16]
    i: int = 0
    j: int = 0
    acc1: uint16 = 0
    acc2: uint16 = 0
    acc3: uint16 = 0
    acc4: uint16 = 0
    acc5: uint16 = 0
    acc6: uint16 = 0
    acc7: uint16 = 0
    acc8: uint16 = 0
    acc9: uint16 = 0
    acc10: uint16 = 0
  i = 0
  while i < 127:
    R[i] = 0
    i = i + 1
  i = 0
  while i < 16:
    acc1 = A[i]
    acc2 = A[i + 16]
    acc3 = A[i + 32]
    acc4 = A[i + 48]
    j = 0
    while j < 16:
      acc5 = B[j]
      acc6 = B[j + 16]
      R[i + j] = u16Add(R[i + j], u16Mul(acc1, acc5))
      R[i + j + 32] = u16Add(R[i + j + 32], u16Mul(acc2, acc6))
      acc7 = u16Add(acc5, acc6)
      acc8 = u16Add(acc1, acc2)
      d01[i + j] = u16Add(d01[i + j], u16Mul(acc7, acc8))
      acc7 = B[j + 32]
      acc8 = B[j + 48]
      R[i + j + 64] = u16Add(R[i + j + 64], u16Mul(acc7, acc3))
      R[i + j + 96] = u16Add(R[i + j + 96], u16Mul(acc8, acc4))
      acc9 = u16Add(acc3, acc4)
      acc10 = u16Add(acc7, acc8)
      d23[i + j] = u16Add(d23[i + j], u16Mul(acc9, acc10))
      acc5 = u16Add(acc5, acc7)
      acc7 = u16Add(acc1, acc3)
      resultD01[i + j] = u16Add(resultD01[i + j], u16Mul(acc5, acc7))
      acc6 = u16Add(acc6, acc8)
      acc8 = u16Add(acc2, acc4)
      resultD01[i + j + 32] = u16Add(resultD01[i + j + 32],
        u16Mul(acc6, acc8))
      acc5 = u16Add(acc5, acc6)
      acc7 = u16Add(acc7, acc8)
      d0123[i + j] = u16Add(d0123[i + j], u16Mul(acc5, acc7))
      j = j + 1
    i = i + 1
  i = 0
  while i < 31:
    d0123[i] = u16Sub(u16Sub(d0123[i], resultD01[i]), resultD01[i + 32])
    d01[i] = u16Sub(u16Sub(d01[i], R[i]), R[i + 32])
    d23[i] = u16Sub(u16Sub(d23[i], R[i + 64]), R[i + 96])
    i = i + 1
  i = 0
  while i < 31:
    resultD01[i + 16] = u16Add(resultD01[i + 16], d0123[i])
    R[i + 16] = u16Add(R[i + 16], d01[i])
    R[i + 80] = u16Add(R[i + 80], d23[i])
    i = i + 1
  i = 0
  while i < 63:
    resultD01[i] = u16Sub(u16Sub(resultD01[i], R[i]), R[i + 64])
    i = i + 1
  i = 0
  while i < 63:
    R[i + 32] = u16Add(R[i + 32], resultD01[i])
    i = i + 1

proc evalSaberToom4Mod(Aw1, Aw2, Aw3, Aw4, Aw5, Aw6, Aw7: var SaberKaratsuba64,
    A: SaberPoly) {.inline.} =
  var
    j: int = 0
    r0: uint16 = 0
    r1: uint16 = 0
    r2: uint16 = 0
    r3: uint16 = 0
    r4: uint16 = 0
    r5: uint16 = 0
    r6: uint16 = 0
    r7: uint16 = 0
  j = 0
  while j < 64:
    r0 = A.coeffs[j]
    r1 = A.coeffs[64 + j]
    r2 = A.coeffs[128 + j]
    r3 = A.coeffs[192 + j]
    r4 = u16Add(r0, r2)
    r5 = u16Add(r1, r3)
    r6 = u16Add(r4, r5)
    r7 = u16Sub(r4, r5)
    Aw3[j] = r6
    Aw4[j] = r7
    r4 = u16Shl(u16Add(u16Shl(r0, 2), r2), 1)
    r5 = u16Add(u16Shl(r1, 2), r3)
    r6 = u16Add(r4, r5)
    r7 = u16Sub(r4, r5)
    Aw5[j] = r6
    Aw6[j] = r7
    r4 = u16Add(u16Add(u16Add(u16Shl(r3, 3), u16Shl(r2, 2)),
      u16Shl(r1, 1)), r0)
    Aw2[j] = r4
    Aw7[j] = r0
    Aw1[j] = r3
    j = j + 1

proc evalSaberToom4Mod(E: var SaberToom4ModEval, A: SaberPoly) {.inline.} =
  evalSaberToom4Mod(E.w1, E.w2, E.w3, E.w4, E.w5, E.w6, E.w7, A)

proc interpolateSaberToom4Mod(C: var SaberToomModWide, W1, W2, W3, W4, W5,
    W6, W7: SaberKaratsuba127) {.inline.} =
  const
    inv3: uint16 = 43691
    inv9: uint16 = 36409
    inv15: uint16 = 61167
  var
    i: int = 0
    r0: uint16 = 0
    r1: uint16 = 0
    r2: uint16 = 0
    r3: uint16 = 0
    r4: uint16 = 0
    r5: uint16 = 0
    r6: uint16 = 0
  i = 0
  while i < 2 * saberN:
    C[i] = 0
    i = i + 1
  i = 0
  while i < 127:
    r0 = W1[i]
    r1 = W2[i]
    r2 = W3[i]
    r3 = W4[i]
    r4 = W5[i]
    r5 = W6[i]
    r6 = W7[i]
    r1 = u16Add(r1, r4)
    r5 = u16Sub(r5, r4)
    r3 = cSarDiffU16(r3, r2, 1)
    r4 = u16Sub(r4, r0)
    r4 = u16Sub(r4, u16Shl(r6, 6))
    r4 = u16Add(u16Shl(r4, 1), r5)
    r2 = u16Add(r2, r3)
    r1 = u16Sub(u16Sub(r1, u16Shl(r2, 6)), r2)
    r2 = u16Sub(r2, r6)
    r2 = u16Sub(r2, r0)
    r1 = u16Add(r1, u16MulSmall(r2, 45))
    r4 = cMulShiftU16(int64(r4) - int64(u16Shl(r2, 3)), inv3, 3)
    r5 = u16Add(r5, r1)
    r1 = cMulShiftU16(int64(r1) + int64(u16Shl(r3, 4)), inv9, 1)
    r3 = u16Neg(u16Add(r3, r1))
    r5 = cMulShiftU16(int64(u16MulSmall(r1, 30)) - int64(r5), inv15, 2)
    r2 = u16Sub(r2, r4)
    r1 = u16Sub(r1, r5)
    C[i] = u16Add(C[i], r6)
    C[i + 64] = u16Add(C[i + 64], r5)
    C[i + 128] = u16Add(C[i + 128], r4)
    C[i + 192] = u16Add(C[i + 192], r3)
    C[i + 256] = u16Add(C[i + 256], r2)
    C[i + 320] = u16Add(C[i + 320], r1)
    C[i + 384] = u16Add(C[i + 384], r0)
    i = i + 1

proc polyMulIntoToom4ModEval(c: var SaberPoly, a: SaberPoly, B: SaberToom4ModEval,
    accumulate: bool) {.inline.} =
  var
    aw1: SaberKaratsuba64
    aw2: SaberKaratsuba64
    aw3: SaberKaratsuba64
    aw4: SaberKaratsuba64
    aw5: SaberKaratsuba64
    aw6: SaberKaratsuba64
    aw7: SaberKaratsuba64
    w1: SaberKaratsuba127
    w2: SaberKaratsuba127
    w3: SaberKaratsuba127
    w4: SaberKaratsuba127
    w5: SaberKaratsuba127
    w6: SaberKaratsuba127
    w7: SaberKaratsuba127
    C: SaberToomModWide
    i: int = 0
    red: uint16 = 0
  evalSaberToom4Mod(aw1, aw2, aw3, aw4, aw5, aw6, aw7, a)
  karatsuba64Mod(w1, aw1, B.w1)
  karatsuba64Mod(w2, aw2, B.w2)
  karatsuba64Mod(w3, aw3, B.w3)
  karatsuba64Mod(w4, aw4, B.w4)
  karatsuba64Mod(w5, aw5, B.w5)
  karatsuba64Mod(w6, aw6, B.w6)
  karatsuba64Mod(w7, aw7, B.w7)
  interpolateSaberToom4Mod(C, w1, w2, w3, w4, w5, w6, w7)
  i = 0
  while i < saberN:
    red = u16Sub(C[i], C[saberN + i])
    storeSaberReduced(c, i, red, accumulate)
    i = i + 1

proc polyMulIntoToom4Mod(c: var SaberPoly, a, b: SaberPoly,
    accumulate: bool) {.inline.} =
  var
    B: SaberToom4ModEval
  evalSaberToom4Mod(B, b)
  polyMulIntoToom4ModEval(c, a, B, accumulate)

proc polyMulInto(c: var SaberPoly, a, b: SaberPoly, accumulate: bool) {.otterBench.} =
  when defined(saberMulRows):
    polyMulIntoRows(c, a, b, accumulate)
  elif defined(saberMulRowsUnroll4):
    polyMulIntoRowsUnroll4(c, a, b, accumulate)
  elif defined(saberMulCoeff):
    polyMulIntoCoeff(c, a, b, accumulate)
  elif defined(saberMulToom4Mod):
    polyMulIntoToom4Mod(c, a, b, accumulate)
  elif defined(saberMulToom4):
    polyMulIntoToom4(c, a, b, accumulate)
  else:
    polyMulIntoTmp(c, a, b, accumulate)

proc matrixVectorMul(c: var SaberPolyVec, p: SaberParams, A: SaberMatrix,
    s: SaberPolyVec, transpose: bool) {.otterBench.} =
  when defined(saberMulToom4Cached):
    var
      E: array[4, SaberToom4ModEval]
  var
    i: int = 0
    j: int = 0
  when defined(saberMulToom4Cached):
    j = 0
    while j < p.l:
      evalSaberToom4Mod(E[j], s[j])
      j = j + 1
  i = 0
  while i < p.l:
    if transpose:
      when defined(saberMulNttScalar):
        polyMulIntoNttSmallB(c[i], A[0][i], s[0], false)
      elif defined(saberMulToom4Cached):
        polyMulIntoToom4ModEval(c[i], A[0][i], E[0], false)
      else:
        polyMulInto(c[i], A[0][i], s[0], false)
      j = 1
      while j < p.l:
        when defined(saberMulNttScalar):
          polyMulIntoNttSmallB(c[i], A[j][i], s[j], true)
        elif defined(saberMulToom4Cached):
          polyMulIntoToom4ModEval(c[i], A[j][i], E[j], true)
        else:
          polyMulInto(c[i], A[j][i], s[j], true)
        j = j + 1
    else:
      when defined(saberMulNttScalar):
        polyMulIntoNttSmallB(c[i], A[i][0], s[0], false)
      elif defined(saberMulToom4Cached):
        polyMulIntoToom4ModEval(c[i], A[i][0], E[0], false)
      else:
        polyMulInto(c[i], A[i][0], s[0], false)
      j = 1
      while j < p.l:
        when defined(saberMulNttScalar):
          polyMulIntoNttSmallB(c[i], A[i][j], s[j], true)
        elif defined(saberMulToom4Cached):
          polyMulIntoToom4ModEval(c[i], A[i][j], E[j], true)
        else:
          polyMulInto(c[i], A[i][j], s[j], true)
        j = j + 1
    i = i + 1

proc innerProd(c: var SaberPoly, p: SaberParams, b, s: SaberPolyVec) {.otterBench.} =
  when defined(saberMulToom4Cached):
    var
      E: array[4, SaberToom4ModEval]
  var
    i: int = 1
  when defined(saberMulToom4Cached):
    i = 0
    while i < p.l:
      evalSaberToom4Mod(E[i], s[i])
      i = i + 1
    polyMulIntoToom4ModEval(c, b[0], E[0], false)
  elif defined(saberMulNttScalar):
    polyMulIntoNttSmallB(c, b[0], s[0], false)
  else:
    polyMulInto(c, b[0], s[0], false)
  i = 1
  while i < p.l:
    when defined(saberMulNttScalar):
      polyMulIntoNttSmallB(c, b[i], s[i], true)
    elif defined(saberMulToom4Cached):
      polyMulIntoToom4ModEval(c, b[i], E[i], true)
    else:
      polyMulInto(c, b[i], s[i], true)
    i = i + 1

when not defined(saberHeapBuffers):
  const
    saberMaxMatrixBytes = 4 * 4 * saberPolyBytes
    saberMaxSecretBytes = 3 * saberN

proc genMatrix(A: var SaberMatrix, p: SaberParams, seed: openArray[byte]) {.otterBench.} =
  when not defined(saberHeapBuffers):
    var
      buf: array[saberMaxMatrixBytes, byte]
      i: int = 0
      o: int = 0
      n: int = 0
    n = p.l * p.polyVecBytes
    shake128Into(buf.toOpenArray(0, n - 1), seed)
    i = 0
    while i < p.l:
      o = i * p.polyVecBytes
      bs2polvecq(A[i], p, buf.toOpenArray(o, o + p.polyVecBytes - 1))
      i = i + 1
    secureClearBytes(buf.toOpenArray(0, n - 1))
  else:
    var
      buf: seq[byte] = @[]
      i: int = 0
      o: int = 0
    buf = newSeq[byte](p.l * p.polyVecBytes)
    shake128Into(buf, seed)
    i = 0
    while i < p.l:
      o = i * p.polyVecBytes
      bs2polvecq(A[i], p, buf.toOpenArray(o, o + p.polyVecBytes - 1))
      i = i + 1
    secureClearBytes(buf)

proc genSecret(s: var SaberPolyVec, p: SaberParams, seed: openArray[byte]) {.otterBench.} =
  when not defined(saberHeapBuffers):
    var
      buf: array[saberMaxSecretBytes, byte]
      i: int = 0
      o: int = 0
      n: int = 0
    n = p.l * p.polyCoinBytes
    shake128Into(buf.toOpenArray(0, n - 1), seed)
    i = 0
    while i < p.l:
      o = i * p.polyCoinBytes
      cbd(s[i], p, buf.toOpenArray(o, o + p.polyCoinBytes - 1))
      i = i + 1
    secureClearBytes(buf.toOpenArray(0, n - 1))
  else:
    var
      buf: seq[byte] = @[]
      i: int = 0
      o: int = 0
    buf = newSeq[byte](p.l * p.polyCoinBytes)
    shake128Into(buf, seed)
    i = 0
    while i < p.l:
      o = i * p.polyCoinBytes
      cbd(s[i], p, buf.toOpenArray(o, o + p.polyCoinBytes - 1))
      i = i + 1
    secureClearBytes(buf)

proc h1(): uint16 {.inline.} =
  result = uint16(1 shl (saberEq - saberEp - 1))

proc h2(p: SaberParams): uint16 {.inline.} =
  result = uint16((1 shl (saberEp - 2)) -
    (1 shl (saberEp - p.et - 1)) +
    (1 shl (saberEq - saberEp - 1)))

proc indcpaKeypair*(pk, sk: var openArray[byte], p: SaberParams,
    R: var PqRandomContext) {.otterBench.} =
  ## Generate a SABER IND-CPA keypair into caller-owned buffers.
  var
    A: SaberMatrix
    s: SaberPolyVec
    res: SaberPolyVec
    seedA: seq[byte] = @[]
    seedHash: array[saberSeedBytes, byte]
    rand: seq[byte] = @[]
    i: int = 0
    j: int = 0
  seedA = pqRandomBytes(R, saberSeedBytes)
  shake128Into(seedHash, seedA)
  copyBytes(pk, p.polyVecCompressedBytes, seedHash)
  rand = pqRandomBytes(R, saberNoiseSeedBytes)
  genSecret(s, p, rand)
  polvecq2bs(sk.toOpenArray(0, p.indcpaSecretKeyBytes - 1), p, s)
  genMatrix(A, p, seedHash)
  matrixVectorMul(res, p, A, s, true)
  i = 0
  while i < p.l:
    j = 0
    while j < saberN:
      res[i].coeffs[j] = (u16Add(res[i].coeffs[j], h1()) shr (saberEq - saberEp)) and
        uint16(saberQ - 1)
      j = j + 1
    i = i + 1
  polvecp2bs(pk.toOpenArray(0, p.polyVecCompressedBytes - 1), p, res)
  secureClearBytes(seedA)
  secureClearBytes(seedHash)
  secureClearBytes(rand)

proc indcpaEnc*(ciphertext: var openArray[byte], m, noiseseed, pk: openArray[byte],
    p: SaberParams) {.otterBench.} =
  ## Encrypt one SABER IND-CPA message.
  var
    A: SaberMatrix
    res: SaberPolyVec
    s: SaberPolyVec
    temp: SaberPolyVec
    vprime: SaberPoly
    message: SaberPoly
    seedAOff: int = 0
    msgOff: int = 0
    i: int = 0
    j: int = 0
  seedAOff = p.polyVecCompressedBytes
  msgOff = p.polyVecCompressedBytes
  genSecret(s, p, noiseseed)
  genMatrix(A, p, pk.toOpenArray(seedAOff, seedAOff + saberSeedBytes - 1))
  matrixVectorMul(res, p, A, s, false)
  i = 0
  while i < p.l:
    j = 0
    while j < saberN:
      res[i].coeffs[j] = (u16Add(res[i].coeffs[j], h1()) shr (saberEq - saberEp)) and
        uint16(saberQ - 1)
      j = j + 1
    i = i + 1
  polvecp2bs(ciphertext.toOpenArray(0, p.polyVecCompressedBytes - 1), p, res)
  bs2polvecp(temp, p, pk.toOpenArray(0, p.polyVecCompressedBytes - 1))
  innerProd(vprime, p, temp, s)
  bs2polmsg(message, m)
  i = 0
  while i < saberN:
    vprime.coeffs[i] = u16Add(vprime.coeffs[i], u16Sub(h1(),
      uint16(uint32(message.coeffs[i]) shl (saberEp - 1))))
    vprime.coeffs[i] = vprime.coeffs[i] and uint16(saberP - 1)
    vprime.coeffs[i] = vprime.coeffs[i] shr (saberEp - p.et)
    i = i + 1
  polt2bs(ciphertext.toOpenArray(msgOff, msgOff + p.scaleBytesKem - 1), p, vprime)
  clearPoly(message)

proc indcpaDec*(m: var openArray[byte], sk, ciphertext: openArray[byte],
    p: SaberParams) {.otterBench.} =
  ## Decrypt one SABER IND-CPA ciphertext.
  var
    temp: SaberPolyVec
    s: SaberPolyVec
    v: SaberPoly
    cm: SaberPoly
    packedCmOff: int = 0
    i: int = 0
  packedCmOff = p.polyVecCompressedBytes
  bs2polvecq(s, p, sk.toOpenArray(0, p.indcpaSecretKeyBytes - 1))
  bs2polvecp(temp, p, ciphertext.toOpenArray(0, p.polyVecCompressedBytes - 1))
  innerProd(v, p, temp, s)
  bs2polt(cm, p, ciphertext.toOpenArray(packedCmOff, packedCmOff + p.scaleBytesKem - 1))
  i = 0
  while i < saberN:
    v.coeffs[i] = u16Add(v.coeffs[i], u16Sub(h2(p),
      uint16(uint32(cm.coeffs[i]) shl (saberEp - p.et))))
    v.coeffs[i] = v.coeffs[i] and uint16(saberP - 1)
    v.coeffs[i] = v.coeffs[i] shr (saberEp - 1)
    i = i + 1
  polmsg2bs(m, v)

proc saberKemKeypairInto*(pk, sk: var openArray[byte], p: SaberParams,
    R: var PqRandomContext) {.otterBench.} =
  ## Generate a SABER CCA KEM keypair.
  var
    pkHash: array[saberHashBytes, byte]
    fallback: seq[byte] = @[]
  indcpaKeypair(pk, sk.toOpenArray(0, p.indcpaSecretKeyBytes - 1), p, R)
  copyBytes(sk, p.indcpaSecretKeyBytes, pk)
  sha3_256Into(pkHash, pk.toOpenArray(0, p.indcpaPublicKeyBytes - 1))
  copyBytes(sk, p.secretKeyBytes - 64, pkHash)
  fallback = pqRandomBytes(R, saberKeyBytes)
  copyBytes(sk, p.secretKeyBytes - saberKeyBytes, fallback)
  secureClearBytes(pkHash)
  secureClearBytes(fallback)

proc saberKemEncInto*(ciphertext, sharedSecret: var openArray[byte],
    pk: openArray[byte], p: SaberParams, R: var PqRandomContext) {.otterBench.} =
  ## Encapsulate with pure-Nim SABER.
  var
    kr: array[64, byte]
    buf: array[64, byte]
    entropy: seq[byte] = @[]
  entropy = pqRandomBytes(R, saberKeyBytes)
  copyBytes(buf, 0, entropy)
  sha3_256Into(buf.toOpenArray(0, 31), buf.toOpenArray(0, 31))
  sha3_256Into(buf.toOpenArray(32, 63), pk.toOpenArray(0, p.indcpaPublicKeyBytes - 1))
  sha3_512Into(kr, buf)
  indcpaEnc(ciphertext, buf.toOpenArray(0, 31), kr.toOpenArray(32, 63), pk, p)
  sha3_256Into(kr.toOpenArray(32, 63), ciphertext.toOpenArray(0, p.ciphertextBytes - 1))
  sha3_256Into(sharedSecret, kr)
  secureClearBytes(entropy)
  secureClearBytes(kr)
  secureClearBytes(buf)

proc saberKemDecInto*(sharedSecret: var openArray[byte], sk, ciphertext: openArray[byte],
    p: SaberParams) {.otterBench.} =
  ## Decapsulate with pure-Nim SABER.
  var
    fail: int = 0
    cmp: seq[byte] = @[]
    buf: array[64, byte]
    kr: array[64, byte]
    pkOff: int = 0
  cmp = newSeq[byte](p.ciphertextBytes)
  pkOff = p.indcpaSecretKeyBytes
  indcpaDec(buf.toOpenArray(0, 31), sk.toOpenArray(0, p.indcpaSecretKeyBytes - 1),
    ciphertext, p)
  copyBytes(buf, 32, sk.toOpenArray(p.secretKeyBytes - 64, p.secretKeyBytes - 33))
  sha3_512Into(kr, buf)
  indcpaEnc(cmp, buf.toOpenArray(0, 31), kr.toOpenArray(32, 63),
    sk.toOpenArray(pkOff, pkOff + p.indcpaPublicKeyBytes - 1), p)
  fail = verifyBytes(ciphertext, cmp)
  sha3_256Into(kr.toOpenArray(32, 63), ciphertext)
  cmovBytes(kr.toOpenArray(0, 31),
    sk.toOpenArray(p.secretKeyBytes - saberKeyBytes, p.secretKeyBytes - 1), uint8(fail))
  sha3_256Into(sharedSecret, kr)
  secureClearBytes(cmp)
  secureClearBytes(buf)
  secureClearBytes(kr)

{.pop.}
