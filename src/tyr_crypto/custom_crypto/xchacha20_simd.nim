import std/bitops
import ./xchacha20

const
  hchacha20InputSize = 16
  sigma = [0x61707865'u32, 0x3320646e'u32, 0x79622d32'u32, 0x6b206574'u32]

type
  ByteSeq = seq[uint8]

  XChaChaBackend* = enum
    xcbAuto,
    xcbScalar,
    xcbSse2,
    xcbAvx2

when defined(sse2):
  import nimsimd/sse2

when defined(avx2):
  import nimsimd/avx
  import nimsimd/avx2

proc load32Le(data: openArray[byte], offset: int): uint32 =
  result =
    (uint32(data[offset]) or
    (uint32(data[offset + 1]) shl 8) or
    (uint32(data[offset + 2]) shl 16) or
    (uint32(data[offset + 3]) shl 24))

when defined(sse2) or defined(avx2):
  const
    chachaBlockLen = 64

  proc store32Le(dst: var ByteSeq, offset: int, value: uint32) =
    dst[offset] = uint8(value and 0xff'u32)
    dst[offset + 1] = uint8((value shr 8) and 0xff'u32)
    dst[offset + 2] = uint8((value shr 16) and 0xff'u32)
    dst[offset + 3] = uint8((value shr 24) and 0xff'u32)

proc store32LeArr(dst: var array[32, byte], offset: int, value: uint32) =
  dst[offset] = byte(value and 0xff'u32)
  dst[offset + 1] = byte((value shr 8) and 0xff'u32)
  dst[offset + 2] = byte((value shr 16) and 0xff'u32)
  dst[offset + 3] = byte((value shr 24) and 0xff'u32)

proc quarterRound(a, b, c, d: var uint32) {.inline.} =
  a = a + b
  d = rotateLeftBits(d xor a, 16)
  c = c + d
  b = rotateLeftBits(b xor c, 12)
  a = a + b
  d = rotateLeftBits(d xor a, 8)
  c = c + d
  b = rotateLeftBits(b xor c, 7)

proc hchacha20(key, nonce: openArray[byte]): array[32, byte] =
  if key.len != 32:
    raise newException(ValueError, "HChaCha20 requires a 32-byte key")
  if nonce.len != hchacha20InputSize:
    raise newException(ValueError, "HChaCha20 requires a 16-byte nonce")
  var state: array[16, uint32]
  var working: array[16, uint32]
  var i: int = 0
  i = 0
  while i < 4:
    state[i] = sigma[i]
    i = i + 1
  i = 0
  while i < 8:
    state[4 + i] = load32Le(key, i * 4)
    i = i + 1
  i = 0
  while i < 4:
    state[12 + i] = load32Le(nonce, i * 4)
    i = i + 1
  working = state
  i = 0
  while i < 10:
    quarterRound(working[0], working[4], working[8], working[12])
    quarterRound(working[1], working[5], working[9], working[13])
    quarterRound(working[2], working[6], working[10], working[14])
    quarterRound(working[3], working[7], working[11], working[15])
    quarterRound(working[0], working[5], working[10], working[15])
    quarterRound(working[1], working[6], working[11], working[12])
    quarterRound(working[2], working[7], working[8], working[13])
    quarterRound(working[3], working[4], working[9], working[14])
    i = i + 1
  i = 0
  while i < 4:
    store32LeArr(result, i * 4, working[i])
    store32LeArr(result, 16 + i * 4, working[12 + i])
    i = i + 1

proc deriveXChaCha20Key(key, nonce: openArray[byte]): array[32, byte] =
  var hnonce: array[hchacha20InputSize, byte]
  var i: int = 0
  i = 0
  while i < hnonce.len:
    hnonce[i] = nonce[i]
    i = i + 1
  hchacha20(key, hnonce)

proc buildChaChaNonce(nonce: openArray[byte]): array[12, byte] =
  var i: int = 0
  i = 0
  while i < 8:
    result[4 + i] = nonce[16 + i]
    i = i + 1

proc resolveBackend(b: XChaChaBackend): XChaChaBackend =
  case b
  of xcbAuto:
    when defined(avx2):
      result = xcbAvx2
    elif defined(sse2):
      result = xcbSse2
    else:
      result = xcbScalar
  else:
    result = b

when defined(sse2):
  type
    Vec4 = M128i

  proc vset1(x: uint32): Vec4 =
    result = mm_set1_epi32(x)

  proc vset4(a, b, c, d: uint32): Vec4 =
    result = mm_set_epi32(int32(d), int32(c), int32(b), int32(a))

  proc vadd(a, b: Vec4): Vec4 =
    result = mm_add_epi32(a, b)

  proc vxor(a, b: Vec4): Vec4 =
    result = mm_xor_si128(a, b)

  proc vor(a, b: Vec4): Vec4 =
    result = mm_or_si128(a, b)

  proc vshl(a: Vec4, n: int): Vec4 =
    result = mm_slli_epi32(a, int32(n))

  proc vshr(a: Vec4, n: int): Vec4 =
    result = mm_srli_epi32(a, int32(n))

  proc vrotl(a: Vec4, n: int): Vec4 =
    result = vor(vshl(a, n), vshr(a, 32 - n))

  proc vqr(a, b, c, d: var Vec4) =
    a = vadd(a, b)
    d = vrotl(vxor(d, a), 16)
    c = vadd(c, d)
    b = vrotl(vxor(b, c), 12)
    a = vadd(a, b)
    d = vrotl(vxor(d, a), 8)
    c = vadd(c, d)
    b = vrotl(vxor(b, c), 7)

  proc chacha20Blocks4(key: array[32, byte], nonce: array[12, byte],
      counter: uint32, outBytes: var ByteSeq, outOffset: int) =
    var
      x0, x1, x2, x3: Vec4
      x4, x5, x6, x7: Vec4
      x8, x9, x10, x11: Vec4
      x12, x13, x14, x15: Vec4
      o0, o1, o2, o3: Vec4
      o4, o5, o6, o7: Vec4
      o8, o9, o10, o11: Vec4
      o12, o13, o14, o15: Vec4
      i: int = 0
      tmp: array[4, uint32]
      base: uint32 = 0
      lane: int = 0
      word: int = 0
      offset: int = 0
      k0, k1, k2, k3, k4, k5, k6, k7: uint32
      n0, n1, n2: uint32
    k0 = load32Le(key, 0)
    k1 = load32Le(key, 4)
    k2 = load32Le(key, 8)
    k3 = load32Le(key, 12)
    k4 = load32Le(key, 16)
    k5 = load32Le(key, 20)
    k6 = load32Le(key, 24)
    k7 = load32Le(key, 28)
    n0 = load32Le(nonce, 0)
    n1 = load32Le(nonce, 4)
    n2 = load32Le(nonce, 8)
    x0 = vset1(sigma[0])
    x1 = vset1(sigma[1])
    x2 = vset1(sigma[2])
    x3 = vset1(sigma[3])
    x4 = vset1(k0)
    x5 = vset1(k1)
    x6 = vset1(k2)
    x7 = vset1(k3)
    x8 = vset1(k4)
    x9 = vset1(k5)
    x10 = vset1(k6)
    x11 = vset1(k7)
    base = counter
    x12 = vset4(base, base + 1, base + 2, base + 3)
    x13 = vset1(n0)
    x14 = vset1(n1)
    x15 = vset1(n2)
    o0 = x0
    o1 = x1
    o2 = x2
    o3 = x3
    o4 = x4
    o5 = x5
    o6 = x6
    o7 = x7
    o8 = x8
    o9 = x9
    o10 = x10
    o11 = x11
    o12 = x12
    o13 = x13
    o14 = x14
    o15 = x15
    i = 0
    while i < 10:
      vqr(x0, x4, x8, x12)
      vqr(x1, x5, x9, x13)
      vqr(x2, x6, x10, x14)
      vqr(x3, x7, x11, x15)
      vqr(x0, x5, x10, x15)
      vqr(x1, x6, x11, x12)
      vqr(x2, x7, x8, x13)
      vqr(x3, x4, x9, x14)
      i = i + 1
    x0 = vadd(x0, o0)
    x1 = vadd(x1, o1)
    x2 = vadd(x2, o2)
    x3 = vadd(x3, o3)
    x4 = vadd(x4, o4)
    x5 = vadd(x5, o5)
    x6 = vadd(x6, o6)
    x7 = vadd(x7, o7)
    x8 = vadd(x8, o8)
    x9 = vadd(x9, o9)
    x10 = vadd(x10, o10)
    x11 = vadd(x11, o11)
    x12 = vadd(x12, o12)
    x13 = vadd(x13, o13)
    x14 = vadd(x14, o14)
    x15 = vadd(x15, o15)
    word = 0
    while word < 16:
      case word
      of 0: mm_storeu_si128(cast[pointer](addr tmp[0]), x0)
      of 1: mm_storeu_si128(cast[pointer](addr tmp[0]), x1)
      of 2: mm_storeu_si128(cast[pointer](addr tmp[0]), x2)
      of 3: mm_storeu_si128(cast[pointer](addr tmp[0]), x3)
      of 4: mm_storeu_si128(cast[pointer](addr tmp[0]), x4)
      of 5: mm_storeu_si128(cast[pointer](addr tmp[0]), x5)
      of 6: mm_storeu_si128(cast[pointer](addr tmp[0]), x6)
      of 7: mm_storeu_si128(cast[pointer](addr tmp[0]), x7)
      of 8: mm_storeu_si128(cast[pointer](addr tmp[0]), x8)
      of 9: mm_storeu_si128(cast[pointer](addr tmp[0]), x9)
      of 10: mm_storeu_si128(cast[pointer](addr tmp[0]), x10)
      of 11: mm_storeu_si128(cast[pointer](addr tmp[0]), x11)
      of 12: mm_storeu_si128(cast[pointer](addr tmp[0]), x12)
      of 13: mm_storeu_si128(cast[pointer](addr tmp[0]), x13)
      of 14: mm_storeu_si128(cast[pointer](addr tmp[0]), x14)
      else: mm_storeu_si128(cast[pointer](addr tmp[0]), x15)
      lane = 0
      while lane < 4:
        offset = outOffset + lane * chachaBlockLen + word * 4
        store32Le(outBytes, offset, tmp[lane])
        lane = lane + 1
      word = word + 1

when defined(avx2):
  type
    Vec8 = M256i

  proc vset1x(x: uint32): Vec8 =
    result = mm256_set1_epi32(x)

  proc vset8(a0, a1, a2, a3, a4, a5, a6, a7: uint32): Vec8 =
    result = mm256_set_epi32(int32(a7), int32(a6), int32(a5), int32(a4),
      int32(a3), int32(a2), int32(a1), int32(a0))

  proc vaddx(a, b: Vec8): Vec8 =
    result = mm256_add_epi32(a, b)

  proc vxorx(a, b: Vec8): Vec8 =
    result = mm256_xor_si256(a, b)

  proc vorx(a, b: Vec8): Vec8 =
    result = mm256_or_si256(a, b)

  proc vshlx(a: Vec8, n: int): Vec8 =
    result = mm256_slli_epi32(a, int32(n))

  proc vshrx(a: Vec8, n: int): Vec8 =
    result = mm256_srli_epi32(a, int32(n))

  proc vrotlx(a: Vec8, n: int): Vec8 =
    result = vorx(vshlx(a, n), vshrx(a, 32 - n))

  proc vqrx(a, b, c, d: var Vec8) =
    a = vaddx(a, b)
    d = vrotlx(vxorx(d, a), 16)
    c = vaddx(c, d)
    b = vrotlx(vxorx(b, c), 12)
    a = vaddx(a, b)
    d = vrotlx(vxorx(d, a), 8)
    c = vaddx(c, d)
    b = vrotlx(vxorx(b, c), 7)

  proc chacha20Blocks8(key: array[32, byte], nonce: array[12, byte],
      counter: uint32, outBytes: var ByteSeq, outOffset: int) =
    var
      x0, x1, x2, x3: Vec8
      x4, x5, x6, x7: Vec8
      x8, x9, x10, x11: Vec8
      x12, x13, x14, x15: Vec8
      o0, o1, o2, o3: Vec8
      o4, o5, o6, o7: Vec8
      o8, o9, o10, o11: Vec8
      o12, o13, o14, o15: Vec8
      i: int = 0
      tmp: array[8, uint32]
      base: uint32 = 0
      lane: int = 0
      word: int = 0
      offset: int = 0
      k0, k1, k2, k3, k4, k5, k6, k7: uint32
      n0, n1, n2: uint32
    k0 = load32Le(key, 0)
    k1 = load32Le(key, 4)
    k2 = load32Le(key, 8)
    k3 = load32Le(key, 12)
    k4 = load32Le(key, 16)
    k5 = load32Le(key, 20)
    k6 = load32Le(key, 24)
    k7 = load32Le(key, 28)
    n0 = load32Le(nonce, 0)
    n1 = load32Le(nonce, 4)
    n2 = load32Le(nonce, 8)
    x0 = vset1x(sigma[0])
    x1 = vset1x(sigma[1])
    x2 = vset1x(sigma[2])
    x3 = vset1x(sigma[3])
    x4 = vset1x(k0)
    x5 = vset1x(k1)
    x6 = vset1x(k2)
    x7 = vset1x(k3)
    x8 = vset1x(k4)
    x9 = vset1x(k5)
    x10 = vset1x(k6)
    x11 = vset1x(k7)
    base = counter
    x12 = vset8(base, base + 1, base + 2, base + 3,
      base + 4, base + 5, base + 6, base + 7)
    x13 = vset1x(n0)
    x14 = vset1x(n1)
    x15 = vset1x(n2)
    o0 = x0
    o1 = x1
    o2 = x2
    o3 = x3
    o4 = x4
    o5 = x5
    o6 = x6
    o7 = x7
    o8 = x8
    o9 = x9
    o10 = x10
    o11 = x11
    o12 = x12
    o13 = x13
    o14 = x14
    o15 = x15
    i = 0
    while i < 10:
      vqrx(x0, x4, x8, x12)
      vqrx(x1, x5, x9, x13)
      vqrx(x2, x6, x10, x14)
      vqrx(x3, x7, x11, x15)
      vqrx(x0, x5, x10, x15)
      vqrx(x1, x6, x11, x12)
      vqrx(x2, x7, x8, x13)
      vqrx(x3, x4, x9, x14)
      i = i + 1
    x0 = vaddx(x0, o0)
    x1 = vaddx(x1, o1)
    x2 = vaddx(x2, o2)
    x3 = vaddx(x3, o3)
    x4 = vaddx(x4, o4)
    x5 = vaddx(x5, o5)
    x6 = vaddx(x6, o6)
    x7 = vaddx(x7, o7)
    x8 = vaddx(x8, o8)
    x9 = vaddx(x9, o9)
    x10 = vaddx(x10, o10)
    x11 = vaddx(x11, o11)
    x12 = vaddx(x12, o12)
    x13 = vaddx(x13, o13)
    x14 = vaddx(x14, o14)
    x15 = vaddx(x15, o15)
    word = 0
    while word < 16:
      case word
      of 0: mm256_storeu_si256(cast[pointer](addr tmp[0]), x0)
      of 1: mm256_storeu_si256(cast[pointer](addr tmp[0]), x1)
      of 2: mm256_storeu_si256(cast[pointer](addr tmp[0]), x2)
      of 3: mm256_storeu_si256(cast[pointer](addr tmp[0]), x3)
      of 4: mm256_storeu_si256(cast[pointer](addr tmp[0]), x4)
      of 5: mm256_storeu_si256(cast[pointer](addr tmp[0]), x5)
      of 6: mm256_storeu_si256(cast[pointer](addr tmp[0]), x6)
      of 7: mm256_storeu_si256(cast[pointer](addr tmp[0]), x7)
      of 8: mm256_storeu_si256(cast[pointer](addr tmp[0]), x8)
      of 9: mm256_storeu_si256(cast[pointer](addr tmp[0]), x9)
      of 10: mm256_storeu_si256(cast[pointer](addr tmp[0]), x10)
      of 11: mm256_storeu_si256(cast[pointer](addr tmp[0]), x11)
      of 12: mm256_storeu_si256(cast[pointer](addr tmp[0]), x12)
      of 13: mm256_storeu_si256(cast[pointer](addr tmp[0]), x13)
      of 14: mm256_storeu_si256(cast[pointer](addr tmp[0]), x14)
      else: mm256_storeu_si256(cast[pointer](addr tmp[0]), x15)
      lane = 0
      while lane < 8:
        offset = outOffset + lane * chachaBlockLen + word * 4
        store32Le(outBytes, offset, tmp[lane])
        lane = lane + 1
      word = word + 1

proc xchacha20StreamSimd*(key, nonce: openArray[byte], length: int,
    initialCounter: uint32 = 0'u32, b: XChaChaBackend = xcbAuto): ByteSeq =
  if length < 0:
    raise newException(ValueError, "length must be non-negative")
  if key.len != 32:
    raise newException(ValueError, "XChaCha20 requires a 32-byte key")
  if nonce.len != xchacha20.xchacha20NonceSize:
    raise newException(ValueError, "XChaCha20 requires a 24-byte nonce")
  var
    rs: ByteSeq = @[]
    subkey: array[32, byte]
    chachaNonce: array[12, byte]
    offset: int = 0
    counter: uint32 = 0
    take: int = 0
    blockBytes: ByteSeq = @[]
    backend: XChaChaBackend
  subkey = deriveXChaCha20Key(key, nonce)
  chachaNonce = buildChaChaNonce(nonce)
  rs.setLen(length)
  backend = resolveBackend(b)
  counter = initialCounter
  case backend
  of xcbAvx2:
    when defined(avx2):
      while offset + (chachaBlockLen * 8) <= length:
        chacha20Blocks8(subkey, chachaNonce, counter, rs, offset)
        counter = counter + 8'u32
        offset = offset + chachaBlockLen * 8
    else:
      discard
  of xcbSse2:
    when defined(sse2):
      while offset + (chachaBlockLen * 4) <= length:
        chacha20Blocks4(subkey, chachaNonce, counter, rs, offset)
        counter = counter + 4'u32
        offset = offset + chachaBlockLen * 4
    else:
      discard
  else:
    discard
  if offset < length:
    take = length - offset
    blockBytes = xchacha20Stream(key, nonce, take, counter)
    copyMem(addr rs[offset], unsafeAddr blockBytes[0], take)
  result = rs
