import ./aes_core as aesCore

when defined(avx2):
  import nimsimd/avx
  import nimsimd/avx2
elif defined(sse2):
  import nimsimd/sse2

const
  aesCtrBlockLen* = 16
  aesCtrNonceLen* = 16

type
  ByteSeq = seq[uint8]

  AesCtrBackend* = enum
    acbAuto,
    acbScalar,
    acbSse2,
    acbAvx2

  AesCtrState* = object
    ctx: Aes256Ctx
    counter: AesBlock

proc resolveBackend(b: AesCtrBackend): AesCtrBackend =
  case b
  of acbAuto:
    when defined(avx2):
      result = acbAvx2
    elif defined(sse2):
      result = acbSse2
    else:
      result = acbScalar
  else:
    result = b

proc initCounter(ns: openArray[uint8]): AesBlock =
  var
    c: AesBlock
    i: int = 0
  i = 0
  while i < aesCtrBlockLen:
    c[i] = ns[i]
    i = i + 1
  result = c

proc incrementCounter(c: var AesBlock) =
  ## Increment the counter as a big-endian 128-bit integer (CTR standard).
  var
    i: int = 0
    carry: uint16 = 1
    v: uint16 = 0
  i = c.len - 1
  while i >= 0 and carry != 0:
    v = uint16(c[i]) + carry
    c[i] = uint8(v and 0xff)
    carry = (v shr 8) and 0x1
    i = i - 1

proc xorBlockScalar(ps: openArray[uint8], ks: openArray[uint8],
    rs: var ByteSeq, o, l: int) =
  var
    i: int = 0
  i = 0
  while i < l:
    rs[o + i] = ps[o + i] xor ks[i]
    i = i + 1

proc xorBlockScalarInPlace(bs: var openArray[uint8], ks: openArray[uint8],
    o, l: int) =
  var
    i: int = 0
  i = 0
  while i < l:
    bs[o + i] = bs[o + i] xor ks[i]
    i = i + 1

when defined(sse2):
  proc xorBlockSse(ps: openArray[uint8], ks: openArray[uint8],
      rs: var ByteSeq, o: int) =
    var
      vp: M128i
      vk: M128i
      vr: M128i
    vp = mm_loadu_si128(cast[pointer](unsafeAddr ps[o]))
    vk = mm_loadu_si128(cast[pointer](unsafeAddr ks[0]))
    vr = mm_xor_si128(vp, vk)
    mm_storeu_si128(cast[pointer](unsafeAddr rs[o]), vr)

  proc xorBlockSseInPlace(bs: var openArray[uint8], ks: openArray[uint8],
      o: int) =
    var
      vp: M128i
      vk: M128i
      vr: M128i
    vp = mm_loadu_si128(cast[pointer](unsafeAddr bs[o]))
    vk = mm_loadu_si128(cast[pointer](unsafeAddr ks[0]))
    vr = mm_xor_si128(vp, vk)
    mm_storeu_si128(cast[pointer](unsafeAddr bs[o]), vr)

when defined(avx2):
  proc xorBlockAvx2(ps: openArray[uint8], ks: openArray[uint8],
      rs: var ByteSeq, o: int) =
    var
      vp: M256i
      vk: M256i
      vr: M256i
    vp = mm256_loadu_si256(cast[pointer](unsafeAddr ps[o]))
    vk = mm256_loadu_si256(cast[pointer](unsafeAddr ks[0]))
    vr = mm256_xor_si256(vp, vk)
    mm256_storeu_si256(cast[pointer](unsafeAddr rs[o]), vr)

  proc xorBlockAvx2InPlace(bs: var openArray[uint8], ks: openArray[uint8],
      o: int) =
    var
      vp: M256i
      vk: M256i
      vr: M256i
    vp = mm256_loadu_si256(cast[pointer](unsafeAddr bs[o]))
    vk = mm256_loadu_si256(cast[pointer](unsafeAddr ks[0]))
    vr = mm256_xor_si256(vp, vk)
    mm256_storeu_si256(cast[pointer](unsafeAddr bs[o]), vr)

proc aesCtrXor*(k, n, ps: openArray[uint8], b: AesCtrBackend = acbAuto): ByteSeq =
  var
    ctx: Aes256Ctx
    counter: AesBlock
    ks0: AesBlock
    rs: ByteSeq = @[]
    offset: int = 0
    take: int = 0
    backend: AesCtrBackend
  when defined(avx2):
    var
      ks1: AesBlock
      ks32: array[32, uint8]
      i: int = 0
  if k.len != 32:
    raise newException(ValueError, "aes ctr requires 32-byte key")
  if n.len != aesCtrNonceLen:
    raise newException(ValueError, "aes ctr requires 16-byte nonce")
  ctx.init(k)
  counter = initCounter(n)
  rs.setLen(ps.len)
  backend = resolveBackend(b)
  case backend
  of acbAvx2:
    when defined(avx2):
      while offset + 32 <= ps.len:
        ks0 = aesCore.encryptBlock(ctx, counter)
        incrementCounter(counter)
        ks1 = aesCore.encryptBlock(ctx, counter)
        incrementCounter(counter)
        i = 0
        while i < 16:
          ks32[i] = ks0[i]
          ks32[i + 16] = ks1[i]
          i = i + 1
        xorBlockAvx2(ps, ks32, rs, offset)
        offset = offset + 32
    else:
      discard
  of acbSse2:
    when defined(sse2):
      while offset + 16 <= ps.len:
        ks0 = aesCore.encryptBlock(ctx, counter)
        incrementCounter(counter)
        xorBlockSse(ps, ks0, rs, offset)
        offset = offset + 16
    else:
      discard
  else:
    discard
  while offset < ps.len:
    ks0 = aesCore.encryptBlock(ctx, counter)
    incrementCounter(counter)
    take = aesCtrBlockLen
    if ps.len - offset < take:
      take = ps.len - offset
    xorBlockScalar(ps, ks0, rs, offset, take)
    offset = offset + take
  result = rs

proc initAesCtrState*(k, n: openArray[uint8]): AesCtrState =
  ## k: AES-256 key bytes.
  ## n: 16-byte nonce/counter.
  if k.len != 32:
    raise newException(ValueError, "aes ctr requires 32-byte key")
  if n.len != aesCtrNonceLen:
    raise newException(ValueError, "aes ctr requires 16-byte nonce")
  var s: AesCtrState
  s.ctx.init(k)
  s.counter = initCounter(n)
  result = s

proc aesCtrXorInPlace*(s: var AesCtrState, ps: var openArray[uint8],
    b: AesCtrBackend = acbAuto) =
  ## s: AES-CTR streaming state.
  ## ps: data to transform in-place.
  ## b: backend selection.
  var
    ks0: AesBlock
    offset: int = 0
    take: int = 0
    backend: AesCtrBackend
  when defined(avx2):
    var
      ks1: AesBlock
      ks32: array[32, uint8]
      i: int = 0
  backend = resolveBackend(b)
  case backend
  of acbAvx2:
    when defined(avx2):
      while offset + 32 <= ps.len:
        ks0 = aesCore.encryptBlock(s.ctx, s.counter)
        incrementCounter(s.counter)
        ks1 = aesCore.encryptBlock(s.ctx, s.counter)
        incrementCounter(s.counter)
        i = 0
        while i < 16:
          ks32[i] = ks0[i]
          ks32[i + 16] = ks1[i]
          i = i + 1
        xorBlockAvx2InPlace(ps, ks32, offset)
        offset = offset + 32
    else:
      discard
  of acbSse2:
    when defined(sse2):
      while offset + 16 <= ps.len:
        ks0 = aesCore.encryptBlock(s.ctx, s.counter)
        incrementCounter(s.counter)
        xorBlockSseInPlace(ps, ks0, offset)
        offset = offset + 16
    else:
      discard
  else:
    discard
  while offset < ps.len:
    ks0 = aesCore.encryptBlock(s.ctx, s.counter)
    incrementCounter(s.counter)
    take = aesCtrBlockLen
    if ps.len - offset < take:
      take = ps.len - offset
    xorBlockScalarInPlace(ps, ks0, offset, take)
    offset = offset + take
