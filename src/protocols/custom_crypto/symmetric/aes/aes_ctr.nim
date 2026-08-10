import ./aes_core as aesCore
import ../secure_memory

when defined(avx2):
  import nimsimd/avx
  import nimsimd/avx2

when defined(sse2) or defined(neon) or defined(arm64) or defined(aarch64):
  import simd_nexus/sequences/byte_streams as simdByteStreams

const
  aesCtrBlockLen* = 16
  aesCtrNonceLen* = 16

type
  ByteSeq = seq[uint8]

  AesCtrBackend* = enum
    acbAuto,
    acbScalar,
    acbSse2,
    acbNeon,
    acbAvx2

  AesCtrState* = object
    ctx: Aes256Ctx
    counter: AesBlock
    keystream: AesBlock
    keystreamOffset: int
    exhausted: bool
    initialized: bool

proc initAesCtrState*(k, n: openArray[uint8]): AesCtrState
proc clear*(s: var AesCtrState) {.inline, raises: [].}
proc aesCtrXorInPlace*(s: var AesCtrState, ps: var openArray[uint8],
    b: AesCtrBackend = acbAuto)

proc resolveBackend(b: AesCtrBackend): AesCtrBackend =
  case b
  of acbAuto:
    when defined(avx2):
      result = acbAvx2
    elif defined(sse2):
      result = acbSse2
    elif defined(neon) or defined(arm64) or defined(aarch64):
      result = acbNeon
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

proc incrementCounter(c: var AesBlock): bool =
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
  result = carry != 0

proc load64Be(A: openArray[uint8], o: int): uint64 {.inline.} =
  var
    i: int = 0
  while i < 8:
    result = (result shl 8) or uint64(A[o + i])
    i = i + 1

proc requireAesCtrBlocks(c: openArray[uint8], blocks: uint64) =
  ## Reject a block count before its 128-bit counter can wrap.
  var
    addend: uint64 = 0
    highWord: uint64 = 0
    lowWord: uint64 = 0
    carry: uint64 = 0
  if blocks == 0:
    return
  addend = blocks - 1'u64
  highWord = load64Be(c, 0)
  lowWord = load64Be(c, 8)
  carry = uint64(addend > uint64.high - lowWord)
  if carry != 0 and highWord == uint64.high:
    raise newException(ValueError, "aes ctr block counter would wrap")

proc requireAesCtrBlockRange(c: openArray[uint8], byteLen: int) =
  var
    blocks: uint64 = 0
  if byteLen < 0:
    raise newException(ValueError, "aes ctr length must be non-negative")
  if byteLen == 0:
    return
  blocks = (uint64(byteLen - 1) div uint64(aesCtrBlockLen)) + 1'u64
  requireAesCtrBlocks(c, blocks)

proc remainingBlockCount(s: AesCtrState, byteLen: int): int =
  var
    buffered: int = 0
    remaining: int = 0
  if byteLen <= 0:
    return 0
  if s.keystreamOffset < aesCtrBlockLen:
    buffered = aesCtrBlockLen - s.keystreamOffset
  remaining = byteLen - min(byteLen, buffered)
  if remaining <= 0:
    return 0
  result = ((remaining - 1) div aesCtrBlockLen) + 1

proc requireAesCtrStateRange(s: AesCtrState, byteLen: int) =
  var
    blocks: int = 0
  if not s.initialized:
    raise newException(ValueError, "aes ctr state is not initialized")
  if byteLen < 0:
    raise newException(ValueError, "aes ctr length must be non-negative")
  blocks = remainingBlockCount(s, byteLen)
  if blocks == 0:
    return
  if s.exhausted:
    raise newException(ValueError, "aes ctr block counter exhausted")
  requireAesCtrBlocks(s.counter, uint64(blocks))

proc xorBlockScalarInPlace(bs: var openArray[uint8], ks: openArray[uint8],
    o, l: int) =
  var
    i: int = 0
  i = 0
  while i < l:
    bs[o + i] = bs[o + i] xor ks[i]
    i = i + 1

when defined(avx2):
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
    s: AesCtrState
    rs: ByteSeq = @[]
  defer:
    secureClearPod(s)
  if k.len != 32:
    raise newException(ValueError, "aes ctr requires 32-byte key")
  if n.len != aesCtrNonceLen:
    raise newException(ValueError, "aes ctr requires 16-byte nonce")
  requireAesCtrBlockRange(n, ps.len)
  s = initAesCtrState(k, n)
  rs = @ps
  aesCtrXorInPlace(s, rs, b)
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
  s.keystreamOffset = aesCtrBlockLen
  s.exhausted = false
  s.initialized = true
  result = s

proc clear*(s: var AesCtrState) {.inline, raises: [].} =
  ## End a streaming operation by wiping its expanded key and counter.
  secureClearPod(s)

proc aesCtrXorInPlace*(s: var AesCtrState, ps: var openArray[uint8],
    b: AesCtrBackend) =
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
  defer:
    secureClearBytes(ks0)
    when defined(avx2):
      secureClearBytes(ks1)
      secureClearBytes(ks32)
  requireAesCtrStateRange(s, ps.len)
  while offset < ps.len and s.keystreamOffset < aesCtrBlockLen:
    ps[offset] = ps[offset] xor s.keystream[s.keystreamOffset]
    s.keystreamOffset = s.keystreamOffset + 1
    offset = offset + 1
  backend = resolveBackend(b)
  case backend
  of acbAvx2:
    when defined(avx2):
      while offset + 32 <= ps.len:
        ks0 = aesCore.encryptBlock(s.ctx, s.counter)
        if incrementCounter(s.counter):
          s.exhausted = true
        ks1 = aesCore.encryptBlock(s.ctx, s.counter)
        if incrementCounter(s.counter):
          s.exhausted = true
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
        if incrementCounter(s.counter):
          s.exhausted = true
        simdByteStreams.xorBytes16InPlace(ps, offset, ks0, 0)
        offset = offset + 16
    else:
      discard
  of acbNeon:
    when defined(neon) or defined(arm64) or defined(aarch64):
      while offset + 16 <= ps.len:
        ks0 = aesCore.encryptBlock(s.ctx, s.counter)
        if incrementCounter(s.counter):
          s.exhausted = true
        simdByteStreams.xorBytes16InPlace(ps, offset, ks0, 0)
        offset = offset + 16
    else:
      discard
  else:
    discard
  while offset < ps.len:
    s.keystream = aesCore.encryptBlock(s.ctx, s.counter)
    if incrementCounter(s.counter):
      s.exhausted = true
    s.keystreamOffset = 0
    take = min(aesCtrBlockLen, ps.len - offset)
    xorBlockScalarInPlace(ps, s.keystream, offset, take)
    s.keystreamOffset = take
    offset = offset + take
