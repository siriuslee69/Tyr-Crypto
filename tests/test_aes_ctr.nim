import std/unittest
import ../src/protocols/custom_crypto/aes_ctr
import ../src/protocols/custom_crypto/aes_core
import ./helpers
when defined(hasNimcrypto):
  import nimcrypto/rijndael
  import nimcrypto/bcmode

proc incrementCounterBe(c: var AesBlock) =
  var
    i: int = c.len - 1
    carry: uint16 = 1
    v: uint16 = 0
  while i >= 0 and carry != 0:
    v = uint16(c[i]) + carry
    c[i] = uint8(v and 0xff)
    carry = (v shr 8) and 0x1
    i = i - 1

proc patternedBytes(l, s: int): seq[byte] =
  ## l: Number of bytes to generate.
  ## s: Per-byte multiplier used to vary the input.
  var
    i: int = 0
  result = newSeq[byte](l)
  while i < l:
    result[i] = byte((i * s + 17) mod 256)
    i = i + 1

proc nearExhaustedNonce(c: int): seq[byte] =
  ## c: Number of AES counter blocks still available.
  var
    i: int = 0
  result = newSeq[byte](aesCtrNonceLen)
  while i < result.len:
    result[i] = 0xff'u8
    i = i + 1
  result[^1] = byte(256 - c)

proc checkBackendBoundaries(b: AesCtrBackend, L: openArray[int]) =
  ## b: Forced AES-CTR backend under test.
  ## L: Input lengths around that backend's SIMD width.
  var
    key = toBytes("0123456789abcdef0123456789abcdef")
    nonce = toBytes("abcdefghijklmnop")
    msg: seq[byte] = @[]
    scalarBytes: seq[byte] = @[]
    backendBytes: seq[byte] = @[]
    i: int = 0
  while i < L.len:
    msg = patternedBytes(L[i], i + 3)
    scalarBytes = aesCtrXor(key, nonce, msg, acbScalar)
    backendBytes = aesCtrXor(key, nonce, msg, b)
    check backendBytes == scalarBytes
    i = i + 1

proc checkCounterBoundary(b: AesCtrBackend, a, r, c: int) =
  ## b: Forced AES-CTR backend under test.
  ## a: Accepted byte length at the final available counter.
  ## r: Rejected byte length that would wrap the counter.
  ## c: Number of AES counter blocks still available.
  var
    key = toBytes("0123456789abcdef0123456789abcdef")
    nonce = nearExhaustedNonce(c)
    accepted = patternedBytes(a, 7)
    scalarBytes: seq[byte] = @[]
    backendBytes: seq[byte] = @[]
  scalarBytes = aesCtrXor(key, nonce, accepted, acbScalar)
  backendBytes = aesCtrXor(key, nonce, accepted, b)
  check backendBytes == scalarBytes
  expect ValueError:
    discard aesCtrXor(key, nonce, newSeq[byte](r), b)

suite "aes ctr":
  test "uninitialized and cleared contexts fail closed":
    var
      ctx128: Aes128Ctx
      ctx256: Aes256Ctx
      state: AesCtrState
      inputBlock: AesBlock
      bytes = newSeq[byte](1)
      key256 = toBytes("0123456789abcdef0123456789abcdef")
    expect ValueError:
      discard encryptBlock(ctx128, inputBlock)
    expect ValueError:
      discard encryptBlock(ctx256, inputBlock)
    expect ValueError:
      aesCtrXorInPlace(state, bytes, acbScalar)
    when defined(aesni):
      var niCtx: Aes128NiCtx
      expect ValueError:
        discard encryptBlock(niCtx, inputBlock)
    ctx256.init(key256)
    expect ValueError:
      ctx256.init(@[byte 1])
    expect ValueError:
      discard encryptBlock(ctx256, inputBlock)
    state = initAesCtrState(key256,
      toBytes("abcdefghijklmnop"))
    clear(state)
    expect ValueError:
      aesCtrXorInPlace(state, bytes, acbScalar)

  test "roundtrip":
    let key = toBytes("0123456789abcdef0123456789abcdef")
    let nonce = toBytes("abcdefghijklmnop")
    let msg = toBytes("aes ctr stream roundtrip")
    let c0 = aesCtrXor(key, nonce, msg, acbScalar)
    let p0 = aesCtrXor(key, nonce, c0, acbScalar)
    check p0 == msg

  test "zero stream vector locks nonce and counter byte order":
    let
      key = toBytes("0123456789abcdef0123456789abcdef")
      nonce = toBytes("abcdefghijklmnop")
      expected = hexToBytes("2caa03ffbc3f459f8427455a83340b7f0e70898b3be783a6d8738257bb6b32cf")
    check aesCtrXor(key, nonce, newSeq[byte](32), acbScalar) == expected

  test "counter increments as big-endian 128-bit integer":
    let
      key = toBytes("0123456789abcdef0123456789abcdef")
      nonce = toBytes("abcdefghijklmnop")
      actual = aesCtrXor(key, nonce, newSeq[byte](32), acbScalar)
    var
      ctx: Aes256Ctx
      counter0: AesBlock
      counter1: AesBlock
      block0: AesBlock
      block1: AesBlock
      expected = newSeq[byte](32)
      i: int = 0
    ctx.init(key)
    i = 0
    while i < counter0.len:
      counter0[i] = nonce[i]
      i = i + 1
    counter1 = counter0
    incrementCounterBe(counter1)
    block0 = encryptBlock(ctx, counter0)
    block1 = encryptBlock(ctx, counter1)
    i = 0
    while i < 16:
      expected[i] = block0[i]
      expected[16 + i] = block1[i]
      i = i + 1
    check actual == expected

  test "streaming state preserves partial keystream blocks":
    let
      key = toBytes("0123456789abcdef0123456789abcdef")
      nonce = toBytes("abcdefghijklmnop")
      msg = toBytes("partial calls must form one continuous AES CTR stream")
      expected = aesCtrXor(key, nonce, msg, acbScalar)
    var
      state = initAesCtrState(key, nonce)
      a = msg[0 ..< 1]
      b = msg[1 ..< 8]
      c = msg[8 ..< 29]
      d = msg[29 ..< msg.len]
    defer:
      clear(state)
    aesCtrXorInPlace(state, a, acbScalar)
    aesCtrXorInPlace(state, b, acbScalar)
    aesCtrXorInPlace(state, c, acbScalar)
    aesCtrXorInPlace(state, d, acbScalar)
    check a & b & c & d == expected

  test "counter wrap is rejected before output reuse":
    let key = toBytes("0123456789abcdef0123456789abcdef")
    var
      nonce = newSeq[byte](16)
      state: AesCtrState
      first = newSeq[byte](1)
      rest = newSeq[byte](15)
      extra = newSeq[byte](1)
    for i in 0 ..< nonce.len:
      nonce[i] = 0xff'u8
    expect ValueError:
      discard aesCtrXor(key, nonce, newSeq[byte](17), acbScalar)
    state = initAesCtrState(key, nonce)
    defer:
      clear(state)
    aesCtrXorInPlace(state, first, acbScalar)
    aesCtrXorInPlace(state, rest, acbScalar)
    expect ValueError:
      aesCtrXorInPlace(state, extra, acbScalar)

  when defined(hasNimcrypto):
    test "matches nimcrypto ctr":
      let key = toBytes("0123456789abcdef0123456789abcdef")
      let nonce = toBytes("abcdefghijklmnop")
      var msg = newSeq[uint8](64)
      for i in 0 ..< msg.len:
        msg[i] = uint8(i * 3)
      let c0 = aesCtrXor(key, nonce, msg, acbScalar)
      var ctx: CTR[aes256]
      ctx.init(key, nonce)
      var outBytes = newSeq[uint8](msg.len)
      ctx.encrypt(msg, outBytes)
      check outBytes == c0

  when defined(sse2):
    test "sse2 boundary matrix matches scalar":
      checkBackendBoundaries(acbSse2, [15, 16, 17])
      checkCounterBoundary(acbSse2, 16, 17, 1)

  when defined(avx2):
    test "avx2 boundary matrix matches scalar":
      checkBackendBoundaries(acbAvx2, [31, 32, 33])
      checkCounterBoundary(acbAvx2, 32, 33, 2)

  when defined(neon) or defined(arm64) or defined(aarch64):
    test "neon boundary matrix matches scalar":
      checkBackendBoundaries(acbNeon, [15, 16, 17])
      checkCounterBoundary(acbNeon, 16, 17, 1)
