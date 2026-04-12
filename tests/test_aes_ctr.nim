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

suite "aes ctr":
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
    test "sse2 matches scalar":
      let key = toBytes("0123456789abcdef0123456789abcdef")
      let nonce = toBytes("abcdefghijklmnop")
      var msg = newSeq[uint8](64)
      for i in 0 ..< msg.len:
        msg[i] = uint8(i)
      let c0 = aesCtrXor(key, nonce, msg, acbScalar)
      let c1 = aesCtrXor(key, nonce, msg, acbSse2)
      check c0 == c1

  when defined(avx2):
    test "avx2 matches scalar":
      let key = toBytes("0123456789abcdef0123456789abcdef")
      let nonce = toBytes("abcdefghijklmnop")
      var msg = newSeq[uint8](96)
      for i in 0 ..< msg.len:
        msg[i] = uint8(255 - i)
      let c0 = aesCtrXor(key, nonce, msg, acbScalar)
      let c1 = aesCtrXor(key, nonce, msg, acbAvx2)
      check c0 == c1
