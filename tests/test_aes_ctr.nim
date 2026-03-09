import std/unittest
import ../src/tyr_crypto/custom_crypto/aes_ctr
import ./helpers
when defined(hasNimcrypto):
  import nimcrypto/rijndael
  import nimcrypto/bcmode

suite "aes ctr":
  test "roundtrip":
    let key = toBytes("0123456789abcdef0123456789abcdef")
    let nonce = toBytes("abcdefghijklmnop")
    let msg = toBytes("aes ctr stream roundtrip")
    let c0 = aesCtrXor(key, nonce, msg, acbScalar)
    let p0 = aesCtrXor(key, nonce, c0, acbScalar)
    check p0 == msg

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
      if outBytes != c0:
        # NOTE: If this fails, it's usually due to CTR counter layout/endianness
        # differences (nonce+counter byte order), not a broken AES core.
        echo "NOTE: AES-CTR vs nimcrypto mismatch likely due to CTR counter layout/endianness differences."
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
