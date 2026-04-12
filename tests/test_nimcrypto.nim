import std/unittest
import ../src/protocols/common
import ../src/protocols/bindings/nimcrypto

when defined(hasNimcrypto):
  import ./helpers

suite "nimcrypto bindings":
  when defined(hasNimcrypto):
    test "AES-256-GCM encrypt/decrypt roundtrip":
      var ctx: Aes256GcmContext
      var key = newSeq[byte](32)
      for i in 0 ..< key.len:
        key[i] = byte(i)
      var iv = newSeq[byte](12)
      for i in 0 ..< iv.len:
        iv[i] = byte(255 - i)

      const plaintextStr = "nimcrypto aead payload"
      const aadStr = "header"
      var plaintext = newSeq[byte](plaintextStr.len)
      for i, ch in plaintextStr:
        plaintext[i] = byte(ord(ch))
      var aad = newSeq[byte](aadStr.len)
      for i, ch in aadStr:
        aad[i] = byte(ord(ch))

      ctx.init(key, iv)
      ctx.aad(aad)
      let ciphertext = ctx.encrypt(plaintext)
      let tag = ctx.tag()

      echo "nimcrypto ciphertext: ", toHex(ciphertext)
      echo "nimcrypto tag: ", toHex(tag)

      var ctxDec: Aes256GcmContext
      ctxDec.init(key, iv)
      ctxDec.aad(aad)
      let decrypted = ctxDec.decrypt(ciphertext)
      let verifyTag = ctxDec.tag()
      check tag == verifyTag
      check decrypted == plaintext

    test "AES-256-GCM matches NIST test vector":
      let key = hexToBytes("0000000000000000000000000000000000000000000000000000000000000000")
      let iv = hexToBytes("000000000000000000000000")
      let plaintext = hexToBytes("00000000000000000000000000000000")
      let expectedCipher = hexToBytes("cea7403d4d606b6e074ec5d3baf39d18")
      let expectedTag = hexToBytes("d0d1c8a799996bf0265b98b5d48ab919")

      var ctx: Aes256GcmContext
      ctx.init(key, iv)
      let ciphertext = ctx.encrypt(plaintext)
      let tagArr = ctx.tag()

      check ciphertext == expectedCipher
      for i in 0 ..< expectedTag.len:
        check tagArr[i] == expectedTag[i]

      var ctxDec: Aes256GcmContext
      ctxDec.init(key, iv)
      let decrypted = ctxDec.decrypt(ciphertext)
      let tagDec = ctxDec.tag()
      check decrypted == plaintext
      for i in 0 ..< expectedTag.len:
        check tagDec[i] == expectedTag[i]
  else:
    test "nimcrypto unavailable raises descriptive error":
      var ctx: Aes256GcmContext
      let key = newSeq[byte](32)
      let iv = newSeq[byte](12)
      expect LibraryUnavailableError:
        ctx.init(key, iv)
