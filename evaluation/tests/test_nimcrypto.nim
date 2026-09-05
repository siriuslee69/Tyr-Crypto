import std/unittest
import ../../src/tyr/helpers/errors
import ../../src/tyr/bindings/nimcrypto

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
      let decrypted = ctxDec.decrypt(ciphertext, tag)
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
      let decrypted = ctxDec.decrypt(ciphertext, tagArr)
      check decrypted == plaintext

    test "AES-256-GCM empty plaintext matches NIST vector":
      let key = newSeq[byte](32)
      let iv = newSeq[byte](12)
      let expectedTag = hexToBytes("530f8afbc74536b9a963b4f1c4cb738b")
      var ctx: Aes256GcmContext
      ctx.init(key, iv)
      check ctx.encrypt(@[]).len == 0
      check @(ctx.tag()) == expectedTag
      var dec: Aes256GcmContext
      dec.init(key, iv)
      check dec.decrypt(@[], expectedTag).len == 0

    test "AES-256-GCM rejects tampering and non-profile tag lengths":
      let key = newSeq[byte](32)
      let iv = newSeq[byte](12)
      let plaintext = hexToBytes("000102030405060708090a0b0c0d0e0f")
      var enc: Aes256GcmContext
      enc.init(key, iv)
      let ciphertext = enc.encrypt(plaintext)
      var tag = @(enc.tag())
      tag[0] = tag[0] xor 1'u8
      var dec: Aes256GcmContext
      dec.init(key, iv)
      expect ValueError:
        discard dec.decrypt(ciphertext, tag)
      for size in [0, 1, 11, 12, 15, 17, 32]:
        var shortTag = newSeq[byte](size)
        var sized: Aes256GcmContext
        sized.init(key, iv)
        expect ValueError:
          discard sized.decrypt(ciphertext, shortTag)

    test "AES-256-GCM enforces nonce and context boundaries":
      let key = newSeq[byte](32)
      let iv = newSeq[byte](12)
      var ctx: Aes256GcmContext
      for size in [0, 1, 11, 13, 16]:
        expect ValueError:
          ctx.init(key, newSeq[byte](size))
      ctx.init(key, iv)
      expect ValueError:
        discard ctx.tag()
      discard ctx.encrypt(@[1'u8])
      expect ValueError:
        discard ctx.encrypt(@[2'u8])
      expect ValueError:
        ctx.aad(@[3'u8])
  else:
    test "nimcrypto unavailable raises descriptive error":
      var ctx: Aes256GcmContext
      let key = newSeq[byte](32)
      let iv = newSeq[byte](12)
      expect LibraryUnavailableError:
        ctx.init(key, iv)
