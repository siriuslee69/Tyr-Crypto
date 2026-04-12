import std/unittest
import ../src/protocols/wrapper/helpers/algorithms
import ../src/protocols/wrapper/basic_api
import ../src/protocols/common
import ./helpers

suite "primitives api":
  test "symEnc and symDec roundtrip xchacha20":
    var
      key: seq[byte] = @[]
      nonce: seq[byte] = @[]
      msg: seq[byte] = @[]
      cipher: seq[byte] = @[]
      plain: seq[byte] = @[]
    key = hexToBytes("79c99798ac67300bbb2704c95c341e3245f3dcb21761b98e52ff45b24f304fc4")
    nonce = hexToBytes("b33ffd3096479bcfbc9aee49417688a0a2554f8d95389419")
    msg = toBytes("dispatch xchacha20")
    cipher = symEnc(scaXChaCha20, key, nonce, msg)
    plain = symDec(scaXChaCha20, key, nonce, cipher)
    check plain == msg

  test "hmacCreate and hmacAuth with blake3":
    var
      key: seq[byte] = @[]
      msg: seq[byte] = @[]
      tag: seq[byte] = @[]
      bad: seq[byte] = @[]
    key = hexToBytes("00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f")
    msg = toBytes("dispatch hmac")
    tag = hmacCreate(maBlake3, key, msg, 32)
    bad = @tag
    bad[0] = bad[0] xor 0x01'u8
    check hmacAuth(maBlake3, key, msg, tag, 32)
    check not hmacAuth(maBlake3, key, msg, bad, 32)

  test "crypoRand returns requested length":
    var
      a: seq[byte] = @[]
      b: seq[byte] = @[]
    a = crypoRand(raSystem, 24)
    b = cryptoRand(raSystemMixed, 24, toBytes("dispatch entropy"))
    check a.len == 24
    check b.len == 24

  test "sha3 dispatch hmac works":
    let key = toBytes("dispatch sha3 key")
    let msg = toBytes("dispatch sha3 msg")
    let tag = hmacCreate(maSha3, key, msg, 32)
    check hmacAuth(maSha3, key, msg, tag, 32)

  test "poly1305 dispatch hmac works":
    let key = hexToBytes("4242424242424242424242424242424242424242424242424242424242424242")
    let msg = toBytes("dispatch poly1305 msg")
    let tag = hmacCreate(maPoly1305, key, msg, 16)
    check hmacAuth(maPoly1305, key, msg, tag, 16)

  when defined(hasLibsodium):
    test "x25519 asymEnc and asymDec roundtrip":
      var
        receiver: AsymKeypair
        cipher: AsymCipher
        shared: seq[byte] = @[]
      receiver = asymKeypair(kaX25519)
      cipher = asymEnc(kaX25519, receiver.publicKey)
      shared = asymDec(kaX25519, receiver.secretKey, cipher)
      check shared == cipher.sharedSecret

    test "ed25519 asymSign and asymVerify roundtrip":
      var
        kp: AsymKeypair
        msg: seq[byte] = @[]
        sig: seq[byte] = @[]
      kp = asymKeypair(saEd25519)
      msg = toBytes("dispatch ed25519 msg")
      sig = asymSign(saEd25519, msg, kp.secretKey)
      check asymVerify(saEd25519, msg, sig, kp.publicKey)
  else:
    test "ed25519 dispatch unavailable raises":
      expect LibraryUnavailableError:
        discard asymKeypair(saEd25519)

  when defined(hasLibsodium) and defined(hasLibOqs):
    test "kyber tier mapping roundtrip":
      var
        kp: AsymKeypair
        cipher: AsymCipher
        shared: seq[byte] = @[]
      kp = asymKeypair(kaKyber0)
      cipher = asymEnc(kaKyber0, kp.publicKey)
      shared = asymDec(kaKyber0, kp.secretKey, cipher)
      check shared == cipher.sharedSecret
