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
      chachaNonce: seq[byte] = @[]
      msg: seq[byte] = @[]
      cipher: seq[byte] = @[]
      plain: seq[byte] = @[]
    key = hexToBytes("79c99798ac67300bbb2704c95c341e3245f3dcb21761b98e52ff45b24f304fc4")
    nonce = hexToBytes("b33ffd3096479bcfbc9aee49417688a0a2554f8d95389419")
    chachaNonce = hexToBytes("000000090000004a00000000")
    msg = toBytes("dispatch xchacha20")
    cipher = symEnc(scaXChaCha20, key, nonce, msg)
    plain = symDec(scaXChaCha20, key, nonce, cipher)
    check plain == msg
    cipher = symEnc(scaChaCha20, key, chachaNonce, msg)
    plain = symDec(scaChaCha20, key, chachaNonce, cipher)
    check plain == msg

  test "nonce-prefixed stream ciphers roundtrip":
    var
      key: seq[byte] = @[]
      nonce24: seq[byte] = @[]
      nonce16: seq[byte] = @[]
      nonce12: seq[byte] = @[]
      msg: seq[byte] = @[]
      payload: seq[byte] = @[]
      i: int = 0
    key = hexToBytes("79c99798ac67300bbb2704c95c341e3245f3dcb21761b98e52ff45b24f304fc4")
    nonce24 = hexToBytes("b33ffd3096479bcfbc9aee49417688a0a2554f8d95389419")
    nonce16 = toBytes("abcdefghijklmnop")
    nonce12 = hexToBytes("000000090000004a00000000")
    msg = toBytes("nonce prefix payload")

    payload = symEncNoncePrefixed(scaXChaCha20, key, nonce24, msg)
    check payload.len == nonce24.len + msg.len
    i = 0
    while i < nonce24.len:
      check payload[i] == nonce24[i]
      i = i + 1
    check symDecNoncePrefixed(scaXChaCha20, key, payload) == msg

    payload = symEncNoncePrefixed(scaChaCha20, key, nonce12, msg)
    check payload.len == nonce12.len + msg.len
    i = 0
    while i < nonce12.len:
      check payload[i] == nonce12[i]
      i = i + 1
    check symDecNoncePrefixed(scaChaCha20, key, payload) == msg

    payload = symEncNoncePrefixed(scaAesCtr, key, nonce16, msg)
    check payload.len == nonce16.len + msg.len
    i = 0
    while i < nonce16.len:
      check payload[i] == nonce16[i]
      i = i + 1
    check symDecNoncePrefixed(scaAesCtr, key, payload) == msg

    payload = symEncNoncePrefixed(scaGimliStream, key, nonce24, msg)
    check payload.len == nonce24.len + msg.len
    i = 0
    while i < nonce24.len:
      check payload[i] == nonce24[i]
      i = i + 1
    check symDecNoncePrefixed(scaGimliStream, key, payload) == msg
    expect ValueError:
      discard symDecNoncePrefixed(scaXChaCha20, key, nonce16)

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
    check hmacCreate(maPoly1305, key, msg).len == 16

  when defined(hasLibsodium):
    test "x25519 encaps and decaps roundtrip":
      var
        receiver: AsymKeypair
        cipher: AsymCipher
        shared: seq[byte] = @[]
      receiver = genKeypair(kaX25519)
      cipher = encaps(kaX25519, receiver.publicKey)
      shared = decaps(kaX25519, receiver.secretKey, cipher)
      check shared == cipher.sharedSecret

  test "ed25519 sign and verify roundtrip":
    var
      kp: AsymKeypair
      msg: seq[byte] = @[]
      sig: seq[byte] = @[]
    kp = genKeypair(saEd25519)
    msg = toBytes("dispatch ed25519 msg")
    sig = sign(saEd25519, msg, kp.secretKey)
    check verify(saEd25519, msg, sig, kp.publicKey)

  when defined(hasLibsodium) and defined(hasLibOqs):
    test "kyber tier mapping roundtrip":
      var
        kp: AsymKeypair
        cipher: AsymCipher
        shared: seq[byte] = @[]
      kp = genKeypair(kaKyber0)
      cipher = encaps(kaKyber0, kp.publicKey)
      shared = decaps(kaKyber0, kp.secretKey, cipher)
      check shared == cipher.sharedSecret
