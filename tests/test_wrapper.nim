import std/[os, unittest]
import ../src/tyr_crypto/wrapper/crypto
import ../src/tyr_crypto/common
import ./helpers
import ./crypto_vectors

proc bytesToString(data: openArray[uint8]): string =
  result = newString(data.len)
  for i, b in data:
    result[i] = char(b)

suite "wrapper crypto":
  test "XChaCha20 wrapper matches vector":
    let vec = wrapperXChaChaVector
    let key = hexToBytes(vec.keyHex)
    let nonce = hexToBytes(vec.nonceHex)
    let plaintext = hexToBytes(vec.plaintextHex)
    let expectedCipher = hexToBytes(vec.cipherHex)
    let expectedTag = hexToBytes(vec.tagHex)

    let state = EncryptionState(algoType: chacha20, keys: @[Key(key: key, keyType: isSym)], nonce: nonce)
    let cipher = encrypt(plaintext, state)
    check cipher.hmacType == HmacType.blake3
    check cipher.ciphertext == expectedCipher
    check cipher.hmac == expectedTag

  test "XChaCha20 encrypt/decrypt roundtrip":
    const nonceLen = 24
    var key = newSeq[uint8](32)
    for i in 0 ..< key.len:
      key[i] = uint8(i)
    var nonce = newSeq[uint8](nonceLen)
    for i in 0 ..< nonce.len:
      nonce[i] = uint8(100 + i)
    var msg = toBytes("wrapper xchacha20 roundtrip")
    msg.add(0'u8)
    msg.add(255'u8)
    let state = EncryptionState(algoType: chacha20, keys: @[Key(key: key, keyType: isSym)], nonce: nonce)
    let cipher = encrypt(msg, state)
    check cipher.hmacType == HmacType.blake3
    let plain = decrypt(cipher, state)
    check plain == msg

  test "XChaCha20 tag mismatch rejects":
    var key = newSeq[uint8](32)
    for i in 0 ..< key.len:
      key[i] = uint8(i)
    var nonce = newSeq[uint8](24)
    for i in 0 ..< nonce.len:
      nonce[i] = uint8(100 + i)
    let state = EncryptionState(algoType: chacha20, keys: @[Key(key: key, keyType: isSym)], nonce: nonce)
    var cipher = encrypt(toBytes("wrapper tag mismatch"), state)
    cipher.hmac[0] = cipher.hmac[0] xor 0x01'u8
    expect ValueError:
      discard decrypt(cipher, state)

  test "XChaCha20 decrypt/write/read roundtrip":
    const nonceLen = 24
    var key = newSeq[uint8](32)
    for i in 0 ..< key.len:
      key[i] = uint8(200 - i)
    var nonce = newSeq[uint8](nonceLen)
    for i in 0 ..< nonce.len:
      nonce[i] = uint8(i xor 0x5a)
    var msg = toBytes("file roundtrip check for xchacha20")
    msg.add(0'u8)
    msg.add(1'u8)
    msg.add(2'u8)
    let state = EncryptionState(algoType: chacha20, keys: @[Key(key: key, keyType: isSym)], nonce: nonce)
    let cipher = encrypt(msg, state)
    let plain = decrypt(cipher, state)

    let path = getTempDir() / "crypto_wrapper_xchacha20.bin"
    defer:
      if fileExists(path):
        removeFile(path)
    writeFile(path, bytesToString(plain))
    let readBack = toBytes(readFile(path))
    check readBack == msg

  when defined(hasNimcrypto):
    test "AES-256-GCM encrypt/decrypt roundtrip":
      var key = newSeq[uint8](32)
      for i in 0 ..< key.len:
        key[i] = uint8(i + 10)
      var nonce = newSeq[uint8](12)
      for i in 0 ..< nonce.len:
        nonce[i] = uint8(255 - i)
      let msg = toBytes("wrapper aes gcm roundtrip")
      let state = EncryptionState(algoType: aes256, keys: @[Key(key: key, keyType: isSym)], nonce: nonce)
      let cipher = encrypt(msg, state)
      check cipher.hmacType == HmacType.aeadTag
      let plain = decrypt(cipher, state)
      check plain == msg
  else:
    test "AES-256-GCM unavailable raises descriptive error":
      var key = newSeq[uint8](32)
      var nonce = newSeq[uint8](12)
      let msg = toBytes("aes")
      let state = EncryptionState(algoType: aes256, keys: @[Key(key: key, keyType: isSym)], nonce: nonce)
      expect LibraryUnavailableError:
        discard encrypt(msg, state)

  when defined(hasNimcrypto):
    test "AES-256-GCM decrypt/write/read roundtrip":
      var key = newSeq[uint8](32)
      for i in 0 ..< key.len:
        key[i] = uint8(31 - i)
      var nonce = newSeq[uint8](12)
      for i in 0 ..< nonce.len:
        nonce[i] = uint8(i * 3 mod 256)
      var msg = toBytes("file roundtrip check for aes gcm")
      msg.add(9'u8)
      msg.add(8'u8)
      let state = EncryptionState(algoType: aes256, keys: @[Key(key: key, keyType: isSym)], nonce: nonce)
      let cipher = encrypt(msg, state)
      let plain = decrypt(cipher, state)

      let path = getTempDir() / "crypto_wrapper_aes.bin"
      defer:
        if fileExists(path):
          removeFile(path)
      writeFile(path, bytesToString(plain))
      let readBack = toBytes(readFile(path))
      check readBack == msg

    test "AES-256-GCM tag mismatch rejects":
      var key = newSeq[uint8](32)
      for i in 0 ..< key.len:
        key[i] = uint8(i + 1)
      var nonce = newSeq[uint8](12)
      for i in 0 ..< nonce.len:
        nonce[i] = uint8(200 - i)
      let state = EncryptionState(algoType: aes256, keys: @[Key(key: key, keyType: isSym)], nonce: nonce)
      var cipher = encrypt(toBytes("aes gcm tamper"), state)
      cipher.hmac[0] = cipher.hmac[0] xor 0x80'u8
      expect ValueError:
        discard decrypt(cipher, state)
