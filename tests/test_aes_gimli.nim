import std/unittest
import ../src/tyr_crypto/wrapper/crypto
import ./helpers

proc buildAesGimliState(keyA, keyG, nonce: seq[uint8], tagLen: uint16): EncryptionState =
  var s: EncryptionState
  s.algoType = aesGimli
  s.keys = @[Key(key: keyA, keyType: isSym), Key(key: keyG, keyType: isSym)]
  s.nonce = nonce
  s.tagLen = tagLen
  result = s

suite "aes gimli":
  test "encrypt/decrypt roundtrip":
    let keyA = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    let keyG = hexToBytes("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100")
    let nonce = hexToBytes("000102030405060708090a0b0c0d0e0f1011121314151617")
    var msg = newSeq[uint8](112)
    for i in 0 ..< msg.len:
      msg[i] = uint8((i * 11) mod 256)
    let state = buildAesGimliState(keyA, keyG, nonce, 64'u16)
    let cipher = encrypt(msg, state)
    check cipher.hmacType == crypto.gimli
    check cipher.hmac.len == 64
    let plain = decrypt(cipher, state)
    check plain == msg

  test "tag mismatch rejects":
    let keyA = hexToBytes("ffffffffffffffffffffffffffffffff00000000000000000000000000000000")
    let keyG = hexToBytes("00000000000000000000000000000000ffffffffffffffffffffffffffffffff")
    let nonce = hexToBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    let msg = toBytes("aes gimli tag check")
    let state = buildAesGimliState(keyA, keyG, nonce, 64'u16)
    var cipher = encrypt(msg, state)
    cipher.hmac[^1] = cipher.hmac[^1] xor 0x01'u8
    expect ValueError:
      discard decrypt(cipher, state)

  test "wrong key rejects":
    let keyA = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    let keyG = hexToBytes("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100")
    let nonce = hexToBytes("000102030405060708090a0b0c0d0e0f1011121314151617")
    let msg = toBytes("aes gimli wrong key")
    let state = buildAesGimliState(keyA, keyG, nonce, 64'u16)
    let cipher = encrypt(msg, state)
    var wrongState = buildAesGimliState(keyA, keyG, nonce, 64'u16)
    wrongState.keys[1].key[0] = wrongState.keys[1].key[0] xor 0xff'u8
    expect ValueError:
      discard decrypt(cipher, wrongState)

  test "tag length variation":
    let keyA = hexToBytes("0101010101010101010101010101010101010101010101010101010101010101")
    let keyG = hexToBytes("0202020202020202020202020202020202020202020202020202020202020202")
    let nonce = hexToBytes("030303030303030303030303030303030303030303030303")
    let msg = toBytes("aes gimli short tag")
    let state = buildAesGimliState(keyA, keyG, nonce, 16'u16)
    let cipher = encrypt(msg, state)
    check cipher.hmac.len == 16
    let plain = decrypt(cipher, state)
    check plain == msg
