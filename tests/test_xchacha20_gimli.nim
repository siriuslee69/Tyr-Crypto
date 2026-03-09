import std/unittest
import ../src/tyr_crypto/wrapper/crypto
import ./helpers

proc buildState(keyX, keyG, nonce: seq[uint8], tagLen: uint16): EncryptionState =
  var s: EncryptionState
  s.algoType = xchacha20Gimli
  s.keys = @[Key(key: keyX, keyType: isSym), Key(key: keyG, keyType: isSym)]
  s.nonce = nonce
  s.tagLen = tagLen
  result = s

suite "xchacha20 gimli":
  test "encrypt/decrypt roundtrip":
    let keyX = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    let keyG = hexToBytes("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100")
    let nonce = hexToBytes("000102030405060708090a0b0c0d0e0f1011121314151617")
    var msg = newSeq[uint8](96)
    for i in 0 ..< msg.len:
      msg[i] = uint8((i * 7) mod 256)
    let state = buildState(keyX, keyG, nonce, 32'u16)
    let cipher = encrypt(msg, state)
    check cipher.hmacType == crypto.gimli
    let plain = decrypt(cipher, state)
    check plain == msg

  test "tag mismatch rejects":
    let keyX = hexToBytes("ffffffffffffffffffffffffffffffff00000000000000000000000000000000")
    let keyG = hexToBytes("00000000000000000000000000000000ffffffffffffffffffffffffffffffff")
    let nonce = hexToBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    let msg = toBytes("xchacha20 gimli tag check")
    let state = buildState(keyX, keyG, nonce, 32'u16)
    var cipher = encrypt(msg, state)
    cipher.hmac[0] = cipher.hmac[0] xor 0x1'u8
    expect ValueError:
      discard decrypt(cipher, state)

  test "wrong key rejects":
    let keyX = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    let keyG = hexToBytes("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100")
    let nonce = hexToBytes("000102030405060708090a0b0c0d0e0f1011121314151617")
    let msg = toBytes("xchacha20 gimli wrong key")
    let state = buildState(keyX, keyG, nonce, 32'u16)
    let cipher = encrypt(msg, state)
    var wrongKeyG = keyG
    wrongKeyG[0] = wrongKeyG[0] xor 0xff'u8
    let wrongState = buildState(keyX, wrongKeyG, nonce, 32'u16)
    expect ValueError:
      discard decrypt(cipher, wrongState)

  test "tag length variation":
    let keyX = hexToBytes("0101010101010101010101010101010101010101010101010101010101010101")
    let keyG = hexToBytes("0202020202020202020202020202020202020202020202020202020202020202")
    let nonce = hexToBytes("030303030303030303030303030303030303030303030303")
    let msg = toBytes("xchacha20 gimli short tag")
    let state = buildState(keyX, keyG, nonce, 16'u16)
    let cipher = encrypt(msg, state)
    check cipher.hmac.len == 16
    let plain = decrypt(cipher, state)
    check plain == msg
