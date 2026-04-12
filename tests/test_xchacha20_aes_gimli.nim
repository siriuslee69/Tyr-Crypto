import std/unittest
import ../src/protocols/wrapper/algorithms
import ../src/protocols/wrapper/suite_api
import ./helpers

proc buildState(keyX, keyA, keyG, nonce: seq[uint8], tagLen: uint16): SymAuthState =
  result = initSymAuthState(csXChaCha20AesGimli, @[keyX, keyA, keyG], nonce, tagLen)

suite "xchacha20 aes gimli":
  test "encrypt/decrypt roundtrip":
    let keyX = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    let keyA = hexToBytes("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100")
    let keyG = hexToBytes("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
    let nonce = hexToBytes("000102030405060708090a0b0c0d0e0f1011121314151617")
    var msg = newSeq[uint8](128)
    for i in 0 ..< msg.len:
      msg[i] = uint8((i * 13) mod 256)
    let state = buildState(keyX, keyA, keyG, nonce, 64'u16)
    let cipher = symAuthEnc(msg, state)
    check cipher.authType == atGimli
    check cipher.auth.len == 64
    let plain = symAuthDec(cipher, state)
    check plain == msg

  test "tag mismatch rejects":
    let keyX = hexToBytes("ffffffffffffffffffffffffffffffff00000000000000000000000000000000")
    let keyA = hexToBytes("00000000000000000000000000000000ffffffffffffffffffffffffffffffff")
    let keyG = hexToBytes("1111111111111111111111111111111122222222222222222222222222222222")
    let nonce = hexToBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    let msg = toBytes("xchacha20 aes gimli tag check")
    let state = buildState(keyX, keyA, keyG, nonce, 64'u16)
    var cipher = symAuthEnc(msg, state)
    cipher.auth[0] = cipher.auth[0] xor 0x1'u8
    expect ValueError:
      discard symAuthDec(cipher, state)

  test "wrong key rejects":
    let keyX = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    let keyA = hexToBytes("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100")
    let keyG = hexToBytes("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
    let nonce = hexToBytes("000102030405060708090a0b0c0d0e0f1011121314151617")
    let msg = toBytes("xchacha20 aes gimli wrong key")
    let state = buildState(keyX, keyA, keyG, nonce, 64'u16)
    let cipher = symAuthEnc(msg, state)
    var wrongKeyG = keyG
    wrongKeyG[0] = wrongKeyG[0] xor 0xff'u8
    let wrongState = buildState(keyX, keyA, wrongKeyG, nonce, 64'u16)
    expect ValueError:
      discard symAuthDec(cipher, wrongState)
