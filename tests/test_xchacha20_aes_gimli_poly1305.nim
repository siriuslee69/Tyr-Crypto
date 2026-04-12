import std/unittest
import ../src/protocols/wrapper/algorithms
import ../src/protocols/wrapper/suite_api
import ../src/protocols/common
import ./helpers

proc buildPolyLayerState(keyX, keyA, keyG, keyP, nonce: seq[uint8],
    tagLen: uint16): SymAuthState =
  result = initSymAuthState(csXChaCha20AesGimliPoly1305,
    @[keyX, keyA, keyG, keyP], nonce, tagLen)

suite "xchacha20 aes gimli poly1305":
  when defined(hasLibsodium):
    test "encrypt/decrypt roundtrip":
      let keyX = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      let keyA = hexToBytes("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100")
      let keyG = hexToBytes("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
      let keyP = hexToBytes("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100")
      let nonce = hexToBytes("000102030405060708090a0b0c0d0e0f1011121314151617")
      var msg = newSeq[uint8](160)
      for i in 0 ..< msg.len:
        msg[i] = uint8((i * 17) mod 256)
      let state = buildPolyLayerState(keyX, keyA, keyG, keyP, nonce, 64'u16)
      let cipher = symAuthEnc(msg, state)
      check cipher.authType == atGimliPoly1305
      check cipher.auth.len == 80
      let plain = symAuthDec(cipher, state)
      check plain == msg

    test "tag mismatch rejects":
      let keyX = hexToBytes("ffffffffffffffffffffffffffffffff00000000000000000000000000000000")
      let keyA = hexToBytes("00000000000000000000000000000000ffffffffffffffffffffffffffffffff")
      let keyG = hexToBytes("1111111111111111111111111111111122222222222222222222222222222222")
      let keyP = hexToBytes("3333333333333333333333333333333344444444444444444444444444444444")
      let nonce = hexToBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
      let msg = toBytes("xchacha20 aes gimli poly1305 tag check")
      let state = buildPolyLayerState(keyX, keyA, keyG, keyP, nonce, 64'u16)
      var cipher = symAuthEnc(msg, state)
      cipher.auth[^1] = cipher.auth[^1] xor 0x1'u8
      expect ValueError:
        discard symAuthDec(cipher, state)

    test "wrong poly1305 key rejects":
      let keyX = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      let keyA = hexToBytes("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100")
      let keyG = hexToBytes("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
      let keyP = hexToBytes("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100")
      let nonce = hexToBytes("000102030405060708090a0b0c0d0e0f1011121314151617")
      let msg = toBytes("xchacha20 aes gimli poly1305 wrong key")
      let state = buildPolyLayerState(keyX, keyA, keyG, keyP, nonce, 64'u16)
      let cipher = symAuthEnc(msg, state)
      var wrongState = buildPolyLayerState(keyX, keyA, keyG, keyP, nonce, 64'u16)
      wrongState.keys[3][0] = wrongState.keys[3][0] xor 0xff'u8
      expect ValueError:
        discard symAuthDec(cipher, wrongState)
  else:
    test "libsodium unavailable raises descriptive error":
      let keyX = newSeq[uint8](32)
      let keyA = newSeq[uint8](32)
      let keyG = newSeq[uint8](32)
      let keyP = newSeq[uint8](32)
      let nonce = newSeq[uint8](24)
      let state = buildPolyLayerState(keyX, keyA, keyG, keyP, nonce, 64'u16)
      expect LibraryUnavailableError:
        discard symAuthEnc(toBytes("poly1305"), state)
