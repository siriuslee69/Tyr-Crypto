import std/unittest
import ../src/protocols/custom_crypto/[blake3, xchacha20, gimli_sponge]
import ./helpers

suite "custom crypto":
  test "BLAKE3 empty message vector":
    let expected = hexToBytes("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
    check blake3Hash(@[]) == expected

  test "BLAKE3 'abc' vector":
    let expected = hexToBytes("6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85")
    let input = @[byte('a'), byte('b'), byte('c')]
    check blake3Hash(input) == expected

  test "BLAKE3 extendable output prefix":
    let expected = hexToBytes("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
    let extended = blake3Hash(@[], outLen = 65)
    check extended.len == 65
    check extended[0 ..< expected.len] == expected

  test "BLAKE3 keyed mode vector locks little-endian word handling":
    let
      key = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      msg = @[byte('a'), byte('b'), byte('c')]
      expected = hexToBytes("6da54495d8152f2bcba87bd7282df70901cdb66b4448ed5f4c7bd2852b8b5532")
    check blake3KeyedHash(key, msg) == expected

  test "HChaCha20 matches libsodium vector":
    let key = hexToBytes("24f11cce8a1b3d61e441561a696c1c1b7e173d084fd4812425435a8896a013dc")
    let nonce = hexToBytes("d9660c5900ae19ddad28d6e06e45fe5e")
    let expected = hexToBytes("5966b3eec3bff1189f831f06afe4d4e3be97fa9235ec8c20d08acfbbb4e851e3")
    let outArr = hchacha20(key, nonce)
    var outSeq = newSeq[byte](outArr.len)
    for i, b in outArr:
      outSeq[i] = b
    check outSeq == expected

  test "XChaCha20 stream vector #1":
    let key = hexToBytes("79c99798ac67300bbb2704c95c341e3245f3dcb21761b98e52ff45b24f304fc4")
    let nonce = hexToBytes("b33ffd3096479bcfbc9aee49417688a0a2554f8d95389419")
    let expected = hexToBytes("c6e9758160083ac604ef90e712ce6e75d7797590744e0cf060f013739c")
    let stream = xchacha20Stream(key, nonce, expected.len)
    check stream == expected

    let decrypted = xchacha20Xor(key, nonce, expected)
    check decrypted == newSeq[byte](expected.len)

  test "XChaCha20 stream vector #4":
    let key = hexToBytes("5f5763ff9a30c95da5c9f2a8dfd7cc6efd9dfb431812c075aa3e4f32e04f53e4")
    let nonce = hexToBytes("a5fa890efa3b9a034d377926ce0e08ee6d7faccaee41b771")
    let expected = hexToBytes("8a1a5ba898bdbcff602b1036e469a18a5e45789d0e8d9837d81a2388a52b0b6a0f51891528f424c4a7f492a8dd7bce8bac19fbdbe1fb379ac0")
    let stream = xchacha20Stream(key, nonce, expected.len)
    check stream == expected

  test "Gimli XOF vector locks little-endian absorb and squeeze":
    let expected = hexToBytes("69278f88816d44133aa1cbfaa56e3364ea39f11784843ac008472aa6508001c5")
    check gimliXof(@[byte 1, 2, 3], @[byte 4, 5], @[byte 6, 7, 8, 9], 32) == expected
