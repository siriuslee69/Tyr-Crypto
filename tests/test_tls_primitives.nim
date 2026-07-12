import std/[strutils, unittest]
import metaPragmas
import ../src/protocols/custom_crypto/sha256
import ./helpers

proc repeatedByte(b: byte, n: int): seq[byte] {.role: {helper}.} =
  ## b/n: byte value and output length for fixed test-vector inputs.
  result = newSeq[byte](n)
  for i in 0 ..< n:
    result[i] = b

suite "TLS foundation primitives":
  test "SHA-256 supports one-shot, incremental, and cloned transcript state":
    var
      S: Sha256Context = initSha256()
      T: Sha256Context
      abc: seq[byte] = toBytes("abc")
      expected: seq[byte] = hexToBytes(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    S.updateSha256(abc.toOpenArray(0, 0))
    T = S
    S.updateSha256(abc.toOpenArray(1, 2))
    T.updateSha256(abc.toOpenArray(1, 2))
    check @(sha256Hash(abc)) == expected
    check @(S.finishSha256()) == expected
    check S.finishSha256() == T.finishSha256()

  test "SHA-256 handles empty and padding-boundary messages":
    var
      emptyExpected: seq[byte] = hexToBytes(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
      bytes55: seq[byte] = repeatedByte(byte('a'), 55)
      bytes56: seq[byte] = repeatedByte(byte('a'), 56)
      bytes64: seq[byte] = repeatedByte(byte('a'), 64)
    check @(sha256Hash(@[])) == emptyExpected
    check @(sha256Hash(bytes55)) == hexToBytes(
      "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318")
    check @(sha256Hash(bytes56)) == hexToBytes(
      "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a")
    check @(sha256Hash(bytes64)) == hexToBytes(
      "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb")

  test "HMAC-SHA-256 matches RFC 4231 case one":
    var
      key: seq[byte] = newSeq[byte](20)
      expected: seq[byte] = hexToBytes(
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
      i: int = 0
    while i < key.len:
      key[i] = 0x0b'u8
      i = i + 1
    check @(hmacSha256(key, toBytes("Hi There"))) == expected

  test "HMAC-SHA-256 reduces keys longer than one block":
    var
      key: seq[byte] = repeatedByte(0xaa'u8, 131)
      expected: seq[byte] = hexToBytes(
        "60e431591ee0b67f0d8a26aacbf5b77f" &
        "8e0bc6213728c5140546040f0ee37f54")
    check @(hmacSha256(key,
      toBytes("Test Using Larger Than Block-Size Key - Hash Key First"))) == expected

  test "HKDF-SHA-256 matches RFC 5869 case one":
    var
      ikm: seq[byte] = newSeq[byte](22)
      salt: seq[byte] = hexToBytes("000102030405060708090a0b0c")
      info: seq[byte] = hexToBytes("f0f1f2f3f4f5f6f7f8f9")
      prkExpected: seq[byte] = hexToBytes(
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
      okmExpected: seq[byte] = hexToBytes(
        "3cb25f25faacd57a90434f64d0362f2a" &
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf" & "34007208d5b887185865")
      i: int = 0
      prk: Sha256Digest
    while i < ikm.len:
      ikm[i] = 0x0b'u8
      i = i + 1
    prk = hkdfSha256Extract(salt, ikm)
    check @prk == prkExpected
    check hkdfSha256Expand(prk, info, 42) == okmExpected

  test "HKDF rejects invalid bounds and frames TLS labels exactly":
    var
      secret: seq[byte] = repeatedByte(0x11'u8, 32)
      context: seq[byte] = @[byte 0xaa, 0xbb]
      info: seq[byte] = @[byte 0x00, 0x10, 0x0a]
    info.add(toBytes("tls13 test"))
    info.add(byte(context.len))
    info.add(context)
    check hkdfExpandLabelSha256(secret, "test", context, 16) ==
      hkdfSha256Expand(secret, info, 16)
    expect(ValueError):
      discard hkdfSha256Expand(newSeq[byte](31), @[], 1)
    expect(ValueError):
      discard hkdfSha256Expand(secret, @[], 255 * sha256DigestBytes + 1)
    expect(ValueError):
      discard hkdfExpandLabelSha256(secret, repeat("x", 250), @[], 16)
