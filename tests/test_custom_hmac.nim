import std/unittest
import ../src/protocols/custom_crypto/[hmac, blake3]
import ./helpers

proc blake3ManualHashHmac(key, msg: openArray[byte], blockLen, outLen: int): seq[byte] =
  var
    normalizedKey: seq[byte] = @[]
    innerKey: seq[byte] = @[]
    outerKey: seq[byte] = @[]
    innerInput: seq[byte] = @[]
    outerInput: seq[byte] = @[]
    mac: seq[byte] = @[]
  normalizedKey = normalizeHmacKeyWithHash(key, blockLen, outLen, blake3Hash)
  innerKey = applyHmacConst(normalizedKey, hmacConstA)
  outerKey = applyHmacConst(normalizedKey, hmacConstB)
  innerInput = @[]
  innerInput.add(innerKey)
  innerInput.add(msg)
  mac = blake3Hash(innerInput, outLen)
  outerInput = @[]
  outerInput.add(outerKey)
  outerInput.add(mac)
  result = blake3Hash(outerInput, outLen)

proc blake3ManualKeyedHmac(key, msg: openArray[byte], blockLen, outLen: int): seq[byte] =
  var
    normalizedKey: seq[byte] = @[]
    innerKeyMaterial: seq[byte] = @[]
    outerKeyMaterial: seq[byte] = @[]
    innerKey: seq[byte] = @[]
    outerKey: seq[byte] = @[]
    mac: seq[byte] = @[]
  normalizedKey = normalizeHmacKeyWithHash(key, blockLen, outLen, blake3Hash)
  innerKeyMaterial = applyHmacConst(normalizedKey, hmacConstA)
  outerKeyMaterial = applyHmacConst(normalizedKey, hmacConstB)
  innerKey = prepareKeyedHmacKey(innerKeyMaterial, 32, blake3Hash)
  outerKey = prepareKeyedHmacKey(outerKeyMaterial, 32, blake3Hash)
  mac = blake3KeyedHash(innerKey, msg, outLen)
  result = blake3KeyedHash(outerKey, mac, outLen)

suite "custom hmac":
  test "blake3 custom hmac from hash matches explicit two-pass formula":
    var
      key: seq[byte] = @[]
      msg: seq[byte] = @[]
      expected: seq[byte] = @[]
      actual: seq[byte] = @[]
    key = hexToBytes("00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f")
    msg = toBytes("custom hmac formula over plain blake3")
    expected = blake3ManualHashHmac(key, msg, blake3HmacBlockLen, 32)
    actual = customHmacFromHash(key, msg, blake3HmacBlockLen, 32, blake3Hash)
    check actual == expected

  test "blake3 custom hmac from keyed hash matches explicit two-pass formula":
    var
      key: seq[byte] = @[]
      msg: seq[byte] = @[]
      expected: seq[byte] = @[]
      actual: seq[byte] = @[]
      wrapped: seq[byte] = @[]
    key = hexToBytes("8899aabbccddeeff0011223344556677102132435465768798a9bacbdcedfe0f")
    msg = toBytes("custom hmac formula over keyed blake3")
    expected = blake3ManualKeyedHmac(key, msg, blake3HmacBlockLen, 32)
    actual = customHmacFromKeyedHash(key, msg, blake3HmacBlockLen, 32,
      proc(k, input: openArray[byte], l: int): seq[byte] =
        blake3KeyedHash(k, input, l),
      blake3Hash, 32)
    wrapped = blake3CustomHmac(key, msg, 32)
    check actual == expected
    check wrapped == expected

  test "long key is reduced and padded to the block length":
    var
      key: seq[byte] = @[]
      i: int = 0
      normalizedHash: seq[byte] = @[]
      derivedFixedKey: seq[byte] = @[]
      tag: seq[byte] = @[]
    key = newSeq[byte](100)
    i = 0
    while i < key.len:
      key[i] = byte((i * 17) and 0xff)
      i = i + 1
    normalizedHash = normalizeHmacKeyWithHash(key, blake3HmacBlockLen, 32, blake3Hash)
    derivedFixedKey = prepareKeyedHmacKey(applyHmacConst(normalizedHash, hmacConstA),
      32, blake3Hash)
    tag = blake3CustomHmac(key, toBytes("long key path"), 32)
    check normalizedHash.len == blake3HmacBlockLen
    check derivedFixedKey.len == 32
    check normalizedHash != newSeq[byte](blake3HmacBlockLen)
    check derivedFixedKey != newSeq[byte](32)
    check tag.len == 32

  test "gimli custom hmac is deterministic and reacts to constants":
    var
      key: seq[byte] = @[]
      msg: seq[byte] = @[]
      a: seq[byte] = @[]
      b: seq[byte] = @[]
      c: seq[byte] = @[]
    key = hexToBytes("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
    msg = toBytes("gimli hmac lane")
    a = gimliCustomHmac(key, msg, 16)
    b = gimliCustomHmac(key, msg, 16)
    c = gimliCustomHmac(key, msg, 16, gimliHmacBlockLen, 0x11'u8, 0x22'u8)
    check a == b
    check a.len == 16
    check a != c
