import std/[base64, strutils, unittest]
import ../src/protocols/custom_crypto/[argon2, blake3, chacha20, xchacha20, gimli_sponge, kdf]
import ./crypto_vectors
import ./helpers

type
  ParsedArgonVector = object
    algorithm: Argon2Algorithm
    passCount: int
    memoryKiB: int
    laneCount: int
    salt: seq[byte]
    rawHash: seq[byte]


proc decodeArgonBase64(s: string): seq[byte] =
  var
    padded: string = s
  while (padded.len mod 4) != 0:
    padded.add('=')
  result = toBytes(decode(padded))


proc parseTaggedInt(s, prefix: string): int =
  if not s.startsWith(prefix):
    raise newException(ValueError, "invalid Argon2 field: " & s)
  result = parseInt(s[prefix.len .. ^1])


proc parseArgonAlgorithm(s: string): Argon2Algorithm =
  if s == "argon2i":
    return a2Argon2i
  if s == "argon2id":
    return a2Argon2id
  raise newException(ValueError, "unsupported Argon2 type: " & s)


proc parseArgonVector(encoded: string): ParsedArgonVector =
  var
    parts: seq[string] = encoded.split('$')
    params: seq[string] = @[]
  if parts.len != 6 or parts[0].len != 0:
    raise newException(ValueError, "invalid encoded Argon2 string")
  result.algorithm = parseArgonAlgorithm(parts[1])
  if parts[2] != "v=19":
    raise newException(ValueError, "unsupported Argon2 version")
  params = parts[3].split(',')
  if params.len != 3:
    raise newException(ValueError, "invalid encoded Argon2 parameter set")
  result.memoryKiB = parseTaggedInt(params[0], "m=")
  result.passCount = parseTaggedInt(params[1], "t=")
  result.laneCount = parseTaggedInt(params[2], "p=")
  result.salt = decodeArgonBase64(parts[4])
  result.rawHash = decodeArgonBase64(parts[5])


proc deriveVectorHash(v: ParsedArgonVector, password: string): seq[byte] =
  var
    passwordBytes: seq[byte] = toBytes(password)
  case v.algorithm
  of a2Argon2i:
    result = argon2iHash(passwordBytes, v.salt, v.passCount, v.memoryKiB,
      v.laneCount, v.rawHash.len)
  of a2Argon2id:
    result = argon2idHash(passwordBytes, v.salt, v.passCount, v.memoryKiB,
      v.laneCount, v.rawHash.len)

proc tinyKdfGenerator(input: openArray[uint8], blockIndex: uint64,
    outLen: int): seq[uint8] =
  var
    i: int = 0
    seedByte: int = 0
  if input.len > 0:
    seedByte = int(input[0])
  result = newSeq[uint8](outLen)
  i = 0
  while i < outLen:
    result[i] = uint8((seedByte + int(blockIndex) * 17 + i) and 0xff)
    i = i + 1

suite "custom crypto":
  test "BLAKE3 empty message vector":
    let expected = hexToBytes("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
    check blake3Hash(@[]) == expected

  test "BLAKE3 'abc' vector":
    let expected = hexToBytes("6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85")
    let input = @[byte('a'), byte('b'), byte('c')]
    check blake3Hash(input) == expected

  test "BLAKE3 extendable output vector":
    let expected = hexToBytes(
      "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a26f5487789e8f660afe6c99ef9e0c52b92e7393024a80459cf91f476f9ffdbda7001c22e159b402631f277ca96f2defdf1078282314e763699a31c5363165421cce14d")
    check blake3Hash(@[], outLen = expected.len) == expected

  test "BLAKE3 keyed mode vector locks little-endian word handling":
    let
      key = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      msg = @[byte('a'), byte('b'), byte('c')]
      expected = hexToBytes("6da54495d8152f2bcba87bd7282df70901cdb66b4448ed5f4c7bd2852b8b5532")
    check blake3KeyedHash(key, msg) == expected

  test "BLAKE3 keyed extendable output vector":
    let
      key = toBytes("whats the Elvish word for friend")
      expected = hexToBytes(
        "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26b18171a2f22a4b94822c701f107153dba24918c4bae4d2945c20ece13387627d3b73cbf97b797d5e59948c7ef788f54372df45e45e4293c7dc18c1d41144a9758be58960856be1eabbe22c2653190de560ca3b2ac4aa692a9210694254c371e851bc8f")
    check blake3KeyedHash(key, @[], expected.len) == expected

  test "BLAKE3 derive-key modes compose through the standard helper":
    let
      context = toBytes("Tyr BLAKE3 derive-key test context")
      material = toBytes("input key material")
      contextKey = blake3Digest(context, b3mDeriveKeyContext)
      derived = blake3Digest(material, b3mDeriveKeyMaterial, contextKey, 64)
      officialContext = "BLAKE3 2019-12-27 16:29:52 test vectors context"
      officialExpected = hexToBytes(
        "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d905630c8be290dfcf3e6842f13bddd573c098c3f17361f1f206b8cad9d088aa4a3f746752c6b0ce6a83b0da81d59649257cdf8eb3e9f7d4998e41021fac119deefb896224ac99f860011f73609e6e0e4540f93b273e56547dfd3aa1a035ba6689d89a0")
    check contextKey.len == 32
    check derived.len == 64
    check blake3DeriveKey(context, material, 64) == derived
    check blake3DeriveKey("Tyr BLAKE3 derive-key test context", material, 64) == derived
    check blake3DeriveKey(officialContext, @[], officialExpected.len) == officialExpected
    expect ValueError:
      discard blake3Digest(context, b3mDeriveKeyContext, contextKey)

  test "ChaCha20 block and stream match RFC 8439 vector":
    let
      key = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      nonce = hexToBytes("000000090000004a00000000")
      expected = hexToBytes(
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e")
      blockBytes = chacha20Block(key, nonce, 1'u32)
    check toHex(blockBytes) == toHex(expected)
    check chacha20Stream(key, nonce, expected.len, 1'u32) == expected
    check chacha20Xor(key, nonce, 1'u32, newSeq[byte](expected.len)) == expected

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

  test "XChaCha20 refuses transforms that wrap the 32-bit block counter":
    let
      key = newSeq[byte](32)
      nonce = newSeq[byte](24)
      msg = newSeq[byte](65)
    check xchacha20Stream(key, nonce, 64, uint32.high).len == 64
    expect ValueError:
      discard xchacha20Stream(key, nonce, 65, uint32.high)
    expect ValueError:
      discard xchacha20Xor(key, nonce, uint32.high, msg)
    var inPlace = msg
    expect ValueError:
      xchacha20XorInPlace(key, nonce, uint32.high, inPlace)

  test "Gimli XOF vector locks little-endian absorb and squeeze":
    let expected = hexToBytes("69278f88816d44133aa1cbfaa56e3364ea39f11784843ac008472aa6508001c5")
    check gimliXof(@[byte 1, 2, 3], @[byte 4, 5], @[byte 6, 7, 8, 9], 32) == expected

  test "Gimli keyed tag and stream require sized key and nonce":
    let
      key = newSeq[byte](32)
      nonce = newSeq[byte](24)
      msg = toBytes("gimli sized inputs")
    check gimliTag(key, nonce, msg, 16).len == 16
    check gimliStreamXor(key, nonce, msg).len == msg.len
    expect ValueError:
      discard gimliTag(@[], nonce, msg, 16)
    expect ValueError:
      discard gimliStreamXor(key, @[], msg)

  test "Argon2i encoded vectors match the raw custom hash":
    var
      i: int = 0
      parsed: ParsedArgonVector
      outHash: seq[byte] = @[]
    i = 0
    while i < argon2iVectors.len:
      parsed = parseArgonVector(argon2iVectors[i].encoded)
      outHash = deriveVectorHash(parsed, argon2iVectors[i].password)
      check outHash == parsed.rawHash
      i = i + 1

  test "Argon2id encoded vectors match the raw custom hash":
    var
      i: int = 0
      parsed: ParsedArgonVector
      outHash: seq[byte] = @[]
    i = 0
    while i < argon2idVectors.len:
      if argon2idVectors[i].shouldPass:
        parsed = parseArgonVector(argon2idVectors[i].encoded)
        outHash = deriveVectorHash(parsed, argon2idVectors[i].password)
        check outHash == parsed.rawHash
      i = i + 1

  test "Argon2id false vectors reject invalid params or mismatch":
    var
      i: int = 0
      parsed: ParsedArgonVector
      outHash: seq[byte] = @[]
    i = 0
    while i < argon2idVectors.len:
      if not argon2idVectors[i].shouldPass:
        parsed = parseArgonVector(argon2idVectors[i].encoded)
        if parsed.passCount < 1:
          expect ValueError:
            discard deriveVectorHash(parsed, argon2idVectors[i].password)
        else:
          outHash = deriveVectorHash(parsed, argon2idVectors[i].password)
          check outHash != parsed.rawHash
      i = i + 1

  test "Argon2i and Argon2id stay deterministic and differ by mode":
    var
      salt: seq[byte] = toBytes(">A 16-bytes salt")
      passwordBytes: seq[byte] = toBytes("Correct Horse Battery Staple")
      p: Argon2Params
      hashI0: seq[byte] = @[]
      hashI1: seq[byte] = @[]
      hashId0: seq[byte] = @[]
      hashId1: seq[byte] = @[]
    p = initArgon2Params(3, 4096, 1, 32)
    hashI0 = argon2iHash(passwordBytes, salt, p)
    hashI1 = argon2iHash(passwordBytes, salt, p)
    hashId0 = argon2idHash(passwordBytes, salt, p)
    hashId1 = argon2idHash(passwordBytes, salt, p)
    check hashI0 == hashI1
    check hashId0 == hashId1
    check hashI0 != hashId0

  test "Argon2 rejects too-small salt and output lengths":
    expect ValueError:
      discard argon2idHash(toBytes("pw"), toBytes("short"), 2, 4096, 1, 32)
    expect ValueError:
      discard argon2idHash(toBytes("pw"), toBytes(">A 16-bytes salt"), 2, 4096, 1, 15)

  test "Custom KDF block index folds bytes evenly":
    var
      indexBlock: seq[byte] = @[]
    indexBlock = @[byte 1, 2, 3, 4, 5, 6, 7, 8,
      8, 7, 6, 5, 4, 3, 2, 1]
    check foldBlockToUint64(indexBlock) == 0x0905050101050509'u64
    check calcKdfBlockIndex(indexBlock, 17) == int(0x0905050101050509'u64 mod 17'u64)
    check calcKdfTargetBlockIndex(indexBlock, 64) == int(0x0905050101050509'u64 mod 48'u64)
    check calcKdfTargetBlockIndex(indexBlock, 64) < 48

  test "Custom KDF uses tail-indexed full-memory rounds":
    var
      p: CustomKdfParams
      seed: seq[byte] = @[]
      outBlock: seq[byte] = @[]
    p = initCustomKdfParams(1, 512, 2, 8)
    seed = @[byte 1]
    outBlock = deriveCustomKdf(seed, p, tinyKdfGenerator)
    check outBlock == @[byte 10, 11, 12, 13, 14, 15, 16, 17]

  test "Custom KDF built-in generators are wired":
    var
      seed: seq[byte] = @[]
      outBlock: seq[byte] = @[]
      repeatBlock: seq[byte] = @[]
      a: CustomKdfAlgorithm
    seed = toBytes("custom kdf seed")
    for alg in CustomKdfAlgorithm:
      a = alg
      outBlock = deriveCustomKdf(seed, a, 2, 1024, 3, 16)
      repeatBlock = deriveCustomKdf(seed, a, 2, 1024, 3, 16)
      check outBlock.len == 16
      check outBlock == repeatBlock

  test "Custom KDF rejects unusable parameters":
    expect ValueError:
      discard deriveCustomKdf(@[byte 1], ckaGimli, 1, 7, 1, 8)
    expect ValueError:
      discard deriveCustomKdf(@[byte 1], ckaGimli, 1, 64, 1, 9)
    expect ValueError:
      discard deriveCustomKdf(@[byte 1], ckaGimli, 1, 504, 1, 8)
