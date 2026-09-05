import std/[os, unittest]
import ../../src/tyr/hashes/blake3
import ./helpers

const
  officialBlake3BoundaryHashes = [
    (inputLen: 1023, hashHex: "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11"),
    (inputLen: 1024, hashHex: "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7"),
    (inputLen: 1025, hashHex: "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444"),
    (inputLen: 2048, hashHex: "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a"),
    (inputLen: 2049, hashHex: "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030")
  ]
  officialBlake3Key = "whats the Elvish word for friend"
  officialBlake3Context = "BLAKE3 2019-12-27 16:29:52 test vectors context"

proc officialBlake3Input(n: int): seq[byte] =
  ## n: official vector input length; bytes repeat from 0 through 250.
  var
    i: int = 0
  result = newSeq[byte](n)
  while i < n:
    result[i] = byte(i mod 251)
    i = i + 1

suite "BLAKE3 streaming":
  test "official vectors cover chunk and tree boundaries":
    var
      i: int = 0
      input: seq[byte] = @[]
      expected: seq[byte] = @[]
      s: Blake3Hasher
    while i < officialBlake3BoundaryHashes.len:
      input = officialBlake3Input(officialBlake3BoundaryHashes[i].inputLen)
      expected = hexToBytes(officialBlake3BoundaryHashes[i].hashHex)
      check blake3Hash(input) == expected
      s = initBlake3Hasher()
      updateBlake3(s, input.toOpenArray(0, 62))
      updateBlake3(s, input.toOpenArray(63, input.len - 1))
      check finalBlake3(s) == expected
      i = i + 1

  test "official keyed and derive-key modes cross one chunk":
    var
      input = officialBlake3Input(1025)
      key = toBytes(officialBlake3Key)
      keyedExpected = hexToBytes(
        "357dc55de0c7e382c900fd6e320acc04146be01db6a8ce7210b7189bd664ea69")
      deriveExpected = hexToBytes(
        "effaa245f065fbf82ac186839a249707c3bddf6d3fdda22d1b95a3c970379bcb")
    check blake3KeyedHash(key, input) == keyedExpected
    check blake3DeriveKey(officialBlake3Context, input) == deriveExpected

  test "stream matches one-shot":
    var
      bs: seq[byte] = @[]
      s: Blake3Hasher
      i: int = 0
      h0: seq[byte] = @[]
      h1: seq[byte] = @[]
    bs.setLen(4096)
    i = 0
    while i < bs.len:
      bs[i] = byte(i mod 251)
      i = i + 1
    h0 = blake3Hash(bs)
    s = initBlake3Hasher()
    updateBlake3(s, bs)
    h1 = finalBlake3(s)
    check h0 == h1
    expect ValueError:
      discard finalBlake3(s)
    expect ValueError:
      updateBlake3(s, @[byte 1])

  test "uninitialized state is rejected":
    var s: Blake3Hasher
    expect ValueError:
      updateBlake3(s, @[byte 1])
    expect ValueError:
      discard finalBlake3(s)

  test "file hash matches one-shot":
    var
      root: string = getTempDir() / "blake3_stream"
      path: string = root / "sample.bin"
      bs: seq[byte] = @[]
      h0: seq[byte] = @[]
      h1: seq[byte] = @[]
      i: int = 0
    createDir(root)
    bs.setLen(2048)
    i = 0
    while i < bs.len:
      bs[i] = byte((i * 13) mod 251)
      i = i + 1
    writeFile(path, bs)
    h0 = blake3Hash(bs)
    h1 = blake3HashFile(path)
    check h0 == h1
