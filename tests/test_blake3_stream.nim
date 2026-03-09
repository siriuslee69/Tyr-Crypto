import std/[os, unittest]
import ../src/tyr_crypto/custom_crypto/blake3

suite "BLAKE3 streaming":
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
