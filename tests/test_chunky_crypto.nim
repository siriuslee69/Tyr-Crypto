import std/unittest
import std/os

import ../src/tyr_crypto/chunkyCrypto
import ../src/tyr_crypto/wrapper/crypto
import ../src/tyr_crypto/chunkyCrypto/level1/nonce_ops
import ./helpers

proc writeBytes(p: string, bs: seq[uint8]) =
  var
    f: File
  if not open(f, p, fmWrite):
    raise newException(IOError, "failed to open output file")
  try:
    if bs.len > 0 and f.writeBuffer(unsafeAddr bs[0], bs.len) != bs.len:
      raise newException(IOError, "failed to write output bytes")
  finally:
    close(f)

proc readBytes(p: string): seq[uint8] =
  let s = readFile(p)
  result = newSeq[uint8](s.len)
  for i, ch in s:
    result[i] = uint8(ord(ch))

proc removeTree(p: string) =
  if not dirExists(p):
    return
  for entry in walkDir(p, relative = false):
    if entry.kind == pcFile:
      removeFile(entry.path)
    elif entry.kind == pcDir:
      removeTree(entry.path)
  if dirExists(p):
    removeDir(p)

proc buildState(keyX, keyA, keyG, nonce: seq[uint8]): EncryptionState =
  var s: EncryptionState
  s.algoType = xchacha20AesGimli
  s.keys = @[
    Key(key: keyX, keyType: isSym),
    Key(key: keyA, keyType: isSym),
    Key(key: keyG, keyType: isSym)
  ]
  s.nonce = nonce
  s.tagLen = 64'u16
  result = s

suite "chunky crypto":
  test "encrypt/decrypt roundtrip":
    let tmpDir = joinPath(getTempDir(), "tyr_chunky_crypto_" & $getCurrentProcessId())
    if dirExists(tmpDir):
      removeTree(tmpDir)
    createDir(tmpDir)
    defer:
      removeTree(tmpDir)
    let inputPath = joinPath(tmpDir, "input.bin")
    let chunkDir = joinPath(tmpDir, "chunks")
    let outputPath = joinPath(tmpDir, "output.bin")
    var data = newSeq[uint8](256 * 1024)
    for i in 0 ..< data.len:
      data[i] = uint8((i * 17) mod 251)
    writeBytes(inputPath, data)

    let keyX = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    let keyA = hexToBytes("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100")
    let keyG = hexToBytes("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
    let nonce = hexToBytes("000102030405060708090a0b0c0d0e0f1011121314151617")
    let state = buildState(keyX, keyA, keyG, nonce)
    var opt = initChunkyOptions()
    opt.chunkBytes = 64 * 1024
    opt.bufferBytes = 4096
    opt.outputDir = chunkDir
    opt.maxThreads = 2
    let manifest = encryptFileChunks(inputPath, chunkDir, state, opt)
    decryptFileChunks(manifest, chunkDir, outputPath, state, opt)
    let outBytes = readBytes(outputPath)
    check outBytes == data

  test "tag mismatch rejects":
    let tmpDir = joinPath(getTempDir(), "tyr_chunky_crypto_tag_" & $getCurrentProcessId())
    if dirExists(tmpDir):
      removeTree(tmpDir)
    createDir(tmpDir)
    defer:
      removeTree(tmpDir)
    let inputPath = joinPath(tmpDir, "input.bin")
    let chunkDir = joinPath(tmpDir, "chunks")
    let outputPath = joinPath(tmpDir, "output.bin")
    let data = toBytes("chunky crypto tamper test")
    writeBytes(inputPath, data)

    let keyX = hexToBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000000000000000000000000000")
    let keyA = hexToBytes("00000000000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    let keyG = hexToBytes("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbcccccccccccccccccccccccccccccccc")
    let nonce = hexToBytes("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    let state = buildState(keyX, keyA, keyG, nonce)
    var opt = initChunkyOptions()
    opt.chunkBytes = 1024
    opt.bufferBytes = 256
    opt.outputDir = chunkDir
    let manifest = encryptFileChunks(inputPath, chunkDir, state, opt)
    let chunkPath = joinPath(chunkDir, manifest.chunkFiles[0])
    var f: File
    if open(f, chunkPath, fmReadWrite):
      let sz = getFileSize(chunkPath)
      if sz > 0:
        setFilePos(f, sz - 1)
        var b: array[1, uint8]
        b[0] = 0'u8
        discard f.writeBuffer(addr b[0], 1)
      close(f)
    expect IOError:
      decryptFileChunks(manifest, chunkDir, outputPath, state, opt)

  test "nonce derivation differs":
    let base = hexToBytes("000102030405060708090a0b0c0d0e0f1011121314151617")
    var bArr: array[24, uint8]
    for i in 0 ..< bArr.len:
      bArr[i] = base[i]
    let n0 = deriveChunkNonce(bArr, 0'u64)
    let n1 = deriveChunkNonce(bArr, 1'u64)
    check n0 != n1

  test "chunk hash deterministic":
    let tmpDir = joinPath(getTempDir(), "tyr_chunky_crypto_hash_" & $getCurrentProcessId())
    if dirExists(tmpDir):
      removeTree(tmpDir)
    createDir(tmpDir)
    defer:
      removeTree(tmpDir)
    let inputPath = joinPath(tmpDir, "input.bin")
    var data = newSeq[uint8](8192)
    for i in 0 ..< data.len:
      data[i] = uint8(i mod 251)
    writeBytes(inputPath, data)
    var opt = initChunkyOptions()
    opt.chunkBytes = 2048
    opt.bufferBytes = 512
    let h0 = hashFileChunks(inputPath, opt, haBlake3Tree)
    let h1 = hashFileChunks(inputPath, opt, haBlake3Tree)
    check h0.len == 32
    check h0 == h1
