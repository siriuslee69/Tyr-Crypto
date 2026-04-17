## ============================================================
## | Sigma Blake3/ChaCha Compare                             |
## | -> Compare Tyr crypto against available upstream libs   |
## ============================================================

import std/[dynlib, os, unittest]

import ../src/protocols/custom_crypto/[blake3, chacha20, xchacha20, xchacha20_simd]
import ../src/protocols/bindings/libsodium
import sigma_bench_and_eval

const
  benchBytes = 8 * 1024
  loops = 20_000
  warmup = 100
  opensslLibNames = when defined(windows):
                      @["libcrypto-3-x64.dll"]
                    elif defined(macosx):
                      @["libcrypto.3.dylib", "libcrypto.dylib"]
                    else:
                      @["libcrypto.so.3", "libcrypto.so"]

type
  AlgoKind = enum
    akTyrBlake3Hash,
    akTyrChaCha20Xor,
    akTyrXChaCha20Xor,
    akTyrXChaCha20SimdSse2,
    akTyrXChaCha20SimdAvx2,
    akLibsodiumXChaCha20Xor,
    akLibsodiumXChaCha20Stream,
    akOpenSslChaCha20

  OpenSslChaCha20Proc = proc (
    outBuf: ptr uint8,
    inBuf: ptr uint8,
    l: csize_t,
    key: ptr uint32,
    counter: ptr uint32
  ) {.cdecl.}

const
  algoNames: array[AlgoKind, string] = [
    "tyr_blake3_hash",
    "tyr_chacha20_xor",
    "tyr_xchacha20_xor",
    "tyr_xchacha20_simd_sse2",
    "tyr_xchacha20_simd_avx2",
    "libsodium_xchacha20_xor",
    "libsodium_xchacha20_stream",
    "openssl_chacha20"
  ]

var
  benchInput: array[benchBytes, byte]
  benchZero: array[benchBytes, byte]
  benchKey32: array[32, byte]
  benchNonce24: array[24, byte]
  benchNonce12: array[12, byte]
  workBuf: array[benchBytes, byte]
  streamBuf: array[benchBytes, byte]
  osslKeyWords: array[8, uint32]
  osslCounterWords: array[4, uint32]
  hasSodiumXCha: bool = false
  hasOpenSslChaCha: bool = false
  opensslHandle: LibHandle = nil
  opensslChaCha20: OpenSslChaCha20Proc = nil

proc fillPattern(bs: var openArray[byte], start: int = 0) =
  var
    i: int = 0
  i = 0
  while i < bs.len:
    bs[i] = byte((start + i) and 0xff)
    i = i + 1

proc load32Le(bs: openArray[byte], offset: int): uint32 =
  result =
    uint32(bs[offset]) or
    (uint32(bs[offset + 1]) shl 8) or
    (uint32(bs[offset + 2]) shl 16) or
    (uint32(bs[offset + 3]) shl 24)

proc appendCandidate(P: var seq[string], dirPath, fileName: string) =
  var
    p: string = ""
  p = joinPath(dirPath, fileName)
  if fileExists(p) or symlinkExists(p):
    P.add(p)

proc initBenchData() =
  var
    i: int = 0
  fillPattern(benchInput, 0x11)
  fillPattern(benchKey32, 0x29)
  fillPattern(benchNonce24, 0x53)
  i = 0
  while i < benchNonce12.len:
    benchNonce12[i] = benchNonce24[i]
    i = i + 1
  i = 0
  while i < osslKeyWords.len:
    osslKeyWords[i] = load32Le(benchKey32, i * 4)
    i = i + 1
  osslCounterWords[0] = 0'u32
  osslCounterWords[1] = load32Le(benchNonce12, 0)
  osslCounterWords[2] = load32Le(benchNonce12, 4)
  osslCounterWords[3] = load32Le(benchNonce12, 8)

proc initLibsodiumIfAvailable() =
  if ensureLibSodiumLoaded():
    ensureSodiumInitialised()
    hasSodiumXCha = true

proc initOpenSslChaChaIfAvailable() =
  var
    P: seq[string] = @[]
  for libName in opensslLibNames:
    appendCandidate(P, joinPath(getCurrentDir(), "build", "openssl", "install", "bin"), libName)
    appendCandidate(P, joinPath(getCurrentDir(), "build", "openssl", "install", "lib"), libName)
    appendCandidate(P, joinPath(parentDir(getCurrentDir()), "openssl", "build", "install", "bin"), libName)
    appendCandidate(P, joinPath(parentDir(getCurrentDir()), "openssl", "build", "install", "lib"), libName)
  for p in P:
    opensslHandle = loadLib(p)
    if opensslHandle != nil:
      break
  if opensslHandle == nil:
    for libName in opensslLibNames:
      opensslHandle = loadLib(libName)
      if opensslHandle != nil:
        break
  if opensslHandle == nil:
    return
  opensslChaCha20 = cast[OpenSslChaCha20Proc](symAddr(opensslHandle, "ChaCha20_ctr32"))
  if opensslChaCha20 != nil:
    hasOpenSslChaCha = true

proc resetWorkBuf() =
  copyMem(addr workBuf[0], unsafeAddr benchInput[0], benchBytes)

proc resetStreamBuf() =
  copyMem(addr streamBuf[0], unsafeAddr benchZero[0], benchBytes)

proc runAlgo(kind: AlgoKind) =
  case kind
  of akTyrBlake3Hash:
    discard blake3Hash(benchInput)
  of akTyrChaCha20Xor:
    resetWorkBuf()
    chacha20XorInPlace(benchKey32, benchNonce12, 0'u32, workBuf)
  of akTyrXChaCha20Xor:
    resetWorkBuf()
    xchacha20XorInPlace(benchKey32, benchNonce24, 0'u32, workBuf)
  of akTyrXChaCha20SimdSse2:
    discard xchacha20StreamSimd(benchKey32, benchNonce24, benchBytes, 0'u32, xcbSse2)
  of akTyrXChaCha20SimdAvx2:
    discard xchacha20StreamSimd(benchKey32, benchNonce24, benchBytes, 0'u32, xcbAvx2)
  of akLibsodiumXChaCha20Xor:
    resetWorkBuf()
    discard crypto_stream_xchacha20_xor(addr workBuf[0], addr workBuf[0],
      culonglong(benchBytes), addr benchNonce24[0], addr benchKey32[0])
  of akLibsodiumXChaCha20Stream:
    resetStreamBuf()
    discard crypto_stream_xchacha20(addr streamBuf[0], culonglong(benchBytes),
      addr benchNonce24[0], addr benchKey32[0])
  of akOpenSslChaCha20:
    resetWorkBuf()
    opensslChaCha20(addr workBuf[0], addr workBuf[0], csize_t(benchBytes),
      addr osslKeyWords[0], addr osslCounterWords[0])

proc makeBenchAlgos(): seq[BenchAlgo] =
  result.add(BenchAlgo(name: algoNames[akTyrBlake3Hash], run: proc () =
    runAlgo(akTyrBlake3Hash)
  ))
  result.add(BenchAlgo(name: algoNames[akTyrChaCha20Xor], run: proc () =
    runAlgo(akTyrChaCha20Xor)
  ))
  result.add(BenchAlgo(name: algoNames[akTyrXChaCha20Xor], run: proc () =
    runAlgo(akTyrXChaCha20Xor)
  ))
  when defined(sse2):
    result.add(BenchAlgo(name: algoNames[akTyrXChaCha20SimdSse2], run: proc () =
      runAlgo(akTyrXChaCha20SimdSse2)
    ))
  when defined(avx2):
    result.add(BenchAlgo(name: algoNames[akTyrXChaCha20SimdAvx2], run: proc () =
      runAlgo(akTyrXChaCha20SimdAvx2)
    ))
  if hasSodiumXCha:
    result.add(BenchAlgo(name: algoNames[akLibsodiumXChaCha20Xor], run: proc () =
      runAlgo(akLibsodiumXChaCha20Xor)
    ))
    result.add(BenchAlgo(name: algoNames[akLibsodiumXChaCha20Stream], run: proc () =
      runAlgo(akLibsodiumXChaCha20Stream)
    ))
  if hasOpenSslChaCha:
    result.add(BenchAlgo(name: algoNames[akOpenSslChaCha20], run: proc () =
      runAlgo(akOpenSslChaCha20)
    ))

suite "Sigma Blake3/ChaCha compare":
  test "benchmark Tyr against available upstream crypto":
    var
      A: seq[BenchAlgo] = @[]
      R: seq[BenchResult] = @[]
    initBenchData()
    initLibsodiumIfAvailable()
    initOpenSslChaChaIfAvailable()
    A = makeBenchAlgos()
    check A.len >= 3
    R = compareAlgorithms(A, loops = loops, warmup = warmup)
    check R.len == A.len
    echo "bench_bytes=", benchBytes, " loops=", loops
    echo "libsodium_xchacha20=", hasSodiumXCha
    echo "openssl_chacha20=", hasOpenSslChaCha
    echo formatBenchResults(R)
