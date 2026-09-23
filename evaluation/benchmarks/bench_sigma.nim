# ============================================================
# | Sigma Benchmark Test                                    |
# | -> Compare custom crypto performance                    |
# ============================================================

import std/[monotimes, unittest]

import ../../src/tyr/hashes/blake3
import ../../src/tyr/ciphers/gimli
import ../../src/tyr/ciphers/gimli_sponge
import ../../src/tyr/ciphers/xchacha20
import ../../src/tyr/ciphers/chacha/xchacha20_simd
import ../../src/tyr/ciphers/aes_ctr
import otter_repo_evaluation

const
  benchBytes = 2048
  loops = 1_000_000

type
  AlgoKind = enum
    akBlake3Xof,
    akGimliXof,
    akXChaCha20,
    akXChaCha20Sse2,
    akXChaCha20Avx2,
    akAesCtrScalar,
    akAesCtrSse2,
    akAesCtrAvx2,
    akGimli,
    akGimliSse,
    akGimliSse4x,
    akGimliAvx8x,
    akBlake3Sse4,
    akBlake3Avx8

  BenchJob = object
    algo: AlgoKind
    totalTicks: int64
    avgTicks: int64

const
  algoNames: array[AlgoKind, string] = [
    "blake3_xof",
    "gimli_xof",
    "xchacha20",
    "xchacha20_sse2",
    "xchacha20_avx2",
    "aes_ctr_scalar",
    "aes_ctr_sse2",
    "aes_ctr_avx2",
    "gimli",
    "gimli_sse",
    "gimli_sse4x",
    "gimli_avx8x",
    "blake3_sse4",
    "blake3_avx8"
  ]

var
  benchInput: array[benchBytes, byte] = default(array[benchBytes, byte])
  benchKey32: array[32, byte] = default(array[32, byte])
  benchNonce24: array[24, byte] = default(array[24, byte])
  benchAesNonce16: array[16, byte] = default(array[16, byte])
  baseState: Gimli_Block = default(Gimli_Block)
  baseCv: Blake3Cv = default(Blake3Cv)
  baseBlock: Blake3Block = default(Blake3Block)

proc fillPattern(bs: var openArray[byte], start: int = 0) =
  var i: int = 0
  i = 0
  while i < bs.len:
    bs[i] = byte((start + i) and 0xff)
    i = i + 1

proc initBenchData() =
  fillPattern(benchInput, 0)
  fillPattern(benchKey32, 0x10)
  fillPattern(benchNonce24, 0x40)
  var ni: int = 0
  ni = 0
  while ni < benchAesNonce16.len:
    benchAesNonce16[ni] = benchNonce24[ni]
    ni = ni + 1
  baseState = [
    0x00010203'u32, 0x04050607'u32, 0x08090a0b'u32, 0x0c0d0e0f'u32,
    0x10111213'u32, 0x14151617'u32, 0x18191a1b'u32, 0x1c1d1e1f'u32,
    0x20212223'u32, 0x24252627'u32, 0x28292a2b'u32, 0x2c2d2e2f'u32
  ]
  var i: int = 0
  i = 0
  while i < 8:
    baseCv[i] = 0x6a09e667'u32 + uint32(i)
    i = i + 1
  i = 0
  while i < 16:
    baseBlock[i] = 0x01020304'u32 + uint32(i) * 0x01010101'u32
    i = i + 1

include "bench_sigma_algorithms.nim"
proc makeJobs(): seq[BenchJob] =
  var jobs: seq[BenchJob] = @[]
  proc addJob(kind: AlgoKind) =
    jobs.add(BenchJob(algo: kind))
  addJob(akBlake3Xof)
  addJob(akGimliXof)
  addJob(akXChaCha20)
  when defined(sse2):
    addJob(akXChaCha20Sse2)
  when defined(avx2):
    addJob(akXChaCha20Avx2)
  addJob(akAesCtrScalar)
  when defined(sse2):
    addJob(akAesCtrSse2)
  when defined(avx2):
    addJob(akAesCtrAvx2)
  addJob(akGimli)
  when declared(gimliPermuteSse):
    addJob(akGimliSse)
  when declared(gimliPermuteSse4x):
    addJob(akGimliSse4x)
  when declared(gimliPermuteAvx8x):
    addJob(akGimliAvx8x)
  when declared(blake3CompressSse4):
    addJob(akBlake3Sse4)
  when declared(blake3CompressAvx8):
    addJob(akBlake3Avx8)
  result = jobs

proc benchThread(arg: ptr BenchJob) {.thread.} =
  var
    i: int = 0
    start = getMonoTime()
    stop: MonoTime = start
  i = 0
  while i < loops:
    runAlgo(arg.algo)
    i = i + 1
  stop = getMonoTime()
  arg.totalTicks = stop.ticks - start.ticks
  if loops > 0:
    arg.avgTicks = arg.totalTicks div loops


include "bench_sigma_suite.nim"
