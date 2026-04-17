# ============================================================
# | Sigma Benchmark Test                                    |
# | -> Compare custom crypto performance                    |
# ============================================================

import std/[monotimes, unittest]

import ../src/protocols/custom_crypto/[blake3, gimli, gimli_sponge, xchacha20,
  xchacha20_simd, aes_ctr]
import sigma_bench_and_eval

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
  benchInput: array[benchBytes, byte]
  benchKey32: array[32, byte]
  benchNonce24: array[24, byte]
  benchAesNonce16: array[16, byte]
  baseState: Gimli_Block
  baseCv: Blake3Cv
  baseBlock: Blake3Block

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

proc runAlgo(kind: AlgoKind) =
  case kind
  of akBlake3Xof:
    discard blake3Hash(benchInput, benchBytes)
  of akGimliXof:
    gimliXofDiscard(benchKey32, benchNonce24, benchInput, benchBytes)
  of akXChaCha20:
    discard xchacha20Xor(benchKey32, benchNonce24, benchInput)
  of akXChaCha20Sse2:
    discard xchacha20StreamSimd(benchKey32, benchNonce24, benchBytes, b = xcbSse2)
  of akXChaCha20Avx2:
    discard xchacha20StreamSimd(benchKey32, benchNonce24, benchBytes, b = xcbAvx2)
  of akAesCtrScalar:
    discard aesCtrXor(benchKey32, benchAesNonce16, benchInput, acbScalar)
  of akAesCtrSse2:
    discard aesCtrXor(benchKey32, benchAesNonce16, benchInput, acbSse2)
  of akAesCtrAvx2:
    discard aesCtrXor(benchKey32, benchAesNonce16, benchInput, acbAvx2)
  of akGimli:
    var s = baseState
    gimliPermute(s)
  of akGimliSse:
    when declared(gimliPermuteSse):
      var s = baseState
      gimliPermuteSse(s)
    else:
      discard
  of akGimliSse4x:
    when declared(gimliPermuteSse4x):
      var ss: array[4, Gimli_Block]
      var i: int = 0
      i = 0
      while i < ss.len:
        ss[i] = baseState
        i = i + 1
      gimliPermuteSse4x(ss)
    else:
      discard
  of akGimliAvx8x:
    when declared(gimliPermuteAvx8x):
      var ss: array[8, Gimli_Block]
      var i: int = 0
      i = 0
      while i < ss.len:
        ss[i] = baseState
        i = i + 1
      gimliPermuteAvx8x(ss)
    else:
      discard
  of akBlake3Sse4:
    when declared(blake3CompressSse4):
      var cvs: array[4, Blake3Cv]
      var blocks: array[4, Blake3Block]
      var i: int = 0
      i = 0
      while i < cvs.len:
        cvs[i] = baseCv
        blocks[i] = baseBlock
        i = i + 1
      discard blake3CompressSse4(cvs, blocks, 0'u64, 64'u32, 0'u32)
    else:
      discard
  of akBlake3Avx8:
    when declared(blake3CompressAvx8):
      var cvs: array[8, Blake3Cv]
      var blocks: array[8, Blake3Block]
      var i: int = 0
      i = 0
      while i < cvs.len:
        cvs[i] = baseCv
        blocks[i] = baseBlock
        i = i + 1
      discard blake3CompressAvx8(cvs, blocks, 0'u64, 64'u32, 0'u32)
    else:
      discard

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
  var i: int = 0
  let start = getMonoTime()
  i = 0
  while i < loops:
    runAlgo(arg.algo)
    i = i + 1
  let stop = getMonoTime()
  arg.totalTicks = stop.ticks - start.ticks
  if loops > 0:
    arg.avgTicks = arg.totalTicks div loops

suite "Sigma performance":
  test "compare crypto throughput over several thousand loops":
    initBenchData()

    when compileOption("threads"):
      var jobs = makeJobs()
      var threads: seq[Thread[ptr BenchJob]] = @[]
      threads.setLen(jobs.len)
      var i: int = 0
      i = 0
      while i < jobs.len:
        createThread(threads[i], benchThread, addr jobs[i])
        i = i + 1
      i = 0
      while i < threads.len:
        joinThread(threads[i])
        i = i + 1

      var results: seq[BenchResult] = @[]
      results.setLen(jobs.len)
      i = 0
      while i < jobs.len:
        results[i] = BenchResult(
          name: algoNames[jobs[i].algo],
          loops: loops,
          totalTicks: jobs[i].totalTicks,
          avgTicks: jobs[i].avgTicks
        )
        i = i + 1
      check results.len == jobs.len
      for r in results:
        check r.loops == loops
        check r.totalTicks > 0
        check r.avgTicks >= 0
      echo formatBenchResults(results)
    else:
      var algos: seq[BenchAlgo] = @[]
      for job in makeJobs():
        let k = job.algo
        algos.add(BenchAlgo(name: algoNames[k], run: proc() =
          runAlgo(k)
        ))
      let results = compareAlgorithms(algos, loops = loops, warmup = 100)
      check results.len == algos.len
      for r in results:
        check r.loops == loops
        check r.totalTicks > 0
        check r.avgTicks >= 0
      echo formatBenchResults(results)
