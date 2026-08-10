## ============================================================
## | Otter Blake3/ChaCha Timing                             |
## | -> Aggregate timing for Tyr Blake3 and ChaCha helpers  |
## ============================================================

import std/[algorithm, tables, unittest]

import ../src/protocols/custom_crypto/[blake3, chacha20, xchacha20, xchacha20_simd]
import otter_repo_evaluation

const
  topFunctions = 12
  loopsHash = 250
  loopsCipher = 2_000
  benchBytes = 8 * 1024

type
  TimingStat = object
    count: int
    total: int64
    max: int64

  TimingEntry = tuple[name: string, stat: TimingStat]

var
  benchInput: array[benchBytes, byte]
  benchKey32: array[32, byte]
  benchNonce24: array[24, byte]
  benchNonce12: array[12, byte]
  workBuf: array[benchBytes, byte]

proc fillPattern(bs: var openArray[byte], start: int = 0) =
  var
    i: int = 0
  i = 0
  while i < bs.len:
    bs[i] = byte((start + i) and 0xff)
    i = i + 1

proc initBenchData() =
  var
    i: int = 0
  fillPattern(benchInput, 0x17)
  fillPattern(benchKey32, 0x37)
  fillPattern(benchNonce24, 0x59)
  i = 0
  while i < benchNonce12.len:
    benchNonce12[i] = benchNonce24[i]
    i = i + 1

proc resetWorkBuf() =
  copyMem(addr workBuf[0], unsafeAddr benchInput[0], benchBytes)

proc aggregateTimings(A: openArray[OtterTimingTuple]): seq[TimingEntry] =
  var
    M: Table[string, TimingStat]
    t: TimingStat
  for e in A:
    if M.hasKey(e.functionName):
      t = M[e.functionName]
    else:
      t = TimingStat()
    t.count = t.count + 1
    t.total = t.total + durationTicks(e)
    if durationTicks(e) > t.max:
      t.max = durationTicks(e)
    M[e.functionName] = t
  for k, v in M.pairs:
    result.add((name: k, stat: v))
  result.sort(proc (a, b: TimingEntry): int =
    if a.stat.total > b.stat.total:
      return -1
    if a.stat.total < b.stat.total:
      return 1
    if a.stat.max > b.stat.max:
      return -1
    if a.stat.max < b.stat.max:
      return 1
    cmp(a.name, b.name)
  )

proc printTopTimings(title: string, A: openArray[TimingEntry], limit: int = topFunctions) =
  var
    i: int = 0
    avg: int64 = 0
    maxItems: int = 0
  echo ""
  echo "## ", title
  maxItems = min(limit, A.len)
  i = 0
  while i < maxItems:
    if A[i].stat.count > 0:
      avg = A[i].stat.total div A[i].stat.count
    else:
      avg = 0
    echo A[i].name, " total=", A[i].stat.total,
      " avg=", avg,
      " max=", A[i].stat.max,
      " count=", A[i].stat.count
    i = i + 1

proc runTimedGroup(title: string, body: proc ()) =
  var
    entries: seq[OtterTimingTuple] = @[]
    stats: seq[TimingEntry] = @[]
  clearTimings()
  body()
  entries = snapshotTimings()
  check entries.len > 0
  stats = aggregateTimings(entries)
  printTopTimings(title, stats)

proc tyrBlake3HashImpl() =
  discard blake3Hash(benchInput)

proc tyrChaCha20XorImpl() =
  resetWorkBuf()
  chacha20XorInPlace(benchKey32, benchNonce12, 0'u32, workBuf)

proc tyrXChaCha20XorImpl() =
  resetWorkBuf()
  xchacha20XorInPlace(benchKey32, benchNonce24, 0'u32, workBuf)

proc tyrXChaCha20StreamImpl() =
  discard xchacha20Stream(benchKey32, benchNonce24, benchBytes, 0'u32)

proc tyrXChaCha20SimdSse2Impl() =
  discard xchacha20StreamSimd(benchKey32, benchNonce24, benchBytes, 0'u32, xcbSse2)

proc tyrXChaCha20SimdAvx2Impl() =
  discard xchacha20StreamSimd(benchKey32, benchNonce24, benchBytes, 0'u32, xcbAvx2)

proc tyrChaCha20BlockImpl() =
  discard chacha20Block(benchKey32, benchNonce12, 0'u32)

proc tyrHChaCha20Impl() =
  discard hchacha20(benchKey32, benchNonce24.toOpenArray(0, 15))

otterInstrument:
  proc tyrBlake3HashBench() =
    tyrBlake3HashImpl()

  proc tyrChaCha20XorBench() =
    tyrChaCha20XorImpl()

  proc tyrXChaCha20XorBench() =
    tyrXChaCha20XorImpl()

  proc tyrXChaCha20StreamBench() =
    tyrXChaCha20StreamImpl()

  proc tyrXChaCha20SimdSse2Bench() =
    tyrXChaCha20SimdSse2Impl()

  proc tyrXChaCha20SimdAvx2Bench() =
    tyrXChaCha20SimdAvx2Impl()

  proc tyrChaCha20BlockBench() =
    tyrChaCha20BlockImpl()

  proc tyrHChaCha20Bench() =
    tyrHChaCha20Impl()

suite "Otter Blake3/ChaCha timing":
  test "report expensive Tyr Blake3 and ChaCha wrappers":
    var
      i: int = 0
    initBenchData()
    setLogPath("build/otter_blake3_chacha_timings.log")

    runTimedGroup("Blake3 Hash", proc () =
      i = 0
      while i < loopsHash:
        tyrBlake3HashBench()
        i = i + 1
    )

    runTimedGroup("ChaCha Family", proc () =
      i = 0
      while i < loopsCipher:
        tyrHChaCha20Bench()
        tyrChaCha20BlockBench()
        tyrChaCha20XorBench()
        tyrXChaCha20XorBench()
        tyrXChaCha20StreamBench()
        when defined(sse2):
          tyrXChaCha20SimdSse2Bench()
        when defined(avx2):
          tyrXChaCha20SimdAvx2Bench()
        i = i + 1
    )
