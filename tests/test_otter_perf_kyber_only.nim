# ============================================================
# | Otter Kyber Timing Test                                 |
# | -> Profile Tyr Kyber hotspots without unrelated PQ      |
# |    modules so optimization loops stay focused/reliable  |
# ============================================================

import std/[algorithm, tables, unittest]

import ../src/protocols/custom_crypto/kyber
import otter_repo_evaluation

const
  topFunctions = 12

type
  TimingStat = object
    count: int
    total: int64
    max: int64

  TimingEntry = tuple[name: string, stat: TimingStat]

proc fillPattern(bs: var openArray[byte], start: int = 0) =
  var
    i: int = 0
  i = 0
  while i < bs.len:
    bs[i] = byte((start + i) and 0xff)
    i = i + 1

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

proc kyber768BenchGenMatrixImpl() =
  var
    p = params(kyber768)
    seed: array[32, byte]
  fillPattern(seed, 0x11)
  discard genMatrix(p, seed, false)

proc kyber768BenchIndcpaKeypairImpl() =
  var
    p = params(kyber768)
    seed = newSeq[byte](32)
  fillPattern(seed, 0x21)
  discard indcpaKeypair(p, seed)

proc kyber768BenchIndcpaEncDecImpl() =
  var
    p = params(kyber768)
    seed = newSeq[byte](32)
    coins = newSeq[byte](32)
    msg = newSeq[byte](32)
    kp: tuple[pk, sk: seq[byte]]
    ct: seq[byte]
    dec: seq[byte]
  fillPattern(seed, 0x31)
  fillPattern(coins, 0x41)
  fillPattern(msg, 0x51)
  kp = indcpaKeypair(p, seed)
  ct = indcpaEnc(p, msg, kp.pk, coins)
  dec = indcpaDec(p, ct, kp.sk)
  doAssert dec == msg

proc kyber768BenchRoundtripImpl() =
  let kp = kyberTyrKeypair(kyber768)
  let env = kyberTyrEncaps(kyber768, kp.publicKey)
  let shared = kyberTyrDecaps(kyber768, kp.secretKey, env.ciphertext)
  doAssert shared == env.sharedSecret

otterInstrument:
  proc kyber768BenchGenMatrix() =
    kyber768BenchGenMatrixImpl()

  proc kyber768BenchIndcpaKeypair() =
    kyber768BenchIndcpaKeypairImpl()

  proc kyber768BenchIndcpaEncDec() =
    kyber768BenchIndcpaEncDecImpl()

  proc kyber768BenchRoundtrip() =
    kyber768BenchRoundtripImpl()

suite "Otter Kyber timing":
  test "report top expensive Tyr Kyber functions":
    var
      i: int = 0
    setLogPath("build/otter_kyber_timings.log")

    runTimedGroup("Kyber768 Roundtrip Hotspots", proc () =
      i = 0
      while i < 5:
        kyber768BenchGenMatrix()
        kyber768BenchIndcpaKeypair()
        kyber768BenchIndcpaEncDec()
        kyber768BenchRoundtrip()
        i = i + 1
    )
