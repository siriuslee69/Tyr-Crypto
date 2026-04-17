# =============================================================
# | Otter Dilithium Timing Test                               |
# | -> Aggregate per-function timings for ML-DSA hotspots     |
# =============================================================

import std/[algorithm, tables, unittest]

import ../src/protocols/custom_crypto/dilithium
import otter_repo_evaluation

const
  topFunctions = 20

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

proc runDilithiumSignVerify(v: DilithiumVariant, msgLen, iterations, fillStart: int) =
  var
    p = params(v)
    msg = newSeq[byte](msgLen)
    pk = newSeq[byte](p.publicKeyBytes)
    sk = newSeq[byte](p.secretKeyBytes)
    sig = newSeq[byte](p.signatureBytes)
    i: int = 0
  fillPattern(msg, fillStart)
  i = 0
  while i < iterations:
    dilithiumTyrKeypairInto(v, pk, sk)
    dilithiumTyrSignInto(v, sig, msg, sk)
    doAssert dilithiumTyrVerify(v, msg, sig, pk)
    i = i + 1

suite "Otter Dilithium timing":
  test "report top expensive Dilithium functions":
    setLogPath("build/otter_dilithium_timings.log")

    runTimedGroup("ML-DSA 44/65/87 Sign+Verify Hotspots", proc () =
      runDilithiumSignVerify(dilithium44, 2048, 4, 0x11)
      runDilithiumSignVerify(dilithium65, 2048, 3, 0x31)
      runDilithiumSignVerify(dilithium87, 2048, 2, 0x51)
    )
