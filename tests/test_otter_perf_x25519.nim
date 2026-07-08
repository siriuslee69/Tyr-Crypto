import std/[algorithm, tables, unittest]

import ../src/protocols/custom_crypto/asymmetric/none_pq/[x25519_common, x25519_impl]
import ../src/protocols/helpers/otter_support
import ../src/protocols/bindings/libsodium
import otter_repo_evaluation

const
  scalarCorpusLen = 8
  scalarLoops = 24
  batch2Loops = 12
  topFunctions = 10

type
  TimingStat = object
    count: int
    total: int64
    max: int64

  TimingEntry = tuple[name: string, stat: TimingStat]

var
  scalarSecrets: array[scalarCorpusLen, X25519Bytes32]
  scalarPublics: array[scalarCorpusLen, X25519Bytes32]
  sse2SecretGroups: array[scalarCorpusLen div 2, array[2, X25519Bytes32]]
  sse2PublicGroups: array[scalarCorpusLen div 2, array[2, X25519Bytes32]]
  avx4SecretGroups: array[scalarCorpusLen div 4, array[4, X25519Bytes32]]
  avx4PublicGroups: array[scalarCorpusLen div 4, array[4, X25519Bytes32]]
  benchSink: uint64 = 0

proc sodiumAvailable(): bool =
  try:
    if not ensureLibSodiumLoaded():
      return false
    ensureSodiumInitialised()
    result = true
  except CatchableError:
    result = false

proc initCorpus() =
  var
    i: int = 0
    j: int = 0
    seedA: seq[byte]
    seedB: seq[byte]
  i = 0
  while i < scalarCorpusLen:
    seedA = newSeq[byte](32)
    seedB = newSeq[byte](32)
    j = 0
    while j < 32:
      seedA[j] = byte((41 + 11 * i + 7 * j) and 0xff)
      seedB[j] = byte((131 + 17 * i + 3 * j) and 0xff)
      j = j + 1
    let
      kpA = x25519TyrKeypairFromSeed(seedA)
      kpB = x25519TyrKeypairFromSeed(seedB)
    scalarSecrets[i] = toFixed32(kpA.secretKey)
    scalarPublics[i] = toFixed32(kpB.publicKey)
    i = i + 1
  i = 0
  while i < scalarCorpusLen div 2:
    sse2SecretGroups[i][0] = scalarSecrets[2 * i]
    sse2SecretGroups[i][1] = scalarSecrets[2 * i + 1]
    sse2PublicGroups[i][0] = scalarPublics[2 * i]
    sse2PublicGroups[i][1] = scalarPublics[2 * i + 1]
    i = i + 1
  i = 0
  while i < scalarCorpusLen div 4:
    for lane in 0 ..< 4:
      avx4SecretGroups[i][lane] = scalarSecrets[4 * i + lane]
      avx4PublicGroups[i][lane] = scalarPublics[4 * i + lane]
    i = i + 1

proc aggregateTimings(entries: openArray[OtterTimingTuple]): seq[TimingEntry] =
  var
    table: Table[string, TimingStat]
    stat: TimingStat
  for entry in entries:
    if table.hasKey(entry.functionName):
      stat = table[entry.functionName]
    else:
      stat = TimingStat()
    stat.count = stat.count + 1
    stat.total = stat.total + durationTicks(entry)
    if durationTicks(entry) > stat.max:
      stat.max = durationTicks(entry)
    table[entry.functionName] = stat
  for key, value in table.pairs:
    result.add((name: key, stat: value))
  result.sort(proc (a, b: TimingEntry): int =
    if a.stat.total > b.stat.total:
      return -1
    if a.stat.total < b.stat.total:
      return 1
    cmp(a.name, b.name)
  )

proc printTopTimings(title: string, entries: openArray[TimingEntry], limit: int = topFunctions) =
  var
    i: int = 0
    avg: int64 = 0
  echo ""
  echo "## ", title
  while i < min(limit, entries.len):
    if entries[i].stat.count > 0:
      avg = entries[i].stat.total div entries[i].stat.count
    else:
      avg = 0
    echo entries[i].name, " total=", entries[i].stat.total,
      " avg=", avg,
      " max=", entries[i].stat.max,
      " count=", entries[i].stat.count
    i = i + 1

proc runTimedGroup(title: string, body: proc ()) =
  clearTimings()
  body()
  let entries = snapshotTimings()
  check entries.len > 0
  printTopTimings(title, aggregateTimings(entries))

proc sodiumScalar(outShared: var X25519Bytes32, secretKey, publicKey: X25519Bytes32): bool =
  otterSpan("x25519.libsodium.runtime.scalar"):
    result = crypto_scalarmult_curve25519(
      addr outShared[0],
      unsafeAddr secretKey[0],
      unsafeAddr publicKey[0]) == 0
    if result:
      result = not isAllZero(outShared)

proc sodiumSerial2(outShared: var array[2, X25519Bytes32],
    secretKeys, publicKeys: array[2, X25519Bytes32]): array[2, bool] =
  otterSpan("x25519.libsodium.runtime.serial2"):
    for lane in 0 ..< 2:
      result[lane] = sodiumScalar(outShared[lane], secretKeys[lane], publicKeys[lane])

proc sodiumSerial4(outShared: var array[4, X25519Bytes32],
    secretKeys, publicKeys: array[4, X25519Bytes32]): array[4, bool] =
  otterSpan("x25519.libsodium.runtime.serial4"):
    for lane in 0 ..< 4:
      result[lane] = sodiumScalar(outShared[lane], secretKeys[lane], publicKeys[lane])

proc profileScalar(work: proc(outShared: var X25519Bytes32,
    secretKey, publicKey: X25519Bytes32): bool {.nimcall.}) =
  var
    outShared: X25519Bytes32
    i: int = 0
    idx: int = 0
  i = 0
  while i < scalarLoops:
    idx = i mod scalarCorpusLen
    discard work(outShared, scalarSecrets[idx], scalarPublics[idx])
    benchSink = benchSink xor uint64(outShared[i and 31])
    i = i + 1

proc profileBatch2(work: proc(outShared: var array[2, X25519Bytes32],
    secretKeys, publicKeys: array[2, X25519Bytes32]): array[2, bool] {.nimcall.}) =
  var
    outShared: array[2, X25519Bytes32]
    ok: array[2, bool]
    i: int = 0
    idx: int = 0
  i = 0
  while i < batch2Loops:
    idx = i mod (scalarCorpusLen div 2)
    ok = work(outShared, sse2SecretGroups[idx], sse2PublicGroups[idx])
    check ok[0] and ok[1]
    benchSink = benchSink xor uint64(outShared[0][i and 31]) xor uint64(outShared[1][(i + 9) and 31])
    i = i + 1

proc profileBatch4(work: proc(outShared: var array[4, X25519Bytes32],
    secretKeys, publicKeys: array[4, X25519Bytes32]): array[4, bool] {.nimcall.}) =
  var
    outShared: array[4, X25519Bytes32]
    ok: array[4, bool]
    i: int = 0
    idx: int = 0
  i = 0
  while i < batch2Loops:
    idx = i mod (scalarCorpusLen div 4)
    ok = work(outShared, avx4SecretGroups[idx], avx4PublicGroups[idx])
    check ok[0] and ok[1] and ok[2] and ok[3]
    benchSink = benchSink xor uint64(outShared[0][i and 31]) xor uint64(outShared[1][(i + 5) and 31]) xor
      uint64(outShared[2][(i + 13) and 31]) xor uint64(outShared[3][(i + 21) and 31])
    i = i + 1

suite "Otter X25519 timing":
  test "report expensive X25519 scalar and batch spans":
    if not sodiumAvailable():
      skip()
    initCorpus()
    setLogPath("build/otter_x25519_timings.log")

    runTimedGroup("Scalar", proc () =
      profileScalar(sodiumScalar)
      profileScalar(x25519ScalarmultRaw)
    )

    when defined(amd64) or defined(i386):
      runTimedGroup("SSE2x Batch", proc () =
        profileBatch2(sodiumSerial2)
        profileBatch2(x25519ScalarmultBatchSse2x)
      )

    when defined(neon) or defined(arm64) or defined(aarch64):
      runTimedGroup("NEON2x Batch", proc () =
        profileBatch2(sodiumSerial2)
        profileBatch2(x25519ScalarmultBatchNeon2x)
      )

    when defined(avx2):
      runTimedGroup("AVX4x Batch", proc () =
        profileBatch4(sodiumSerial4)
        profileBatch4(x25519ScalarmultBatchAvx4x)
      )

    echo ""
    echo "benchSink=", benchSink
