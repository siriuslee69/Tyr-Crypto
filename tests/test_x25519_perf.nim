import std/[monotimes, strformat, times, unittest]

import ../src/protocols/custom_crypto/asymmetric/none_pq/[x25519_common, x25519_impl]
import ../src/protocols/bindings/libsodium

const
  scalarCorpusLen = 32
  scalarIterations = 12_000
  batch2Iterations = 6_000

type
  BenchRow = object
    name: string
    nsPerOp: float64
    nsPerCall: float64
    opsPerCall: int
    checksum: uint64

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
      seedA[j] = byte((17 + 29 * i + 7 * j) and 0xff)
      seedB[j] = byte((101 + 13 * i + 5 * j) and 0xff)
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

proc sodiumScalar(outShared: var X25519Bytes32, secretKey, publicKey: X25519Bytes32): bool =
  result = crypto_scalarmult_curve25519(
    addr outShared[0],
    unsafeAddr secretKey[0],
    unsafeAddr publicKey[0]) == 0
  if result:
    result = not isAllZero(outShared)

proc sodiumSerial2(outShared: var array[2, X25519Bytes32],
    secretKeys, publicKeys: array[2, X25519Bytes32]): array[2, bool] =
  var lane: int = 0
  while lane < 2:
    result[lane] = sodiumScalar(outShared[lane], secretKeys[lane], publicKeys[lane])
    lane = lane + 1

proc sodiumSerial4(outShared: var array[4, X25519Bytes32],
    secretKeys, publicKeys: array[4, X25519Bytes32]): array[4, bool] =
  var lane: int = 0
  while lane < 4:
    result[lane] = sodiumScalar(outShared[lane], secretKeys[lane], publicKeys[lane])
    lane = lane + 1

proc benchScalar(name: string, iterations: int,
    work: proc(outShared: var X25519Bytes32, secretKey, publicKey: X25519Bytes32): bool {.nimcall.}): BenchRow =
  var
    outShared: X25519Bytes32
    i: int = 0
    idx: int = 0
    start: MonoTime
    elapsedNs: int64 = 0
  i = 0
  while i < 256:
    idx = i mod scalarCorpusLen
    discard work(outShared, scalarSecrets[idx], scalarPublics[idx])
    benchSink = benchSink xor uint64(outShared[i and 31])
    i = i + 1
  start = getMonoTime()
  i = 0
  while i < iterations:
    idx = i mod scalarCorpusLen
    discard work(outShared, scalarSecrets[idx], scalarPublics[idx])
    benchSink = benchSink xor uint64(outShared[i and 31])
    i = i + 1
  elapsedNs = inNanoseconds(getMonoTime() - start)
  result.name = name
  result.opsPerCall = 1
  result.nsPerCall = float64(elapsedNs) / float64(iterations)
  result.nsPerOp = result.nsPerCall
  result.checksum = benchSink

proc benchBatch2(name: string, iterations: int,
    work: proc(outShared: var array[2, X25519Bytes32],
      secretKeys, publicKeys: array[2, X25519Bytes32]): array[2, bool] {.nimcall.}): BenchRow =
  var
    outShared: array[2, X25519Bytes32]
    ok: array[2, bool]
    i: int = 0
    idx: int = 0
    start: MonoTime
    elapsedNs: int64 = 0
  i = 0
  while i < 128:
    idx = i mod (scalarCorpusLen div 2)
    ok = work(outShared, sse2SecretGroups[idx], sse2PublicGroups[idx])
    benchSink = benchSink xor uint64(outShared[0][i and 31]) xor uint64(outShared[1][(i + 7) and 31])
    doAssert ok[0] and ok[1]
    i = i + 1
  start = getMonoTime()
  i = 0
  while i < iterations:
    idx = i mod (scalarCorpusLen div 2)
    ok = work(outShared, sse2SecretGroups[idx], sse2PublicGroups[idx])
    benchSink = benchSink xor uint64(outShared[0][i and 31]) xor uint64(outShared[1][(i + 7) and 31])
    doAssert ok[0] and ok[1]
    i = i + 1
  elapsedNs = inNanoseconds(getMonoTime() - start)
  result.name = name
  result.opsPerCall = 2
  result.nsPerCall = float64(elapsedNs) / float64(iterations)
  result.nsPerOp = float64(elapsedNs) / float64(iterations * 2)
  result.checksum = benchSink

proc benchBatch4(name: string, iterations: int,
    work: proc(outShared: var array[4, X25519Bytes32],
      secretKeys, publicKeys: array[4, X25519Bytes32]): array[4, bool] {.nimcall.}): BenchRow =
  var
    outShared: array[4, X25519Bytes32]
    ok: array[4, bool]
    i: int = 0
    idx: int = 0
    start: MonoTime
    elapsedNs: int64 = 0
  i = 0
  while i < 96:
    idx = i mod (scalarCorpusLen div 4)
    ok = work(outShared, avx4SecretGroups[idx], avx4PublicGroups[idx])
    benchSink = benchSink xor uint64(outShared[0][i and 31]) xor
      uint64(outShared[1][(i + 3) and 31]) xor
      uint64(outShared[2][(i + 11) and 31]) xor
      uint64(outShared[3][(i + 17) and 31])
    doAssert ok[0] and ok[1] and ok[2] and ok[3]
    i = i + 1
  start = getMonoTime()
  i = 0
  while i < iterations:
    idx = i mod (scalarCorpusLen div 4)
    ok = work(outShared, avx4SecretGroups[idx], avx4PublicGroups[idx])
    benchSink = benchSink xor uint64(outShared[0][i and 31]) xor
      uint64(outShared[1][(i + 3) and 31]) xor
      uint64(outShared[2][(i + 11) and 31]) xor
      uint64(outShared[3][(i + 17) and 31])
    doAssert ok[0] and ok[1] and ok[2] and ok[3]
    i = i + 1
  elapsedNs = inNanoseconds(getMonoTime() - start)
  result.name = name
  result.opsPerCall = 4
  result.nsPerCall = float64(elapsedNs) / float64(iterations)
  result.nsPerOp = float64(elapsedNs) / float64(iterations * 4)
  result.checksum = benchSink

proc formatDelta(a, b: float64): string =
  let pct = ((a - b) / b) * 100.0
  result = &"{pct:+.2f}%"

proc printRows(title: string, rows: openArray[BenchRow]) =
  var baselineNs: float64 = 0.0
  echo ""
  echo "## ", title
  if rows.len > 1:
    baselineNs = rows[0].nsPerOp
  for row in rows:
    var line = &"{row.name}: {row.nsPerOp:.2f} ns/op"
    line &= &" {row.nsPerCall:.2f} ns/call"
    if baselineNs > 0.0 and row.name != rows[0].name:
      line &= &" vs {rows[0].name} {formatDelta(row.nsPerOp, baselineNs)}"
    echo line

suite "x25519 perf":
  test "benchmark custom impl against libsodium baseline":
    let sodiumOk = sodiumAvailable()
    initCorpus()

    var scalarRows: seq[BenchRow] = @[]
    if sodiumOk:
      scalarRows.add(benchScalar("libsodium.runtime.scalar", scalarIterations, sodiumScalar))
    scalarRows.add(benchScalar("tyr.scalar", scalarIterations, x25519ScalarmultRaw))
    printRows("Scalar", scalarRows)

    when defined(amd64) or defined(i386):
      var sse2Rows: seq[BenchRow] = @[]
      if sodiumOk:
        sse2Rows.add(benchBatch2("libsodium.runtime.serial2", batch2Iterations, sodiumSerial2))
      sse2Rows.add(benchBatch2("tyr.sse2x", batch2Iterations, x25519ScalarmultBatchSse2x))
      printRows("SSE2x Batch", sse2Rows)

    when defined(neon) or defined(arm64) or defined(aarch64):
      var neon2Rows: seq[BenchRow] = @[]
      if sodiumOk:
        neon2Rows.add(benchBatch2("libsodium.runtime.serial2", batch2Iterations, sodiumSerial2))
      neon2Rows.add(benchBatch2("tyr.neon2x", batch2Iterations, x25519ScalarmultBatchNeon2x))
      printRows("NEON2x Batch", neon2Rows)

    when defined(avx2):
      var avx4Rows: seq[BenchRow] = @[]
      if sodiumOk:
        avx4Rows.add(benchBatch4("libsodium.runtime.serial4", batch2Iterations, sodiumSerial4))
      avx4Rows.add(benchBatch4("tyr.avx4x", batch2Iterations, x25519ScalarmultBatchAvx4x))
      printRows("AVX4x Batch", avx4Rows)

    echo ""
    echo "benchSink=", benchSink
