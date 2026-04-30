import std/[monotimes, strformat, strutils, times, unittest]

import ../src/protocols/custom_crypto/asymmetric/none_pq/[x25519_common, x25519_pass1, x25519_pass2, x25519_pass3, x25519_pass4, x25519_ref10_c]
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
      kpA = x25519_pass4.x25519TyrKeypairFromSeed(seedA)
      kpB = x25519_pass4.x25519TyrKeypairFromSeed(seedB)
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

proc ref10Scalar(outShared: var X25519Bytes32, secretKey, publicKey: X25519Bytes32): bool =
  result = tyr_x25519_ref10_scalarmult(
    addr outShared[0],
    unsafeAddr secretKey[0],
    unsafeAddr publicKey[0]) == 0
  if result:
    result = not isAllZero(outShared)

proc sodiumScalar(outShared: var X25519Bytes32, secretKey, publicKey: X25519Bytes32): bool =
  result = crypto_scalarmult_curve25519(
    addr outShared[0],
    unsafeAddr secretKey[0],
    unsafeAddr publicKey[0]) == 0
  if result:
    result = not isAllZero(outShared)

proc ref10Serial2(outShared: var array[2, X25519Bytes32],
    secretKeys, publicKeys: array[2, X25519Bytes32]): array[2, bool] =
  var lane: int = 0
  while lane < 2:
    result[lane] = ref10Scalar(outShared[lane], secretKeys[lane], publicKeys[lane])
    lane = lane + 1

proc sodiumSerial2(outShared: var array[2, X25519Bytes32],
    secretKeys, publicKeys: array[2, X25519Bytes32]): array[2, bool] =
  var lane: int = 0
  while lane < 2:
    result[lane] = sodiumScalar(outShared[lane], secretKeys[lane], publicKeys[lane])
    lane = lane + 1

proc ref10Serial4(outShared: var array[4, X25519Bytes32],
    secretKeys, publicKeys: array[4, X25519Bytes32]): array[4, bool] =
  var lane: int = 0
  while lane < 4:
    result[lane] = ref10Scalar(outShared[lane], secretKeys[lane], publicKeys[lane])
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

proc printRows(title: string, rows: openArray[BenchRow], pass1Prefix: string) =
  var
    pass1Ns: float64 = 0.0
    prevNs: float64 = 0.0
  echo ""
  echo "## ", title
  for row in rows:
    if row.name == pass1Prefix:
      pass1Ns = row.nsPerOp
      prevNs = row.nsPerOp
      break
  for row in rows:
    var line = &"{row.name}: {row.nsPerOp:.2f} ns/op"
    line &= &" {row.nsPerCall:.2f} ns/call"
    if row.name.startsWith("tyr.pass"):
      if pass1Ns > 0.0:
        line &= &" vs pass1 {formatDelta(row.nsPerOp, pass1Ns)}"
      if row.name != pass1Prefix and prevNs > 0.0:
        line &= &" vs prev {formatDelta(row.nsPerOp, prevNs)}"
      prevNs = row.nsPerOp
    echo line

suite "x25519 perf":
  test "benchmark custom passes against libsodium baselines":
    if not sodiumAvailable():
      skip()
    initCorpus()

    let scalarRows = @[
      benchScalar("libsodium.ref10.scalar", scalarIterations, ref10Scalar),
      benchScalar("libsodium.runtime.scalar", scalarIterations, sodiumScalar),
      benchScalar("tyr.pass1.scalar", scalarIterations, x25519_pass1.x25519ScalarmultRaw),
      benchScalar("tyr.pass2.scalar", scalarIterations, x25519_pass2.x25519ScalarmultRaw),
      benchScalar("tyr.pass3.scalar", scalarIterations, x25519_pass3.x25519ScalarmultRaw),
      benchScalar("tyr.pass4.scalar", scalarIterations, x25519_pass4.x25519ScalarmultRaw)
    ]
    printRows("Scalar", scalarRows, "tyr.pass1.scalar")

    when defined(amd64) or defined(i386):
      let sse2Rows = @[
        benchBatch2("libsodium.ref10.serial2", batch2Iterations, ref10Serial2),
        benchBatch2("libsodium.runtime.serial2", batch2Iterations, sodiumSerial2),
        benchBatch2("tyr.pass1.sse2x", batch2Iterations, x25519_pass1.x25519ScalarmultBatchSse2x),
        benchBatch2("tyr.pass2.sse2x", batch2Iterations, x25519_pass2.x25519ScalarmultBatchSse2x),
        benchBatch2("tyr.pass3.sse2x", batch2Iterations, x25519_pass3.x25519ScalarmultBatchSse2x),
        benchBatch2("tyr.pass4.sse2x", batch2Iterations, x25519_pass4.x25519ScalarmultBatchSse2x)
      ]
      printRows("SSE2x Batch", sse2Rows, "tyr.pass1.sse2x")

    when defined(neon) or defined(arm64) or defined(aarch64):
      let neon2Rows = @[
        benchBatch2("libsodium.ref10.serial2", batch2Iterations, ref10Serial2),
        benchBatch2("libsodium.runtime.serial2", batch2Iterations, sodiumSerial2),
        benchBatch2("tyr.pass1.neon2x", batch2Iterations, x25519_pass1.x25519ScalarmultBatchNeon2x),
        benchBatch2("tyr.pass2.neon2x", batch2Iterations, x25519_pass2.x25519ScalarmultBatchNeon2x),
        benchBatch2("tyr.pass3.neon2x", batch2Iterations, x25519_pass3.x25519ScalarmultBatchNeon2x),
        benchBatch2("tyr.pass4.neon2x", batch2Iterations, x25519_pass4.x25519ScalarmultBatchNeon2x)
      ]
      printRows("NEON2x Batch", neon2Rows, "tyr.pass1.neon2x")

    when defined(avx2):
      let avx4Rows = @[
        benchBatch4("libsodium.ref10.serial4", batch2Iterations, ref10Serial4),
        benchBatch4("libsodium.runtime.serial4", batch2Iterations, sodiumSerial4),
        benchBatch4("tyr.pass1.avx4x", batch2Iterations, x25519_pass1.x25519ScalarmultBatchAvx4x),
        benchBatch4("tyr.pass2.avx4x", batch2Iterations, x25519_pass2.x25519ScalarmultBatchAvx4x),
        benchBatch4("tyr.pass3.avx4x", batch2Iterations, x25519_pass3.x25519ScalarmultBatchAvx4x),
        benchBatch4("tyr.pass4.avx4x", batch2Iterations, x25519_pass4.x25519ScalarmultBatchAvx4x)
      ]
      printRows("AVX4x Batch", avx4Rows, "tyr.pass1.avx4x")

    echo ""
    echo "benchSink=", benchSink
