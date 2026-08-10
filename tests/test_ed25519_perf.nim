import std/[monotimes, strformat, times, unittest]

import ../src/protocols/custom_crypto/ed25519 as customEd25519

const
  corpusLen = 8
  keyIterations = 32
  signIterations = 32
  verifyIterations = 16

type
  BenchRow = object
    name: string
    nsPerOp: float64
    checksum: uint64

var
  seeds: array[corpusLen, seq[byte]]
  messages: array[corpusLen, seq[byte]]
  publicKeys: array[corpusLen, seq[byte]]
  secretKeys: array[corpusLen, seq[byte]]
  signatures: array[corpusLen, seq[byte]]
  benchSink: uint64 = 0

proc initCorpus() =
  var
    i: int = 0
    j: int = 0
  while i < corpusLen:
    seeds[i] = newSeq[byte](32)
    messages[i] = newSeq[byte](32 + i)
    j = 0
    while j < 32:
      seeds[i][j] = byte((19 + i * 31 + j * 7) and 0xff)
      inc j
    j = 0
    while j < messages[i].len:
      messages[i][j] = byte((91 + i * 13 + j * 5) and 0xff)
      inc j
    var kp = customEd25519.ed25519TyrKeypairFromSeed(seeds[i])
    publicKeys[i] = kp.publicKey
    secretKeys[i] = kp.secretKey
    signatures[i] = customEd25519.ed25519TyrSign(messages[i], secretKeys[i])
    inc i

proc benchKeypair(): BenchRow =
  var
    i: int = 0
    idx: int = 0
    start: MonoTime
    elapsedNs: int64 = 0
  start = getMonoTime()
  while i < keyIterations:
    idx = i mod corpusLen
    var kp = customEd25519.ed25519TyrKeypairFromSeed(seeds[idx])
    benchSink = benchSink xor uint64(kp.publicKey[i and 31])
    inc i
  elapsedNs = inNanoseconds(getMonoTime() - start)
  result.name = "tyr.ed25519.keypair"
  result.nsPerOp = float64(elapsedNs) / float64(keyIterations)
  result.checksum = benchSink

proc benchSign(): BenchRow =
  var
    i: int = 0
    idx: int = 0
    start: MonoTime
    elapsedNs: int64 = 0
  start = getMonoTime()
  while i < signIterations:
    idx = i mod corpusLen
    var sig = customEd25519.ed25519TyrSign(messages[idx], secretKeys[idx])
    benchSink = benchSink xor uint64(sig[i and 63])
    inc i
  elapsedNs = inNanoseconds(getMonoTime() - start)
  result.name = "tyr.ed25519.sign"
  result.nsPerOp = float64(elapsedNs) / float64(signIterations)
  result.checksum = benchSink

proc benchVerify(): BenchRow =
  var
    i: int = 0
    idx: int = 0
    start: MonoTime
    elapsedNs: int64 = 0
    ok: bool = false
  start = getMonoTime()
  while i < verifyIterations:
    idx = i mod corpusLen
    ok = customEd25519.ed25519TyrVerify(messages[idx], signatures[idx], publicKeys[idx])
    doAssert ok
    benchSink = benchSink xor uint64(signatures[idx][i and 63])
    inc i
  elapsedNs = inNanoseconds(getMonoTime() - start)
  result.name = "tyr.ed25519.verify"
  result.nsPerOp = float64(elapsedNs) / float64(verifyIterations)
  result.checksum = benchSink

proc printRow(r: BenchRow) =
  echo &"{r.name}: {r.nsPerOp:.2f} ns/op checksum={r.checksum}"

suite "ed25519 perf":
  test "benchmark custom Ed25519 core operations":
    initCorpus()
    printRow(benchKeypair())
    printRow(benchSign())
    printRow(benchVerify())
