## ============================================================
## | Custom KDF Benchmark <- tail/full-memory round table |
## ============================================================

import std/[algorithm, monotimes, os, strutils]

import ../src/protocols/custom_crypto/kdf as custom_kdf

const
  defaultMemoryKiB = 64
  defaultRounds = 5
  defaultHashCount = 2
  defaultBlockSize = 64
  defaultLoops = 2
  defaultWarmup = 1
  ticksPerSecond = 1_000_000_000.0

type
  BenchProc = proc () {.closure.}

  BenchSpec = object
    name: string
    algo: custom_kdf.CustomKdfAlgorithm
    loops: int
    warmup: int
    memoryBytes: int
    rounds: int
    hashCount: int
    blockSize: int
    run: BenchProc

  BenchRow = object
    name: string
    loops: int
    warmup: int
    totalTicks: int64
    avgTicks: int64
    opsPerSecond: float64
    mibPerSecond: float64

var
  benchSink: uint64 = 0


proc makePatternBytes(l, start: int): seq[byte] =
  ## l: byte count.
  ## start: first byte pattern value.
  var
    i: int = 0
  result = newSeq[byte](l)
  i = 0
  while i < l:
    result[i] = byte((start + i) and 0xff)
    i = i + 1


proc mixBytes(A: openArray[byte]) =
  ## A: benchmark result bytes to fold into the sink.
  var
    mid: int = 0
  if A.len <= 0:
    benchSink = benchSink xor 0x9e3779b97f4a7c15'u64
    return
  mid = A.len shr 1
  benchSink = benchSink xor uint64(A[0])
  benchSink = benchSink xor (uint64(A[mid]) shl 8)
  benchSink = benchSink xor (uint64(A[A.len - 1]) shl 16)
  benchSink = benchSink xor (uint64(A.len) shl 24)


proc parsePositiveInt(args: seq[string], idx, fallback: int,
    label: string): int =
  ## args: command-line arguments.
  ## idx: argument index.
  ## fallback: default value.
  ## label: error label.
  var
    raw: string = ""
    parsed: int = 0
  if idx >= args.len:
    return fallback
  raw = args[idx].strip()
  try:
    parsed = parseInt(raw)
  except ValueError:
    raise newException(ValueError, label & " must be an integer")
  if parsed <= 0:
    raise newException(ValueError, label & " must be positive")
  result = parsed


proc algoName(a: custom_kdf.CustomKdfAlgorithm): string =
  ## a: KDF block generator selector.
  case a
  of custom_kdf.ckaGimli:
    result = "gimli"
  of custom_kdf.ckaBlake3:
    result = "blake3"
  of custom_kdf.ckaSha3:
    result = "sha3"
  of custom_kdf.ckaShake128:
    result = "shake128"
  of custom_kdf.ckaShake256:
    result = "shake256"
  of custom_kdf.ckaChaCha20:
    result = "chacha20"
  of custom_kdf.ckaXChaCha20:
    result = "xchacha20"
  of custom_kdf.ckaAesCtr:
    result = "aes_ctr"


proc formatFloat2(v: float64): string =
  ## v: float value.
  result = formatFloat(v, ffDecimal, 2)


proc rowCompare(a, b: BenchRow): int =
  ## a: left row.
  ## b: right row.
  if a.avgTicks < b.avgTicks:
    return -1
  if a.avgTicks > b.avgTicks:
    return 1
  result = cmp(a.name, b.name)


proc buildSpec(a: custom_kdf.CustomKdfAlgorithm, seed: seq[byte],
    memoryBytes, rounds, hashCount, blockSize, loops, warmup: int): BenchSpec =
  ## a: KDF block generator selector.
  ## seed: deterministic KDF seed bytes.
  ## memoryBytes: flat memory byte count.
  ## rounds: KDF round count.
  ## hashCount: KDF hash-count parameter.
  ## blockSize: KDF block-size parameter.
  ## loops: measured loop count.
  ## warmup: warmup loop count.
  result.name = algoName(a)
  result.algo = a
  result.loops = loops
  result.warmup = warmup
  result.memoryBytes = memoryBytes
  result.rounds = rounds
  result.hashCount = hashCount
  result.blockSize = blockSize
  result.run = proc () =
    var
      outBlock: seq[byte] = @[]
    outBlock = custom_kdf.deriveCustomKdf(seed, a, rounds, memoryBytes,
      hashCount, blockSize)
    mixBytes(outBlock)
    benchSink = benchSink + uint64(ord(a) + 1)


proc benchmarkSpec(s: BenchSpec): BenchRow =
  ## s: benchmark specification.
  var
    i: int = 0
    startTime: MonoTime
    stopTime: MonoTime
    seconds: float64 = 0.0
    totalMiB: float64 = 0.0
  i = 0
  while i < s.warmup:
    s.run()
    i = i + 1
  startTime = getMonoTime()
  i = 0
  while i < s.loops:
    s.run()
    i = i + 1
  stopTime = getMonoTime()
  result.name = s.name
  result.loops = s.loops
  result.warmup = s.warmup
  result.totalTicks = stopTime.ticks - startTime.ticks
  if s.loops > 0:
    result.avgTicks = result.totalTicks div s.loops
  seconds = float64(result.totalTicks) / ticksPerSecond
  if seconds > 0.0:
    result.opsPerSecond = float64(s.loops) / seconds
    totalMiB = (float64(s.memoryBytes) * float64(s.loops)) / 1024.0 / 1024.0
    result.mibPerSecond = totalMiB / seconds


proc buildSpecs(memoryBytes, rounds, hashCount, blockSize, loops,
    warmup: int): seq[BenchSpec] =
  ## memoryBytes: flat memory byte count.
  ## rounds: KDF round count.
  ## hashCount: KDF hash-count parameter.
  ## blockSize: KDF block-size parameter.
  ## loops: measured loop count.
  ## warmup: warmup loop count.
  var
    seed: seq[byte] = @[]
    a: custom_kdf.CustomKdfAlgorithm
  seed = makePatternBytes(64, 0x42)
  for alg in custom_kdf.CustomKdfAlgorithm:
    a = alg
    result.add(buildSpec(a, seed, memoryBytes, rounds, hashCount, blockSize,
      loops, warmup))


proc benchmarkSpecs(S: openArray[BenchSpec]): seq[BenchRow] =
  ## S: benchmark specs.
  var
    i: int = 0
  result = newSeq[BenchRow](S.len)
  i = 0
  while i < S.len:
    result[i] = benchmarkSpec(S[i])
    i = i + 1


proc printTable(rows: seq[BenchRow]) =
  ## rows: benchmark result rows.
  var
    sorted: seq[BenchRow] = @[]
    i: int = 0
    rank: int = 1
  sorted = @rows
  sorted.sort(rowCompare)
  echo ""
  echo "| rank | generator | avg_ms | total_ms | ops/s | MiB/s(memory fill) |"
  echo "| ---: | --- | ---: | ---: | ---: | ---: |"
  i = 0
  while i < sorted.len:
    echo "| ", rank, " | ", sorted[i].name, " | ",
      formatFloat2(float64(sorted[i].avgTicks) / 1_000_000.0), " | ",
      formatFloat2(float64(sorted[i].totalTicks) / 1_000_000.0), " | ",
      formatFloat2(sorted[i].opsPerSecond), " | ",
      formatFloat2(sorted[i].mibPerSecond), " |"
    i = i + 1
    rank = rank + 1


proc printUsage() =
  echo "Usage: bench_custom_kdf [memoryKiB rounds hashCount blockSize loops warmup]"
  echo "Defaults: ", defaultMemoryKiB, " ", defaultRounds, " ", defaultHashCount,
    " ", defaultBlockSize, " ", defaultLoops, " ", defaultWarmup


proc main() =
  var
    args: seq[string] = @[]
    memoryKiB: int = 0
    memoryBytes: int = 0
    rounds: int = 0
    hashCount: int = 0
    blockSize: int = 0
    loops: int = 0
    warmup: int = 0
    specs: seq[BenchSpec] = @[]
    rows: seq[BenchRow] = @[]
  args = commandLineParams()
  if args.len > 0 and (args[0] == "-h" or args[0] == "--help"):
    printUsage()
    return
  memoryKiB = parsePositiveInt(args, 0, defaultMemoryKiB, "memoryKiB")
  rounds = parsePositiveInt(args, 1, defaultRounds, "rounds")
  hashCount = parsePositiveInt(args, 2, defaultHashCount, "hashCount")
  blockSize = parsePositiveInt(args, 3, defaultBlockSize, "blockSize")
  loops = parsePositiveInt(args, 4, defaultLoops, "loops")
  warmup = parsePositiveInt(args, 5, defaultWarmup, "warmup")
  memoryBytes = memoryKiB * 1024
  echo "# Tyr Custom KDF Benchmark"
  echo ""
  echo "Parameters: memoryKiB=", memoryKiB, " rounds=", rounds,
    " hashCount=", hashCount, " blockSize=", blockSize,
    " loops=", loops, " warmup=", warmup
  specs = buildSpecs(memoryBytes, rounds, hashCount, blockSize, loops, warmup)
  rows = benchmarkSpecs(specs)
  printTable(rows)
  echo ""
  echo "Sink: ", benchSink


when isMainModule:
  main()
