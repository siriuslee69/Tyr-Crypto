## =====================================================================
## | Asymmetric Benchmark Collector                                     |
## | -> Collect summary + function timings for desktop and Android runs  |
## =====================================================================

import std/[algorithm, json, math, monotimes, os, parseopt, strformat, strutils, tables, times]

import ../src/protocols/custom_crypto/[kyber, frodo, bike, mceliece, dilithium, falcon, sphincs]
import ../src/protocols/custom_crypto/ntru as custom_ntru
import ../src/protocols/custom_crypto/saber as custom_saber
import ../src/protocols/custom_crypto/asymmetric/none_pq/[x25519_common, x25519_pass1, x25519_pass2, x25519_pass3, x25519_pass4]
import ../src/protocols/custom_crypto/asymmetric/pq/kyber/[params as kyber_params, operations as kyber_ops, indcpa]
import ../src/protocols/custom_crypto/asymmetric/pq/frodo/params as frodo_params
import ../src/protocols/custom_crypto/asymmetric/pq/bike/params as bike_params
import ../src/protocols/custom_crypto/asymmetric/pq/mceliece/params as mceliece_params
import ../src/protocols/custom_crypto/asymmetric/pq/dilithium/params as dilithium_params
import ../src/protocols/custom_crypto/asymmetric/pq/falcon/[params as falcon_params,
  sign as pure_falcon_sign, pure_verify as pure_falcon_verify, randomness as falcon_randomness]
import ../src/protocols/custom_crypto/asymmetric/pq/sphincs/[params as sphincs_params, operations as sphincs_ops]
import otter_repo_evaluation

type
  BenchProfile = enum
    bpDesktop
    bpMobile

  BenchPhase = enum
    bphBoth
    bphSummary
    bphFunction

  BenchProc = proc() {.closure.}

  TimingStat = object
    count: int
    total: int64
    max: int64

  TimingEntry = tuple[name: string, stat: TimingStat]

  X25519Corpus = object
    scalarSecrets: array[32, X25519Bytes32]
    scalarPublics: array[32, X25519Bytes32]
    batch2Secrets: array[16, array[2, X25519Bytes32]]
    batch2Publics: array[16, array[2, X25519Bytes32]]
    batch4Secrets: array[8, array[4, X25519Bytes32]]
    batch4Publics: array[8, array[4, X25519Bytes32]]

var
  gFalconDeterministicBase: int = 0
  gFalconDeterministicOffset: int = 0
  gCollectorVerbose: bool = false

proc fillPattern(A: var openArray[byte], start: int = 0) =
  var
    i: int = 0
  i = 0
  while i < A.len:
    A[i] = byte((start + i) and 0xff)
    i = i + 1

proc patternSeq(n, start: int): seq[byte] =
  result = newSeq[byte](n)
  fillPattern(result, start)

proc featureList(): seq[string] =
  when defined(amd64):
    result.add("amd64")
  when defined(i386):
    result.add("i386")
  when defined(arm64):
    result.add("arm64")
  when defined(aarch64):
    result.add("aarch64")
  when defined(sse2):
    result.add("sse2")
  when defined(avx2):
    result.add("avx2")
  when defined(neon):
    result.add("neon")
  when defined(release):
    result.add("release")
  when defined(otterTiming):
    result.add("otterTiming")
  when defined(frodoAvx2SaStripeSse):
    result.add("frodoAvx2SaStripeSse")
  when defined(ntruMulTmp):
    result.add("ntruMulTmp")
  when defined(ntruMulRows):
    result.add("ntruMulRows")
  when defined(ntruMulRowsUnroll4):
    result.add("ntruMulRowsUnroll4")
  when defined(ntruMulCoeff):
    result.add("ntruMulCoeff")
  when defined(ntruMulToom4):
    result.add("ntruMulToom4")
  when defined(ntruMulToom4K2):
    result.add("ntruMulToom4K2")
  when not defined(ntruMulTmp) and not defined(ntruMulRows) and
      not defined(ntruMulRowsUnroll4) and not defined(ntruMulCoeff) and
      not defined(ntruMulToom4) and not defined(ntruMulToom4K2):
    result.add("ntruMulToom4K2Default")
  when defined(ntruIsoSample):
    result.add("ntruIsoSample")
  when defined(saberMulRows):
    result.add("saberMulRows")
  when defined(saberMulRowsUnroll4):
    result.add("saberMulRowsUnroll4")
  when defined(saberMulCoeff):
    result.add("saberMulCoeff")
  when defined(saberMulToom4):
    result.add("saberMulToom4")
  when defined(saberMulToom4Mod):
    result.add("saberMulToom4Mod")
  when defined(saberMulToom4Cached):
    result.add("saberMulToom4Cached")
  when defined(saberMulNttScalar):
    result.add("saberMulNttScalar")
  when defined(saberHeapBuffers):
    result.add("saberHeapBuffers")
  else:
    result.add("saberStackBuffersDefault")
  when defined(saberStackBuffers):
    result.add("saberStackBuffers")

proc compiledBackendLabel(): string =
  when defined(avx2) and defined(sse2) and defined(frodoAvx2SaStripeSse):
    result = "native_avx2_sse128_sa"
  elif defined(avx2):
    result = "native_avx2"
  elif defined(neon) or defined(arm64) or defined(aarch64):
    result = "native_neon"
  elif defined(sse2):
    result = "native_sse2"
  else:
    result = "native_scalar"

proc parseProfile(s: string): BenchProfile =
  let lower = s.toLowerAscii()
  if lower == "mobile" or lower == "phone" or lower == "android":
    return bpMobile
  result = bpDesktop

proc parseArgs(): tuple[
    outPath: string,
    deviceLabel: string,
    deviceKind: string,
    deviceModel: string,
    deviceOs: string,
    profile: BenchProfile,
    onlyFamilies: seq[string],
    onlyImplementations: seq[string],
    onlyBackends: seq[string],
    verbose: bool,
    loopScale: float,
    phase: BenchPhase] =
  result.loopScale = 1.0
  var
    p = initOptParser(commandLineParams())
  result.deviceLabel = getEnv("COMPUTERNAME", "desktop")
  result.deviceKind = "desktop"
  result.deviceModel = ""
  result.deviceOs = hostOS
  result.profile = bpDesktop
  while true:
    p.next()
    case p.kind
    of cmdEnd:
      break
    of cmdLongOption, cmdShortOption:
      case p.key
      of "out", "o":
        result.outPath = p.val
      of "device-label":
        result.deviceLabel = p.val
      of "device-kind":
        result.deviceKind = p.val
      of "device-model":
        result.deviceModel = p.val
      of "device-os":
        result.deviceOs = p.val
      of "profile":
        result.profile = parseProfile(p.val)
      of "only":
        for item in p.val.split(','):
          let trimmed = item.strip().toLowerAscii()
          if trimmed.len > 0:
            result.onlyFamilies.add(trimmed)
      of "implementation", "impl":
        for item in p.val.split(','):
          let trimmed = item.strip().toLowerAscii()
          if trimmed.len > 0:
            result.onlyImplementations.add(trimmed)
      of "backend":
        for item in p.val.split(','):
          let trimmed = item.strip().toLowerAscii()
          if trimmed.len > 0:
            result.onlyBackends.add(trimmed)
      of "verbose", "v":
        result.verbose = true
      of "scale":
        try:
          result.loopScale = parseFloat(p.val)
        except ValueError:
          result.loopScale = 1.0
      of "phase":
        let lower = p.val.toLowerAscii()
        case lower
        of "summary":
          result.phase = bphSummary
        of "function", "functions":
          result.phase = bphFunction
        else:
          result.phase = bphBoth
      else:
        discard
    of cmdArgument:
      if result.outPath.len == 0:
        result.outPath = p.key

proc benchLoops(profile: BenchProfile, family, variant, mode: string): tuple[loops, warmup, opsPerCall: int] =
  result.opsPerCall = 1
  if family == "x25519":
    if mode == "batch4":
      result.opsPerCall = 4
      if profile == bpDesktop:
        result.loops = 3000
        result.warmup = 64
      else:
        result.loops = 0
        result.warmup = 0
      return
    if mode == "batch2":
      result.opsPerCall = 2
      if profile == bpDesktop:
        result.loops = 6000
        result.warmup = 96
      else:
        result.loops = 2000
        result.warmup = 32
      return
    if profile == bpDesktop:
      result.loops = 12000
      result.warmup = 128
    else:
      result.loops = 4000
      result.warmup = 48
    return

  if family == "kyber":
    if profile == bpDesktop:
      result.loops = 80
      result.warmup = 4
    else:
      result.loops = 12
      result.warmup = 1
    return

  if family == "frodo":
    if profile == bpDesktop:
      result.warmup = 1
      case variant
      of "frodo640aes", "frodo640shake":
        result.loops = 8
      of "frodo976aes", "frodo976shake":
        result.loops = 4
      else:
        result.loops = 2
    else:
      result.warmup = 0
      case variant
      of "frodo640aes", "frodo640shake":
        result.loops = 2
      else:
        result.loops = 1
    return

  if family == "ntru":
    result.warmup = 0
    if profile == bpDesktop:
      case variant
      of "ntruHps4096821", "ntruHrss701":
        result.loops = 1
      else:
        result.loops = 2
    else:
      result.loops = 1
    return

  if family == "saber":
    if profile == bpDesktop:
      result.warmup = 1
      case variant
      of "fireSaber":
        result.loops = 2
      else:
        result.loops = 4
    else:
      result.warmup = 0
      result.loops = 1
    return

  if family == "bike":
    if profile == bpDesktop:
      result.loops = 12
      result.warmup = 2
    else:
      result.loops = 3
      result.warmup = 0
    return

  if family == "mceliece":
    if profile == bpDesktop:
      result.loops = 1
      result.warmup = 0
    else:
      result.loops = 1
      result.warmup = 0
    return

  if family == "dilithium":
    if profile == bpDesktop:
      result.loops = 10
      result.warmup = 1
    else:
      result.loops = 3
      result.warmup = 0
    return

  if family == "falcon":
    if profile == bpDesktop:
      result.loops = 2
      result.warmup = 0
    else:
      result.loops = 1
      result.warmup = 0
    return

  if family == "sphincs":
    if profile == bpDesktop:
      result.loops = 1
      result.warmup = 0
    else:
      result.loops = 1
      result.warmup = 0
    return

proc functionLoops(profile: BenchProfile, family: string): tuple[loops, warmup: int] =
  if family == "x25519":
    if profile == bpDesktop:
      result.loops = 32
      result.warmup = 4
    else:
      result.loops = 16
      result.warmup = 2
    return
  if family == "kyber":
    if profile == bpDesktop:
      result.loops = 4
      result.warmup = 1
    else:
      result.loops = 2
      result.warmup = 0
    return
  if family == "frodo":
    if profile == bpDesktop:
      result.loops = 1
      result.warmup = 0
    else:
      result.loops = 1
      result.warmup = 0
    return
  if family == "ntru":
    result.loops = 1
    result.warmup = 0
    return
  if family == "saber":
    if profile == bpDesktop:
      result.loops = 1
      result.warmup = 0
    else:
      result.loops = 1
      result.warmup = 0
    return
  if family == "bike":
    if profile == bpDesktop:
      result.loops = 3
      result.warmup = 1
    else:
      result.loops = 1
      result.warmup = 0
    return
  if family == "mceliece":
    result.loops = 1
    result.warmup = 0
    return
  if family == "dilithium":
    if profile == bpDesktop:
      result.loops = 3
      result.warmup = 1
    else:
      result.loops = 1
      result.warmup = 0
    return
  if family == "falcon":
    result.loops = 1
    result.warmup = 0
    return
  if family == "sphincs":
    result.loops = 1
    result.warmup = 0
    return

proc applyScale(count: int, scale: float): int =
  if count <= 0:
    return 0
  if scale <= 0:
    return 1
  result = int(ceil(float(count) * scale))
  if result < 1:
    result = 1

proc applyScale(cfg: var tuple[loops, warmup, opsPerCall: int], scale: float) =
  cfg.loops = applyScale(cfg.loops, scale)
  cfg.warmup = (if cfg.warmup == 0: 0 else: applyScale(cfg.warmup, scale))

proc applyScale(cfg: var tuple[loops, warmup: int], scale: float) =
  cfg.loops = applyScale(cfg.loops, scale)
  cfg.warmup = (if cfg.warmup == 0: 0 else: applyScale(cfg.warmup, scale))

proc familyEnabled(onlyFamilies: seq[string], family: string): bool =
  if onlyFamilies.len == 0:
    return true
  if family == "falcon" and ("falcon512" in onlyFamilies or "falcon-512" in onlyFamilies or
      "falcon1024" in onlyFamilies or "falcon-1024" in onlyFamilies):
    return true
  result = family.toLowerAscii() in onlyFamilies

proc falconVariantEnabled(onlyFamilies: seq[string], v: FalconVariant): bool =
  if onlyFamilies.len == 0 or "falcon" in onlyFamilies:
    return true
  case v
  of falcon512:
    result = "falcon512" in onlyFamilies or "falcon-512" in onlyFamilies
  of falcon1024:
    result = "falcon1024" in onlyFamilies or "falcon-1024" in onlyFamilies

proc implEnabled(onlyImplementations: seq[string], implementation: string): bool =
  if onlyImplementations.len == 0:
    return true
  result = implementation.toLowerAscii() in onlyImplementations

proc backendEnabled(onlyBackends: seq[string], backend: string): bool =
  if onlyBackends.len == 0:
    return true
  result = backend.toLowerAscii() in onlyBackends

proc trace(verbose: bool, msg: string) =
  if verbose:
    echo msg

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
    cmp(a.name, b.name)
  )

proc buildMetadata(deviceLabel, deviceKind, deviceModel, deviceOs: string, profile: BenchProfile,
    scale: float, phase: BenchPhase): JsonNode =
  var
    featureNodes: seq[JsonNode] = @[]
  for f in featureList():
    featureNodes.add(%f)
  result = %*{
    "generated_local": now().format("yyyy-MM-dd'T'HH:mm:sszzz"),
    "generated_utc": getTime().utc.format("yyyy-MM-dd'T'HH:mm:ss'Z'"),
    "device_label": deviceLabel,
    "device_kind": deviceKind,
    "device_model": deviceModel,
    "device_os": deviceOs,
    "profile": (if profile == bpDesktop: "desktop" else: "mobile"),
    "loop_scale": scale,
    "phase": (case phase
      of bphSummary: "summary"
      of bphFunction: "function"
      of bphBoth: "both"),
    "compiled_backend": compiledBackendLabel(),
    "features": featureNodes
  }

proc addSummaryRow(rows: var seq[JsonNode], deviceLabel, deviceKind, family, variant,
    implementation, backend, operation: string, loops, warmup, opsPerCall: int, body: BenchProc,
    verbose: bool = false) =
  var
    i: int = 0
    elapsedNs: int64 = 0
    start: MonoTime
  trace(verbose or gCollectorVerbose, "summary-row:" & family & ":" & variant & ":" & implementation & ":" & backend &
    ":" & operation & ":loops=" & $loops)
  i = 0
  while i < warmup:
    body()
    i = i + 1
  start = getMonoTime()
  i = 0
  while i < loops:
    body()
    i = i + 1
  elapsedNs = inNanoseconds(getMonoTime() - start)
  rows.add(%*{
    "kind": "summary",
    "device_label": deviceLabel,
    "device_kind": deviceKind,
    "family": family,
    "variant": variant,
    "implementation": implementation,
    "backend": backend,
    "operation": operation,
    "loops": loops,
    "warmup": warmup,
    "ops_per_call": opsPerCall,
    "total_ns": elapsedNs,
    "avg_ns_per_call": (if loops > 0: float(elapsedNs) / float(loops) else: 0.0),
    "avg_ns_per_op": (if loops > 0 and opsPerCall > 0: float(elapsedNs) / float(loops * opsPerCall) else: 0.0)
  })

proc addSummaryRowFromNs(rows: var seq[JsonNode], deviceLabel, deviceKind, family, variant,
    implementation, backend, operation: string, loops, warmup, opsPerCall: int, elapsedNs: int64) =
  rows.add(%*{
    "kind": "summary",
    "device_label": deviceLabel,
    "device_kind": deviceKind,
    "family": family,
    "variant": variant,
    "implementation": implementation,
    "backend": backend,
    "operation": operation,
    "loops": loops,
    "warmup": warmup,
    "ops_per_call": opsPerCall,
    "total_ns": elapsedNs,
    "avg_ns_per_call": (if loops > 0: float(elapsedNs) / float(loops) else: 0.0),
    "avg_ns_per_op": (if loops > 0 and opsPerCall > 0: float(elapsedNs) / float(loops * opsPerCall) else: 0.0)
  })

proc addFunctionRows(rows: var seq[JsonNode], deviceLabel, deviceKind, family, variant,
    implementation, backend, operation, groupName: string, loops, warmup: int, body: BenchProc,
    verbose: bool = false) =
  var
    entries: seq[OtterTimingTuple] = @[]
    stats: seq[TimingEntry] = @[]
    i: int = 0
    avgTicks: int64 = 0
  trace(verbose or gCollectorVerbose, "function-group:" & family & ":" & variant & ":" & implementation & ":" & backend &
    ":" & operation & ":loops=" & $loops)
  i = 0
  while i < warmup:
    body()
    i = i + 1
  clearTimings()
  i = 0
  while i < loops:
    otterSpan(groupName):
      body()
    i = i + 1
  entries = snapshotTimings()
  stats = aggregateTimings(entries)
  for entry in stats:
    if entry.stat.count > 0:
      avgTicks = entry.stat.total div entry.stat.count
    else:
      avgTicks = 0
    rows.add(%*{
      "kind": "function",
      "device_label": deviceLabel,
      "device_kind": deviceKind,
      "family": family,
      "variant": variant,
      "implementation": implementation,
      "backend": backend,
      "operation": operation,
      "group_name": groupName,
      "function_name": entry.name,
      "loops": loops,
      "warmup": warmup,
      "call_count": entry.stat.count,
      "total_ticks": entry.stat.total,
      "avg_ticks": avgTicks,
      "max_ticks": entry.stat.max
    })

proc initX25519Corpus(S: var X25519Corpus) =
  var
    i: int = 0
    j: int = 0
    seedA: seq[byte]
    seedB: seq[byte]
  i = 0
  while i < S.scalarSecrets.len:
    seedA = newSeq[byte](32)
    seedB = newSeq[byte](32)
    j = 0
    while j < 32:
      seedA[j] = byte((17 + 29 * i + 7 * j) and 0xff)
      seedB[j] = byte((101 + 13 * i + 5 * j) and 0xff)
      j = j + 1
    var
      kpA = x25519_pass4.x25519TyrKeypairFromSeed(seedA)
      kpB = x25519_pass4.x25519TyrKeypairFromSeed(seedB)
    S.scalarSecrets[i] = toFixed32(kpA.secretKey)
    S.scalarPublics[i] = toFixed32(kpB.publicKey)
    i = i + 1
  i = 0
  while i < S.batch2Secrets.len:
    S.batch2Secrets[i][0] = S.scalarSecrets[2 * i]
    S.batch2Secrets[i][1] = S.scalarSecrets[2 * i + 1]
    S.batch2Publics[i][0] = S.scalarPublics[2 * i]
    S.batch2Publics[i][1] = S.scalarPublics[2 * i + 1]
    i = i + 1
  i = 0
  while i < S.batch4Secrets.len:
    for lane in 0 ..< 4:
      S.batch4Secrets[i][lane] = S.scalarSecrets[4 * i + lane]
      S.batch4Publics[i][lane] = S.scalarPublics[4 * i + lane]
    i = i + 1

proc measureX25519ScalarPass(passNo: int, corpus: var X25519Corpus, loops, warmup: int): int64 =
  var
    i: int = 0
    idx: int = 0
    outShared: X25519Bytes32
    start: MonoTime
  while i < warmup:
    case passNo
    of 1: doAssert x25519_pass1.x25519ScalarmultRaw(outShared, corpus.scalarSecrets[idx], corpus.scalarPublics[idx])
    of 2: doAssert x25519_pass2.x25519ScalarmultRaw(outShared, corpus.scalarSecrets[idx], corpus.scalarPublics[idx])
    of 3: doAssert x25519_pass3.x25519ScalarmultRaw(outShared, corpus.scalarSecrets[idx], corpus.scalarPublics[idx])
    of 4: doAssert x25519_pass4.x25519ScalarmultRaw(outShared, corpus.scalarSecrets[idx], corpus.scalarPublics[idx])
    else: discard
    idx = (idx + 1) mod corpus.scalarSecrets.len
    inc i
  start = getMonoTime()
  i = 0
  while i < loops:
    case passNo
    of 1: doAssert x25519_pass1.x25519ScalarmultRaw(outShared, corpus.scalarSecrets[idx], corpus.scalarPublics[idx])
    of 2: doAssert x25519_pass2.x25519ScalarmultRaw(outShared, corpus.scalarSecrets[idx], corpus.scalarPublics[idx])
    of 3: doAssert x25519_pass3.x25519ScalarmultRaw(outShared, corpus.scalarSecrets[idx], corpus.scalarPublics[idx])
    of 4: doAssert x25519_pass4.x25519ScalarmultRaw(outShared, corpus.scalarSecrets[idx], corpus.scalarPublics[idx])
    else: discard
    idx = (idx + 1) mod corpus.scalarSecrets.len
    inc i
  result = inNanoseconds(getMonoTime() - start)

when defined(sse2):
  proc measureX25519Batch2SsePass(passNo: int, corpus: var X25519Corpus, loops, warmup: int): int64 =
    var
      i: int = 0
      idx: int = 0
      outShared: array[2, X25519Bytes32]
      ok: array[2, bool]
      start: MonoTime
    while i < warmup:
      case passNo
      of 1: ok = x25519_pass1.x25519ScalarmultBatchSse2x(outShared, corpus.batch2Secrets[idx], corpus.batch2Publics[idx])
      of 2: ok = x25519_pass2.x25519ScalarmultBatchSse2x(outShared, corpus.batch2Secrets[idx], corpus.batch2Publics[idx])
      of 3: ok = x25519_pass3.x25519ScalarmultBatchSse2x(outShared, corpus.batch2Secrets[idx], corpus.batch2Publics[idx])
      of 4: ok = x25519_pass4.x25519ScalarmultBatchSse2x(outShared, corpus.batch2Secrets[idx], corpus.batch2Publics[idx])
      else: discard
      doAssert ok[0] and ok[1]
      idx = (idx + 1) mod corpus.batch2Secrets.len
      inc i
    start = getMonoTime()
    i = 0
    while i < loops:
      case passNo
      of 1: ok = x25519_pass1.x25519ScalarmultBatchSse2x(outShared, corpus.batch2Secrets[idx], corpus.batch2Publics[idx])
      of 2: ok = x25519_pass2.x25519ScalarmultBatchSse2x(outShared, corpus.batch2Secrets[idx], corpus.batch2Publics[idx])
      of 3: ok = x25519_pass3.x25519ScalarmultBatchSse2x(outShared, corpus.batch2Secrets[idx], corpus.batch2Publics[idx])
      of 4: ok = x25519_pass4.x25519ScalarmultBatchSse2x(outShared, corpus.batch2Secrets[idx], corpus.batch2Publics[idx])
      else: discard
      doAssert ok[0] and ok[1]
      idx = (idx + 1) mod corpus.batch2Secrets.len
      inc i
    result = inNanoseconds(getMonoTime() - start)

when defined(neon) or defined(arm64) or defined(aarch64):
  proc measureX25519Batch2NeonPass(passNo: int, corpus: var X25519Corpus, loops, warmup: int): int64 =
    var
      i: int = 0
      idx: int = 0
      outShared: array[2, X25519Bytes32]
      ok: array[2, bool]
      start: MonoTime
    while i < warmup:
      case passNo
      of 1: ok = x25519_pass1.x25519ScalarmultBatchNeon2x(outShared, corpus.batch2Secrets[idx], corpus.batch2Publics[idx])
      of 2: ok = x25519_pass2.x25519ScalarmultBatchNeon2x(outShared, corpus.batch2Secrets[idx], corpus.batch2Publics[idx])
      of 3: ok = x25519_pass3.x25519ScalarmultBatchNeon2x(outShared, corpus.batch2Secrets[idx], corpus.batch2Publics[idx])
      of 4: ok = x25519_pass4.x25519ScalarmultBatchNeon2x(outShared, corpus.batch2Secrets[idx], corpus.batch2Publics[idx])
      else: discard
      doAssert ok[0] and ok[1]
      idx = (idx + 1) mod corpus.batch2Secrets.len
      inc i
    start = getMonoTime()
    i = 0
    while i < loops:
      case passNo
      of 1: ok = x25519_pass1.x25519ScalarmultBatchNeon2x(outShared, corpus.batch2Secrets[idx], corpus.batch2Publics[idx])
      of 2: ok = x25519_pass2.x25519ScalarmultBatchNeon2x(outShared, corpus.batch2Secrets[idx], corpus.batch2Publics[idx])
      of 3: ok = x25519_pass3.x25519ScalarmultBatchNeon2x(outShared, corpus.batch2Secrets[idx], corpus.batch2Publics[idx])
      of 4: ok = x25519_pass4.x25519ScalarmultBatchNeon2x(outShared, corpus.batch2Secrets[idx], corpus.batch2Publics[idx])
      else: discard
      doAssert ok[0] and ok[1]
      idx = (idx + 1) mod corpus.batch2Secrets.len
      inc i
    result = inNanoseconds(getMonoTime() - start)

when defined(avx2):
  proc measureX25519Batch4AvxPass(passNo: int, corpus: var X25519Corpus, loops, warmup: int): int64 =
    var
      i: int = 0
      idx: int = 0
      outShared: array[4, X25519Bytes32]
      ok: array[4, bool]
      start: MonoTime
    while i < warmup:
      case passNo
      of 1: ok = x25519_pass1.x25519ScalarmultBatchAvx4x(outShared, corpus.batch4Secrets[idx], corpus.batch4Publics[idx])
      of 2: ok = x25519_pass2.x25519ScalarmultBatchAvx4x(outShared, corpus.batch4Secrets[idx], corpus.batch4Publics[idx])
      of 3: ok = x25519_pass3.x25519ScalarmultBatchAvx4x(outShared, corpus.batch4Secrets[idx], corpus.batch4Publics[idx])
      of 4: ok = x25519_pass4.x25519ScalarmultBatchAvx4x(outShared, corpus.batch4Secrets[idx], corpus.batch4Publics[idx])
      else: discard
      doAssert ok[0] and ok[1] and ok[2] and ok[3]
      idx = (idx + 1) mod corpus.batch4Secrets.len
      inc i
    start = getMonoTime()
    i = 0
    while i < loops:
      case passNo
      of 1: ok = x25519_pass1.x25519ScalarmultBatchAvx4x(outShared, corpus.batch4Secrets[idx], corpus.batch4Publics[idx])
      of 2: ok = x25519_pass2.x25519ScalarmultBatchAvx4x(outShared, corpus.batch4Secrets[idx], corpus.batch4Publics[idx])
      of 3: ok = x25519_pass3.x25519ScalarmultBatchAvx4x(outShared, corpus.batch4Secrets[idx], corpus.batch4Publics[idx])
      of 4: ok = x25519_pass4.x25519ScalarmultBatchAvx4x(outShared, corpus.batch4Secrets[idx], corpus.batch4Publics[idx])
      else: discard
      doAssert ok[0] and ok[1] and ok[2] and ok[3]
      idx = (idx + 1) mod corpus.batch4Secrets.len
      inc i
    result = inNanoseconds(getMonoTime() - start)

proc makeX25519ScalarBench(
    work: proc(outShared: var X25519Bytes32, secretKey, publicKey: X25519Bytes32): bool {.nimcall.},
    corpus: X25519Corpus): BenchProc =
  var
    idx: int = 0
  result = proc() =
    var
      outShared: X25519Bytes32
    doAssert work(outShared, corpus.scalarSecrets[idx], corpus.scalarPublics[idx])
    idx = (idx + 1) mod corpus.scalarSecrets.len

proc makeX25519Batch2Bench(
    work: proc(outShared: var array[2, X25519Bytes32], secretKeys, publicKeys: array[2, X25519Bytes32]): array[2, bool] {.nimcall.},
    corpus: X25519Corpus): BenchProc =
  var
    idx: int = 0
  result = proc() =
    var
      outShared: array[2, X25519Bytes32]
      ok: array[2, bool]
    ok = work(outShared, corpus.batch2Secrets[idx], corpus.batch2Publics[idx])
    doAssert ok[0] and ok[1]
    idx = (idx + 1) mod corpus.batch2Secrets.len

proc makeX25519Batch4Bench(
    work: proc(outShared: var array[4, X25519Bytes32], secretKeys, publicKeys: array[4, X25519Bytes32]): array[4, bool] {.nimcall.},
    corpus: X25519Corpus): BenchProc =
  var
    idx: int = 0
  result = proc() =
    var
      outShared: array[4, X25519Bytes32]
      ok: array[4, bool]
    ok = work(outShared, corpus.batch4Secrets[idx], corpus.batch4Publics[idx])
    doAssert ok[0] and ok[1] and ok[2] and ok[3]
    idx = (idx + 1) mod corpus.batch4Secrets.len

proc falconDeterministicCallback(randomArray: ptr uint8, bytesToRead: csize_t) {.cdecl.} =
  var
    outBytes = cast[ptr UncheckedArray[uint8]](randomArray)
    i: int = 0
  while i < int(bytesToRead):
    outBytes[i] = byte((gFalconDeterministicBase + gFalconDeterministicOffset + i) and 0xff)
    i = i + 1
  gFalconDeterministicOffset = gFalconDeterministicOffset + int(bytesToRead)

proc resetFalconDeterministic(base: int) =
  gFalconDeterministicBase = base
  gFalconDeterministicOffset = 0

proc makeKyberRoundtripBench(v: KyberVariant): BenchProc =
  var
    keySeed = patternSeq(32, 0x10 + ord(v) * 17)
    envSeed = patternSeq(32, 0x60 + ord(v) * 13)
  result = proc() =
    let kp = kyberTyrKeypair(v, keySeed)
    let env = kyberTyrEncaps(v, kp.publicKey, envSeed)
    let shared = kyberTyrDecaps(v, kp.secretKey, env.ciphertext)
    doAssert shared == env.sharedSecret

proc makeKyberFunctionBench(v: KyberVariant): BenchProc =
  var
    p = kyber_params.params(v)
    seed = patternSeq(32, 0x21 + ord(v) * 7)
    coins = patternSeq(32, 0x41 + ord(v) * 9)
    msg = patternSeq(32, 0x61 + ord(v) * 11)
  result = proc() =
    discard genMatrix(p, seed, false)
    let kp = indcpaKeypair(p, seed)
    let ct = indcpaEnc(p, msg, kp.pk, coins)
    let dec = indcpaDec(p, ct, kp.sk)
    doAssert dec == msg
    let tyrKp = kyberTyrKeypair(v, seed)
    let env = kyberTyrEncaps(v, tyrKp.publicKey, coins)
    let shared = kyberTyrDecaps(v, tyrKp.secretKey, env.ciphertext)
    doAssert shared == env.sharedSecret

proc makeFrodoRoundtripBench(v: FrodoVariant): BenchProc =
  var
    p = frodo_params.params(v)
    keyRnd = patternSeq(p.keypairRandomBytes, 0x31 + ord(v) * 5)
    encRnd = patternSeq(p.encapsRandomBytes, 0x71 + ord(v) * 3)
  result = proc() =
    let kp = frodoTyrKeypair(v, keyRnd)
    let env = frodoTyrEncaps(v, kp.publicKey, encRnd)
    let shared = frodoTyrDecaps(v, kp.secretKey, env.ciphertext)
    doAssert shared == env.sharedSecret

proc makeNtruRoundtripBench(v: custom_ntru.NtruVariant): BenchProc =
  var
    keySeed = patternSeq(48, 0x33 + ord(v) * 5)
    encSeed = patternSeq(48, 0x73 + ord(v) * 7)
  result = proc() =
    let kp = custom_ntru.ntruTyrKeypair(v, keySeed)
    let env = custom_ntru.ntruTyrEncaps(v, kp.publicKey, encSeed)
    let shared = custom_ntru.ntruTyrDecaps(v, kp.secretKey, env.ciphertext)
    doAssert shared == env.sharedSecret

proc makeSaberRoundtripBench(v: custom_saber.SaberVariant): BenchProc =
  var
    keySeed = patternSeq(48, 0x35 + ord(v) * 5)
    encSeed = patternSeq(48, 0x75 + ord(v) * 7)
  result = proc() =
    let kp = custom_saber.saberTyrKeypair(v, keySeed)
    let env = custom_saber.saberTyrEncaps(v, kp.publicKey, encSeed)
    let shared = custom_saber.saberTyrDecaps(v, kp.secretKey, env.ciphertext)
    doAssert shared == env.sharedSecret

proc makeBikeRoundtripBench(v: BikeVariant): BenchProc =
  var
    keyRnd = patternSeq(bike_params.bikeKeypairRandomBytes, 0x25 + ord(v) * 9)
    encRnd = patternSeq(bike_params.bikeEncapsRandomBytes, 0x65 + ord(v) * 7)
  result = proc() =
    let kp = bikeTyrKeypair(v, keyRnd)
    let env = bikeTyrEncaps(v, kp.publicKey, encRnd)
    let shared = bikeTyrDecaps(v, kp.secretKey, env.ciphertext)
    doAssert shared == env.sharedSecret

proc makeMcElieceRoundtripBench(v: McElieceVariant): BenchProc =
  var
    keySeed = patternSeq(32, 0x19 + ord(v) * 15)
  result = proc() =
    let kp = mcelieceTyrKeypair(v, keySeed)
    let env = mcelieceTyrEncaps(v, kp.publicKey)
    let shared = mcelieceTyrDecaps(v, kp.secretKey, env.ciphertext)
    doAssert shared == env.sharedSecret

proc makeDilithiumRoundtripBench(v: DilithiumVariant): BenchProc =
  var
    p = dilithium_params.params(v)
    seed = patternSeq(dilithium_params.dilithiumSeedBytes, 0x29 + ord(v) * 19)
    rnd = patternSeq(dilithium_params.dilithiumRndBytes, 0x79 + ord(v) * 13)
    msg = patternSeq(2048, 0x51 + ord(v) * 5)
  result = proc() =
    let kp = dilithiumTyrKeypair(v, seed)
    let sig = dilithiumTyrSignDerand(v, msg, kp.secretKey, rnd)
    doAssert dilithiumTyrVerify(v, msg, sig, kp.publicKey)
    doAssert sig.len == p.signatureBytes

proc makeFalconSignVerifyBench(v: FalconVariant, preparedMode, purePreparedMode: bool): BenchProc =
  var
    msg = patternSeq(128 + ord(v) * 32, 0x35 + ord(v) * 11)
  result = proc() =
    falcon_randomness.falconSetRandombytesCallback(falconDeterministicCallback)
    defer:
      falcon_randomness.falconClearRandombytesCallback()
    resetFalconDeterministic(0x20 + ord(v) * 0x20)
    let kp = falconTyrKeypair(v, falconScalar)
    if purePreparedMode:
      var prepared = pure_falcon_sign.prepareSecretKey(v, kp.secretKey)
      defer:
        pure_falcon_sign.clearExpandedSecret(prepared)
      let sig = pure_falcon_sign.falconSignPrepared(prepared, msg, v)
      doAssert pure_falcon_verify.falconVerifyPure(v, msg, sig, kp.publicKey)
      return
    if preparedMode:
      var prepared = falconTyrPrepareSecret(v, kp.secretKey, falconScalar)
      defer:
        falconTyrClearPreparedSecret(prepared)
      resetFalconDeterministic(0x70 + ord(v) * 0x20)
      let sig = falconTyrSignPrepared(prepared, msg)
      doAssert falconTyrVerify(v, msg, sig, kp.publicKey, falconScalar)
      return
    resetFalconDeterministic(0x50 + ord(v) * 0x20)
    let sig = falconTyrSign(v, msg, kp.secretKey, falconScalar)
    doAssert falconTyrVerify(v, msg, sig, kp.publicKey, falconScalar)

proc makeSphincsRoundtripBench(v: SphincsVariant): BenchProc =
  var
    p = sphincs_params.params(v)
    seed = patternSeq(p.seedBytes, 0x2B + ord(v) * 7)
    optrand = patternSeq(16, 0x7B + ord(v) * 13)
    msg = patternSeq(64, 0x55 + ord(v) * 9)
  result = proc() =
    let kp = sphincsTyrSeedKeypair(v, seed)
    let sig = sphincsTyrSignDerand(v, msg, kp.secretKey, optrand)
    doAssert sphincsTyrVerify(v, msg, sig, kp.publicKey)

proc collectSummaryRows(rows: var seq[JsonNode], deviceLabel, deviceKind: string, profile: BenchProfile,
    onlyFamilies, onlyImplementations, onlyBackends: seq[string], verbose: bool, scale: float) =
  var
    xCorpus: X25519Corpus
    cfg: tuple[loops, warmup, opsPerCall: int]
  initX25519Corpus(xCorpus)
  if familyEnabled(onlyFamilies, "x25519"):
    trace(verbose, "summary:x25519")
    cfg = benchLoops(profile, "x25519", "curve25519", "scalar")
    applyScale(cfg, scale)
    if implEnabled(onlyImplementations, "pass1") and backendEnabled(onlyBackends, "scalar"):
      addSummaryRowFromNs(rows, deviceLabel, deviceKind, "x25519", "curve25519", "pass1", "scalar", "shared_secret",
        cfg.loops, cfg.warmup, cfg.opsPerCall, measureX25519ScalarPass(1, xCorpus, cfg.loops, cfg.warmup))
    if implEnabled(onlyImplementations, "pass2") and backendEnabled(onlyBackends, "scalar"):
      addSummaryRowFromNs(rows, deviceLabel, deviceKind, "x25519", "curve25519", "pass2", "scalar", "shared_secret",
        cfg.loops, cfg.warmup, cfg.opsPerCall, measureX25519ScalarPass(2, xCorpus, cfg.loops, cfg.warmup))
    if implEnabled(onlyImplementations, "pass3") and backendEnabled(onlyBackends, "scalar"):
      addSummaryRowFromNs(rows, deviceLabel, deviceKind, "x25519", "curve25519", "pass3", "scalar", "shared_secret",
        cfg.loops, cfg.warmup, cfg.opsPerCall, measureX25519ScalarPass(3, xCorpus, cfg.loops, cfg.warmup))
    if implEnabled(onlyImplementations, "pass4") and backendEnabled(onlyBackends, "scalar"):
      addSummaryRowFromNs(rows, deviceLabel, deviceKind, "x25519", "curve25519", "pass4", "scalar", "shared_secret",
        cfg.loops, cfg.warmup, cfg.opsPerCall, measureX25519ScalarPass(4, xCorpus, cfg.loops, cfg.warmup))
    when defined(sse2):
      cfg = benchLoops(profile, "x25519", "curve25519", "batch2")
      applyScale(cfg, scale)
      if implEnabled(onlyImplementations, "pass1") and backendEnabled(onlyBackends, "sse2x"):
        addSummaryRowFromNs(rows, deviceLabel, deviceKind, "x25519", "curve25519", "pass1", "sse2x", "shared_secret_batch",
          cfg.loops, cfg.warmup, cfg.opsPerCall, measureX25519Batch2SsePass(1, xCorpus, cfg.loops, cfg.warmup))
      if implEnabled(onlyImplementations, "pass2") and backendEnabled(onlyBackends, "sse2x"):
        addSummaryRowFromNs(rows, deviceLabel, deviceKind, "x25519", "curve25519", "pass2", "sse2x", "shared_secret_batch",
          cfg.loops, cfg.warmup, cfg.opsPerCall, measureX25519Batch2SsePass(2, xCorpus, cfg.loops, cfg.warmup))
      if implEnabled(onlyImplementations, "pass3") and backendEnabled(onlyBackends, "sse2x"):
        addSummaryRowFromNs(rows, deviceLabel, deviceKind, "x25519", "curve25519", "pass3", "sse2x", "shared_secret_batch",
          cfg.loops, cfg.warmup, cfg.opsPerCall, measureX25519Batch2SsePass(3, xCorpus, cfg.loops, cfg.warmup))
      if implEnabled(onlyImplementations, "pass4") and backendEnabled(onlyBackends, "sse2x"):
        addSummaryRowFromNs(rows, deviceLabel, deviceKind, "x25519", "curve25519", "pass4", "sse2x", "shared_secret_batch",
          cfg.loops, cfg.warmup, cfg.opsPerCall, measureX25519Batch2SsePass(4, xCorpus, cfg.loops, cfg.warmup))
    when defined(neon) or defined(arm64) or defined(aarch64):
      cfg = benchLoops(profile, "x25519", "curve25519", "batch2")
      applyScale(cfg, scale)
      if implEnabled(onlyImplementations, "pass1") and backendEnabled(onlyBackends, "neon2x"):
        addSummaryRowFromNs(rows, deviceLabel, deviceKind, "x25519", "curve25519", "pass1", "neon2x", "shared_secret_batch",
          cfg.loops, cfg.warmup, cfg.opsPerCall, measureX25519Batch2NeonPass(1, xCorpus, cfg.loops, cfg.warmup))
      if implEnabled(onlyImplementations, "pass2") and backendEnabled(onlyBackends, "neon2x"):
        addSummaryRowFromNs(rows, deviceLabel, deviceKind, "x25519", "curve25519", "pass2", "neon2x", "shared_secret_batch",
          cfg.loops, cfg.warmup, cfg.opsPerCall, measureX25519Batch2NeonPass(2, xCorpus, cfg.loops, cfg.warmup))
      if implEnabled(onlyImplementations, "pass3") and backendEnabled(onlyBackends, "neon2x"):
        addSummaryRowFromNs(rows, deviceLabel, deviceKind, "x25519", "curve25519", "pass3", "neon2x", "shared_secret_batch",
          cfg.loops, cfg.warmup, cfg.opsPerCall, measureX25519Batch2NeonPass(3, xCorpus, cfg.loops, cfg.warmup))
      if implEnabled(onlyImplementations, "pass4") and backendEnabled(onlyBackends, "neon2x"):
        addSummaryRowFromNs(rows, deviceLabel, deviceKind, "x25519", "curve25519", "pass4", "neon2x", "shared_secret_batch",
          cfg.loops, cfg.warmup, cfg.opsPerCall, measureX25519Batch2NeonPass(4, xCorpus, cfg.loops, cfg.warmup))
    when defined(avx2):
      cfg = benchLoops(profile, "x25519", "curve25519", "batch4")
      applyScale(cfg, scale)
      if implEnabled(onlyImplementations, "pass1") and backendEnabled(onlyBackends, "avx4x"):
        addSummaryRowFromNs(rows, deviceLabel, deviceKind, "x25519", "curve25519", "pass1", "avx4x", "shared_secret_batch",
          cfg.loops, cfg.warmup, cfg.opsPerCall, measureX25519Batch4AvxPass(1, xCorpus, cfg.loops, cfg.warmup))
      if implEnabled(onlyImplementations, "pass2") and backendEnabled(onlyBackends, "avx4x"):
        addSummaryRowFromNs(rows, deviceLabel, deviceKind, "x25519", "curve25519", "pass2", "avx4x", "shared_secret_batch",
          cfg.loops, cfg.warmup, cfg.opsPerCall, measureX25519Batch4AvxPass(2, xCorpus, cfg.loops, cfg.warmup))
      if implEnabled(onlyImplementations, "pass3") and backendEnabled(onlyBackends, "avx4x"):
        addSummaryRowFromNs(rows, deviceLabel, deviceKind, "x25519", "curve25519", "pass3", "avx4x", "shared_secret_batch",
          cfg.loops, cfg.warmup, cfg.opsPerCall, measureX25519Batch4AvxPass(3, xCorpus, cfg.loops, cfg.warmup))
      if implEnabled(onlyImplementations, "pass4") and backendEnabled(onlyBackends, "avx4x"):
        addSummaryRowFromNs(rows, deviceLabel, deviceKind, "x25519", "curve25519", "pass4", "avx4x", "shared_secret_batch",
          cfg.loops, cfg.warmup, cfg.opsPerCall, measureX25519Batch4AvxPass(4, xCorpus, cfg.loops, cfg.warmup))

  if familyEnabled(onlyFamilies, "kyber"):
    trace(verbose, "summary:kyber")
    for v in [kyber512, kyber768, kyber1024]:
      cfg = benchLoops(profile, "kyber", $v, "roundtrip")
      applyScale(cfg, scale)
      addSummaryRow(rows, deviceLabel, deviceKind, "kyber", $v, "tyr", compiledBackendLabel(), "roundtrip",
        cfg.loops, cfg.warmup, cfg.opsPerCall, makeKyberRoundtripBench(v))

  if familyEnabled(onlyFamilies, "frodo"):
    trace(verbose, "summary:frodo")
    for v in [frodo640aes, frodo640shake, frodo976aes, frodo976shake, frodo1344aes, frodo1344shake]:
      cfg = benchLoops(profile, "frodo", $v, "roundtrip")
      applyScale(cfg, scale)
      addSummaryRow(rows, deviceLabel, deviceKind, "frodo", $v, "tyr", compiledBackendLabel(), "roundtrip",
        cfg.loops, cfg.warmup, cfg.opsPerCall, makeFrodoRoundtripBench(v))

  if familyEnabled(onlyFamilies, "ntru"):
    trace(verbose, "summary:ntru")
    for v in [custom_ntru.ntruHps2048509, custom_ntru.ntruHps2048677,
        custom_ntru.ntruHps4096821, custom_ntru.ntruHrss701]:
      cfg = benchLoops(profile, "ntru", $v, "roundtrip")
      applyScale(cfg, scale)
      addSummaryRow(rows, deviceLabel, deviceKind, "ntru", $v, "tyr", compiledBackendLabel(), "roundtrip",
        cfg.loops, cfg.warmup, cfg.opsPerCall, makeNtruRoundtripBench(v))

  if familyEnabled(onlyFamilies, "saber"):
    trace(verbose, "summary:saber")
    for v in [custom_saber.lightSaber, custom_saber.saber, custom_saber.fireSaber]:
      cfg = benchLoops(profile, "saber", $v, "roundtrip")
      applyScale(cfg, scale)
      addSummaryRow(rows, deviceLabel, deviceKind, "saber", $v, "tyr", compiledBackendLabel(), "roundtrip",
        cfg.loops, cfg.warmup, cfg.opsPerCall, makeSaberRoundtripBench(v))

  if familyEnabled(onlyFamilies, "bike"):
    trace(verbose, "summary:bike")
    cfg = benchLoops(profile, "bike", "bikeL1", "roundtrip")
    applyScale(cfg, scale)
    addSummaryRow(rows, deviceLabel, deviceKind, "bike", "bikeL1", "tyr", compiledBackendLabel(), "roundtrip",
      cfg.loops, cfg.warmup, cfg.opsPerCall, makeBikeRoundtripBench(bikeL1))

  if familyEnabled(onlyFamilies, "mceliece"):
    trace(verbose, "summary:mceliece")
    for v in [mceliece6688128f, mceliece6960119f, mceliece8192128f]:
      cfg = benchLoops(profile, "mceliece", $v, "roundtrip")
      applyScale(cfg, scale)
      addSummaryRow(rows, deviceLabel, deviceKind, "mceliece", $v, "tyr", compiledBackendLabel(), "roundtrip",
        cfg.loops, cfg.warmup, cfg.opsPerCall, makeMcElieceRoundtripBench(v))

  if familyEnabled(onlyFamilies, "dilithium"):
    trace(verbose, "summary:dilithium")
    for v in [dilithium44, dilithium65, dilithium87]:
      cfg = benchLoops(profile, "dilithium", $v, "sign_verify")
      applyScale(cfg, scale)
      addSummaryRow(rows, deviceLabel, deviceKind, "dilithium", $v, "tyr", compiledBackendLabel(), "sign_verify",
        cfg.loops, cfg.warmup, cfg.opsPerCall, makeDilithiumRoundtripBench(v))

  if familyEnabled(onlyFamilies, "falcon"):
    trace(verbose, "summary:falcon")
    for v in [falcon512, falcon1024]:
      if not falconVariantEnabled(onlyFamilies, v):
        continue
      cfg = benchLoops(profile, "falcon", $v, "sign_verify")
      applyScale(cfg, scale)
      addSummaryRow(rows, deviceLabel, deviceKind, "falcon", $v, "scalar", "scalar", "sign_verify",
        cfg.loops, cfg.warmup, cfg.opsPerCall, makeFalconSignVerifyBench(v, false, false))
      addSummaryRow(rows, deviceLabel, deviceKind, "falcon", $v, "prepared", "scalar", "sign_verify",
        cfg.loops, cfg.warmup, cfg.opsPerCall, makeFalconSignVerifyBench(v, true, false))
      addSummaryRow(rows, deviceLabel, deviceKind, "falcon", $v, "pure_prepared", "scalar", "sign_verify",
        cfg.loops, cfg.warmup, cfg.opsPerCall, makeFalconSignVerifyBench(v, false, true))

  if familyEnabled(onlyFamilies, "sphincs"):
    trace(verbose, "summary:sphincs")
    cfg = benchLoops(profile, "sphincs", "sphincsShake128fSimple", "sign_verify")
    applyScale(cfg, scale)
    addSummaryRow(rows, deviceLabel, deviceKind, "sphincs", "sphincsShake128fSimple", "tyr",
      compiledBackendLabel(), "sign_verify", cfg.loops, cfg.warmup, cfg.opsPerCall,
      makeSphincsRoundtripBench(sphincsShake128fSimple))

proc collectFunctionRows(rows: var seq[JsonNode], deviceLabel, deviceKind: string, profile: BenchProfile,
    onlyFamilies, onlyImplementations, onlyBackends: seq[string], verbose: bool, scale: float) =
  var
    xCorpus: X25519Corpus
    cfg: tuple[loops, warmup: int]
  initX25519Corpus(xCorpus)
  if familyEnabled(onlyFamilies, "x25519"):
    trace(verbose, "functions:x25519")
    cfg = functionLoops(profile, "x25519")
    applyScale(cfg, scale)
    addFunctionRows(rows, deviceLabel, deviceKind, "x25519", "curve25519", "pass1", "scalar",
      "shared_secret", "x25519.pass1.scalar", cfg.loops, cfg.warmup,
      makeX25519ScalarBench(x25519_pass1.x25519ScalarmultRaw, xCorpus))
    addFunctionRows(rows, deviceLabel, deviceKind, "x25519", "curve25519", "pass2", "scalar",
      "shared_secret", "x25519.pass2.scalar", cfg.loops, cfg.warmup,
      makeX25519ScalarBench(x25519_pass2.x25519ScalarmultRaw, xCorpus))
    addFunctionRows(rows, deviceLabel, deviceKind, "x25519", "curve25519", "pass3", "scalar",
      "shared_secret", "x25519.pass3.scalar", cfg.loops, cfg.warmup,
      makeX25519ScalarBench(x25519_pass3.x25519ScalarmultRaw, xCorpus))
    addFunctionRows(rows, deviceLabel, deviceKind, "x25519", "curve25519", "pass4", "scalar",
      "shared_secret", "x25519.pass4.scalar", cfg.loops, cfg.warmup,
      makeX25519ScalarBench(x25519_pass4.x25519ScalarmultRaw, xCorpus))
    when defined(sse2):
      addFunctionRows(rows, deviceLabel, deviceKind, "x25519", "curve25519", "pass4", "sse2x",
        "shared_secret_batch", "x25519.pass4.sse2x", cfg.loops, cfg.warmup,
        makeX25519Batch2Bench(x25519_pass4.x25519ScalarmultBatchSse2x, xCorpus))
    when defined(neon) or defined(arm64) or defined(aarch64):
      addFunctionRows(rows, deviceLabel, deviceKind, "x25519", "curve25519", "pass4", "neon2x",
        "shared_secret_batch", "x25519.pass4.neon2x", cfg.loops, cfg.warmup,
        makeX25519Batch2Bench(x25519_pass4.x25519ScalarmultBatchNeon2x, xCorpus))
    when defined(avx2):
      addFunctionRows(rows, deviceLabel, deviceKind, "x25519", "curve25519", "pass4", "avx4x",
        "shared_secret_batch", "x25519.pass4.avx4x", cfg.loops, cfg.warmup,
        makeX25519Batch4Bench(x25519_pass4.x25519ScalarmultBatchAvx4x, xCorpus))

  if familyEnabled(onlyFamilies, "kyber"):
    trace(verbose, "functions:kyber")
    for v in [kyber512, kyber768, kyber1024]:
      cfg = functionLoops(profile, "kyber")
      applyScale(cfg, scale)
      addFunctionRows(rows, deviceLabel, deviceKind, "kyber", $v, "tyr", compiledBackendLabel(),
        "roundtrip_hotspots", "kyber." & $v, cfg.loops, cfg.warmup, makeKyberFunctionBench(v))

  if familyEnabled(onlyFamilies, "frodo"):
    trace(verbose, "functions:frodo")
    for v in [frodo640aes, frodo640shake, frodo976aes, frodo976shake, frodo1344aes, frodo1344shake]:
      cfg = functionLoops(profile, "frodo")
      applyScale(cfg, scale)
      addFunctionRows(rows, deviceLabel, deviceKind, "frodo", $v, "tyr", compiledBackendLabel(),
        "roundtrip_hotspots", "frodo." & $v, cfg.loops, cfg.warmup, makeFrodoRoundtripBench(v))

  if familyEnabled(onlyFamilies, "ntru"):
    trace(verbose, "functions:ntru")
    for v in [custom_ntru.ntruHps2048509, custom_ntru.ntruHps2048677,
        custom_ntru.ntruHps4096821, custom_ntru.ntruHrss701]:
      cfg = functionLoops(profile, "ntru")
      applyScale(cfg, scale)
      addFunctionRows(rows, deviceLabel, deviceKind, "ntru", $v, "tyr", compiledBackendLabel(),
        "roundtrip_hotspots", "ntru." & $v, cfg.loops, cfg.warmup, makeNtruRoundtripBench(v))

  if familyEnabled(onlyFamilies, "saber"):
    trace(verbose, "functions:saber")
    for v in [custom_saber.lightSaber, custom_saber.saber, custom_saber.fireSaber]:
      cfg = functionLoops(profile, "saber")
      applyScale(cfg, scale)
      addFunctionRows(rows, deviceLabel, deviceKind, "saber", $v, "tyr", compiledBackendLabel(),
        "roundtrip_hotspots", "saber." & $v, cfg.loops, cfg.warmup, makeSaberRoundtripBench(v))

  if familyEnabled(onlyFamilies, "bike"):
    trace(verbose, "functions:bike")
    cfg = functionLoops(profile, "bike")
    applyScale(cfg, scale)
    addFunctionRows(rows, deviceLabel, deviceKind, "bike", "bikeL1", "tyr", compiledBackendLabel(),
      "roundtrip_hotspots", "bike.bikeL1", cfg.loops, cfg.warmup, makeBikeRoundtripBench(bikeL1))

  if familyEnabled(onlyFamilies, "mceliece"):
    trace(verbose, "functions:mceliece")
    for v in [mceliece6688128f, mceliece6960119f, mceliece8192128f]:
      cfg = functionLoops(profile, "mceliece")
      applyScale(cfg, scale)
      addFunctionRows(rows, deviceLabel, deviceKind, "mceliece", $v, "tyr", compiledBackendLabel(),
        "roundtrip_hotspots", "mceliece." & $v, cfg.loops, cfg.warmup, makeMcElieceRoundtripBench(v))

  if familyEnabled(onlyFamilies, "dilithium"):
    trace(verbose, "functions:dilithium")
    for v in [dilithium44, dilithium65, dilithium87]:
      cfg = functionLoops(profile, "dilithium")
      applyScale(cfg, scale)
      addFunctionRows(rows, deviceLabel, deviceKind, "dilithium", $v, "tyr", compiledBackendLabel(),
        "sign_verify_hotspots", "dilithium." & $v, cfg.loops, cfg.warmup, makeDilithiumRoundtripBench(v))

  if familyEnabled(onlyFamilies, "falcon"):
    trace(verbose, "functions:falcon")
    for v in [falcon512, falcon1024]:
      if not falconVariantEnabled(onlyFamilies, v):
        continue
      cfg = functionLoops(profile, "falcon")
      applyScale(cfg, scale)
      addFunctionRows(rows, deviceLabel, deviceKind, "falcon", $v, "scalar", "scalar",
        "sign_verify_hotspots", "falcon.scalar." & $v, cfg.loops, cfg.warmup, makeFalconSignVerifyBench(v, false, false))
      addFunctionRows(rows, deviceLabel, deviceKind, "falcon", $v, "prepared", "scalar",
        "sign_verify_hotspots", "falcon.prepared." & $v, cfg.loops, cfg.warmup, makeFalconSignVerifyBench(v, true, false))
      addFunctionRows(rows, deviceLabel, deviceKind, "falcon", $v, "pure_prepared", "scalar",
        "sign_verify_hotspots", "falcon.pure_prepared." & $v, cfg.loops, cfg.warmup, makeFalconSignVerifyBench(v, false, true))

  if familyEnabled(onlyFamilies, "sphincs"):
    trace(verbose, "functions:sphincs")
    cfg = functionLoops(profile, "sphincs")
    applyScale(cfg, scale)
    addFunctionRows(rows, deviceLabel, deviceKind, "sphincs", "sphincsShake128fSimple", "tyr",
      compiledBackendLabel(), "sign_verify_hotspots", "sphincs.shake128f", cfg.loops, cfg.warmup,
      makeSphincsRoundtripBench(sphincsShake128fSimple))

when isMainModule:
  let args = parseArgs()
  var
    rows: seq[JsonNode] = @[]
    root: JsonNode
    payload: string = ""
  gCollectorVerbose = args.verbose
  if args.phase in {bphBoth, bphSummary}:
    collectSummaryRows(rows, args.deviceLabel, args.deviceKind, args.profile,
      args.onlyFamilies, args.onlyImplementations, args.onlyBackends, args.verbose, args.loopScale)
  if args.phase in {bphBoth, bphFunction}:
    collectFunctionRows(rows, args.deviceLabel, args.deviceKind, args.profile,
      args.onlyFamilies, args.onlyImplementations, args.onlyBackends, args.verbose, args.loopScale)
  root = %*{
    "metadata": buildMetadata(args.deviceLabel, args.deviceKind, args.deviceModel, args.deviceOs, args.profile, args.loopScale, args.phase),
    "rows": rows
  }
  when defined(otterTiming):
    clearTimings()
  payload = pretty(root)
  if args.outPath.len > 0:
    createDir(parentDir(args.outPath))
    writeFile(args.outPath, payload)
  else:
    echo payload
