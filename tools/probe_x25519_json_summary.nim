## ==========================================================
## | X25519 JSON Summary Probe                              |
## | -> x25519-only summary collector without big imports   |
## ==========================================================

import std/[json, monotimes, os, parseopt, strutils, times]
when defined(posix):
  import std/posix

import ../src/protocols/custom_crypto/asymmetric/none_pq/[x25519_common, x25519_pass1, x25519_pass2, x25519_pass3, x25519_pass4]

type
  X25519Corpus = object
    scalarSecrets: array[32, X25519Bytes32]
    scalarPublics: array[32, X25519Bytes32]
    batch2Secrets: array[16, array[2, X25519Bytes32]]
    batch2Publics: array[16, array[2, X25519Bytes32]]

proc fillPattern(A: var openArray[byte], start: int) =
  var i = 0
  while i < A.len:
    A[i] = byte((start + i) and 0xff)
    inc i

proc initCorpus(S: var X25519Corpus) =
  var
    i = 0
    j = 0
    seedA: seq[byte]
    seedB: seq[byte]
  while i < S.scalarSecrets.len:
    seedA = newSeq[byte](32)
    seedB = newSeq[byte](32)
    j = 0
    while j < 32:
      seedA[j] = byte((17 + 29 * i + 7 * j) and 0xff)
      seedB[j] = byte((101 + 13 * i + 5 * j) and 0xff)
      inc j
    let
      kpA = x25519_pass4.x25519TyrKeypairFromSeed(seedA)
      kpB = x25519_pass4.x25519TyrKeypairFromSeed(seedB)
    S.scalarSecrets[i] = toFixed32(kpA.secretKey)
    S.scalarPublics[i] = toFixed32(kpB.publicKey)
    inc i
  i = 0
  while i < S.batch2Secrets.len:
    S.batch2Secrets[i][0] = S.scalarSecrets[2 * i]
    S.batch2Secrets[i][1] = S.scalarSecrets[2 * i + 1]
    S.batch2Publics[i][0] = S.scalarPublics[2 * i]
    S.batch2Publics[i][1] = S.scalarPublics[2 * i + 1]
    inc i

proc measureScalar(passNo, loops, warmup: int, S: var X25519Corpus): int64 =
  var
    i = 0
    idx = 0
    outShared: X25519Bytes32
    start: MonoTime
  while i < warmup:
    case passNo
    of 1: doAssert x25519_pass1.x25519ScalarmultRaw(outShared, S.scalarSecrets[idx], S.scalarPublics[idx])
    of 2: doAssert x25519_pass2.x25519ScalarmultRaw(outShared, S.scalarSecrets[idx], S.scalarPublics[idx])
    of 3: doAssert x25519_pass3.x25519ScalarmultRaw(outShared, S.scalarSecrets[idx], S.scalarPublics[idx])
    of 4: doAssert x25519_pass4.x25519ScalarmultRaw(outShared, S.scalarSecrets[idx], S.scalarPublics[idx])
    else: discard
    idx = (idx + 1) mod S.scalarSecrets.len
    inc i
  start = getMonoTime()
  i = 0
  while i < loops:
    case passNo
    of 1: doAssert x25519_pass1.x25519ScalarmultRaw(outShared, S.scalarSecrets[idx], S.scalarPublics[idx])
    of 2: doAssert x25519_pass2.x25519ScalarmultRaw(outShared, S.scalarSecrets[idx], S.scalarPublics[idx])
    of 3: doAssert x25519_pass3.x25519ScalarmultRaw(outShared, S.scalarSecrets[idx], S.scalarPublics[idx])
    of 4: doAssert x25519_pass4.x25519ScalarmultRaw(outShared, S.scalarSecrets[idx], S.scalarPublics[idx])
    else: discard
    idx = (idx + 1) mod S.scalarSecrets.len
    inc i
  result = inNanoseconds(getMonoTime() - start)

when defined(neon) or defined(arm64) or defined(aarch64):
  proc measureNeon(passNo, loops, warmup: int, S: var X25519Corpus): int64 =
    var
      i = 0
      idx = 0
      outShared: array[2, X25519Bytes32]
      ok: array[2, bool]
      start: MonoTime
    while i < warmup:
      case passNo
      of 1: ok = x25519_pass1.x25519ScalarmultBatchNeon2x(outShared, S.batch2Secrets[idx], S.batch2Publics[idx])
      of 2: ok = x25519_pass2.x25519ScalarmultBatchNeon2x(outShared, S.batch2Secrets[idx], S.batch2Publics[idx])
      of 3: ok = x25519_pass3.x25519ScalarmultBatchNeon2x(outShared, S.batch2Secrets[idx], S.batch2Publics[idx])
      of 4: ok = x25519_pass4.x25519ScalarmultBatchNeon2x(outShared, S.batch2Secrets[idx], S.batch2Publics[idx])
      else: discard
      doAssert ok[0] and ok[1]
      idx = (idx + 1) mod S.batch2Secrets.len
      inc i
    start = getMonoTime()
    i = 0
    while i < loops:
      case passNo
      of 1: ok = x25519_pass1.x25519ScalarmultBatchNeon2x(outShared, S.batch2Secrets[idx], S.batch2Publics[idx])
      of 2: ok = x25519_pass2.x25519ScalarmultBatchNeon2x(outShared, S.batch2Secrets[idx], S.batch2Publics[idx])
      of 3: ok = x25519_pass3.x25519ScalarmultBatchNeon2x(outShared, S.batch2Secrets[idx], S.batch2Publics[idx])
      of 4: ok = x25519_pass4.x25519ScalarmultBatchNeon2x(outShared, S.batch2Secrets[idx], S.batch2Publics[idx])
      else: discard
      doAssert ok[0] and ok[1]
      idx = (idx + 1) mod S.batch2Secrets.len
      inc i
    result = inNanoseconds(getMonoTime() - start)

proc addRow(rows: var JsonNode, implementation, backend, operation: string, loops, warmup, opsPerCall: int, elapsedNs: int64) =
  rows.add(%*{
    "kind": "summary",
    "device_label": "probe",
    "device_kind": "phone",
    "family": "x25519",
    "variant": "curve25519",
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

when isMainModule:
  var
    scale = 0.5
    outPath = ""
    p = initOptParser(commandLineParams())
    corpus: X25519Corpus
    rows = newJArray()
    root: JsonNode
    payload: string
    scalarLoops: int
    scalarWarmup: int
    batchLoops: int
    batchWarmup: int
  while true:
    p.next()
    case p.kind
    of cmdEnd:
      break
    of cmdLongOption, cmdShortOption:
      case p.key
      of "scale":
        scale = parseFloat(p.val)
      of "out":
        outPath = p.val
      else:
        discard
    of cmdArgument:
      discard

  initCorpus(corpus)
  scalarLoops = max(1, int(4000 * scale))
  scalarWarmup = max(1, int(48 * scale))
  batchLoops = max(1, int(2000 * scale))
  batchWarmup = max(1, int(32 * scale))
  addRow(rows, "pass1", "scalar", "shared_secret", scalarLoops, scalarWarmup, 1, measureScalar(1, scalarLoops, scalarWarmup, corpus))
  addRow(rows, "pass2", "scalar", "shared_secret", scalarLoops, scalarWarmup, 1, measureScalar(2, scalarLoops, scalarWarmup, corpus))
  addRow(rows, "pass3", "scalar", "shared_secret", scalarLoops, scalarWarmup, 1, measureScalar(3, scalarLoops, scalarWarmup, corpus))
  addRow(rows, "pass4", "scalar", "shared_secret", scalarLoops, scalarWarmup, 1, measureScalar(4, scalarLoops, scalarWarmup, corpus))
  when defined(neon) or defined(arm64) or defined(aarch64):
    addRow(rows, "pass1", "neon2x", "shared_secret_batch", batchLoops, batchWarmup, 2, measureNeon(1, batchLoops, batchWarmup, corpus))
    addRow(rows, "pass2", "neon2x", "shared_secret_batch", batchLoops, batchWarmup, 2, measureNeon(2, batchLoops, batchWarmup, corpus))
    addRow(rows, "pass3", "neon2x", "shared_secret_batch", batchLoops, batchWarmup, 2, measureNeon(3, batchLoops, batchWarmup, corpus))
    addRow(rows, "pass4", "neon2x", "shared_secret_batch", batchLoops, batchWarmup, 2, measureNeon(4, batchLoops, batchWarmup, corpus))

  root = %*{
    "metadata": {
      "generated_local": now().format("yyyy-MM-dd'T'HH:mm:sszzz"),
      "generated_utc": getTime().utc.format("yyyy-MM-dd'T'HH:mm:ss'Z'"),
      "loop_scale": scale
    },
    "rows": rows
  }
  payload = pretty(root)
  if outPath.len > 0:
    createDir(parentDir(outPath))
    writeFile(outPath, payload)
  else:
    echo payload
  if getEnv("JSON_PROBE_FAST_EXIT") == "1":
    when defined(posix):
      _exit(0)
