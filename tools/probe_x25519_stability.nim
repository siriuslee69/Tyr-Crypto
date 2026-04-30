## ============================================================
## | X25519 Stability Probe                                   |
## | -> Minimal stress runner for one pass/backend at a time  |
## ============================================================

import std/[os, parseopt, strutils]

import ../src/protocols/custom_crypto/asymmetric/none_pq/[x25519_common, x25519_pass1, x25519_pass2, x25519_pass3, x25519_pass4]

type
  ProbeMode = enum
    pmScalar
    pmNeon2x
    pmSse2x
    pmAvx4x

  ProbePass = range[1..4]

proc fillPattern(A: var openArray[byte], start: int) =
  var i = 0
  while i < A.len:
    A[i] = byte((start + i) and 0xff)
    inc i

proc patternSeq(n, start: int): seq[byte] =
  result = newSeq[byte](n)
  fillPattern(result, start)

proc buildCorpus2(secretKeys, publicKeys: var array[2, X25519Bytes32]) =
  var
    lane = 0
    i = 0
    seedA: seq[byte]
    seedB: seq[byte]
  while lane < 2:
    seedA = newSeq[byte](32)
    seedB = newSeq[byte](32)
    i = 0
    while i < 32:
      seedA[i] = byte((31 * lane + 7 * i + 11) and 0xff)
      seedB[i] = byte((97 + 19 * lane + 5 * i) and 0xff)
      inc i
    let
      kpA = x25519_pass4.x25519TyrKeypairFromSeed(seedA)
      kpB = x25519_pass4.x25519TyrKeypairFromSeed(seedB)
    secretKeys[lane] = toFixed32(kpA.secretKey)
    publicKeys[lane] = toFixed32(kpB.publicKey)
    inc lane

proc buildCorpus4(secretKeys, publicKeys: var array[4, X25519Bytes32]) =
  var
    lane = 0
    i = 0
    seedA: seq[byte]
    seedB: seq[byte]
  while lane < 4:
    seedA = newSeq[byte](32)
    seedB = newSeq[byte](32)
    i = 0
    while i < 32:
      seedA[i] = byte((13 + 41 * lane + 9 * i) and 0xff)
      seedB[i] = byte((173 + 23 * lane + 3 * i) and 0xff)
      inc i
    let
      kpA = x25519_pass4.x25519TyrKeypairFromSeed(seedA)
      kpB = x25519_pass4.x25519TyrKeypairFromSeed(seedB)
    secretKeys[lane] = toFixed32(kpA.secretKey)
    publicKeys[lane] = toFixed32(kpB.publicKey)
    inc lane

proc parsePass(s: string): ProbePass =
  let n = parseInt(s)
  if n < 1 or n > 4:
    raise newException(ValueError, "pass must be 1..4")
  result = ProbePass(n)

proc parseMode(s: string): ProbeMode =
  case s.toLowerAscii()
  of "scalar":
    result = pmScalar
  of "neon2x":
    result = pmNeon2x
  of "sse2x":
    result = pmSse2x
  of "avx4x":
    result = pmAvx4x
  else:
    raise newException(ValueError, "mode must be scalar|neon2x|sse2x|avx4x")

proc scalarProc(passNo: ProbePass): proc(outShared: var X25519Bytes32, secretKey, publicKey: X25519Bytes32): bool {.nimcall.} =
  case passNo
  of 1: result = x25519_pass1.x25519ScalarmultRaw
  of 2: result = x25519_pass2.x25519ScalarmultRaw
  of 3: result = x25519_pass3.x25519ScalarmultRaw
  of 4: result = x25519_pass4.x25519ScalarmultRaw

when defined(neon) or defined(arm64) or defined(aarch64):
  proc batch2NeonProc(passNo: ProbePass): proc(outShared: var array[2, X25519Bytes32], secretKeys, publicKeys: array[2, X25519Bytes32]): array[2, bool] {.nimcall.} =
    case passNo
    of 1: result = x25519_pass1.x25519ScalarmultBatchNeon2x
    of 2: result = x25519_pass2.x25519ScalarmultBatchNeon2x
    of 3: result = x25519_pass3.x25519ScalarmultBatchNeon2x
    of 4: result = x25519_pass4.x25519ScalarmultBatchNeon2x

when defined(sse2):
  proc batch2SseProc(passNo: ProbePass): proc(outShared: var array[2, X25519Bytes32], secretKeys, publicKeys: array[2, X25519Bytes32]): array[2, bool] {.nimcall.} =
    case passNo
    of 1: result = x25519_pass1.x25519ScalarmultBatchSse2x
    of 2: result = x25519_pass2.x25519ScalarmultBatchSse2x
    of 3: result = x25519_pass3.x25519ScalarmultBatchSse2x
    of 4: result = x25519_pass4.x25519ScalarmultBatchSse2x

when defined(avx2):
  proc batch4Proc(passNo: ProbePass): proc(outShared: var array[4, X25519Bytes32], secretKeys, publicKeys: array[4, X25519Bytes32]): array[4, bool] {.nimcall.} =
    case passNo
    of 1: result = x25519_pass1.x25519ScalarmultBatchAvx4x
    of 2: result = x25519_pass2.x25519ScalarmultBatchAvx4x
    of 3: result = x25519_pass3.x25519ScalarmultBatchAvx4x
    of 4: result = x25519_pass4.x25519ScalarmultBatchAvx4x

when isMainModule:
  var
    passNo: ProbePass = 4
    mode: ProbeMode = pmScalar
    loops = 100
    warmup = 4
    progressEvery = 100
    p = initOptParser(commandLineParams())
  while true:
    p.next()
    case p.kind
    of cmdEnd:
      break
    of cmdLongOption, cmdShortOption:
      case p.key
      of "pass":
        passNo = parsePass(p.val)
      of "mode":
        mode = parseMode(p.val)
      of "loops":
        loops = parseInt(p.val)
      of "warmup":
        warmup = parseInt(p.val)
      of "progress":
        progressEvery = parseInt(p.val)
      else:
        discard
    of cmdArgument:
      discard

  echo "x25519 probe start pass=", passNo, " mode=", mode, " warmup=", warmup, " loops=", loops

  case mode
  of pmScalar:
    var
      secretKey = patternSeq(32, 11)
      publicKey = patternSeq(32, 91)
      kpA = x25519_pass4.x25519TyrKeypairFromSeed(secretKey)
      kpB = x25519_pass4.x25519TyrKeypairFromSeed(publicKey)
      sk = toFixed32(kpA.secretKey)
      pk = toFixed32(kpB.publicKey)
      outShared: X25519Bytes32
      work = scalarProc(passNo)
      i = 0
    while i < warmup:
      doAssert work(outShared, sk, pk)
      inc i
    i = 0
    while i < loops:
      doAssert work(outShared, sk, pk)
      if progressEvery > 0 and ((i + 1) mod progressEvery) == 0:
        echo "loop=", i + 1
      inc i
  of pmNeon2x:
    when defined(neon) or defined(arm64) or defined(aarch64):
      var
        secretKeys: array[2, X25519Bytes32]
        publicKeys: array[2, X25519Bytes32]
        outShared: array[2, X25519Bytes32]
        ok: array[2, bool]
        work = batch2NeonProc(passNo)
        i = 0
      buildCorpus2(secretKeys, publicKeys)
      while i < warmup:
        ok = work(outShared, secretKeys, publicKeys)
        doAssert ok[0] and ok[1]
        inc i
      i = 0
      while i < loops:
        ok = work(outShared, secretKeys, publicKeys)
        doAssert ok[0] and ok[1]
        if progressEvery > 0 and ((i + 1) mod progressEvery) == 0:
          echo "loop=", i + 1
        inc i
    else:
      raise newException(ValueError, "neon2x mode unavailable on this build")
  of pmSse2x:
    when defined(sse2):
      var
        secretKeys: array[2, X25519Bytes32]
        publicKeys: array[2, X25519Bytes32]
        outShared: array[2, X25519Bytes32]
        ok: array[2, bool]
        work = batch2SseProc(passNo)
        i = 0
      buildCorpus2(secretKeys, publicKeys)
      while i < warmup:
        ok = work(outShared, secretKeys, publicKeys)
        doAssert ok[0] and ok[1]
        inc i
      i = 0
      while i < loops:
        ok = work(outShared, secretKeys, publicKeys)
        doAssert ok[0] and ok[1]
        if progressEvery > 0 and ((i + 1) mod progressEvery) == 0:
          echo "loop=", i + 1
        inc i
    else:
      raise newException(ValueError, "sse2x mode unavailable on this build")
  of pmAvx4x:
    when defined(avx2):
      var
        secretKeys: array[4, X25519Bytes32]
        publicKeys: array[4, X25519Bytes32]
        outShared: array[4, X25519Bytes32]
        ok: array[4, bool]
        work = batch4Proc(passNo)
        i = 0
      buildCorpus4(secretKeys, publicKeys)
      while i < warmup:
        ok = work(outShared, secretKeys, publicKeys)
        doAssert ok[0] and ok[1] and ok[2] and ok[3]
        inc i
      i = 0
      while i < loops:
        ok = work(outShared, secretKeys, publicKeys)
        doAssert ok[0] and ok[1] and ok[2] and ok[3]
        if progressEvery > 0 and ((i + 1) mod progressEvery) == 0:
          echo "loop=", i + 1
        inc i
    else:
      raise newException(ValueError, "avx4x mode unavailable on this build")

  echo "x25519 probe done"
