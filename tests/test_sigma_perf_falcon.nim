# ============================================================
# | Sigma Falcon Benchmark                                  |
# | -> Compare Tyr Falcon phases against the current liboqs |
# ============================================================

import std/[os, strutils, unittest]

import ../src/protocols/custom_crypto/falcon as custom_falcon
import ../src/protocols/custom_crypto/asymmetric/pq/falcon/[format, sign as pure_falcon_sign, pure_verify as pure_falcon_verify]
import sigma_bench_and_eval

when defined(hasLibOqs):
  import ../src/protocols/bindings/liboqs

const
  keypairLoops = 5
  prepareLoops = 10
  signLoops = 10
  preparedSignLoops = 10
  verifyLoops = 30
  warmKeypair = 1
  warmPrepare = 1
  warmSign = 1
  warmPreparedSign = 1
  warmVerify = 2

type
  BenchGroup = object
    title: string
    loops: int
    warmup: int
    algos: seq[BenchAlgo]

when defined(hasLibOqs):
  var
    oqsDeterministicBase: int = 0
    oqsDeterministicOffset: int = 0

  proc oqsDeterministicCallback(random_array: ptr uint8, bytes_to_read: csize_t) {.cdecl.} =
    var
      outBytes = cast[ptr UncheckedArray[uint8]](random_array)
      i: int = 0
    while i < int(bytes_to_read):
      outBytes[i] = byte((oqsDeterministicBase + oqsDeterministicOffset + i) and 0xff)
      i = i + 1
    oqsDeterministicOffset = oqsDeterministicOffset + int(bytes_to_read)

  proc resetOqsDeterministic(base: int) =
    oqsDeterministicBase = base
    oqsDeterministicOffset = 0

var
  falconDeterministicBase: int = 0
  falconDeterministicOffset: int = 0

proc falconDeterministicCallback(random_array: ptr uint8, bytes_to_read: csize_t) {.cdecl.} =
  var
    outBytes = cast[ptr UncheckedArray[uint8]](random_array)
    i: int = 0
  while i < int(bytes_to_read):
    outBytes[i] = byte((falconDeterministicBase + falconDeterministicOffset + i) and 0xff)
    i = i + 1
  falconDeterministicOffset = falconDeterministicOffset + int(bytes_to_read)

proc resetFalconDeterministic(base: int) =
  falconDeterministicBase = base
  falconDeterministicOffset = 0

proc fillPattern(bs: var openArray[byte], start: int = 0) =
  var
    i: int = 0
  while i < bs.len:
    bs[i] = byte((start + i) and 0xff)
    i = i + 1

proc appendGroup(groups: var seq[BenchGroup], title: string, loops, warmup: int,
    algos: seq[BenchAlgo]) =
  var
    filtered: seq[BenchAlgo] = @[]
  for algo in algos:
    if algo.name.len > 0 and algo.run != nil:
      filtered.add(algo)
  if filtered.len == 0:
    return
  groups.add(BenchGroup(title: title, loops: loops, warmup: warmup, algos: filtered))

proc printGroup(g: BenchGroup, results: openArray[BenchResult]) =
  echo ""
  echo "## ", g.title, " loops=", g.loops, " warmup=", g.warmup
  echo formatBenchResults(results)

proc selectedBackend(): custom_falcon.FalconBackend =
  custom_falcon.defaultBackend()

proc tyrBackendLabel(): string =
  "tyr_falcon_" & custom_falcon.backendName(selectedBackend())

proc methodName(v: custom_falcon.FalconVariant): string =
  case v
  of custom_falcon.falcon512:
    "Falcon-512"
  of custom_falcon.falcon1024:
    "Falcon-1024"

proc buildCustomKeypair(name: string, v: custom_falcon.FalconVariant, seedBase: int): BenchAlgo =
  let p = custom_falcon.falconParamsTable[v]
  var
    pk = newSeq[byte](p.publicKeyBytes)
    sk = newSeq[byte](p.secretKeyBytes)
    counter: int = 0
  result.name = name
  result.run = proc() =
    resetFalconDeterministic(seedBase + counter)
    custom_falcon.falconTyrKeypairInto(v, pk, sk, selectedBackend())
    counter = counter + 1

proc buildCustomPrepare(name: string, v: custom_falcon.FalconVariant, seedBase: int): BenchAlgo =
  let p = custom_falcon.falconParamsTable[v]
  var
    pk = newSeq[byte](p.publicKeyBytes)
    sk = newSeq[byte](p.secretKeyBytes)
  resetFalconDeterministic(seedBase)
  custom_falcon.falconTyrKeypairInto(v, pk, sk, selectedBackend())
  result.name = name
  result.run = proc() =
    var prepared = custom_falcon.falconTyrPrepareSecret(v, sk, selectedBackend())
    custom_falcon.falconTyrClearPreparedSecret(prepared)

proc buildPurePrepare(name: string, v: custom_falcon.FalconVariant, seedBase: int): BenchAlgo =
  let p = custom_falcon.falconParamsTable[v]
  var
    pk = newSeq[byte](p.publicKeyBytes)
    sk = newSeq[byte](p.secretKeyBytes)
  resetFalconDeterministic(seedBase)
  custom_falcon.falconTyrKeypairInto(v, pk, sk, selectedBackend())
  result.name = name
  result.run = proc() =
    var prepared = pure_falcon_sign.prepareSecretKey(v, sk)
    pure_falcon_sign.clearExpandedSecret(prepared)

proc buildCustomSign(name: string, v: custom_falcon.FalconVariant, seedBase,
    rndBase: int, msg: openArray[byte]): BenchAlgo =
  let p = custom_falcon.falconParamsTable[v]
  let msgBuf = @msg
  var
    pk = newSeq[byte](p.publicKeyBytes)
    sk = newSeq[byte](p.secretKeyBytes)
    sig = newSeq[byte](p.signatureBytes)
    sigLen: int = 0
    counter: int = 0
  resetFalconDeterministic(seedBase)
  custom_falcon.falconTyrKeypairInto(v, pk, sk, selectedBackend())
  result.name = name
  result.run = proc() =
    resetFalconDeterministic(rndBase + counter)
    custom_falcon.falconTyrSignInto(v, sig, sigLen, msgBuf, sk, selectedBackend())
    counter = counter + 1

proc buildPureSign(name: string, v: custom_falcon.FalconVariant, seedBase,
    rndBase: int, msg: openArray[byte]): BenchAlgo =
  let p = custom_falcon.falconParamsTable[v]
  let msgBuf = @msg
  var
    pk = newSeq[byte](p.publicKeyBytes)
    sk = newSeq[byte](p.secretKeyBytes)
    counter: int = 0
  resetFalconDeterministic(seedBase)
  custom_falcon.falconTyrKeypairInto(v, pk, sk, selectedBackend())
  result.name = name
  result.run = proc() =
    var
      nonce = newSeq[byte](falconNonceLen)
      seed = newSeq[byte](pure_falcon_sign.falconSignSeedBytes)
    fillPattern(nonce, rndBase + counter)
    fillPattern(seed, rndBase + counter + falconNonceLen)
    discard pure_falcon_sign.falconSignDerand(v, msgBuf, sk, nonce, seed)
    counter = counter + 1

proc buildCustomPreparedSign(name: string, v: custom_falcon.FalconVariant, seedBase,
    rndBase: int, msg: openArray[byte]): BenchAlgo =
  let p = custom_falcon.falconParamsTable[v]
  let msgBuf = @msg
  var
    pk = newSeq[byte](p.publicKeyBytes)
    sk = newSeq[byte](p.secretKeyBytes)
    prepared: custom_falcon.FalconPreparedSecret
    sig = newSeq[byte](p.signatureBytes)
    sigLen: int = 0
    counter: int = 0
  resetFalconDeterministic(seedBase)
  custom_falcon.falconTyrKeypairInto(v, pk, sk, selectedBackend())
  prepared = custom_falcon.falconTyrPrepareSecret(v, sk, selectedBackend())
  result.name = name
  result.run = proc() =
    resetFalconDeterministic(rndBase + counter)
    custom_falcon.falconTyrSignPreparedInto(prepared, sig, sigLen, msgBuf)
    counter = counter + 1

proc buildPurePreparedSign(name: string, v: custom_falcon.FalconVariant, seedBase,
    rndBase: int, msg: openArray[byte]): BenchAlgo =
  let p = custom_falcon.falconParamsTable[v]
  let msgBuf = @msg
  var
    pk = newSeq[byte](p.publicKeyBytes)
    sk = newSeq[byte](p.secretKeyBytes)
    prepared: pure_falcon_sign.FalconExpandedSecret
    counter: int = 0
  resetFalconDeterministic(seedBase)
  custom_falcon.falconTyrKeypairInto(v, pk, sk, selectedBackend())
  prepared = pure_falcon_sign.prepareSecretKey(v, sk)
  result.name = name
  result.run = proc() =
    var
      nonce = newSeq[byte](falconNonceLen)
      seed = newSeq[byte](pure_falcon_sign.falconSignSeedBytes)
    fillPattern(nonce, rndBase + counter)
    fillPattern(seed, rndBase + counter + falconNonceLen)
    discard pure_falcon_sign.falconSignPreparedDerand(prepared, msgBuf, nonce, seed, v)
    counter = counter + 1

proc buildCustomVerify(name: string, v: custom_falcon.FalconVariant, seedBase,
    rndBase: int, msg: openArray[byte]): BenchAlgo =
  let p = custom_falcon.falconParamsTable[v]
  let msgBuf = @msg
  var
    pk = newSeq[byte](p.publicKeyBytes)
    sk = newSeq[byte](p.secretKeyBytes)
    sig: seq[byte]
  resetFalconDeterministic(seedBase)
  custom_falcon.falconTyrKeypairInto(v, pk, sk, selectedBackend())
  resetFalconDeterministic(rndBase)
  sig = custom_falcon.falconTyrSign(v, msgBuf, sk, selectedBackend())
  result.name = name
  result.run = proc() =
    doAssert custom_falcon.falconTyrVerify(v, msgBuf, sig, pk, selectedBackend())

proc buildPureVerify(name: string, v: custom_falcon.FalconVariant, seedBase,
    rndBase: int, msg: openArray[byte]): BenchAlgo =
  let p = custom_falcon.falconParamsTable[v]
  let msgBuf = @msg
  var
    pk = newSeq[byte](p.publicKeyBytes)
    sk = newSeq[byte](p.secretKeyBytes)
    nonce = newSeq[byte](falconNonceLen)
    seed = newSeq[byte](pure_falcon_sign.falconSignSeedBytes)
    sig: seq[byte]
  resetFalconDeterministic(seedBase)
  custom_falcon.falconTyrKeypairInto(v, pk, sk, selectedBackend())
  fillPattern(nonce, rndBase)
  fillPattern(seed, rndBase + falconNonceLen)
  sig = pure_falcon_sign.falconSignDerand(v, msgBuf, sk, nonce, seed)
  result.name = name
  result.run = proc() =
    doAssert pure_falcon_verify.falconVerifyPure(v, msgBuf, sig, pk)

when defined(hasLibOqs):
  proc printLiboqsProfile() =
    var
      buildRoot: string = getEnv("LIBOQS_BUILD_ROOT").strip()
      profilePath: string = ""
    if buildRoot.len == 0:
      buildRoot = joinPath(getCurrentDir(), "build", "liboqs")
    profilePath = joinPath(buildRoot, "install", "tyr_liboqs_profile.txt")
    echo "liboqs build root: ", buildRoot
    if fileExists(profilePath):
      echo readFile(profilePath).strip()
    else:
      echo "liboqs profile metadata not found at ", profilePath

  proc buildOqsKeypair(name, algId: string, seedBase: int,
      holders: var seq[ptr OqsSig]): BenchAlgo =
    let sig = OQS_SIG_new(algId)
    if sig == nil:
      echo "Skipping ", name, ": liboqs algorithm unavailable (", algId, ")"
      return
    holders.add(sig)
    var
      pk = newSeq[uint8](int sig[].length_public_key)
      sk = newSeq[uint8](int sig[].length_secret_key)
      counter: int = 0
    result.name = name
    result.run = proc() =
      resetOqsDeterministic(seedBase + counter)
      requireSuccess(OQS_SIG_keypair(sig, addr pk[0], addr sk[0]), name & "_keypair")
      counter = counter + 1

  proc buildOqsSign(name, algId: string, seedBase, rndBase: int, msg: openArray[byte],
      holders: var seq[ptr OqsSig]): BenchAlgo =
    let sig = OQS_SIG_new(algId)
    if sig == nil:
      echo "Skipping ", name, ": liboqs algorithm unavailable (", algId, ")"
      return
    holders.add(sig)
    let msgBuf = @msg
    var
      pk = newSeq[uint8](int sig[].length_public_key)
      sk = newSeq[uint8](int sig[].length_secret_key)
      signature = newSeq[uint8](int sig[].length_signature)
      sigLen: csize_t = 0
      counter: int = 0
    resetOqsDeterministic(seedBase)
    requireSuccess(OQS_SIG_keypair(sig, addr pk[0], addr sk[0]), name & "_setup_keypair")
    result.name = name
    result.run = proc() =
      resetOqsDeterministic(rndBase + counter)
      sigLen = 0
      requireSuccess(OQS_SIG_sign(sig, addr signature[0], addr sigLen, unsafeAddr msgBuf[0],
        csize_t(msgBuf.len), addr sk[0]), name & "_sign")
      counter = counter + 1

  proc buildOqsVerify(name, algId: string, seedBase, rndBase: int, msg: openArray[byte],
      holders: var seq[ptr OqsSig]): BenchAlgo =
    let sig = OQS_SIG_new(algId)
    if sig == nil:
      echo "Skipping ", name, ": liboqs algorithm unavailable (", algId, ")"
      return
    holders.add(sig)
    let msgBuf = @msg
    var
      pk = newSeq[uint8](int sig[].length_public_key)
      sk = newSeq[uint8](int sig[].length_secret_key)
      signature = newSeq[uint8](int sig[].length_signature)
      sigLen: csize_t = 0
    resetOqsDeterministic(seedBase)
    requireSuccess(OQS_SIG_keypair(sig, addr pk[0], addr sk[0]), name & "_setup_keypair")
    resetOqsDeterministic(rndBase)
    requireSuccess(OQS_SIG_sign(sig, addr signature[0], addr sigLen, unsafeAddr msgBuf[0],
      csize_t(msgBuf.len), addr sk[0]), name & "_setup_sign")
    result.name = name
    result.run = proc() =
      requireSuccess(OQS_SIG_verify(sig, unsafeAddr msgBuf[0], csize_t(msgBuf.len), addr signature[0],
        sigLen, addr pk[0]), name & "_verify")

proc runGroup(g: BenchGroup) =
  let results = compareAlgorithms(g.algos, loops = g.loops, warmup = g.warmup)
  check results.len == g.algos.len
  for r in results:
    check r.loops == g.loops
    check r.totalTicks > 0
    check r.avgTicks >= 0
  printGroup(g, results)

suite "Sigma Falcon performance":
  test "compare split Tyr Falcon phases against liboqs":
    when not defined(hasLibOqs):
      checkpoint("Sigma Falcon benchmark requires -d:hasLibOqs")
    else:
      var
        sigHolders: seq[ptr OqsSig] = @[]
        groups: seq[BenchGroup] = @[]
        msgShort = newSeq[byte](128)
        msgLong = newSeq[byte](2048)
        i: int = 0
      if not ensureLibOqsLoaded():
        checkpoint("liboqs runtime unavailable; skipping Sigma Falcon benchmark")
      else:
        OQS_randombytes_custom_algorithm(oqsDeterministicCallback)
        custom_falcon.falconSetRandombytesCallback(falconDeterministicCallback)
        defer:
          custom_falcon.falconClearRandombytesCallback()
          discard OQS_randombytes_switch_algorithm(oqsRandAlgSystem.cstring)
          i = 0
          while i < sigHolders.len:
            if sigHolders[i] != nil:
              OQS_SIG_free(sigHolders[i])
            i = i + 1

        echo ""
        echo "Tyr build profile: ", tyrBackendLabel()
        printLiboqsProfile()

        fillPattern(msgShort, 0x31)
        fillPattern(msgLong, 0x55)

        for v in [custom_falcon.falcon512, custom_falcon.falcon1024]:
          appendGroup(groups, methodName(v) & " keypair", keypairLoops, warmKeypair, @[
            buildCustomKeypair(tyrBackendLabel() & "_" & methodName(v).toLowerAscii() & "_keypair",
              v, 0x10 + ord(v) * 17),
            buildOqsKeypair("oqs_" & methodName(v).toLowerAscii() & "_keypair", methodName(v),
              0x10 + ord(v) * 17, sigHolders)
          ])
          appendGroup(groups, methodName(v) & " prepare expanded key", prepareLoops, warmPrepare, @[
            buildCustomPrepare(tyrBackendLabel() & "_" & methodName(v).toLowerAscii() & "_prepare",
              v, 0x28 + ord(v) * 17)
            ,
            buildPurePrepare("tyr_falcon_pure_" & methodName(v).toLowerAscii() & "_prepare",
              v, 0x28 + ord(v) * 17)
          ])
          appendGroup(groups, methodName(v) & " sign", signLoops, warmSign, @[
            buildCustomSign(tyrBackendLabel() & "_" & methodName(v).toLowerAscii() & "_sign", v,
              0x40 + ord(v) * 17, 0x70 + ord(v) * 17, msgLong),
            buildPureSign("tyr_falcon_pure_" & methodName(v).toLowerAscii() & "_sign", v,
              0x40 + ord(v) * 17, 0x70 + ord(v) * 17, msgLong),
            buildOqsSign("oqs_" & methodName(v).toLowerAscii() & "_sign", methodName(v),
              0x40 + ord(v) * 17, 0x70 + ord(v) * 17, msgLong, sigHolders)
          ])
          appendGroup(groups, methodName(v) & " sign (prepared)", preparedSignLoops, warmPreparedSign, @[
            buildCustomPreparedSign(tyrBackendLabel() & "_" & methodName(v).toLowerAscii() & "_sign_prepared",
              v, 0x58 + ord(v) * 17, 0x88 + ord(v) * 17, msgLong),
            buildPurePreparedSign("tyr_falcon_pure_" & methodName(v).toLowerAscii() & "_sign_prepared",
              v, 0x58 + ord(v) * 17, 0x88 + ord(v) * 17, msgLong),
            buildOqsSign("oqs_" & methodName(v).toLowerAscii() & "_sign_prepared_baseline", methodName(v),
              0x58 + ord(v) * 17, 0x88 + ord(v) * 17, msgLong, sigHolders)
          ])
          appendGroup(groups, methodName(v) & " verify", verifyLoops, warmVerify, @[
            buildCustomVerify(tyrBackendLabel() & "_" & methodName(v).toLowerAscii() & "_verify", v,
              0x90 + ord(v) * 17, 0xC0 + ord(v) * 17, msgShort),
            buildPureVerify("tyr_falcon_pure_" & methodName(v).toLowerAscii() & "_verify", v,
              0x90 + ord(v) * 17, 0xC0 + ord(v) * 17, msgShort),
            buildOqsVerify("oqs_" & methodName(v).toLowerAscii() & "_verify", methodName(v),
              0x90 + ord(v) * 17, 0xC0 + ord(v) * 17, msgShort, sigHolders)
          ])

        check groups.len > 0
        for g in groups:
          runGroup(g)
