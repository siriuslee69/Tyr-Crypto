# ============================================================
# | Sigma Dilithium Benchmark                               |
# | -> Split ML-DSA keypair/sign/verify for Tyr vs liboqs   |
# ============================================================

import std/[os, strutils, unittest]

import ../src/protocols/custom_crypto/dilithium as custom_dilithium
import sigma_bench_and_eval

when defined(hasLibOqs):
  import ../src/protocols/bindings/liboqs

const
  keypairLoops = 30
  signLoops = 30
  verifyLoops = 80
  warmKeypair = 2
  warmSign = 2
  warmVerify = 3

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
    i = 0
    while i < int(bytes_to_read):
      outBytes[i] = byte((oqsDeterministicBase + oqsDeterministicOffset + i) and 0xff)
      i = i + 1
    oqsDeterministicOffset = oqsDeterministicOffset + int(bytes_to_read)

  proc resetOqsDeterministic(base: int) =
    oqsDeterministicBase = base
    oqsDeterministicOffset = 0

proc fillPattern(bs: var openArray[byte], start: int = 0) =
  var
    i: int = 0
  i = 0
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

proc methodName(v: custom_dilithium.DilithiumVariant): string =
  case v
  of custom_dilithium.dilithium44:
    result = oqsSigDilithium0
  of custom_dilithium.dilithium65:
    result = oqsSigDilithium1
  of custom_dilithium.dilithium87:
    result = oqsSigDilithium2

proc buildCustomKeypair(name: string, v: custom_dilithium.DilithiumVariant,
    seedBase: int): BenchAlgo =
  let p = custom_dilithium.dilithiumParamsTable[v]
  var
    pk = newSeq[byte](p.publicKeyBytes)
    sk = newSeq[byte](p.secretKeyBytes)
    seed: array[custom_dilithium.dilithiumSeedBytes, byte]
    counter: int = 0
  result.name = name
  result.run = proc() =
    fillPattern(seed, seedBase + counter)
    custom_dilithium.dilithiumTyrKeypairInto(v, pk, sk, seed)
    counter = counter + 1

proc buildCustomSign(name: string, v: custom_dilithium.DilithiumVariant,
    seedBase, rndBase: int, msg: openArray[byte]): BenchAlgo =
  let p = custom_dilithium.dilithiumParamsTable[v]
  let msgBuf = @msg
  var
    pk = newSeq[byte](p.publicKeyBytes)
    sk = newSeq[byte](p.secretKeyBytes)
    sig = newSeq[byte](p.signatureBytes)
    seed: array[custom_dilithium.dilithiumSeedBytes, byte]
    rnd: array[custom_dilithium.dilithiumRndBytes, byte]
    counter: int = 0
  fillPattern(seed, seedBase)
  custom_dilithium.dilithiumTyrKeypairInto(v, pk, sk, seed)
  result.name = name
  result.run = proc() =
    fillPattern(rnd, rndBase + counter)
    custom_dilithium.dilithiumTyrSignDerandInto(v, sig, msgBuf, sk, rnd)
    counter = counter + 1

proc buildCustomVerify(name: string, v: custom_dilithium.DilithiumVariant,
    seedBase, rndBase: int, msg: openArray[byte]): BenchAlgo =
  let p = custom_dilithium.dilithiumParamsTable[v]
  let msgBuf = @msg
  var
    pk = newSeq[byte](p.publicKeyBytes)
    sk = newSeq[byte](p.secretKeyBytes)
    sig = newSeq[byte](p.signatureBytes)
    seed: array[custom_dilithium.dilithiumSeedBytes, byte]
    rnd: array[custom_dilithium.dilithiumRndBytes, byte]
  fillPattern(seed, seedBase)
  fillPattern(rnd, rndBase)
  custom_dilithium.dilithiumTyrKeypairInto(v, pk, sk, seed)
  custom_dilithium.dilithiumTyrSignDerandInto(v, sig, msgBuf, sk, rnd)
  result.name = name
  result.run = proc() =
    doAssert custom_dilithium.dilithiumTyrVerify(v, msgBuf, sig, pk)

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

suite "Sigma Dilithium performance":
  test "compare split pure-Nim ML-DSA phases against liboqs":
    when not defined(hasLibOqs):
      checkpoint("Sigma Dilithium benchmark requires -d:hasLibOqs")
    else:
      var
        sigHolders: seq[ptr OqsSig] = @[]
        groups: seq[BenchGroup] = @[]
        msgLong = newSeq[byte](2048)
        i: int = 0
      if not ensureLibOqsLoaded():
        checkpoint("liboqs runtime unavailable; skipping Sigma Dilithium benchmark")
      else:
        OQS_randombytes_custom_algorithm(oqsDeterministicCallback)
        defer:
          discard OQS_randombytes_switch_algorithm(oqsRandAlgSystem.cstring)
          i = 0
          while i < sigHolders.len:
            if sigHolders[i] != nil:
              OQS_SIG_free(sigHolders[i])
            i = i + 1

        echo ""
        when defined(avx2):
          echo "Tyr build profile: simd_avx2"
        elif defined(sse2):
          echo "Tyr build profile: simd_sse2"
        else:
          echo "Tyr build profile: scalar"
        printLiboqsProfile()

        fillPattern(msgLong, 0x55)

        for v in [custom_dilithium.dilithium44, custom_dilithium.dilithium65,
            custom_dilithium.dilithium87]:
          appendGroup(groups, methodName(v) & " keypair", keypairLoops, warmKeypair, @[
            buildCustomKeypair("tyr_" & methodName(v).toLowerAscii() & "_keypair", v, 0x10 + ord(v) * 17),
            buildOqsKeypair("oqs_" & methodName(v).toLowerAscii() & "_keypair", methodName(v),
              0x10 + ord(v) * 17, sigHolders)
          ])
          appendGroup(groups, methodName(v) & " sign", signLoops, warmSign, @[
            buildCustomSign("tyr_" & methodName(v).toLowerAscii() & "_sign", v,
              0x40 + ord(v) * 17, 0x70 + ord(v) * 17, msgLong),
            buildOqsSign("oqs_" & methodName(v).toLowerAscii() & "_sign", methodName(v),
              0x40 + ord(v) * 17, 0x70 + ord(v) * 17, msgLong, sigHolders)
          ])
          appendGroup(groups, methodName(v) & " verify", verifyLoops, warmVerify, @[
            buildCustomVerify("tyr_" & methodName(v).toLowerAscii() & "_verify", v,
              0x90 + ord(v) * 17, 0xC0 + ord(v) * 17, msgLong),
            buildOqsVerify("oqs_" & methodName(v).toLowerAscii() & "_verify", methodName(v),
              0x90 + ord(v) * 17, 0xC0 + ord(v) * 17, msgLong, sigHolders)
          ])

        check groups.len > 0
        for g in groups:
          runGroup(g)
