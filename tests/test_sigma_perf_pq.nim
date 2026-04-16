# ============================================================
# | Sigma PQ Benchmark Test                                 |
# | -> Compare Tyr pure-Nim PQ backends vs liboqs           |
# ============================================================

import std/unittest

import ../src/protocols/custom_crypto/[kyber as custom_kyber,
  frodo as custom_frodo,
  bike as custom_bike,
  mceliece as custom_mceliece,
  dilithium as custom_dilithium,
  sphincs as custom_sphincs]
import sigma_bench_and_eval

when defined(hasLibOqs):
  import ../src/protocols/bindings/liboqs

const
  fastLoops = 100
  mediumLoops = 20
  slowLoops = 5
  verySlowLoops = 2
  warmFast = 3
  warmMedium = 2
  warmSlow = 1
  warmVerySlow = 1

type
  BenchGroup = object
    title: string
    loops: int
    warmup: int
    algos: seq[BenchAlgo]

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

proc buildCustomKyberRoundtrip(name: string, v: custom_kyber.KyberVariant): BenchAlgo =
  result.name = name
  result.run = proc() =
    let kp = custom_kyber.kyberTyrKeypair(v)
    let env = custom_kyber.kyberTyrEncaps(v, kp.publicKey)
    let shared = custom_kyber.kyberTyrDecaps(v, kp.secretKey, env.ciphertext)
    doAssert shared == env.sharedSecret

proc buildCustomFrodoRoundtrip(name: string, v: custom_frodo.FrodoVariant): BenchAlgo =
  result.name = name
  result.run = proc() =
    let kp = custom_frodo.frodoTyrKeypair(v)
    let env = custom_frodo.frodoTyrEncaps(v, kp.publicKey)
    let shared = custom_frodo.frodoTyrDecaps(v, kp.secretKey, env.ciphertext)
    doAssert shared == env.sharedSecret

proc buildCustomBikeRoundtrip(name: string, v: custom_bike.BikeVariant): BenchAlgo =
  result.name = name
  result.run = proc() =
    let kp = custom_bike.bikeTyrKeypair(v)
    let env = custom_bike.bikeTyrEncaps(v, kp.publicKey)
    let shared = custom_bike.bikeTyrDecaps(v, kp.secretKey, env.ciphertext)
    doAssert shared == env.sharedSecret

proc buildCustomMcElieceRoundtrip(name: string, v: custom_mceliece.McElieceVariant): BenchAlgo =
  result.name = name
  result.run = proc() =
    let kp = custom_mceliece.mcelieceTyrKeypair(v)
    let env = custom_mceliece.mcelieceTyrEncaps(v, kp.publicKey)
    let shared = custom_mceliece.mcelieceTyrDecaps(v, kp.secretKey, env.ciphertext)
    doAssert shared == env.sharedSecret

proc buildCustomDilithiumRoundtrip(name: string, v: custom_dilithium.DilithiumVariant,
    msg: openArray[byte]): BenchAlgo =
  let msgBuf = @msg
  result.name = name
  result.run = proc() =
    let kp = custom_dilithium.dilithiumTyrKeypair(v)
    let sig = custom_dilithium.dilithiumTyrSign(v, msgBuf, kp.secretKey)
    doAssert custom_dilithium.dilithiumTyrVerify(v, msgBuf, sig, kp.publicKey)

proc buildCustomSphincsRoundtrip(name: string, v: custom_sphincs.SphincsVariant,
    msg: openArray[byte]): BenchAlgo =
  let msgBuf = @msg
  result.name = name
  result.run = proc() =
    let kp = custom_sphincs.sphincsTyrKeypair(v)
    let sig = custom_sphincs.sphincsTyrSign(v, msgBuf, kp.secretKey)
    doAssert custom_sphincs.sphincsTyrVerify(v, msgBuf, sig, kp.publicKey)

when defined(hasLibOqs):
  proc buildOqsKemRoundtrip(name, algId: string, holders: var seq[ptr OqsKem]): BenchAlgo =
    let kem = OQS_KEM_new(algId)
    if kem == nil:
      echo "Skipping ", name, ": liboqs algorithm unavailable (", algId, ")"
      return
    holders.add(kem)
    var
      pk = newSeq[uint8](int kem[].length_public_key)
      sk = newSeq[uint8](int kem[].length_secret_key)
      ct = newSeq[uint8](int kem[].length_ciphertext)
      ssE = newSeq[uint8](int kem[].length_shared_secret)
      ssD = newSeq[uint8](int kem[].length_shared_secret)
    result.name = name
    result.run = proc() =
      requireSuccess(OQS_KEM_keypair(kem, addr pk[0], addr sk[0]), name & "_keypair")
      requireSuccess(OQS_KEM_encaps(kem, addr ct[0], addr ssE[0], addr pk[0]), name & "_encaps")
      requireSuccess(OQS_KEM_decaps(kem, addr ssD[0], addr ct[0], addr sk[0]), name & "_decaps")
      doAssert ssD == ssE

  proc buildOqsSigRoundtrip(name, algId: string, msg: openArray[byte],
      holders: var seq[ptr OqsSig]): BenchAlgo =
    let sig = OQS_SIG_new(algId)
    if sig == nil:
      echo "Skipping ", name, ": liboqs algorithm unavailable (", algId, ")"
      return
    let msgBuf = @msg
    holders.add(sig)
    var
      pk = newSeq[uint8](int sig[].length_public_key)
      sk = newSeq[uint8](int sig[].length_secret_key)
      signature = newSeq[uint8](int sig[].length_signature)
      sigLen: csize_t = 0
    result.name = name
    result.run = proc() =
      requireSuccess(OQS_SIG_keypair(sig, addr pk[0], addr sk[0]), name & "_keypair")
      sigLen = 0
      requireSuccess(OQS_SIG_sign(sig, addr signature[0], addr sigLen, unsafeAddr msgBuf[0],
        csize_t(msgBuf.len), addr sk[0]), name & "_sign")
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

suite "Sigma PQ performance":
  test "compare pure-Nim PQ backends against liboqs":
    when not defined(hasLibOqs):
      checkpoint("Sigma PQ benchmark requires -d:hasLibOqs")
    else:
      var
        kemHolders: seq[ptr OqsKem] = @[]
        sigHolders: seq[ptr OqsSig] = @[]
        groups: seq[BenchGroup] = @[]
        msgShort = newSeq[byte](64)
        msgLong = newSeq[byte](2048)
        kemAlgos: seq[BenchAlgo] = @[]
        sigAlgos: seq[BenchAlgo] = @[]
        i: int = 0
      if not ensureLibOqsLoaded():
        checkpoint("liboqs runtime unavailable; skipping Sigma PQ benchmark")
      else:
        defer:
          i = 0
          while i < kemHolders.len:
            if kemHolders[i] != nil:
              OQS_KEM_free(kemHolders[i])
            i = i + 1
          i = 0
          while i < sigHolders.len:
            if sigHolders[i] != nil:
              OQS_SIG_free(sigHolders[i])
            i = i + 1

        fillPattern(msgShort, 0x21)
        fillPattern(msgLong, 0x55)

        kemAlgos = @[
          buildCustomKyberRoundtrip("tyr_kyber768_roundtrip", custom_kyber.kyber768),
          buildOqsKemRoundtrip("oqs_kyber768_roundtrip", oqsAlgKyber768, kemHolders)
        ]
        appendGroup(groups, "Kyber768 KEM Roundtrip", fastLoops, warmFast, kemAlgos)

        kemAlgos = @[
          buildCustomKyberRoundtrip("tyr_kyber1024_roundtrip", custom_kyber.kyber1024),
          buildOqsKemRoundtrip("oqs_kyber1024_roundtrip", oqsAlgKyber1024, kemHolders)
        ]
        appendGroup(groups, "Kyber1024 KEM Roundtrip", fastLoops, warmFast, kemAlgos)

        kemAlgos = @[
          buildCustomFrodoRoundtrip("tyr_frodo976aes_roundtrip", custom_frodo.frodo976aes),
          buildOqsKemRoundtrip("oqs_frodo976aes_roundtrip", oqsAlgFrodoKEM976, kemHolders)
        ]
        appendGroup(groups, "Frodo976AES KEM Roundtrip", mediumLoops, warmMedium, kemAlgos)

        kemAlgos = @[
          buildCustomBikeRoundtrip("tyr_bike_l1_roundtrip", custom_bike.bikeL1),
          buildOqsKemRoundtrip("oqs_bike_l1_roundtrip", oqsAlgBike0, kemHolders)
        ]
        appendGroup(groups, "BIKE-L1 KEM Roundtrip", mediumLoops, warmMedium, kemAlgos)

        kemAlgos = @[
          buildCustomMcElieceRoundtrip("tyr_mceliece6688128f_roundtrip", custom_mceliece.mceliece6688128f),
          buildOqsKemRoundtrip("oqs_mceliece6688128f_roundtrip", oqsAlgClassicMcEliece6688128f, kemHolders)
        ]
        appendGroup(groups, "Classic McEliece 6688128f KEM Roundtrip", verySlowLoops, warmVerySlow, kemAlgos)

        sigAlgos = @[
          buildCustomDilithiumRoundtrip("tyr_mldsa44_roundtrip", custom_dilithium.dilithium44, msgLong),
          buildOqsSigRoundtrip("oqs_mldsa44_roundtrip", oqsSigDilithium0, msgLong, sigHolders)
        ]
        appendGroup(groups, "ML-DSA-44 Sign+Verify Roundtrip", mediumLoops, warmMedium, sigAlgos)

        sigAlgos = @[
          buildCustomDilithiumRoundtrip("tyr_mldsa65_roundtrip", custom_dilithium.dilithium65, msgLong),
          buildOqsSigRoundtrip("oqs_mldsa65_roundtrip", oqsSigDilithium1, msgLong, sigHolders)
        ]
        appendGroup(groups, "ML-DSA-65 Sign+Verify Roundtrip", mediumLoops, warmMedium, sigAlgos)

        sigAlgos = @[
          buildCustomDilithiumRoundtrip("tyr_mldsa87_roundtrip", custom_dilithium.dilithium87, msgLong),
          buildOqsSigRoundtrip("oqs_mldsa87_roundtrip", oqsSigDilithium2, msgLong, sigHolders)
        ]
        appendGroup(groups, "ML-DSA-87 Sign+Verify Roundtrip", mediumLoops, warmMedium, sigAlgos)

        sigAlgos = @[
          buildCustomSphincsRoundtrip("tyr_sphincs_shake128f_roundtrip",
            custom_sphincs.sphincsShake128fSimple, msgShort),
          buildOqsSigRoundtrip("oqs_sphincs_shake128f_roundtrip",
            oqsSigSphincsShake128fSimple, msgShort, sigHolders)
        ]
        appendGroup(groups, "SPHINCS+-SHAKE-128f-simple Sign+Verify Roundtrip",
          slowLoops, warmSlow, sigAlgos)

        check groups.len > 0
        for g in groups:
          runGroup(g)
