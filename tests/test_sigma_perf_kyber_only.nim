# ============================================================
# | Sigma Kyber Benchmark Test                              |
# | -> Compare Tyr Kyber vs liboqs without unrelated PQ     |
# |    modules so optimization loops stay focused/reliable  |
# ============================================================

import std/unittest

import ../src/protocols/custom_crypto/kyber as custom_kyber
import sigma_bench_and_eval

when defined(hasLibOqs):
  import ../src/protocols/bindings/liboqs

const
  fastLoops = 100
  warmFast = 3

type
  BenchGroup = object
    title: string
    loops: int
    warmup: int
    algos: seq[BenchAlgo]

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

proc runGroup(g: BenchGroup) =
  let results = compareAlgorithms(g.algos, loops = g.loops, warmup = g.warmup)
  check results.len == g.algos.len
  for r in results:
    check r.loops == g.loops
    check r.totalTicks > 0
    check r.avgTicks >= 0
  printGroup(g, results)

suite "Sigma Kyber performance":
  test "compare pure-Nim Kyber against liboqs":
    when not defined(hasLibOqs):
      checkpoint("Sigma Kyber benchmark requires -d:hasLibOqs")
    else:
      var
        kemHolders: seq[ptr OqsKem] = @[]
        groups: seq[BenchGroup] = @[]
        kemAlgos: seq[BenchAlgo] = @[]
        i: int = 0
      if not ensureLibOqsLoaded():
        checkpoint("liboqs runtime unavailable; skipping Sigma Kyber benchmark")
      else:
        defer:
          i = 0
          while i < kemHolders.len:
            if kemHolders[i] != nil:
              OQS_KEM_free(kemHolders[i])
            i = i + 1

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

        check groups.len == 2
        for g in groups:
          runGroup(g)
