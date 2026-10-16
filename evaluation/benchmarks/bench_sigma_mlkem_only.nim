# ============================================================
# | Sigma ML-KEM Benchmark Test                              |
# | -> Compare Tyr ML-KEM vs liboqs without unrelated PQ     |
# |    modules so optimization loops stay focused/reliable  |
# ============================================================

import std/unittest

import ../../src/tyr/kems/mlkem as custom_mlkem
import otter_repo_evaluation

when defined(hasLibOqs):
  import ../../src/tyr/bindings/liboqs

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

proc buildCustomMlKemRoundtrip(name: string, v: custom_mlkem.MlKemVariant): BenchAlgo =
  result.name = name
  result.run = proc() =
    let kp = custom_mlkem.mlkemTyrKeypair(v)
    let env = custom_mlkem.mlkemTyrEncaps(v, kp.publicKey)
    let shared = custom_mlkem.mlkemTyrDecaps(v, kp.secretKey, env.ciphertext)
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

suite "Sigma ML-KEM performance":
  test "compare pure-Nim ML-KEM against liboqs":
    when not defined(hasLibOqs):
      checkpoint("Sigma ML-KEM benchmark requires -d:hasLibOqs")
    else:
      var
        kemHolders: seq[ptr OqsKem] = @[]
        groups: seq[BenchGroup] = @[]
        kemAlgos: seq[BenchAlgo] = @[]
        i: int = 0
      if not ensureLibOqsLoaded():
        checkpoint("liboqs runtime unavailable; skipping Sigma ML-KEM benchmark")
      else:
        defer:
          i = 0
          while i < kemHolders.len:
            if kemHolders[i] != nil:
              OQS_KEM_free(kemHolders[i])
            i = i + 1

        kemAlgos = @[
          buildCustomMlKemRoundtrip("tyr_mlkem768_roundtrip", custom_mlkem.mlkem768),
          buildOqsKemRoundtrip("oqs_mlkem768_roundtrip", oqsAlgMlKem768, kemHolders)
        ]
        appendGroup(groups, "ML-KEM-768 KEM Roundtrip", fastLoops, warmFast, kemAlgos)

        kemAlgos = @[
          buildCustomMlKemRoundtrip("tyr_mlkem1024_roundtrip", custom_mlkem.mlkem1024),
          buildOqsKemRoundtrip("oqs_mlkem1024_roundtrip", oqsAlgMlKem1024, kemHolders)
        ]
        appendGroup(groups, "ML-KEM-1024 KEM Roundtrip", fastLoops, warmFast, kemAlgos)

        check groups.len == 2
        for g in groups:
          runGroup(g)
