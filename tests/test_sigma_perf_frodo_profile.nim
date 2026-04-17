## ============================================================
## | Sigma Frodo Profile Benchmark                           |
## | -> Compare Tyr Frodo against one explicit liboqs build  |
## ============================================================

import std/[os, strutils, unittest]

import ../src/protocols/custom_crypto/frodo as custom_frodo
import sigma_bench_and_eval

when defined(hasLibOqs):
  import ../src/protocols/bindings/liboqs

type
  ProfileInfo = object
    buildRoot: string
    metadataPath: string
    metadata: seq[string]

proc loadProfileInfo(): ProfileInfo =
  var
    buildRoot: string = getEnv("LIBOQS_BUILD_ROOT").strip()
    metadataPath: string = ""
  if buildRoot.len == 0:
    buildRoot = joinPath(getCurrentDir(), "build", "liboqs")
  metadataPath = joinPath(buildRoot, "install", "tyr_liboqs_profile.txt")
  result.buildRoot = buildRoot
  result.metadataPath = metadataPath
  if fileExists(metadataPath):
    result.metadata = readFile(metadataPath).splitLines()

proc printProfileInfo(info: ProfileInfo) =
  var
    i: int = 0
  echo "## liboqs build root: ", info.buildRoot
  echo "## liboqs profile metadata: ", info.metadataPath
  if info.metadata.len == 0:
    echo "## liboqs profile metadata missing"
    return
  i = 0
  while i < info.metadata.len:
    if info.metadata[i].len > 0:
      echo "## ", info.metadata[i]
    i = i + 1

proc buildCustomFrodoRoundtrip(name: string, v: custom_frodo.FrodoVariant): BenchAlgo =
  result.name = name
  result.run = proc() =
    var
      kp = custom_frodo.frodoTyrKeypair(v)
      env = custom_frodo.frodoTyrEncaps(v, kp.publicKey)
      shared = custom_frodo.frodoTyrDecaps(v, kp.secretKey, env.ciphertext)
    doAssert shared == env.sharedSecret

when defined(hasLibOqs):
  proc buildOqsKemRoundtrip(name, algId: string, holders: var seq[ptr OqsKem]): BenchAlgo =
    var
      kem = OQS_KEM_new(algId)
      pk: seq[uint8] = @[]
      sk: seq[uint8] = @[]
      ct: seq[uint8] = @[]
      ssE: seq[uint8] = @[]
      ssD: seq[uint8] = @[]
    if kem == nil:
      echo "Skipping ", name, ": liboqs algorithm unavailable (", algId, ")"
      return
    holders.add(kem)
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

suite "Sigma Frodo profile performance":
  test "compare Tyr Frodo against one explicit liboqs build":
    when not defined(hasLibOqs):
      checkpoint("Sigma Frodo profile benchmark requires -d:hasLibOqs")
    else:
      var
        info: ProfileInfo = loadProfileInfo()
        holders: seq[ptr OqsKem] = @[]
        algos: seq[BenchAlgo] = @[]
        results: seq[BenchResult] = @[]
        i: int = 0
      printProfileInfo(info)
      if not ensureLibOqsLoaded():
        checkpoint("liboqs runtime unavailable; skipping Frodo profile benchmark")
      else:
        defer:
          i = 0
          while i < holders.len:
            if holders[i] != nil:
              OQS_KEM_free(holders[i])
            i = i + 1
        algos = @[
          buildCustomFrodoRoundtrip("tyr_frodo976aes_roundtrip", custom_frodo.frodo976aes),
          buildOqsKemRoundtrip("oqs_frodo976aes_roundtrip", oqsAlgFrodoKEM976, holders)
        ]
        results = compareAlgorithms(algos, loops = 5, warmup = 1)
        check results.len == algos.len
        echo formatBenchResults(results)
