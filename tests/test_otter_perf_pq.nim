# ============================================================
# | Otter PQ Timing Test                                    |
# | -> Aggregate per-function timings for Tyr PQ backends   |
# ============================================================

import std/[algorithm, tables, unittest]

import ../src/protocols/custom_crypto/[kyber, frodo, bike, mceliece, dilithium, falcon, sphincs]
import ../src/protocols/custom_crypto/asymmetric/pq/kyber/[params, indcpa]
import ../src/protocols/custom_crypto/asymmetric/pq/falcon/[sign as pure_falcon_sign, pure_verify as pure_falcon_verify]
import otter_repo_evaluation

const
  topFunctions = 12

type
  TimingStat = object
    count: int
    total: int64
    max: int64

  TimingEntry = tuple[name: string, stat: TimingStat]

proc fillPattern(bs: var openArray[byte], start: int = 0) =
  var
    i: int = 0
  i = 0
  while i < bs.len:
    bs[i] = byte((start + i) and 0xff)
    i = i + 1

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
    if a.stat.max > b.stat.max:
      return -1
    if a.stat.max < b.stat.max:
      return 1
    cmp(a.name, b.name)
  )

proc printTopTimings(title: string, A: openArray[TimingEntry], limit: int = topFunctions) =
  var
    i: int = 0
    avg: int64 = 0
    maxItems: int = 0
  echo ""
  echo "## ", title
  maxItems = min(limit, A.len)
  i = 0
  while i < maxItems:
    if A[i].stat.count > 0:
      avg = A[i].stat.total div A[i].stat.count
    else:
      avg = 0
    echo A[i].name, " total=", A[i].stat.total,
      " avg=", avg,
      " max=", A[i].stat.max,
      " count=", A[i].stat.count
    i = i + 1

proc runTimedGroup(title: string, body: proc ()) =
  var
    entries: seq[OtterTimingTuple] = @[]
    stats: seq[TimingEntry] = @[]
  clearTimings()
  body()
  entries = snapshotTimings()
  check entries.len > 0
  stats = aggregateTimings(entries)
  printTopTimings(title, stats)

proc kyber768BenchGenMatrixImpl() =
  var
    p = params(kyber768)
    seed: array[32, byte]
  fillPattern(seed, 0x11)
  discard genMatrix(p, seed, false)

proc kyber768BenchIndcpaKeypairImpl() =
  var
    p = params(kyber768)
    seed = newSeq[byte](32)
  fillPattern(seed, 0x21)
  discard indcpaKeypair(p, seed)

proc kyber768BenchIndcpaEncDecImpl() =
  var
    p = params(kyber768)
    seed = newSeq[byte](32)
    coins = newSeq[byte](32)
    msg = newSeq[byte](32)
    kp: tuple[pk, sk: seq[byte]]
    ct: seq[byte]
    dec: seq[byte]
  fillPattern(seed, 0x31)
  fillPattern(coins, 0x41)
  fillPattern(msg, 0x51)
  kp = indcpaKeypair(p, seed)
  ct = indcpaEnc(p, msg, kp.pk, coins)
  dec = indcpaDec(p, ct, kp.sk)
  doAssert dec == msg

proc kyber768BenchRoundtripImpl() =
  let kp = kyberTyrKeypair(kyber768)
  let env = kyberTyrEncaps(kyber768, kp.publicKey)
  let shared = kyberTyrDecaps(kyber768, kp.secretKey, env.ciphertext)
  doAssert shared == env.sharedSecret

proc frodo976BenchRoundtripImpl() =
  let kp = frodoTyrKeypair(frodo976aes)
  let env = frodoTyrEncaps(frodo976aes, kp.publicKey)
  let shared = frodoTyrDecaps(frodo976aes, kp.secretKey, env.ciphertext)
  doAssert shared == env.sharedSecret

proc bikeL1BenchRoundtripImpl() =
  let kp = bikeTyrKeypair(bikeL1)
  let env = bikeTyrEncaps(bikeL1, kp.publicKey)
  let shared = bikeTyrDecaps(bikeL1, kp.secretKey, env.ciphertext)
  doAssert shared == env.sharedSecret

proc mceliece6688128fBenchRoundtripImpl() =
  let kp = mcelieceTyrKeypair(mceliece6688128f)
  let env = mcelieceTyrEncaps(mceliece6688128f, kp.publicKey)
  let shared = mcelieceTyrDecaps(mceliece6688128f, kp.secretKey, env.ciphertext)
  doAssert shared == env.sharedSecret

proc dilithium44BenchSignVerifyImpl() =
  var
    p = params(dilithium44)
    msg: array[2048, byte]
    pk = newSeq[byte](p.publicKeyBytes)
    sk = newSeq[byte](p.secretKeyBytes)
    sig = newSeq[byte](p.signatureBytes)
  fillPattern(msg, 0x61)
  dilithiumTyrKeypairInto(dilithium44, pk, sk)
  dilithiumTyrSignInto(dilithium44, sig, msg, sk)
  doAssert dilithiumTyrVerify(dilithium44, msg, sig, pk)

proc falcon512BenchSignVerifyImpl() =
  var
    msg = newSeq[byte](128)
  fillPattern(msg, 0x69)
  let kp = falconTyrKeypair(falcon512)
  let sig = falconTyrSign(falcon512, msg, kp.secretKey)
  doAssert falconTyrVerify(falcon512, msg, sig, kp.publicKey)

proc falcon512BenchPreparedSignVerifyImpl() =
  var
    msg = newSeq[byte](128)
    kp: FalconTyrKeypair
    prepared: FalconPreparedSecret
    sig: seq[byte]
  fillPattern(msg, 0x6D)
  kp = falconTyrKeypair(falcon512)
  prepared = falconTyrPrepareSecret(falcon512, kp.secretKey)
  sig = falconTyrSignPrepared(prepared, msg)
  doAssert falconTyrVerify(falcon512, msg, sig, kp.publicKey)
  falconTyrClearPreparedSecret(prepared)
  falconTyrClearKeypair(kp)

proc falcon512PurePreparedSignVerifyImpl() =
  var
    msg = newSeq[byte](128)
    kp: FalconTyrKeypair
    prepared: pure_falcon_sign.FalconExpandedSecret
    sig: seq[byte]
  fillPattern(msg, 0x73)
  kp = falconTyrKeypair(falcon512)
  prepared = pure_falcon_sign.prepareSecretKey(falcon512, kp.secretKey)
  sig = pure_falcon_sign.falconSignPrepared(prepared, msg, falcon512)
  doAssert pure_falcon_verify.falconVerifyPure(falcon512, msg, sig, kp.publicKey)
  pure_falcon_sign.clearExpandedSecret(prepared)
  falconTyrClearKeypair(kp)

proc sphincsShake128fBenchSignVerifyImpl() =
  var
    msg = newSeq[byte](64)
  fillPattern(msg, 0x71)
  let kp = sphincsTyrKeypair(sphincsShake128fSimple)
  let sig = sphincsTyrSign(sphincsShake128fSimple, msg, kp.secretKey)
  doAssert sphincsTyrVerify(sphincsShake128fSimple, msg, sig, kp.publicKey)

otterInstrument:
  proc kyber768BenchGenMatrix() =
    kyber768BenchGenMatrixImpl()

  proc kyber768BenchIndcpaKeypair() =
    kyber768BenchIndcpaKeypairImpl()

  proc kyber768BenchIndcpaEncDec() =
    kyber768BenchIndcpaEncDecImpl()

  proc kyber768BenchRoundtrip() =
    kyber768BenchRoundtripImpl()

  proc frodo976BenchRoundtrip() =
    frodo976BenchRoundtripImpl()

  proc bikeL1BenchRoundtrip() =
    bikeL1BenchRoundtripImpl()

  proc mceliece6688128fBenchRoundtrip() =
    mceliece6688128fBenchRoundtripImpl()

  proc dilithium44BenchSignVerify() =
    dilithium44BenchSignVerifyImpl()

  proc falcon512BenchSignVerify() =
    falcon512BenchSignVerifyImpl()

  proc falcon512BenchPreparedSignVerify() =
    falcon512BenchPreparedSignVerifyImpl()

  proc falcon512PurePreparedSignVerify() =
    falcon512PurePreparedSignVerifyImpl()

  proc sphincsShake128fBenchSignVerify() =
    sphincsShake128fBenchSignVerifyImpl()

suite "Otter PQ timing":
  test "report top expensive Tyr PQ functions":
    var
      msgShort = newSeq[byte](64)
      msgLong = newSeq[byte](2048)
      i: int = 0
    setLogPath("build/otter_pq_timings.log")
    fillPattern(msgShort, 0x21)
    fillPattern(msgLong, 0x55)

    runTimedGroup("Kyber768 Roundtrip Hotspots", proc () =
      i = 0
      while i < 5:
        kyber768BenchGenMatrix()
        kyber768BenchIndcpaKeypair()
        kyber768BenchIndcpaEncDec()
        kyber768BenchRoundtrip()
        i = i + 1
    )

    runTimedGroup("Frodo976AES Roundtrip Hotspots", proc () =
      i = 0
      while i < 2:
        frodo976BenchRoundtrip()
        i = i + 1
    )

    runTimedGroup("BIKE-L1 Roundtrip Hotspots", proc () =
      i = 0
      while i < 3:
        bikeL1BenchRoundtrip()
        i = i + 1
    )

    runTimedGroup("Classic McEliece 6688128f Roundtrip Hotspots", proc () =
      mceliece6688128fBenchRoundtrip()
    )

    runTimedGroup("ML-DSA-44 Sign+Verify Hotspots", proc () =
      i = 0
      while i < 5:
        dilithium44BenchSignVerify()
        i = i + 1
    )

    runTimedGroup("Falcon-512 Sign+Verify Hotspots", proc () =
      i = 0
      while i < 3:
        falcon512BenchSignVerify()
        i = i + 1
    )

    runTimedGroup("Falcon-512 Prepared Sign+Verify Hotspots", proc () =
      i = 0
      while i < 3:
        falcon512BenchPreparedSignVerify()
        i = i + 1
    )

    runTimedGroup("Falcon-512 Pure Prepared Sign+Verify Hotspots", proc () =
      i = 0
      while i < 3:
        falcon512PurePreparedSignVerify()
        i = i + 1
    )

    runTimedGroup("SPHINCS+-SHAKE-128f-simple Sign+Verify Hotspots", proc () =
      i = 0
      while i < 2:
        sphincsShake128fBenchSignVerify()
        i = i + 1
    )
