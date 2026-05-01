## ============================================================
## | Custom Crypto Benchmark Table <- unified Tyr report      |
## ============================================================

import std/[algorithm, monotimes, os, strutils]

import ../src/protocols/custom_crypto/chacha20 as custom_chacha20
import ../src/protocols/custom_crypto/xchacha20 as custom_xchacha20
import ../src/protocols/custom_crypto/xchacha20_simd as custom_xchacha20_simd
import ../src/protocols/custom_crypto/aes_ctr as custom_aes_ctr
import ../src/protocols/custom_crypto/gimli_sponge as custom_gimli_sponge
import ../src/protocols/custom_crypto/blake3 as custom_blake3
import ../src/protocols/custom_crypto/sha3 as custom_sha3
import ../src/protocols/custom_crypto/poly1305 as custom_poly1305
import ../src/protocols/custom_crypto/hmac as custom_hmac
import ../src/protocols/custom_crypto/kyber as custom_kyber
import ../src/protocols/custom_crypto/frodo as custom_frodo
import ../src/protocols/custom_crypto/bike as custom_bike
import ../src/protocols/custom_crypto/mceliece as custom_mceliece
import ../src/protocols/custom_crypto/dilithium as custom_dilithium
import ../src/protocols/custom_crypto/falcon as custom_falcon
import ../src/protocols/custom_crypto/sphincs as custom_sphincs

const
  smallBytes = 64
  largeBytes = 8 * 1024
  byteLoopsSmall = 200_000
  byteWarmupSmall = 500
  byteLoopsLarge = 20_000
  byteWarmupLarge = 100
  kyberLoops = 100
  kyberWarmup = 3
  frodoBikeLoops = 20
  frodoBikeWarmup = 2
  mcelieceLoops = 2
  mcelieceWarmup = 1
  dilithiumKeypairLoops = 30
  dilithiumSignLoops = 30
  dilithiumVerifyLoops = 80
  dilithiumKeypairWarmup = 2
  dilithiumSignWarmup = 2
  dilithiumVerifyWarmup = 3
  falconKeypairLoops = 2
  falconPrepareLoops = 3
  falconSignLoops = 3
  falconSignPreparedLoops = 3
  falconVerifyLoops = 8
  falconKeypairWarmup = 0
  falconPrepareWarmup = 0
  falconSignWarmup = 0
  falconSignPreparedWarmup = 0
  falconVerifyWarmup = 1
  sphincsKeypairLoops = 2
  sphincsSignLoops = 2
  sphincsVerifyLoops = 5
  sphincsWarmup = 1
  fastCorpusCount = 4
  slowCorpusCount = 2
  bytesToSecondsDivisor = 1_000_000_000.0

type
  BenchProc = proc () {.closure.}

  RateKind = enum
    rkBytes,
    rkOps

  BenchSpec = object
    name: string
    loops: int
    warmup: int
    rateKind: RateKind
    workPerLoop: int64
    run: BenchProc

  BenchRow = object
    name: string
    loops: int
    warmup: int
    totalTicks: int64
    avgTicks: int64
    rateValue: float64

  ByteBenchContext = object
    key32: seq[byte]
    nonce12: seq[byte]
    nonce16: seq[byte]
    nonce24: seq[byte]
    msg: seq[byte]

  FrodoBenchVariant = object
    name: string
    variant: custom_frodo.FrodoVariant

  FalconBenchVariant = object
    name: string
    variant: custom_falcon.FalconVariant

const
  frodoBenchVariants = [
    FrodoBenchVariant(name: "frodo640aes", variant: custom_frodo.frodo640aes),
    FrodoBenchVariant(name: "frodo640shake", variant: custom_frodo.frodo640shake),
    FrodoBenchVariant(name: "frodo976aes", variant: custom_frodo.frodo976aes),
    FrodoBenchVariant(name: "frodo976shake", variant: custom_frodo.frodo976shake),
    FrodoBenchVariant(name: "frodo1344aes", variant: custom_frodo.frodo1344aes),
    FrodoBenchVariant(name: "frodo1344shake", variant: custom_frodo.frodo1344shake)
  ]

  falconBenchVariants = [
    FalconBenchVariant(name: "falcon512", variant: custom_falcon.falcon512),
    FalconBenchVariant(name: "falcon1024", variant: custom_falcon.falcon1024)
  ]

var
  benchSink: uint64 = 0
  falconDeterministicBase: int = 0
  falconDeterministicOffset: int = 0

proc falconDeterministicCallback(random_array: ptr uint8, bytes_to_read: csize_t) {.cdecl.} =
  var
    outBytes: ptr UncheckedArray[uint8]
    i: int = 0
  outBytes = cast[ptr UncheckedArray[uint8]](random_array)
  i = 0
  while i < int(bytes_to_read):
    outBytes[i] = byte((falconDeterministicBase + falconDeterministicOffset + i) and 0xff)
    i = i + 1
  falconDeterministicOffset = falconDeterministicOffset + int(bytes_to_read)

proc resetFalconDeterministic(base: int) =
  falconDeterministicBase = base
  falconDeterministicOffset = 0

proc makePatternBytes(l, start: int): seq[byte] =
  var
    i: int = 0
  result = newSeq[byte](l)
  i = 0
  while i < l:
    result[i] = byte((start + i) and 0xff)
    i = i + 1

proc makeCorpus(itemLen, count, start: int): seq[seq[byte]] =
  var
    i: int = 0
  result = newSeq[seq[byte]](count)
  i = 0
  while i < count:
    result[i] = makePatternBytes(itemLen, start + i * 17)
    i = i + 1

proc initByteBenchContext(msgLen, start: int): ByteBenchContext =
  result.key32 = makePatternBytes(32, start + 0x01)
  result.nonce12 = makePatternBytes(12, start + 0x21)
  result.nonce16 = makePatternBytes(16, start + 0x31)
  result.nonce24 = makePatternBytes(24, start + 0x41)
  result.msg = makePatternBytes(msgLen, start + 0x61)

proc nextIndex(counter: var int, l: int): int {.inline.} =
  if l <= 0:
    return 0
  result = counter mod l
  counter = counter + 1

proc mixBytes(A: openArray[byte]) =
  var
    mid: int = 0
  if A.len <= 0:
    benchSink = benchSink xor 0x9E3779B97F4A7C15'u64
    return
  mid = A.len shr 1
  benchSink = benchSink xor uint64(A[0])
  benchSink = benchSink xor (uint64(A[mid]) shl 8)
  benchSink = benchSink xor (uint64(A[A.len - 1]) shl 16)
  benchSink = benchSink xor (uint64(A.len) shl 24)

proc mixBytesLen(A: openArray[byte], l: int) =
  var
    mid: int = 0
  if l <= 0:
    benchSink = benchSink xor 0xA5A5A5A5A5A5A5A5'u64
    return
  mid = l shr 1
  benchSink = benchSink xor uint64(A[0])
  benchSink = benchSink xor (uint64(A[mid]) shl 8)
  benchSink = benchSink xor (uint64(A[l - 1]) shl 16)
  benchSink = benchSink xor (uint64(l) shl 24)

proc mixBool(ok: bool) =
  if ok:
    benchSink = benchSink xor 1'u64
  else:
    benchSink = benchSink xor 2'u64

proc mixInt(v: int) =
  benchSink = benchSink xor uint64(v and 0x7fffffff)

proc byteLoops(msgLen: int): int =
  if msgLen <= smallBytes:
    return byteLoopsSmall
  result = byteLoopsLarge

proc byteWarmup(msgLen: int): int =
  if msgLen <= smallBytes:
    return byteWarmupSmall
  result = byteWarmupLarge

proc addByteSpec(S: var seq[BenchSpec], name: string, msgLen: int, run: BenchProc) =
  S.add(BenchSpec(
    name: name,
    loops: byteLoops(msgLen),
    warmup: byteWarmup(msgLen),
    rateKind: rkBytes,
    workPerLoop: msgLen,
    run: run
  ))

proc addOpsSpec(S: var seq[BenchSpec], name: string, loops, warmup: int, run: BenchProc) =
  S.add(BenchSpec(
    name: name,
    loops: loops,
    warmup: warmup,
    rateKind: rkOps,
    workPerLoop: 1,
    run: run
  ))

proc formatRate(v: float64): string =
  result = formatFloat(v, ffDecimal, 2)

proc rowCompare(a, b: BenchRow): int =
  if a.avgTicks < b.avgTicks:
    return -1
  if a.avgTicks > b.avgTicks:
    return 1
  if a.totalTicks < b.totalTicks:
    return -1
  if a.totalTicks > b.totalTicks:
    return 1
  result = cmp(a.name, b.name)

proc calculateRate(spec: BenchSpec, totalTicks: int64): float64 =
  var
    seconds: float64 = 0.0
    totalWork: float64 = 0.0
  if totalTicks <= 0:
    return 0.0
  seconds = float64(totalTicks) / bytesToSecondsDivisor
  if seconds <= 0.0:
    return 0.0
  if spec.rateKind == rkBytes:
    totalWork = float64(spec.workPerLoop) * float64(spec.loops)
    return (totalWork / 1024.0 / 1024.0) / seconds
  result = float64(spec.loops) / seconds

proc benchmarkSpec(spec: BenchSpec): BenchRow =
  var
    i: int = 0
    startTime: MonoTime
    stopTime: MonoTime
  i = 0
  while i < spec.warmup:
    spec.run()
    i = i + 1
  startTime = getMonoTime()
  i = 0
  while i < spec.loops:
    spec.run()
    i = i + 1
  stopTime = getMonoTime()
  result.name = spec.name
  result.loops = spec.loops
  result.warmup = spec.warmup
  result.totalTicks = stopTime.ticks - startTime.ticks
  if spec.loops > 0:
    result.avgTicks = result.totalTicks div spec.loops
  else:
    result.avgTicks = 0
  result.rateValue = calculateRate(spec, result.totalTicks)

proc benchmarkSpecs(A: openArray[BenchSpec]): seq[BenchRow] =
  var
    i: int = 0
  result = newSeq[BenchRow](A.len)
  i = 0
  while i < A.len:
    result[i] = benchmarkSpec(A[i])
    i = i + 1

proc rowsUseMixedLoops(A: openArray[BenchRow]): bool =
  var
    i: int = 0
    baseLoops: int = 0
    baseWarmup: int = 0
  if A.len <= 1:
    return false
  baseLoops = A[0].loops
  baseWarmup = A[0].warmup
  i = 1
  while i < A.len:
    if A[i].loops != baseLoops or A[i].warmup != baseWarmup:
      return true
    i = i + 1
  result = false

proc printTable(title, rateHeader: string, rows: seq[BenchRow], notes: seq[string]) =
  var
    sorted: seq[BenchRow] = @[]
    i: int = 0
    rank: int = 0
    winner: BenchRow
  sorted = @rows
  sorted.sort(rowCompare)
  echo ""
  echo "## ", title
  if rowsUseMixedLoops(sorted):
    echo "Note: per-row loop counts reuse the existing Sigma buckets; avg_ticks and ", rateHeader,
      " normalize the comparison."
  winner = sorted[0]
  echo "Winner: `", winner.name, "` avg_ticks=", winner.avgTicks, " ", rateHeader, "=",
    formatRate(winner.rateValue)
  echo ""
  echo "| rank | algorithm | avg_ticks | total_ticks | ", rateHeader, " |"
  echo "| ---: | --- | ---: | ---: | ---: |"
  i = 0
  rank = 1
  while i < sorted.len:
    echo "| ", rank, " | ", sorted[i].name, " | ", sorted[i].avgTicks, " | ",
      sorted[i].totalTicks, " | ", formatRate(sorted[i].rateValue), " |"
    i = i + 1
    rank = rank + 1
  if notes.len > 0:
    echo ""
    echo "Notes: ", notes.join("; ")

proc buildSymmetricSpecs(msgLen: int, notes: var seq[string]): seq[BenchSpec] =
  var
    ctx: ByteBenchContext
  ctx = initByteBenchContext(msgLen, 0x11 + (msgLen and 0xff))
  addByteSpec(result, "chacha20", msgLen, proc() =
    var outBytes = custom_chacha20.chacha20Xor(ctx.key32, ctx.nonce12, ctx.msg)
    mixBytes(outBytes)
  )
  addByteSpec(result, "xchacha20", msgLen, proc() =
    var outBytes = custom_xchacha20.xchacha20TyrXor(ctx.key32, ctx.nonce24, ctx.msg)
    mixBytes(outBytes)
  )
  when defined(sse2):
    addByteSpec(result, "xchacha20_sse2", msgLen, proc() =
      var outBytes = custom_xchacha20_simd.xchacha20StreamSimd(
        ctx.key32, ctx.nonce24, msgLen, 0'u32, custom_xchacha20_simd.xcbSse2)
      mixBytes(outBytes)
    )
  else:
    notes.add("xchacha20_sse2 omitted (requires -d:sse2)")
  when defined(avx2):
    addByteSpec(result, "xchacha20_avx2", msgLen, proc() =
      var outBytes = custom_xchacha20_simd.xchacha20StreamSimd(
        ctx.key32, ctx.nonce24, msgLen, 0'u32, custom_xchacha20_simd.xcbAvx2)
      mixBytes(outBytes)
    )
  else:
    notes.add("xchacha20_avx2 omitted (requires -d:avx2)")
  addByteSpec(result, "aes_ctr_scalar", msgLen, proc() =
    var outBytes = custom_aes_ctr.aesCtrTyrXor(
      ctx.key32, ctx.nonce16, ctx.msg, custom_aes_ctr.acbScalar)
    mixBytes(outBytes)
  )
  when defined(sse2):
    addByteSpec(result, "aes_ctr_sse2", msgLen, proc() =
      var outBytes = custom_aes_ctr.aesCtrTyrXor(
        ctx.key32, ctx.nonce16, ctx.msg, custom_aes_ctr.acbSse2)
      mixBytes(outBytes)
    )
  else:
    notes.add("aes_ctr_sse2 omitted (requires -d:sse2)")
  when defined(avx2):
    addByteSpec(result, "aes_ctr_avx2", msgLen, proc() =
      var outBytes = custom_aes_ctr.aesCtrTyrXor(
        ctx.key32, ctx.nonce16, ctx.msg, custom_aes_ctr.acbAvx2)
      mixBytes(outBytes)
    )
  else:
    notes.add("aes_ctr_avx2 omitted (requires -d:avx2)")
  addByteSpec(result, "gimli_stream", msgLen, proc() =
    var outBytes = custom_gimli_sponge.gimliTyrStreamXor(ctx.key32, ctx.nonce24, ctx.msg)
    mixBytes(outBytes)
  )

proc buildHashSpecs(msgLen: int, notes: var seq[string]): seq[BenchSpec] =
  var
    ctx: ByteBenchContext
  ctx = initByteBenchContext(msgLen, 0x71 + (msgLen and 0xff))
  discard notes
  addByteSpec(result, "blake3", msgLen, proc() =
    var outBytes = custom_blake3.blake3TyrHash(ctx.msg, 32)
    mixBytes(outBytes)
  )
  addByteSpec(result, "sha3_256", msgLen, proc() =
    var outBytes = custom_sha3.sha3TyrHash(ctx.msg, 32)
    mixBytes(outBytes)
  )
  addByteSpec(result, "shake128_32", msgLen, proc() =
    var outBytes = custom_sha3.shake128Tyr(ctx.msg, 32)
    mixBytes(outBytes)
  )
  addByteSpec(result, "shake256_32", msgLen, proc() =
    var outBytes = custom_sha3.shake256Tyr(ctx.msg, 32)
    mixBytes(outBytes)
  )
  addByteSpec(result, "gimli_xof_32", msgLen, proc() =
    var outBytes = custom_gimli_sponge.gimliTyrXof(ctx.key32, ctx.nonce24, ctx.msg, 32)
    mixBytes(outBytes)
  )

proc buildMacSpecs(msgLen: int, notes: var seq[string]): seq[BenchSpec] =
  var
    ctx: ByteBenchContext
  ctx = initByteBenchContext(msgLen, 0xC1 + (msgLen and 0xff))
  discard notes
  addByteSpec(result, "blake3_keyed_hash", msgLen, proc() =
    var outBytes = custom_blake3.blake3TyrKeyedHash(ctx.key32, ctx.msg, 32)
    mixBytes(outBytes)
  )
  addByteSpec(result, "gimli_tag_32", msgLen, proc() =
    var outBytes = custom_gimli_sponge.gimliTyrTag(ctx.key32, ctx.nonce24, ctx.msg, 32)
    mixBytes(outBytes)
  )
  addByteSpec(result, "poly1305_tag", msgLen, proc() =
    var outBytes = custom_poly1305.poly1305TyrTag(ctx.key32, ctx.msg)
    mixBytes(outBytes)
  )
  addByteSpec(result, "blake3_hmac_keyed", msgLen, proc() =
    var outBytes = custom_hmac.blake3CustomHmac(ctx.key32, ctx.msg, 32)
    mixBytes(outBytes)
  )
  addByteSpec(result, "blake3_hmac_hash", msgLen, proc() =
    var outBytes = custom_hmac.blake3CustomHmacFromHash(ctx.key32, ctx.msg, 32)
    mixBytes(outBytes)
  )
  addByteSpec(result, "gimli_hmac_32", msgLen, proc() =
    var outBytes = custom_hmac.gimliCustomHmac(ctx.key32, ctx.msg, 32)
    mixBytes(outBytes)
  )
  addByteSpec(result, "sha3_hmac_32", msgLen, proc() =
    var outBytes = custom_hmac.sha3CustomHmac(ctx.key32, ctx.msg, 32)
    mixBytes(outBytes)
  )
  addByteSpec(result, "poly1305_hmac", msgLen, proc() =
    var outBytes = custom_hmac.poly1305CustomHmac(ctx.key32, ctx.msg)
    mixBytes(outBytes)
  )

proc buildKyberKeypairSpec(v: custom_kyber.KyberVariant, name: string): BenchSpec =
  var
    seeds: seq[seq[byte]]
    counter: int = 0
  seeds = makeCorpus(custom_kyber.kyberSymBytes, fastCorpusCount, 0x10 + ord(v) * 19)
  result.name = name
  result.loops = kyberLoops
  result.warmup = kyberWarmup
  result.rateKind = rkOps
  result.workPerLoop = 1
  result.run = proc() =
    var
      idx: int = 0
      kp: custom_kyber.KyberTyrKeypair
    idx = nextIndex(counter, seeds.len)
    kp = custom_kyber.kyberTyrKeypair(v, seeds[idx])
    mixBytes(kp.publicKey)
    mixBytes(kp.secretKey)

proc buildKyberEncapsSpec(v: custom_kyber.KyberVariant, name: string): BenchSpec =
  var
    kpSeed: seq[byte]
    kp: custom_kyber.KyberTyrKeypair
    seeds: seq[seq[byte]]
    counter: int = 0
  kpSeed = makePatternBytes(custom_kyber.kyberSymBytes, 0x50 + ord(v) * 19)
  kp = custom_kyber.kyberTyrKeypair(v, kpSeed)
  seeds = makeCorpus(custom_kyber.kyberSymBytes, fastCorpusCount, 0x70 + ord(v) * 19)
  result.name = name
  result.loops = kyberLoops
  result.warmup = kyberWarmup
  result.rateKind = rkOps
  result.workPerLoop = 1
  result.run = proc() =
    var
      idx: int = 0
      env: custom_kyber.KyberTyrCipher
    idx = nextIndex(counter, seeds.len)
    env = custom_kyber.kyberTyrEncaps(v, kp.publicKey, seeds[idx])
    mixBytes(env.ciphertext)
    mixBytes(env.sharedSecret)

proc buildKyberDecapsSpec(v: custom_kyber.KyberVariant, name: string): BenchSpec =
  var
    kpSeed: seq[byte]
    kp: custom_kyber.KyberTyrKeypair
    seeds: seq[seq[byte]]
    envs: seq[custom_kyber.KyberTyrCipher]
    counter: int = 0
    i: int = 0
  kpSeed = makePatternBytes(custom_kyber.kyberSymBytes, 0x90 + ord(v) * 19)
  kp = custom_kyber.kyberTyrKeypair(v, kpSeed)
  seeds = makeCorpus(custom_kyber.kyberSymBytes, fastCorpusCount, 0xB0 + ord(v) * 19)
  envs = newSeq[custom_kyber.KyberTyrCipher](seeds.len)
  i = 0
  while i < seeds.len:
    envs[i] = custom_kyber.kyberTyrEncaps(v, kp.publicKey, seeds[i])
    i = i + 1
  result.name = name
  result.loops = kyberLoops
  result.warmup = kyberWarmup
  result.rateKind = rkOps
  result.workPerLoop = 1
  result.run = proc() =
    var
      idx: int = 0
      shared: seq[byte]
    idx = nextIndex(counter, envs.len)
    shared = custom_kyber.kyberTyrDecaps(v, kp.secretKey, envs[idx].ciphertext)
    mixBytes(shared)

proc buildFrodoKeypairSpec(v: custom_frodo.FrodoVariant, name: string): BenchSpec =
  var
    p: custom_frodo.FrodoParams
    seeds: seq[seq[byte]]
    counter: int = 0
  p = params(v)
  seeds = makeCorpus(p.keypairRandomBytes, slowCorpusCount, 0x14 + ord(v) * 17)
  result.name = name
  result.loops = frodoBikeLoops
  result.warmup = frodoBikeWarmup
  result.rateKind = rkOps
  result.workPerLoop = 1
  result.run = proc() =
    var
      idx: int = 0
      kp: custom_frodo.FrodoTyrKeypair
    idx = nextIndex(counter, seeds.len)
    kp = custom_frodo.frodoTyrKeypair(v, seeds[idx])
    mixBytes(kp.publicKey)
    mixBytes(kp.secretKey)

proc buildFrodoEncapsSpec(v: custom_frodo.FrodoVariant, name: string): BenchSpec =
  var
    p: custom_frodo.FrodoParams
    kpSeed: seq[byte]
    kp: custom_frodo.FrodoTyrKeypair
    mus: seq[seq[byte]]
    counter: int = 0
  p = params(v)
  kpSeed = makePatternBytes(p.keypairRandomBytes, 0x44 + ord(v) * 17)
  kp = custom_frodo.frodoTyrKeypair(v, kpSeed)
  mus = makeCorpus(p.encapsRandomBytes, slowCorpusCount, 0x64 + ord(v) * 17)
  result.name = name
  result.loops = frodoBikeLoops
  result.warmup = frodoBikeWarmup
  result.rateKind = rkOps
  result.workPerLoop = 1
  result.run = proc() =
    var
      idx: int = 0
      env: custom_frodo.FrodoTyrCipher
    idx = nextIndex(counter, mus.len)
    env = custom_frodo.frodoTyrEncaps(v, kp.publicKey, mus[idx])
    mixBytes(env.ciphertext)
    mixBytes(env.sharedSecret)

proc buildFrodoDecapsSpec(v: custom_frodo.FrodoVariant, name: string): BenchSpec =
  var
    p: custom_frodo.FrodoParams
    kpSeed: seq[byte]
    kp: custom_frodo.FrodoTyrKeypair
    mus: seq[seq[byte]]
    envs: seq[custom_frodo.FrodoTyrCipher]
    counter: int = 0
    i: int = 0
  p = params(v)
  kpSeed = makePatternBytes(p.keypairRandomBytes, 0x84 + ord(v) * 17)
  kp = custom_frodo.frodoTyrKeypair(v, kpSeed)
  mus = makeCorpus(p.encapsRandomBytes, slowCorpusCount, 0xA4 + ord(v) * 17)
  envs = newSeq[custom_frodo.FrodoTyrCipher](mus.len)
  i = 0
  while i < mus.len:
    envs[i] = custom_frodo.frodoTyrEncaps(v, kp.publicKey, mus[i])
    i = i + 1
  result.name = name
  result.loops = frodoBikeLoops
  result.warmup = frodoBikeWarmup
  result.rateKind = rkOps
  result.workPerLoop = 1
  result.run = proc() =
    var
      idx: int = 0
      shared: seq[byte]
    idx = nextIndex(counter, envs.len)
    shared = custom_frodo.frodoTyrDecaps(v, kp.secretKey, envs[idx].ciphertext)
    mixBytes(shared)

proc buildBikeKeypairSpec(v: custom_bike.BikeVariant, name: string): BenchSpec =
  var
    p: custom_bike.BikeParams
    seeds: seq[seq[byte]]
    counter: int = 0
  p = params(v)
  seeds = makeCorpus(p.keypairRandomBytes, slowCorpusCount, 0x18 + ord(v) * 17)
  result.name = name
  result.loops = frodoBikeLoops
  result.warmup = frodoBikeWarmup
  result.rateKind = rkOps
  result.workPerLoop = 1
  result.run = proc() =
    var
      idx: int = 0
      kp: custom_bike.BikeTyrKeypair
    idx = nextIndex(counter, seeds.len)
    kp = custom_bike.bikeTyrKeypair(v, seeds[idx])
    mixBytes(kp.publicKey)
    mixBytes(kp.secretKey)

proc buildBikeEncapsSpec(v: custom_bike.BikeVariant, name: string): BenchSpec =
  var
    p: custom_bike.BikeParams
    kpSeed: seq[byte]
    kp: custom_bike.BikeTyrKeypair
    seeds: seq[seq[byte]]
    counter: int = 0
  p = params(v)
  kpSeed = makePatternBytes(p.keypairRandomBytes, 0x48 + ord(v) * 17)
  kp = custom_bike.bikeTyrKeypair(v, kpSeed)
  seeds = makeCorpus(p.encapsRandomBytes, slowCorpusCount, 0x68 + ord(v) * 17)
  result.name = name
  result.loops = frodoBikeLoops
  result.warmup = frodoBikeWarmup
  result.rateKind = rkOps
  result.workPerLoop = 1
  result.run = proc() =
    var
      idx: int = 0
      env: custom_bike.BikeTyrCipher
    idx = nextIndex(counter, seeds.len)
    env = custom_bike.bikeTyrEncaps(v, kp.publicKey, seeds[idx])
    mixBytes(env.ciphertext)
    mixBytes(env.sharedSecret)

proc buildBikeDecapsSpec(v: custom_bike.BikeVariant, name: string): BenchSpec =
  var
    p: custom_bike.BikeParams
    kpSeed: seq[byte]
    kp: custom_bike.BikeTyrKeypair
    seeds: seq[seq[byte]]
    envs: seq[custom_bike.BikeTyrCipher]
    counter: int = 0
    i: int = 0
  p = params(v)
  kpSeed = makePatternBytes(p.keypairRandomBytes, 0x88 + ord(v) * 17)
  kp = custom_bike.bikeTyrKeypair(v, kpSeed)
  seeds = makeCorpus(p.encapsRandomBytes, slowCorpusCount, 0xA8 + ord(v) * 17)
  envs = newSeq[custom_bike.BikeTyrCipher](seeds.len)
  i = 0
  while i < seeds.len:
    envs[i] = custom_bike.bikeTyrEncaps(v, kp.publicKey, seeds[i])
    i = i + 1
  result.name = name
  result.loops = frodoBikeLoops
  result.warmup = frodoBikeWarmup
  result.rateKind = rkOps
  result.workPerLoop = 1
  result.run = proc() =
    var
      idx: int = 0
      shared: seq[byte]
    idx = nextIndex(counter, envs.len)
    shared = custom_bike.bikeTyrDecaps(v, kp.secretKey, envs[idx].ciphertext)
    mixBytes(shared)

proc buildMcelieceKeypairSpec(v: custom_mceliece.McElieceVariant, name: string): BenchSpec =
  var
    seeds: seq[seq[byte]]
    counter: int = 0
  seeds = makeCorpus(32, slowCorpusCount, 0x1C + ord(v) * 17)
  result.name = name
  result.loops = mcelieceLoops
  result.warmup = mcelieceWarmup
  result.rateKind = rkOps
  result.workPerLoop = 1
  result.run = proc() =
    var
      idx: int = 0
      kp: custom_mceliece.McElieceTyrKeypair
    idx = nextIndex(counter, seeds.len)
    kp = custom_mceliece.mcelieceTyrKeypair(v, seeds[idx])
    mixBytes(kp.publicKey)
    mixBytes(kp.secretKey)

proc buildMcelieceEncapsSpec(v: custom_mceliece.McElieceVariant, name: string): BenchSpec =
  var
    kpSeed: seq[byte]
    kp: custom_mceliece.McElieceTyrKeypair
  kpSeed = makePatternBytes(32, 0x4C + ord(v) * 17)
  kp = custom_mceliece.mcelieceTyrKeypair(v, kpSeed)
  result.name = name
  result.loops = mcelieceLoops
  result.warmup = mcelieceWarmup
  result.rateKind = rkOps
  result.workPerLoop = 1
  result.run = proc() =
    var env = custom_mceliece.mcelieceTyrEncaps(v, kp.publicKey)
    mixBytes(env.ciphertext)
    mixBytes(env.sharedSecret)

proc buildMcelieceDecapsSpec(v: custom_mceliece.McElieceVariant, name: string): BenchSpec =
  var
    kpSeed: seq[byte]
    kp: custom_mceliece.McElieceTyrKeypair
    envs: seq[custom_mceliece.McElieceTyrCipher]
    counter: int = 0
    i: int = 0
  kpSeed = makePatternBytes(32, 0x8C + ord(v) * 17)
  kp = custom_mceliece.mcelieceTyrKeypair(v, kpSeed)
  envs = newSeq[custom_mceliece.McElieceTyrCipher](slowCorpusCount)
  i = 0
  while i < envs.len:
    envs[i] = custom_mceliece.mcelieceTyrEncaps(v, kp.publicKey)
    i = i + 1
  result.name = name
  result.loops = mcelieceLoops
  result.warmup = mcelieceWarmup
  result.rateKind = rkOps
  result.workPerLoop = 1
  result.run = proc() =
    var
      idx: int = 0
      shared: seq[byte]
    idx = nextIndex(counter, envs.len)
    shared = custom_mceliece.mcelieceTyrDecaps(v, kp.secretKey, envs[idx].ciphertext)
    mixBytes(shared)

proc buildFalconKeypairSpec(v: custom_falcon.FalconVariant, b: custom_falcon.FalconBackend,
    name: string): BenchSpec
proc buildFalconPrepareSpec(v: custom_falcon.FalconVariant, b: custom_falcon.FalconBackend,
    name: string): BenchSpec
proc buildFalconSignSpec(v: custom_falcon.FalconVariant, b: custom_falcon.FalconBackend,
    name: string): BenchSpec
proc buildFalconSignPreparedSpec(v: custom_falcon.FalconVariant, b: custom_falcon.FalconBackend,
    name: string): BenchSpec
proc buildFalconVerifySpec(v: custom_falcon.FalconVariant, b: custom_falcon.FalconBackend,
    name: string): BenchSpec

proc falconRowName(v: FalconBenchVariant, b: custom_falcon.FalconBackend): string =
  result = v.name & "_" & custom_falcon.backendName(b)

proc falconBenchVariantEnabled(v: FalconBenchVariant): bool =
  var
    token: string = getEnv("TYR_FALCON_BENCH_VARIANT").strip().toLowerAscii()
  if token.len == 0 or token == "all":
    return true
  if v.name == "falcon512":
    return token == "512" or token == "falcon512" or token == "falcon-512"
  if v.name == "falcon1024":
    return token == "1024" or token == "falcon1024" or token == "falcon-1024"
  result = false

proc appendFrodoKeypairSpecs(S: var seq[BenchSpec]) =
  var i: int = 0
  i = 0
  while i < frodoBenchVariants.len:
    addOpsSpec(S, frodoBenchVariants[i].name, frodoBikeLoops, frodoBikeWarmup,
      buildFrodoKeypairSpec(frodoBenchVariants[i].variant, frodoBenchVariants[i].name).run)
    i = i + 1

proc appendFrodoEncapsSpecs(S: var seq[BenchSpec]) =
  var i: int = 0
  i = 0
  while i < frodoBenchVariants.len:
    addOpsSpec(S, frodoBenchVariants[i].name, frodoBikeLoops, frodoBikeWarmup,
      buildFrodoEncapsSpec(frodoBenchVariants[i].variant, frodoBenchVariants[i].name).run)
    i = i + 1

proc appendFrodoDecapsSpecs(S: var seq[BenchSpec]) =
  var i: int = 0
  i = 0
  while i < frodoBenchVariants.len:
    addOpsSpec(S, frodoBenchVariants[i].name, frodoBikeLoops, frodoBikeWarmup,
      buildFrodoDecapsSpec(frodoBenchVariants[i].variant, frodoBenchVariants[i].name).run)
    i = i + 1

proc appendFalconKeypairSpecs(S: var seq[BenchSpec], notes: var seq[string]) =
  var
    i: int = 0
    rowName: string
  i = 0
  while i < falconBenchVariants.len:
    if not falconBenchVariantEnabled(falconBenchVariants[i]):
      i = i + 1
      continue
    rowName = falconRowName(falconBenchVariants[i], custom_falcon.falconScalar)
    addOpsSpec(S, rowName, falconKeypairLoops, falconKeypairWarmup,
      buildFalconKeypairSpec(falconBenchVariants[i].variant, custom_falcon.falconScalar, rowName).run)
    i = i + 1
  if custom_falcon.backendAvailable(custom_falcon.falconSimd):
    i = 0
    while i < falconBenchVariants.len:
      if not falconBenchVariantEnabled(falconBenchVariants[i]):
        i = i + 1
        continue
      rowName = falconRowName(falconBenchVariants[i], custom_falcon.falconSimd)
      addOpsSpec(S, rowName, falconKeypairLoops, falconKeypairWarmup,
        buildFalconKeypairSpec(falconBenchVariants[i].variant, custom_falcon.falconSimd, rowName).run)
      i = i + 1
  else:
    notes.add("falcon_simd128 rows omitted (requires SSE2 or ARM64/NEON support)")

proc appendFalconSignSpecs(S: var seq[BenchSpec], notes: var seq[string]) =
  var
    i: int = 0
    rowName: string
  i = 0
  while i < falconBenchVariants.len:
    if not falconBenchVariantEnabled(falconBenchVariants[i]):
      i = i + 1
      continue
    rowName = falconRowName(falconBenchVariants[i], custom_falcon.falconScalar)
    addOpsSpec(S, rowName, falconSignLoops, falconSignWarmup,
      buildFalconSignSpec(falconBenchVariants[i].variant, custom_falcon.falconScalar, rowName).run)
    i = i + 1
  if custom_falcon.backendAvailable(custom_falcon.falconSimd):
    i = 0
    while i < falconBenchVariants.len:
      if not falconBenchVariantEnabled(falconBenchVariants[i]):
        i = i + 1
        continue
      rowName = falconRowName(falconBenchVariants[i], custom_falcon.falconSimd)
      addOpsSpec(S, rowName, falconSignLoops, falconSignWarmup,
        buildFalconSignSpec(falconBenchVariants[i].variant, custom_falcon.falconSimd, rowName).run)
      i = i + 1
  else:
    notes.add("falcon_simd128 rows omitted (requires SSE2 or ARM64/NEON support)")

proc appendFalconVerifySpecs(S: var seq[BenchSpec], notes: var seq[string]) =
  var
    i: int = 0
    rowName: string
  i = 0
  while i < falconBenchVariants.len:
    if not falconBenchVariantEnabled(falconBenchVariants[i]):
      i = i + 1
      continue
    rowName = falconRowName(falconBenchVariants[i], custom_falcon.falconScalar)
    addOpsSpec(S, rowName, falconVerifyLoops, falconVerifyWarmup,
      buildFalconVerifySpec(falconBenchVariants[i].variant, custom_falcon.falconScalar, rowName).run)
    i = i + 1
  if custom_falcon.backendAvailable(custom_falcon.falconSimd):
    i = 0
    while i < falconBenchVariants.len:
      if not falconBenchVariantEnabled(falconBenchVariants[i]):
        i = i + 1
        continue
      rowName = falconRowName(falconBenchVariants[i], custom_falcon.falconSimd)
      addOpsSpec(S, rowName, falconVerifyLoops, falconVerifyWarmup,
        buildFalconVerifySpec(falconBenchVariants[i].variant, custom_falcon.falconSimd, rowName).run)
      i = i + 1
  else:
    notes.add("falcon_simd128 rows omitted (requires SSE2 or ARM64/NEON support)")

proc appendFalconPrepareSpecs(S: var seq[BenchSpec], notes: var seq[string]) =
  var
    i: int = 0
    rowName: string
  i = 0
  while i < falconBenchVariants.len:
    if not falconBenchVariantEnabled(falconBenchVariants[i]):
      i = i + 1
      continue
    rowName = falconRowName(falconBenchVariants[i], custom_falcon.falconScalar)
    addOpsSpec(S, rowName, falconPrepareLoops, falconPrepareWarmup,
      buildFalconPrepareSpec(falconBenchVariants[i].variant, custom_falcon.falconScalar, rowName).run)
    i = i + 1
  if custom_falcon.backendAvailable(custom_falcon.falconSimd):
    i = 0
    while i < falconBenchVariants.len:
      if not falconBenchVariantEnabled(falconBenchVariants[i]):
        i = i + 1
        continue
      rowName = falconRowName(falconBenchVariants[i], custom_falcon.falconSimd)
      addOpsSpec(S, rowName, falconPrepareLoops, falconPrepareWarmup,
        buildFalconPrepareSpec(falconBenchVariants[i].variant, custom_falcon.falconSimd, rowName).run)
      i = i + 1
  else:
    notes.add("falcon_simd128 rows omitted (requires SSE2 or ARM64/NEON support)")

proc appendFalconPreparedSignSpecs(S: var seq[BenchSpec], notes: var seq[string]) =
  var
    i: int = 0
    rowName: string
  i = 0
  while i < falconBenchVariants.len:
    if not falconBenchVariantEnabled(falconBenchVariants[i]):
      i = i + 1
      continue
    rowName = falconRowName(falconBenchVariants[i], custom_falcon.falconScalar)
    addOpsSpec(S, rowName, falconSignPreparedLoops, falconSignPreparedWarmup,
      buildFalconSignPreparedSpec(falconBenchVariants[i].variant, custom_falcon.falconScalar, rowName).run)
    i = i + 1
  if custom_falcon.backendAvailable(custom_falcon.falconSimd):
    i = 0
    while i < falconBenchVariants.len:
      if not falconBenchVariantEnabled(falconBenchVariants[i]):
        i = i + 1
        continue
      rowName = falconRowName(falconBenchVariants[i], custom_falcon.falconSimd)
      addOpsSpec(S, rowName, falconSignPreparedLoops, falconSignPreparedWarmup,
        buildFalconSignPreparedSpec(falconBenchVariants[i].variant, custom_falcon.falconSimd, rowName).run)
      i = i + 1
  else:
    notes.add("falcon_simd128 rows omitted (requires SSE2 or ARM64/NEON support)")

proc buildKemKeypairSpecs(notes: var seq[string]): seq[BenchSpec] =
  discard notes
  addOpsSpec(result, "kyber512", kyberLoops, kyberWarmup, buildKyberKeypairSpec(custom_kyber.kyber512, "kyber512").run)
  addOpsSpec(result, "kyber768", kyberLoops, kyberWarmup, buildKyberKeypairSpec(custom_kyber.kyber768, "kyber768").run)
  addOpsSpec(result, "kyber1024", kyberLoops, kyberWarmup, buildKyberKeypairSpec(custom_kyber.kyber1024, "kyber1024").run)
  appendFrodoKeypairSpecs(result)
  addOpsSpec(result, "bike_l1", frodoBikeLoops, frodoBikeWarmup, buildBikeKeypairSpec(custom_bike.bikeL1, "bike_l1").run)
  addOpsSpec(result, "mceliece6688128f", mcelieceLoops, mcelieceWarmup, buildMcelieceKeypairSpec(custom_mceliece.mceliece6688128f, "mceliece6688128f").run)
  addOpsSpec(result, "mceliece6960119f", mcelieceLoops, mcelieceWarmup, buildMcelieceKeypairSpec(custom_mceliece.mceliece6960119f, "mceliece6960119f").run)
  addOpsSpec(result, "mceliece8192128f", mcelieceLoops, mcelieceWarmup, buildMcelieceKeypairSpec(custom_mceliece.mceliece8192128f, "mceliece8192128f").run)

proc buildKemEncapsSpecs(notes: var seq[string]): seq[BenchSpec] =
  notes.add("Classic McEliece encaps rows use the current public API randomness because the facade does not expose a deterministic encaps seed")
  addOpsSpec(result, "kyber512", kyberLoops, kyberWarmup, buildKyberEncapsSpec(custom_kyber.kyber512, "kyber512").run)
  addOpsSpec(result, "kyber768", kyberLoops, kyberWarmup, buildKyberEncapsSpec(custom_kyber.kyber768, "kyber768").run)
  addOpsSpec(result, "kyber1024", kyberLoops, kyberWarmup, buildKyberEncapsSpec(custom_kyber.kyber1024, "kyber1024").run)
  appendFrodoEncapsSpecs(result)
  addOpsSpec(result, "bike_l1", frodoBikeLoops, frodoBikeWarmup, buildBikeEncapsSpec(custom_bike.bikeL1, "bike_l1").run)
  addOpsSpec(result, "mceliece6688128f", mcelieceLoops, mcelieceWarmup, buildMcelieceEncapsSpec(custom_mceliece.mceliece6688128f, "mceliece6688128f").run)
  addOpsSpec(result, "mceliece6960119f", mcelieceLoops, mcelieceWarmup, buildMcelieceEncapsSpec(custom_mceliece.mceliece6960119f, "mceliece6960119f").run)
  addOpsSpec(result, "mceliece8192128f", mcelieceLoops, mcelieceWarmup, buildMcelieceEncapsSpec(custom_mceliece.mceliece8192128f, "mceliece8192128f").run)

proc buildKemDecapsSpecs(notes: var seq[string]): seq[BenchSpec] =
  discard notes
  addOpsSpec(result, "kyber512", kyberLoops, kyberWarmup, buildKyberDecapsSpec(custom_kyber.kyber512, "kyber512").run)
  addOpsSpec(result, "kyber768", kyberLoops, kyberWarmup, buildKyberDecapsSpec(custom_kyber.kyber768, "kyber768").run)
  addOpsSpec(result, "kyber1024", kyberLoops, kyberWarmup, buildKyberDecapsSpec(custom_kyber.kyber1024, "kyber1024").run)
  appendFrodoDecapsSpecs(result)
  addOpsSpec(result, "bike_l1", frodoBikeLoops, frodoBikeWarmup, buildBikeDecapsSpec(custom_bike.bikeL1, "bike_l1").run)
  addOpsSpec(result, "mceliece6688128f", mcelieceLoops, mcelieceWarmup, buildMcelieceDecapsSpec(custom_mceliece.mceliece6688128f, "mceliece6688128f").run)
  addOpsSpec(result, "mceliece6960119f", mcelieceLoops, mcelieceWarmup, buildMcelieceDecapsSpec(custom_mceliece.mceliece6960119f, "mceliece6960119f").run)
  addOpsSpec(result, "mceliece8192128f", mcelieceLoops, mcelieceWarmup, buildMcelieceDecapsSpec(custom_mceliece.mceliece8192128f, "mceliece8192128f").run)

proc buildDilithiumKeypairSpec(v: custom_dilithium.DilithiumVariant, name: string): BenchSpec =
  var
    p: custom_dilithium.DilithiumParams
    pk: seq[byte]
    sk: seq[byte]
    seeds: seq[seq[byte]]
    counter: int = 0
  p = params(v)
  pk = newSeq[byte](p.publicKeyBytes)
  sk = newSeq[byte](p.secretKeyBytes)
  seeds = makeCorpus(custom_dilithium.dilithiumSeedBytes, fastCorpusCount, 0x20 + ord(v) * 17)
  result.name = name
  result.loops = dilithiumKeypairLoops
  result.warmup = dilithiumKeypairWarmup
  result.rateKind = rkOps
  result.workPerLoop = 1
  result.run = proc() =
    var idx: int = 0
    idx = nextIndex(counter, seeds.len)
    custom_dilithium.dilithiumTyrKeypairInto(v, pk, sk, seeds[idx])
    mixBytes(pk)
    mixBytes(sk)

proc buildDilithiumSignSpec(v: custom_dilithium.DilithiumVariant, name: string): BenchSpec =
  var
    p: custom_dilithium.DilithiumParams
    pk: seq[byte]
    sk: seq[byte]
    msg: seq[byte]
    sig: seq[byte]
    seed: seq[byte]
    rnds: seq[seq[byte]]
    counter: int = 0
  p = params(v)
  pk = newSeq[byte](p.publicKeyBytes)
  sk = newSeq[byte](p.secretKeyBytes)
  sig = newSeq[byte](p.signatureBytes)
  msg = makePatternBytes(2048, 0x40 + ord(v) * 17)
  seed = makePatternBytes(custom_dilithium.dilithiumSeedBytes, 0x60 + ord(v) * 17)
  rnds = makeCorpus(custom_dilithium.dilithiumRndBytes, fastCorpusCount, 0x80 + ord(v) * 17)
  custom_dilithium.dilithiumTyrKeypairInto(v, pk, sk, seed)
  result.name = name
  result.loops = dilithiumSignLoops
  result.warmup = dilithiumSignWarmup
  result.rateKind = rkOps
  result.workPerLoop = 1
  result.run = proc() =
    var idx: int = 0
    idx = nextIndex(counter, rnds.len)
    custom_dilithium.dilithiumTyrSignDerandInto(v, sig, msg, sk, rnds[idx])
    mixBytes(sig)

proc buildDilithiumVerifySpec(v: custom_dilithium.DilithiumVariant, name: string): BenchSpec =
  var
    p: custom_dilithium.DilithiumParams
    pk: seq[byte]
    sk: seq[byte]
    msg: seq[byte]
    sig: seq[byte]
    seed: seq[byte]
    rnd: seq[byte]
  p = params(v)
  pk = newSeq[byte](p.publicKeyBytes)
  sk = newSeq[byte](p.secretKeyBytes)
  sig = newSeq[byte](p.signatureBytes)
  msg = makePatternBytes(2048, 0xA0 + ord(v) * 17)
  seed = makePatternBytes(custom_dilithium.dilithiumSeedBytes, 0xC0 + ord(v) * 17)
  rnd = makePatternBytes(custom_dilithium.dilithiumRndBytes, 0xE0 + ord(v) * 17)
  custom_dilithium.dilithiumTyrKeypairInto(v, pk, sk, seed)
  custom_dilithium.dilithiumTyrSignDerandInto(v, sig, msg, sk, rnd)
  result.name = name
  result.loops = dilithiumVerifyLoops
  result.warmup = dilithiumVerifyWarmup
  result.rateKind = rkOps
  result.workPerLoop = 1
  result.run = proc() =
    var ok: bool = false
    ok = custom_dilithium.dilithiumTyrVerify(v, msg, sig, pk)
    doAssert ok
    mixBool(ok)

proc buildFalconKeypairSpec(v: custom_falcon.FalconVariant, b: custom_falcon.FalconBackend,
    name: string): BenchSpec =
  var
    p: custom_falcon.FalconParams
    pk: seq[byte]
    sk: seq[byte]
    counter: int = 0
    seedBase: int = 0
  p = params(v)
  pk = newSeq[byte](p.publicKeyBytes)
  sk = newSeq[byte](p.secretKeyBytes)
  seedBase = 0x24 + ord(v) * 23
  if b == custom_falcon.falconSimd:
    seedBase = seedBase + 0x100
  result.name = name
  result.loops = falconKeypairLoops
  result.warmup = falconKeypairWarmup
  result.rateKind = rkOps
  result.workPerLoop = 1
  result.run = proc() =
    resetFalconDeterministic(seedBase + counter)
    custom_falcon.falconTyrKeypairInto(v, pk, sk, b)
    counter = counter + 1
    mixBytes(pk)
    mixBytes(sk)

proc buildFalconPrepareSpec(v: custom_falcon.FalconVariant, b: custom_falcon.FalconBackend,
    name: string): BenchSpec =
  var
    p: custom_falcon.FalconParams
    pk: seq[byte]
    sk: seq[byte]
    prepared: custom_falcon.FalconPreparedSecret
    seedBase: int = 0
  p = params(v)
  pk = newSeq[byte](p.publicKeyBytes)
  sk = newSeq[byte](p.secretKeyBytes)
  seedBase = 0x44 + ord(v) * 23
  if b == custom_falcon.falconSimd:
    seedBase = seedBase + 0x100
  resetFalconDeterministic(seedBase)
  custom_falcon.falconTyrKeypairInto(v, pk, sk, b)
  result.name = name
  result.loops = falconPrepareLoops
  result.warmup = falconPrepareWarmup
  result.rateKind = rkOps
  result.workPerLoop = 1
  result.run = proc() =
    prepared = custom_falcon.falconTyrPrepareSecret(v, sk, b)
    mixInt(prepared.expanded.tree.len)
    custom_falcon.falconTyrClearPreparedSecret(prepared)

proc buildFalconSignSpec(v: custom_falcon.FalconVariant, b: custom_falcon.FalconBackend,
    name: string): BenchSpec =
  var
    p: custom_falcon.FalconParams
    pk: seq[byte]
    sk: seq[byte]
    sig: seq[byte]
    sigLen: int = 0
    msg: seq[byte]
    counter: int = 0
    seedBase: int = 0
    rndBase: int = 0
  p = params(v)
  pk = newSeq[byte](p.publicKeyBytes)
  sk = newSeq[byte](p.secretKeyBytes)
  sig = newSeq[byte](p.signatureBytes)
  msg = makePatternBytes(2048, 0x64 + ord(v) * 23)
  seedBase = 0x84 + ord(v) * 23
  rndBase = 0xA4 + ord(v) * 23
  if b == custom_falcon.falconSimd:
    seedBase = seedBase + 0x100
    rndBase = rndBase + 0x100
  resetFalconDeterministic(seedBase)
  custom_falcon.falconTyrKeypairInto(v, pk, sk, b)
  result.name = name
  result.loops = falconSignLoops
  result.warmup = falconSignWarmup
  result.rateKind = rkOps
  result.workPerLoop = 1
  result.run = proc() =
    resetFalconDeterministic(rndBase + counter)
    custom_falcon.falconTyrSignInto(v, sig, sigLen, msg, sk, b)
    counter = counter + 1
    mixBytesLen(sig, sigLen)

proc buildFalconSignPreparedSpec(v: custom_falcon.FalconVariant, b: custom_falcon.FalconBackend,
    name: string): BenchSpec =
  var
    p: custom_falcon.FalconParams
    pk: seq[byte]
    sk: seq[byte]
    prepared: custom_falcon.FalconPreparedSecret
    sig: seq[byte]
    sigLen: int = 0
    msg: seq[byte]
    counter: int = 0
    seedBase: int = 0
    rndBase: int = 0
  p = params(v)
  pk = newSeq[byte](p.publicKeyBytes)
  sk = newSeq[byte](p.secretKeyBytes)
  sig = newSeq[byte](p.signatureBytes)
  msg = makePatternBytes(2048, 0xC4 + ord(v) * 23)
  seedBase = 0xE4 + ord(v) * 23
  rndBase = 0x104 + ord(v) * 23
  if b == custom_falcon.falconSimd:
    seedBase = seedBase + 0x100
    rndBase = rndBase + 0x100
  resetFalconDeterministic(seedBase)
  custom_falcon.falconTyrKeypairInto(v, pk, sk, b)
  prepared = custom_falcon.falconTyrPrepareSecret(v, sk, b)
  result.name = name
  result.loops = falconSignPreparedLoops
  result.warmup = falconSignPreparedWarmup
  result.rateKind = rkOps
  result.workPerLoop = 1
  result.run = proc() =
    resetFalconDeterministic(rndBase + counter)
    custom_falcon.falconTyrSignPreparedInto(prepared, sig, sigLen, msg)
    counter = counter + 1
    mixBytesLen(sig, sigLen)

proc buildFalconVerifySpec(v: custom_falcon.FalconVariant, b: custom_falcon.FalconBackend,
    name: string): BenchSpec =
  var
    p: custom_falcon.FalconParams
    pk: seq[byte]
    sk: seq[byte]
    sig: seq[byte]
    msg: seq[byte]
    seedBase: int = 0
    rndBase: int = 0
  p = params(v)
  pk = newSeq[byte](p.publicKeyBytes)
  sk = newSeq[byte](p.secretKeyBytes)
  msg = makePatternBytes(128, 0x144 + ord(v) * 23)
  seedBase = 0x164 + ord(v) * 23
  rndBase = 0x184 + ord(v) * 23
  if b == custom_falcon.falconSimd:
    seedBase = seedBase + 0x100
    rndBase = rndBase + 0x100
  resetFalconDeterministic(seedBase)
  custom_falcon.falconTyrKeypairInto(v, pk, sk, b)
  resetFalconDeterministic(rndBase)
  sig = custom_falcon.falconTyrSign(v, msg, sk, b)
  result.name = name
  result.loops = falconVerifyLoops
  result.warmup = falconVerifyWarmup
  result.rateKind = rkOps
  result.workPerLoop = 1
  result.run = proc() =
    var ok: bool = false
    ok = custom_falcon.falconTyrVerify(v, msg, sig, pk, b)
    doAssert ok
    mixBool(ok)

proc buildSphincsKeypairSpec(v: custom_sphincs.SphincsVariant, name: string): BenchSpec =
  var
    p: custom_sphincs.SphincsParams
    seeds: seq[seq[byte]]
    counter: int = 0
  p = params(v)
  seeds = makeCorpus(p.seedBytes, slowCorpusCount, 0x28 + ord(v) * 17)
  result.name = name
  result.loops = sphincsKeypairLoops
  result.warmup = sphincsWarmup
  result.rateKind = rkOps
  result.workPerLoop = 1
  result.run = proc() =
    var
      idx: int = 0
      kp: custom_sphincs.SphincsTyrKeypair
    idx = nextIndex(counter, seeds.len)
    kp = custom_sphincs.sphincsTyrKeypair(v, seeds[idx])
    mixBytes(kp.publicKey)
    mixBytes(kp.secretKey)

proc buildSphincsSignSpec(v: custom_sphincs.SphincsVariant, name: string): BenchSpec =
  var
    p: custom_sphincs.SphincsParams
    seed: seq[byte]
    kp: custom_sphincs.SphincsTyrKeypair
    msg: seq[byte]
    optrands: seq[seq[byte]]
    counter: int = 0
  p = params(v)
  seed = makePatternBytes(p.seedBytes, 0x48 + ord(v) * 17)
  kp = custom_sphincs.sphincsTyrKeypair(v, seed)
  msg = makePatternBytes(64, 0x68 + ord(v) * 17)
  optrands = makeCorpus(p.n, slowCorpusCount, 0x88 + ord(v) * 17)
  result.name = name
  result.loops = sphincsSignLoops
  result.warmup = sphincsWarmup
  result.rateKind = rkOps
  result.workPerLoop = 1
  result.run = proc() =
    var
      idx: int = 0
      sig: seq[byte]
    idx = nextIndex(counter, optrands.len)
    sig = custom_sphincs.sphincsTyrSignDerand(v, msg, kp.secretKey, optrands[idx])
    mixBytes(sig)

proc buildSphincsVerifySpec(v: custom_sphincs.SphincsVariant, name: string): BenchSpec =
  var
    p: custom_sphincs.SphincsParams
    seed: seq[byte]
    kp: custom_sphincs.SphincsTyrKeypair
    msg: seq[byte]
    optrand: seq[byte]
    sig: seq[byte]
  p = params(v)
  seed = makePatternBytes(p.seedBytes, 0xA8 + ord(v) * 17)
  kp = custom_sphincs.sphincsTyrKeypair(v, seed)
  msg = makePatternBytes(64, 0xC8 + ord(v) * 17)
  optrand = makePatternBytes(p.n, 0xE8 + ord(v) * 17)
  sig = custom_sphincs.sphincsTyrSignDerand(v, msg, kp.secretKey, optrand)
  result.name = name
  result.loops = sphincsVerifyLoops
  result.warmup = sphincsWarmup
  result.rateKind = rkOps
  result.workPerLoop = 1
  result.run = proc() =
    var ok: bool = false
    ok = custom_sphincs.sphincsTyrVerify(v, msg, sig, kp.publicKey)
    doAssert ok
    mixBool(ok)

proc buildSignatureKeypairSpecs(notes: var seq[string]): seq[BenchSpec] =
  addOpsSpec(result, "dilithium44", dilithiumKeypairLoops, dilithiumKeypairWarmup,
    buildDilithiumKeypairSpec(custom_dilithium.dilithium44, "dilithium44").run)
  addOpsSpec(result, "dilithium65", dilithiumKeypairLoops, dilithiumKeypairWarmup,
    buildDilithiumKeypairSpec(custom_dilithium.dilithium65, "dilithium65").run)
  addOpsSpec(result, "dilithium87", dilithiumKeypairLoops, dilithiumKeypairWarmup,
    buildDilithiumKeypairSpec(custom_dilithium.dilithium87, "dilithium87").run)
  appendFalconKeypairSpecs(result, notes)
  addOpsSpec(result, "sphincs_shake128f_simple", sphincsKeypairLoops, sphincsWarmup,
    buildSphincsKeypairSpec(custom_sphincs.sphincsShake128fSimple, "sphincs_shake128f_simple").run)

proc buildSignatureSignSpecs(notes: var seq[string]): seq[BenchSpec] =
  addOpsSpec(result, "dilithium44", dilithiumSignLoops, dilithiumSignWarmup,
    buildDilithiumSignSpec(custom_dilithium.dilithium44, "dilithium44").run)
  addOpsSpec(result, "dilithium65", dilithiumSignLoops, dilithiumSignWarmup,
    buildDilithiumSignSpec(custom_dilithium.dilithium65, "dilithium65").run)
  addOpsSpec(result, "dilithium87", dilithiumSignLoops, dilithiumSignWarmup,
    buildDilithiumSignSpec(custom_dilithium.dilithium87, "dilithium87").run)
  appendFalconSignSpecs(result, notes)
  addOpsSpec(result, "sphincs_shake128f_simple", sphincsSignLoops, sphincsWarmup,
    buildSphincsSignSpec(custom_sphincs.sphincsShake128fSimple, "sphincs_shake128f_simple").run)

proc buildSignatureVerifySpecs(notes: var seq[string]): seq[BenchSpec] =
  addOpsSpec(result, "dilithium44", dilithiumVerifyLoops, dilithiumVerifyWarmup,
    buildDilithiumVerifySpec(custom_dilithium.dilithium44, "dilithium44").run)
  addOpsSpec(result, "dilithium65", dilithiumVerifyLoops, dilithiumVerifyWarmup,
    buildDilithiumVerifySpec(custom_dilithium.dilithium65, "dilithium65").run)
  addOpsSpec(result, "dilithium87", dilithiumVerifyLoops, dilithiumVerifyWarmup,
    buildDilithiumVerifySpec(custom_dilithium.dilithium87, "dilithium87").run)
  appendFalconVerifySpecs(result, notes)
  addOpsSpec(result, "sphincs_shake128f_simple", sphincsVerifyLoops, sphincsWarmup,
    buildSphincsVerifySpec(custom_sphincs.sphincsShake128fSimple, "sphincs_shake128f_simple").run)

proc buildFalconPrepareSpecs(notes: var seq[string]): seq[BenchSpec] =
  appendFalconPrepareSpecs(result, notes)

proc buildFalconPreparedSignSpecs(notes: var seq[string]): seq[BenchSpec] =
  appendFalconPreparedSignSpecs(result, notes)

proc buildProfileLine(): string =
  result = "release="
  when defined(release):
    result.add("on")
  else:
    result.add("off")
  result.add(" threads=")
  if compileOption("threads"):
    result.add("on")
  else:
    result.add("off")
  result.add(" sse2=")
  when defined(sse2):
    result.add("on")
  else:
    result.add("off")
  result.add(" avx2=")
  when defined(avx2):
    result.add("on")
  else:
    result.add("off")
  result.add(" aesni=")
  when defined(aesni):
    result.add("on")
  else:
    result.add("off")

proc printUsageAndQuit() =
  echo "Usage: bench_custom_crypto_table [bytes] [kem] [signature] [falcon]"
  quit(1)

proc normalizeSectionName(s: string): string =
  result = s.strip().toLowerAscii()

proc collectRequestedSections(): seq[string] =
  var
    raw: seq[string]
    i: int = 0
    name: string
  raw = commandLineParams()
  i = 0
  while i < raw.len:
    name = normalizeSectionName(raw[i])
    if name == "all":
      return @[]
    if name != "bytes" and name != "kem" and name != "signature" and name != "falcon":
      printUsageAndQuit()
    if name notin result:
      result.add(name)
    i = i + 1

proc sectionRequested(requested: openArray[string], name: string): bool =
  if requested.len <= 0:
    return true
  result = name in requested

proc runByteTables() =
  var
    notes: seq[string] = @[]
    specs: seq[BenchSpec] = @[]
    rows: seq[BenchRow] = @[]
  notes = @[]
  specs = buildSymmetricSpecs(smallBytes, notes)
  rows = benchmarkSpecs(specs)
  printTable("Symmetric 64 B latency", "MiB/s", rows, notes)
  notes = @[]
  specs = buildSymmetricSpecs(largeBytes, notes)
  rows = benchmarkSpecs(specs)
  printTable("Symmetric 8 KiB throughput", "MiB/s", rows, notes)

  notes = @[]
  specs = buildHashSpecs(smallBytes, notes)
  rows = benchmarkSpecs(specs)
  printTable("Hash 64 B latency", "MiB/s", rows, notes)
  notes = @[]
  specs = buildHashSpecs(largeBytes, notes)
  rows = benchmarkSpecs(specs)
  printTable("Hash 8 KiB throughput", "MiB/s", rows, notes)

  notes = @[]
  specs = buildMacSpecs(smallBytes, notes)
  rows = benchmarkSpecs(specs)
  printTable("MAC 64 B latency", "MiB/s", rows, notes)
  notes = @[]
  specs = buildMacSpecs(largeBytes, notes)
  rows = benchmarkSpecs(specs)
  printTable("MAC 8 KiB throughput", "MiB/s", rows, notes)

proc runKemTables() =
  var
    notes: seq[string] = @[]
    specs: seq[BenchSpec] = @[]
    rows: seq[BenchRow] = @[]
  notes = @[]
  specs = buildKemKeypairSpecs(notes)
  rows = benchmarkSpecs(specs)
  printTable("KEM keypair", "ops/s", rows, notes)

  notes = @[]
  specs = buildKemEncapsSpecs(notes)
  rows = benchmarkSpecs(specs)
  printTable("KEM encaps", "ops/s", rows, notes)

  notes = @[]
  specs = buildKemDecapsSpecs(notes)
  rows = benchmarkSpecs(specs)
  printTable("KEM decaps", "ops/s", rows, notes)

proc runSignatureTables() =
  var
    notes: seq[string] = @[]
    specs: seq[BenchSpec] = @[]
    rows: seq[BenchRow] = @[]
  notes = @[]
  specs = buildSignatureKeypairSpecs(notes)
  rows = benchmarkSpecs(specs)
  printTable("Signature keypair", "ops/s", rows, notes)

  notes = @[]
  specs = buildSignatureSignSpecs(notes)
  rows = benchmarkSpecs(specs)
  printTable("Signature sign", "ops/s", rows, notes)

  notes = @[]
  specs = buildSignatureVerifySpecs(notes)
  rows = benchmarkSpecs(specs)
  printTable("Signature verify", "ops/s", rows, notes)

proc runFalconOnlyTables() =
  var
    notes: seq[string] = @[]
    specs: seq[BenchSpec] = @[]
    rows: seq[BenchRow] = @[]
  notes = @[]
  specs = buildFalconPrepareSpecs(notes)
  rows = benchmarkSpecs(specs)
  printTable("Falcon prepare", "ops/s", rows, notes)

  notes = @[]
  specs = buildFalconPreparedSignSpecs(notes)
  rows = benchmarkSpecs(specs)
  printTable("Falcon sign_prepared", "ops/s", rows, notes)

proc main() =
  var requestedSections: seq[string] = @[]
  echo "# Tyr Custom-Crypto Benchmark Report"
  echo ""
  echo "Build profile: ", buildProfileLine()
  requestedSections = collectRequestedSections()
  custom_falcon.falconSetRandombytesCallback(falconDeterministicCallback)
  try:
    if sectionRequested(requestedSections, "bytes"):
      runByteTables()
    if sectionRequested(requestedSections, "kem"):
      runKemTables()
    if sectionRequested(requestedSections, "signature"):
      runSignatureTables()
    if sectionRequested(requestedSections, "falcon"):
      runFalconOnlyTables()
  finally:
    custom_falcon.falconClearRandombytesCallback()
  if benchSink == 0'u64:
    echo ""
    echo "Checksum: 0"

when isMainModule:
  main()
