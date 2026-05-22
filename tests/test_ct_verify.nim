import std/[algorithm, monotimes, unittest]

import ./helpers
import ../src/protocols/custom_crypto/asymmetric/pq/common/ct_compare
import ../src/protocols/custom_crypto/dilithium as custom_dilithium
import ../src/protocols/custom_crypto/sphincs as custom_sphincs
import ../src/protocols/custom_crypto/mceliece as custom_mceliece

proc fillSeed(seed: var seq[byte], base: int) =
  var i = 0
  while i < seed.len:
    seed[i] = uint8((base + i) mod 256)
    i = i + 1

proc medianNanos(samples: openArray[int64]): int64 =
  var sorted = newSeq[int64](samples.len)
  for i in 0 ..< samples.len:
    sorted[i] = samples[i]
  algorithm.sort(sorted)
  result = sorted[sorted.len div 2]

const
  timingWarmupIterations = 4
  dilithium44DigestLateOffset = 31
  sphincsShake128fTreeTailBytes = 66 * 16

proc measureDilithiumVerifyAtOffset(msg, sig, pk: openArray[byte], flipOffset: int,
    iterations: int): int64 =
  var
    badSig = newSeq[byte](sig.len)
  for i in 0 ..< sig.len:
    badSig[i] = sig[i]
  badSig[flipOffset] = badSig[flipOffset] xor 0x01'u8
  var warmup = 0
  while warmup < timingWarmupIterations:
    discard custom_dilithium.dilithiumTyrVerify(custom_dilithium.dilithium44, msg, badSig, pk)
    warmup = warmup + 1
  var samples = newSeq[int64](iterations)
  var run = 0
  while run < iterations:
    let t0 = getMonoTime()
    discard custom_dilithium.dilithiumTyrVerify(custom_dilithium.dilithium44, msg, badSig, pk)
    samples[run] = getMonoTime().ticks - t0.ticks
    run = run + 1
  result = medianNanos(samples)

proc measureSphincsVerifyAtOffset(msg, sig, pk: openArray[byte], flipOffset: int,
    iterations: int): int64 =
  var
    badSig = newSeq[byte](sig.len)
  for i in 0 ..< sig.len:
    badSig[i] = sig[i]
  badSig[flipOffset] = badSig[flipOffset] xor 0x01'u8
  var warmup = 0
  while warmup < timingWarmupIterations:
    discard custom_sphincs.sphincsTyrVerify(custom_sphincs.sphincsShake128fSimple, msg, badSig, pk)
    warmup = warmup + 1
  var samples = newSeq[int64](iterations)
  var run = 0
  while run < iterations:
    let t0 = getMonoTime()
    discard custom_sphincs.sphincsTyrVerify(custom_sphincs.sphincsShake128fSimple, msg, badSig, pk)
    samples[run] = getMonoTime().ticks - t0.ticks
    run = run + 1
  result = medianNanos(samples)

proc timingRatioWithin(a, b: int64; maxRatio: float): bool =
  if a <= 0 or b <= 0:
    return false
  let
    lo = min(a, b).float
    hi = max(a, b).float
  result = (hi / lo) <= maxRatio

suite "constant-time compare helpers":
  test "verifyBytes accepts equal buffers":
    let a = @[byte 1, 2, 3, 4]
    check verifyBytes(a, a) == 0
    check bytesEqualCt(a, a)

  test "verifyBytes rejects unequal length":
    check verifyBytes(@[byte 1, 2], @[byte 1, 2, 3]) == 1
    check not bytesEqualCt(@[byte 1, 2], @[byte 1, 2, 3])

  test "verifyBytes rejects first and last differing bytes":
    check verifyBytes(@[byte 1, 2, 3], @[byte 9, 2, 3]) == 1
    check verifyBytes(@[byte 1, 2, 3], @[byte 1, 2, 9]) == 1

  test "uint16MaskAllOnesCt recognizes full masks":
    check uint16MaskAllOnesCt(0xFFFF'u16)
    check not uint16MaskAllOnesCt(0xFFFE'u16)
    check not uint16MaskAllOnesCt(0x0000'u16)

suite "constant-time verify regressions":
  test "dilithium rejects single-byte signature flips at multiple offsets":
    let msg = toBytes("ct-verify dilithium message")
    var seed = newSeq[byte](32)
    fillSeed(seed, 31)
    let kp = custom_dilithium.dilithiumTyrKeypair(custom_dilithium.dilithium44, seed)
    let sig = custom_dilithium.dilithiumTyrSign(custom_dilithium.dilithium44, msg, kp.secretKey)
    check custom_dilithium.dilithiumTyrVerify(custom_dilithium.dilithium44, msg, sig, kp.publicKey)
    for offset in [0, sig.len div 2, sig.len - 1]:
      var bad = newSeq[byte](sig.len)
      for i in 0 ..< sig.len:
        bad[i] = sig[i]
      bad[offset] = bad[offset] xor 0x01'u8
      check not custom_dilithium.dilithiumTyrVerify(custom_dilithium.dilithium44, msg, bad, kp.publicKey)

  test "sphincs rejects single-byte signature flips at multiple offsets":
    let msg = toBytes("ct-verify sphincs message")
    var seed = newSeq[byte](48)
    fillSeed(seed, 47)
    let kp = custom_sphincs.sphincsTyrKeypair(custom_sphincs.sphincsShake128fSimple, seed)
    let sig = custom_sphincs.sphincsTyrSign(custom_sphincs.sphincsShake128fSimple, msg, kp.secretKey)
    check custom_sphincs.sphincsTyrVerify(custom_sphincs.sphincsShake128fSimple, msg, sig, kp.publicKey)
    for offset in [0, sig.len div 2, sig.len - 1]:
      var bad = newSeq[byte](sig.len)
      for i in 0 ..< sig.len:
        bad[i] = sig[i]
      bad[offset] = bad[offset] xor 0x01'u8
      check not custom_sphincs.sphincsTyrVerify(custom_sphincs.sphincsShake128fSimple, msg, bad, kp.publicKey)

  test "mceliece invalid ciphertext uses implicit rejection":
    var seed = newSeq[byte](32)
    let variant = custom_mceliece.mceliece6960119f
    fillSeed(seed, 61)
    let
      kp = custom_mceliece.mcelieceTyrKeypair(variant, seed)
      env = custom_mceliece.mcelieceTyrEncaps(variant, kp.publicKey)
      good = custom_mceliece.mcelieceTyrTryDecaps(variant, kp.secretKey, env.ciphertext)
    var tampered = newSeq[byte](env.ciphertext.len)
    for i in 0 ..< tampered.len:
      tampered[i] = env.ciphertext[i]
    tampered[0] = tampered[0] xor 0x01'u8
    let bad = custom_mceliece.mcelieceTyrTryDecaps(variant, kp.secretKey, tampered)
    check good.ok
    check good.sharedSecret == env.sharedSecret
    check not bad.ok
    check bad.sharedSecret.len == env.sharedSecret.len
    check bad.sharedSecret != env.sharedSecret

  test "dilithium verify timing is stable across early vs late digest mismatch":
    const
      iterations = 64
      maxRatio = 1.35
    let msg = toBytes("ct-verify dilithium timing message")
    var seed = newSeq[byte](32)
    fillSeed(seed, 83)
    let
      kp = custom_dilithium.dilithiumTyrKeypair(custom_dilithium.dilithium44, seed)
      sig = custom_dilithium.dilithiumTyrSign(custom_dilithium.dilithium44, msg, kp.secretKey)
      earlyNs = measureDilithiumVerifyAtOffset(msg, sig, kp.publicKey, 0, iterations)
      lateNs = measureDilithiumVerifyAtOffset(msg, sig, kp.publicKey, dilithium44DigestLateOffset, iterations)
    check timingRatioWithin(earlyNs, lateNs, maxRatio)

  test "sphincs verify timing is stable across early vs late root mismatch":
    const
      iterations = 16
      maxRatio = 1.40
    let msg = toBytes("ct-verify sphincs timing message")
    var seed = newSeq[byte](48)
    fillSeed(seed, 97)
    let
      kp = custom_sphincs.sphincsTyrKeypair(custom_sphincs.sphincsShake128fSimple, seed)
      sig = custom_sphincs.sphincsTyrSign(custom_sphincs.sphincsShake128fSimple, msg, kp.secretKey)
      earlyNs = measureSphincsVerifyAtOffset(msg, sig, kp.publicKey, sig.len - sphincsShake128fTreeTailBytes, iterations)
      lateNs = measureSphincsVerifyAtOffset(msg, sig, kp.publicKey, sig.len - 1, iterations)
    check timingRatioWithin(earlyNs, lateNs, maxRatio)
