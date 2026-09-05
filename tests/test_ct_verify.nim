{.define: tyrCryptoTestHooks.}

import std/[monotimes, unittest]

import ./helpers
import ../src/tyr/helpers/common/ct_compare
import ../src/tyr/signatures/dilithium as custom_dilithium
import ../src/tyr/signatures/sphincs as custom_sphincs
import ../src/tyr/kems/mceliece as custom_mceliece

proc fillSeed(seed: var seq[byte], base: int) =
  var i = 0
  while i < seed.len:
    seed[i] = uint8((base + i) mod 256)
    i = i + 1

const
  timingWarmupIterations = 4
  dilithium44DigestLateOffset = 31
  sphincsShake128fTreeTailBytes = 66 * 16

proc fastestNanos(A: openArray[int64]): int64 =
  ## A: measured run times, in nanoseconds.
  ##
  ## Reports the fastest run rather than the middle one. Everything the
  ## operating system does to a timed run - handing the core to another
  ## process, a page fault, a clock change - only ever makes that run
  ## longer. So the fastest run is the one closest to the true cost of
  ## the work, and it is the only summary that stays steady while the
  ## rest of the test suite is running beside it.
  ##
  ##   samples:  ###  #  ############   #####
  ##             ^
  ##             +-- taken: nothing has been added to this one
  var
    i: int = 0
  result = 0
  while i < A.len:
    if A[i] > 0 and (result == 0 or A[i] < result):
      result = A[i]
    i = i + 1

proc fastestVerifyNanos(S: openArray[byte], flipOffset, iterations: int,
    verify: proc (B: seq[byte]): bool): int64 =
  ## S: a valid signature, copied and then corrupted.
  ## flipOffset: which byte to flip, which decides how early the
  ##   verification is able to notice the signature is wrong.
  ## iterations: how many timed runs to take.
  ## verify: the verification under measurement.
  ##
  ## A verification that leaks nothing takes the same time whether the
  ## wrong byte sits at the front or at the back.
  var
    badSig: seq[byte] = newSeq[byte](S.len)
    samples: seq[int64] = newSeq[int64](iterations)
    t0: MonoTime
    i: int = 0
  while i < S.len:
    badSig[i] = S[i]
    i = i + 1
  badSig[flipOffset] = badSig[flipOffset] xor 0x01'u8
  i = 0
  while i < timingWarmupIterations:
    discard verify(badSig)
    i = i + 1
  i = 0
  while i < iterations:
    t0 = getMonoTime()
    discard verify(badSig)
    samples[i] = getMonoTime().ticks - t0.ticks
    i = i + 1
  result = fastestNanos(samples)

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
      iterations = 256
      maxRatio = 1.35
    let msg = toBytes("ct-verify dilithium timing message")
    var seed = newSeq[byte](32)
    fillSeed(seed, 83)
    let
      kp = custom_dilithium.dilithiumTyrKeypair(custom_dilithium.dilithium44, seed)
      sig = custom_dilithium.dilithiumTyrSign(custom_dilithium.dilithium44, msg, kp.secretKey)
      earlyNs = fastestVerifyNanos(sig, 0, iterations, proc (B: seq[byte]): bool =
        custom_dilithium.dilithiumTyrVerify(custom_dilithium.dilithium44, msg, B,
          kp.publicKey))
      lateNs = fastestVerifyNanos(sig, dilithium44DigestLateOffset, iterations,
        proc (B: seq[byte]): bool =
          custom_dilithium.dilithiumTyrVerify(custom_dilithium.dilithium44, msg, B,
            kp.publicKey))
    checkpoint("fastest early=" & $earlyNs & "ns late=" & $lateNs & "ns")
    check timingRatioWithin(earlyNs, lateNs, maxRatio)

  test "sphincs verify timing is stable across early vs late root mismatch":
    const
      iterations = 256
      maxRatio = 1.40
    let msg = toBytes("ct-verify sphincs timing message")
    var seed = newSeq[byte](48)
    fillSeed(seed, 97)
    let
      kp = custom_sphincs.sphincsTyrKeypair(custom_sphincs.sphincsShake128fSimple, seed)
      sig = custom_sphincs.sphincsTyrSign(custom_sphincs.sphincsShake128fSimple, msg, kp.secretKey)
      earlyNs = fastestVerifyNanos(sig, sig.len - sphincsShake128fTreeTailBytes,
        iterations, proc (B: seq[byte]): bool =
          custom_sphincs.sphincsTyrVerify(custom_sphincs.sphincsShake128fSimple,
            msg, B, kp.publicKey))
      lateNs = fastestVerifyNanos(sig, sig.len - 1, iterations,
        proc (B: seq[byte]): bool =
          custom_sphincs.sphincsTyrVerify(custom_sphincs.sphincsShake128fSimple,
            msg, B, kp.publicKey))
    checkpoint("fastest early=" & $earlyNs & "ns late=" & $lateNs & "ns")
    check timingRatioWithin(earlyNs, lateNs, maxRatio)
