## ============================================================
## | Falcon Tyr Test                                          |
## | -> Direct correctness checks for the vendored Falcon API |
## ============================================================

import std/unittest

import ../src/protocols/custom_crypto/falcon
import ../src/protocols/custom_crypto/asymmetric/pq/falcon/format
import ../src/protocols/custom_crypto/asymmetric/pq/falcon/pure_verify
import ../src/protocols/custom_crypto/asymmetric/pq/falcon/sign

var
  falconDeterministicBase: int = 0
  falconDeterministicOffset: int = 0

proc fillPattern(bs: var openArray[byte], start: int = 0) =
  var
    i: int = 0
  while i < bs.len:
    bs[i] = byte((start + i) and 0xff)
    i = i + 1

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

suite "falcon tyr":
  test "falcon512 scalar roundtrip succeeds":
    var
      msg = newSeq[byte](96)
      kp: FalconTyrKeypair
      sig: seq[byte]
    fillPattern(msg, 0x21)
    falconSetRandombytesCallback(falconDeterministicCallback)
    defer:
      falconTyrClearKeypair(kp)
      falconClearRandombytesCallback()
    resetFalconDeterministic(0x10)
    kp = falconTyrKeypair(falcon512, falconScalar)
    resetFalconDeterministic(0x40)
    sig = falconTyrSign(falcon512, msg, kp.secretKey, falconScalar)
    check falconTyrVerify(falcon512, msg, sig, kp.publicKey, falconScalar)

  test "falcon1024 scalar roundtrip succeeds":
    var
      msg = newSeq[byte](192)
      kp: FalconTyrKeypair
      sig: seq[byte]
    fillPattern(msg, 0x33)
    falconSetRandombytesCallback(falconDeterministicCallback)
    defer:
      falconTyrClearKeypair(kp)
      falconClearRandombytesCallback()
    resetFalconDeterministic(0x50)
    kp = falconTyrKeypair(falcon1024, falconScalar)
    resetFalconDeterministic(0x80)
    sig = falconTyrSign(falcon1024, msg, kp.secretKey, falconScalar)
    check falconTyrVerify(falcon1024, msg, sig, kp.publicKey, falconScalar)

  test "falcon512 scalar prepared roundtrip succeeds":
    var
      msg = newSeq[byte](120)
      kp: FalconTyrKeypair
      prepared: FalconPreparedSecret
      sig: seq[byte]
    fillPattern(msg, 0x47)
    falconSetRandombytesCallback(falconDeterministicCallback)
    defer:
      falconTyrClearPreparedSecret(prepared)
      falconTyrClearKeypair(kp)
      falconClearRandombytesCallback()
    resetFalconDeterministic(0x14)
    kp = falconTyrKeypair(falcon512, falconScalar)
    prepared = falconTyrPrepareSecret(falcon512, kp.secretKey, falconScalar)
    resetFalconDeterministic(0x58)
    sig = falconTyrSignPrepared(prepared, msg)
    check falconTyrVerify(falcon512, msg, sig, kp.publicKey, falconScalar)

  test "falcon1024 scalar prepared roundtrip succeeds":
    var
      msg = newSeq[byte](208)
      kp: FalconTyrKeypair
      prepared: FalconPreparedSecret
      sig: seq[byte]
    fillPattern(msg, 0x63)
    falconSetRandombytesCallback(falconDeterministicCallback)
    defer:
      falconTyrClearPreparedSecret(prepared)
      falconTyrClearKeypair(kp)
      falconClearRandombytesCallback()
    resetFalconDeterministic(0x6A)
    kp = falconTyrKeypair(falcon1024, falconScalar)
    prepared = falconTyrPrepareSecret(falcon1024, kp.secretKey, falconScalar)
    resetFalconDeterministic(0x9C)
    sig = falconTyrSignPrepared(prepared, msg)
    check falconTyrVerify(falcon1024, msg, sig, kp.publicKey, falconScalar)

  test "pure Nim Falcon-512 verify accepts scalar signature":
    var
      msg = newSeq[byte](112)
      kp: FalconTyrKeypair
      sig: seq[byte]
    fillPattern(msg, 0x29)
    falconSetRandombytesCallback(falconDeterministicCallback)
    defer:
      falconTyrClearKeypair(kp)
      falconClearRandombytesCallback()
    resetFalconDeterministic(0x24)
    kp = falconTyrKeypair(falcon512, falconScalar)
    resetFalconDeterministic(0x5E)
    sig = falconTyrSign(falcon512, msg, kp.secretKey, falconScalar)
    check falconVerifyPure(falcon512, msg, sig, kp.publicKey)

  test "pure Nim Falcon-1024 verify accepts scalar signature":
    var
      msg = newSeq[byte](224)
      kp: FalconTyrKeypair
      sig: seq[byte]
    fillPattern(msg, 0x35)
    falconSetRandombytesCallback(falconDeterministicCallback)
    defer:
      falconTyrClearKeypair(kp)
      falconClearRandombytesCallback()
    resetFalconDeterministic(0x62)
    kp = falconTyrKeypair(falcon1024, falconScalar)
    resetFalconDeterministic(0x98)
    sig = falconTyrSign(falcon1024, msg, kp.secretKey, falconScalar)
    check falconVerifyPure(falcon1024, msg, sig, kp.publicKey)

  test "pure Nim Falcon-512 prepared sign matches scalar prepared sign":
    var
      msg = newSeq[byte](160)
      nonce = newSeq[byte](falconNonceLen)
      seed = newSeq[byte](falconSignSeedBytes)
      kp: FalconTyrKeypair
      preparedScalar: FalconPreparedSecret
      preparedPure: FalconExpandedSecret
      sigScalar: seq[byte]
      sigPure: seq[byte]
    fillPattern(msg, 0x4A)
    fillPattern(nonce, 0xB0)
    fillPattern(seed, 0xB0 + falconNonceLen)
    falconSetRandombytesCallback(falconDeterministicCallback)
    defer:
      clearExpandedSecret(preparedPure)
      falconTyrClearPreparedSecret(preparedScalar)
      falconTyrClearKeypair(kp)
      falconClearRandombytesCallback()
    resetFalconDeterministic(0x2C)
    kp = falconTyrKeypair(falcon512, falconScalar)
    preparedScalar = falconTyrPrepareSecret(falcon512, kp.secretKey, falconScalar)
    preparedPure = prepareSecretKey(falcon512, kp.secretKey)
    resetFalconDeterministic(0xB0)
    sigScalar = falconTyrSignPrepared(preparedScalar, msg)
    sigPure = falconSignPreparedDerand(preparedPure, msg, nonce, seed, falcon512)
    check sigPure == sigScalar
    check falconVerifyPure(falcon512, msg, sigPure, kp.publicKey)

  test "pure Nim Falcon-1024 prepared sign matches scalar prepared sign":
    var
      msg = newSeq[byte](240)
      nonce = newSeq[byte](falconNonceLen)
      seed = newSeq[byte](falconSignSeedBytes)
      kp: FalconTyrKeypair
      preparedScalar: FalconPreparedSecret
      preparedPure: FalconExpandedSecret
      sigScalar: seq[byte]
      sigPure: seq[byte]
    fillPattern(msg, 0x5C)
    fillPattern(nonce, 0xC4)
    fillPattern(seed, 0xC4 + falconNonceLen)
    falconSetRandombytesCallback(falconDeterministicCallback)
    defer:
      clearExpandedSecret(preparedPure)
      falconTyrClearPreparedSecret(preparedScalar)
      falconTyrClearKeypair(kp)
      falconClearRandombytesCallback()
    resetFalconDeterministic(0x46)
    kp = falconTyrKeypair(falcon1024, falconScalar)
    preparedScalar = falconTyrPrepareSecret(falcon1024, kp.secretKey, falconScalar)
    preparedPure = prepareSecretKey(falcon1024, kp.secretKey)
    resetFalconDeterministic(0xC4)
    sigScalar = falconTyrSignPrepared(preparedScalar, msg)
    sigPure = falconSignPreparedDerand(preparedPure, msg, nonce, seed, falcon1024)
    check sigPure == sigScalar
    check falconVerifyPure(falcon1024, msg, sigPure, kp.publicKey)

  when falconCompileHasSimd:
    test "scalar and simd outputs match under deterministic randomness":
      var
        msg = newSeq[byte](144)
        kpScalar: FalconTyrKeypair
        kpSimd: FalconTyrKeypair
        sigScalar: seq[byte]
        sigSimd: seq[byte]
      fillPattern(msg, 0x77)
      falconSetRandombytesCallback(falconDeterministicCallback)
      defer:
        falconTyrClearKeypair(kpScalar)
        falconTyrClearKeypair(kpSimd)
        falconClearRandombytesCallback()
      resetFalconDeterministic(0x90)
      kpScalar = falconTyrKeypair(falcon512, falconScalar)
      resetFalconDeterministic(0x90)
      kpSimd = falconTyrKeypair(falcon512, falconSimd)
      check kpScalar.publicKey == kpSimd.publicKey
      check kpScalar.secretKey == kpSimd.secretKey
      resetFalconDeterministic(0xC0)
      sigScalar = falconTyrSign(falcon512, msg, kpScalar.secretKey, falconScalar)
      resetFalconDeterministic(0xC0)
      sigSimd = falconTyrSign(falcon512, msg, kpSimd.secretKey, falconSimd)
      check sigScalar == sigSimd
      check falconTyrVerify(falcon512, msg, sigScalar, kpScalar.publicKey, falconScalar)
      check falconTyrVerify(falcon512, msg, sigSimd, kpSimd.publicKey, falconSimd)

    test "scalar and simd prepared outputs match under deterministic randomness":
      var
        msg = newSeq[byte](176)
        kpScalar: FalconTyrKeypair
        kpSimd: FalconTyrKeypair
        preparedScalar: FalconPreparedSecret
        preparedSimd: FalconPreparedSecret
        sigScalar: seq[byte]
        sigSimd: seq[byte]
      fillPattern(msg, 0x88)
      falconSetRandombytesCallback(falconDeterministicCallback)
      defer:
        falconTyrClearPreparedSecret(preparedScalar)
        falconTyrClearPreparedSecret(preparedSimd)
        falconTyrClearKeypair(kpScalar)
        falconTyrClearKeypair(kpSimd)
        falconClearRandombytesCallback()
      resetFalconDeterministic(0xA4)
      kpScalar = falconTyrKeypair(falcon512, falconScalar)
      resetFalconDeterministic(0xA4)
      kpSimd = falconTyrKeypair(falcon512, falconSimd)
      check kpScalar.publicKey == kpSimd.publicKey
      check kpScalar.secretKey == kpSimd.secretKey
      preparedScalar = falconTyrPrepareSecret(falcon512, kpScalar.secretKey, falconScalar)
      preparedSimd = falconTyrPrepareSecret(falcon512, kpSimd.secretKey, falconSimd)
      resetFalconDeterministic(0xD8)
      sigScalar = falconTyrSignPrepared(preparedScalar, msg)
      resetFalconDeterministic(0xD8)
      sigSimd = falconTyrSignPrepared(preparedSimd, msg)
      check sigScalar == sigSimd
      check falconTyrVerify(falcon512, msg, sigScalar, kpScalar.publicKey, falconScalar)
      check falconTyrVerify(falcon512, msg, sigSimd, kpSimd.publicKey, falconSimd)
