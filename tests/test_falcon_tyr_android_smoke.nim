## ==================================================================
## | Falcon Tyr Android Smoke Test                                   |
## | -> Smaller Falcon-512 subset for the Android fast harness path  |
## ==================================================================

import std/unittest

import ../src/protocols/custom_crypto/falcon

var
  falconDeterministicBaseAndroid: int = 0
  falconDeterministicOffsetAndroid: int = 0

proc fillPatternAndroid(bs: var openArray[byte], start: int = 0) =
  var
    i: int = 0
  while i < bs.len:
    bs[i] = byte((start + i) and 0xff)
    i = i + 1

proc falconDeterministicCallbackAndroid(randomArray: ptr uint8, bytesToRead: csize_t) {.cdecl.} =
  var
    outBytes = cast[ptr UncheckedArray[uint8]](randomArray)
    i: int = 0
  while i < int(bytesToRead):
    outBytes[i] = byte((falconDeterministicBaseAndroid + falconDeterministicOffsetAndroid + i) and 0xff)
    i = i + 1
  falconDeterministicOffsetAndroid = falconDeterministicOffsetAndroid + int(bytesToRead)

proc resetFalconDeterministicAndroid(base: int) =
  falconDeterministicBaseAndroid = base
  falconDeterministicOffsetAndroid = 0

suite "falcon tyr android smoke":
  test "falcon512 scalar roundtrip succeeds":
    var
      msg = newSeq[byte](96)
      kp: FalconTyrKeypair
      sig: seq[byte]
    fillPatternAndroid(msg, 0x21)
    falconSetRandombytesCallback(falconDeterministicCallbackAndroid)
    defer:
      falconTyrClearKeypair(kp)
      falconClearRandombytesCallback()
    resetFalconDeterministicAndroid(0x10)
    kp = falconTyrKeypair(falcon512, falconScalar)
    resetFalconDeterministicAndroid(0x40)
    sig = falconTyrSign(falcon512, msg, kp.secretKey, falconScalar)
    check falconTyrVerify(falcon512, msg, sig, kp.publicKey, falconScalar)

  test "falcon512 scalar prepared roundtrip succeeds":
    var
      msg = newSeq[byte](120)
      kp: FalconTyrKeypair
      prepared: FalconPreparedSecret
      sig: seq[byte]
    fillPatternAndroid(msg, 0x47)
    falconSetRandombytesCallback(falconDeterministicCallbackAndroid)
    defer:
      falconTyrClearPreparedSecret(prepared)
      falconTyrClearKeypair(kp)
      falconClearRandombytesCallback()
    resetFalconDeterministicAndroid(0x14)
    kp = falconTyrKeypair(falcon512, falconScalar)
    prepared = falconTyrPrepareSecret(falcon512, kp.secretKey, falconScalar)
    resetFalconDeterministicAndroid(0x58)
    sig = falconTyrSignPrepared(prepared, msg)
    check falconTyrVerify(falcon512, msg, sig, kp.publicKey, falconScalar)

  when falconCompileHasSimd:
    test "falcon512 scalar and simd outputs match":
      var
        msg = newSeq[byte](112)
        kpScalar: FalconTyrKeypair
        kpSimd: FalconTyrKeypair
        sigScalar: seq[byte]
        sigSimd: seq[byte]
      fillPatternAndroid(msg, 0x33)
      falconSetRandombytesCallback(falconDeterministicCallbackAndroid)
      defer:
        falconTyrClearKeypair(kpScalar)
        falconTyrClearKeypair(kpSimd)
        falconClearRandombytesCallback()
      resetFalconDeterministicAndroid(0x50)
      kpScalar = falconTyrKeypair(falcon512, falconScalar)
      resetFalconDeterministicAndroid(0x50)
      kpSimd = falconTyrKeypair(falcon512, falconSimd)
      check kpScalar.publicKey == kpSimd.publicKey
      check kpScalar.secretKey == kpSimd.secretKey
      resetFalconDeterministicAndroid(0x80)
      sigScalar = falconTyrSign(falcon512, msg, kpScalar.secretKey, falconScalar)
      resetFalconDeterministicAndroid(0x80)
      sigSimd = falconTyrSign(falcon512, msg, kpSimd.secretKey, falconSimd)
      check sigScalar == sigSimd
      check falconTyrVerify(falcon512, msg, sigScalar, kpScalar.publicKey, falconScalar)
      check falconTyrVerify(falcon512, msg, sigSimd, kpSimd.publicKey, falconSimd)

    test "falcon512 scalar and simd prepared signing match":
      var
        msg = newSeq[byte](128)
        kpScalar: FalconTyrKeypair
        kpSimd: FalconTyrKeypair
        preparedScalar: FalconPreparedSecret
        preparedSimd: FalconPreparedSecret
        sigScalar: seq[byte]
        sigSimd: seq[byte]
      fillPatternAndroid(msg, 0x47)
      falconSetRandombytesCallback(falconDeterministicCallbackAndroid)
      defer:
        falconTyrClearPreparedSecret(preparedScalar)
        falconTyrClearPreparedSecret(preparedSimd)
        falconTyrClearKeypair(kpScalar)
        falconTyrClearKeypair(kpSimd)
        falconClearRandombytesCallback()
      resetFalconDeterministicAndroid(0x90)
      kpScalar = falconTyrKeypair(falcon512, falconScalar)
      resetFalconDeterministicAndroid(0x90)
      kpSimd = falconTyrKeypair(falcon512, falconSimd)
      preparedScalar = falconTyrPrepareSecret(falcon512, kpScalar.secretKey, falconScalar)
      preparedSimd = falconTyrPrepareSecret(falcon512, kpSimd.secretKey, falconSimd)
      resetFalconDeterministicAndroid(0xC0)
      sigScalar = falconTyrSignPrepared(preparedScalar, msg)
      resetFalconDeterministicAndroid(0xC0)
      sigSimd = falconTyrSignPrepared(preparedSimd, msg)
      check sigScalar == sigSimd
      check falconTyrVerify(falcon512, msg, sigScalar, kpScalar.publicKey, falconScalar)
      check falconTyrVerify(falcon512, msg, sigSimd, kpSimd.publicKey, falconSimd)
