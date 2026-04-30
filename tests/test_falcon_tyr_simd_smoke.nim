## ==================================================================
## | Falcon Tyr SIMD Smoke Test                                      |
## | -> Focused Falcon-512 scalar vs SIMD validation for fast passes |
## ==================================================================

import std/unittest

import ../src/protocols/custom_crypto/falcon

var
  falconSmokeBase: int = 0
  falconSmokeOffset: int = 0

proc fillFalconSmoke(bs: var openArray[byte], start: int = 0) =
  var
    i: int = 0
  while i < bs.len:
    bs[i] = byte((start + i) and 0xff)
    i = i + 1

proc falconSmokeCallback(randomArray: ptr uint8, bytesToRead: csize_t) {.cdecl.} =
  var
    outBytes = cast[ptr UncheckedArray[uint8]](randomArray)
    i: int = 0
  while i < int(bytesToRead):
    outBytes[i] = byte((falconSmokeBase + falconSmokeOffset + i) and 0xff)
    i = i + 1
  falconSmokeOffset = falconSmokeOffset + int(bytesToRead)

proc resetFalconSmoke(base: int) =
  falconSmokeBase = base
  falconSmokeOffset = 0

suite "falcon tyr simd smoke":
  test "falcon512 scalar roundtrip succeeds":
    var
      msg = newSeq[byte](96)
      kp: FalconTyrKeypair
      sig: seq[byte]
    fillFalconSmoke(msg, 0x21)
    falconSetRandombytesCallback(falconSmokeCallback)
    defer:
      falconTyrClearKeypair(kp)
      falconClearRandombytesCallback()
    resetFalconSmoke(0x10)
    kp = falconTyrKeypair(falcon512, falconScalar)
    resetFalconSmoke(0x40)
    sig = falconTyrSign(falcon512, msg, kp.secretKey, falconScalar)
    check falconTyrVerify(falcon512, msg, sig, kp.publicKey, falconScalar)

  when falconCompileHasSimd:
    test "falcon512 scalar and simd outputs match":
      var
        msg = newSeq[byte](112)
        kpScalar: FalconTyrKeypair
        kpSimd: FalconTyrKeypair
        sigScalar: seq[byte]
        sigSimd: seq[byte]
      fillFalconSmoke(msg, 0x33)
      falconSetRandombytesCallback(falconSmokeCallback)
      defer:
        falconTyrClearKeypair(kpScalar)
        falconTyrClearKeypair(kpSimd)
        falconClearRandombytesCallback()
      resetFalconSmoke(0x50)
      kpScalar = falconTyrKeypair(falcon512, falconScalar)
      resetFalconSmoke(0x50)
      kpSimd = falconTyrKeypair(falcon512, falconSimd)
      check kpScalar.publicKey == kpSimd.publicKey
      check kpScalar.secretKey == kpSimd.secretKey
      resetFalconSmoke(0x80)
      sigScalar = falconTyrSign(falcon512, msg, kpScalar.secretKey, falconScalar)
      resetFalconSmoke(0x80)
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
      fillFalconSmoke(msg, 0x47)
      falconSetRandombytesCallback(falconSmokeCallback)
      defer:
        falconTyrClearPreparedSecret(preparedScalar)
        falconTyrClearPreparedSecret(preparedSimd)
        falconTyrClearKeypair(kpScalar)
        falconTyrClearKeypair(kpSimd)
        falconClearRandombytesCallback()
      resetFalconSmoke(0x90)
      kpScalar = falconTyrKeypair(falcon512, falconScalar)
      resetFalconSmoke(0x90)
      kpSimd = falconTyrKeypair(falcon512, falconSimd)
      preparedScalar = falconTyrPrepareSecret(falcon512, kpScalar.secretKey, falconScalar)
      preparedSimd = falconTyrPrepareSecret(falcon512, kpSimd.secretKey, falconSimd)
      resetFalconSmoke(0xC0)
      sigScalar = falconTyrSignPrepared(preparedScalar, msg)
      resetFalconSmoke(0xC0)
      sigSimd = falconTyrSignPrepared(preparedSimd, msg)
      check sigScalar == sigSimd
      check falconTyrVerify(falcon512, msg, sigScalar, kpScalar.publicKey, falconScalar)
      check falconTyrVerify(falcon512, msg, sigSimd, kpSimd.publicKey, falconSimd)
