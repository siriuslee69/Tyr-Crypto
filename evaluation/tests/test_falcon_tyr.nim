## ============================================================
## | Falcon Tyr Test                                          |
## | -> Direct correctness checks for the vendored Falcon API |
## ============================================================

import std/[os, strutils, unittest]

import ../../src/tyr/signatures/falcon as falcon
import ../../src/tyr/signatures/falcon/randomness
import ../../src/tyr/signatures/falcon/codec
import ../../src/tyr/signatures/falcon/fpr
import ../../src/tyr/signatures/falcon/format
import ../../src/tyr/signatures/falcon/pure_verify
import ../../src/tyr/signatures/falcon/sign

import tyrPragmas

when defined(hasLibOqs):
  import ../../src/tyr/bindings/liboqs

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

proc selectedFalconTestVariant(): string =
  result = getEnv("TYR_FALCON_TEST_VARIANT").strip().toLowerAscii()

proc runFalcon512Tests(): bool =
  var
    token: string = selectedFalconTestVariant()
  result = token.len == 0 or token == "all" or token == "512" or
    token == "falcon512" or token == "falcon-512"

proc runFalcon1024Tests(): bool =
  var
    token: string = selectedFalconTestVariant()
  result = token.len == 0 or token == "all" or token == "1024" or
    token == "falcon1024" or token == "falcon-1024"

template falcon512Test(testName: string, body: untyped) =
  if runFalcon512Tests():
    test testName:
      body

template falcon1024Test(testName: string, body: untyped) =
  if runFalcon1024Tests():
    test testName:
      body

suite "falcon tyr":
  test "integer FPR arithmetic preserves exact small values":
    var
      three: FalconFpr = fprOf(3)
      four: FalconFpr = fprOf(4)
      seven: FalconFpr = fprOf(7)
      twelve: FalconFpr = fprOf(12)
      two: FalconFpr = fprOf(2)
    check fprAdd(three, four) == seven
    check fprMul(three, four) == twelve
    check fprDiv(twelve, four) == three
    check fprSqrt(four) == two
    check fprRint(fprOneHalf) == 0
    check fprRint(fprAdd(fprOne, fprOneHalf)) == 2
    check fprFloor(fprNeg(fprOneHalf)) == -1
    check fprTrunc(fprNeg(fprOneHalf)) == 0

  falcon512Test "falcon512 scalar roundtrip succeeds":
    var
      p = params(falcon512)
      msg = newSeq[byte](96)
      kp: FalconTyrKeypair
      sig, malformedSig, malformedPk: seq[byte]
      i: int = 0
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

    malformedSig = sig
    malformedSig.setLen(sig.len - 1)
    check not falconTyrVerify(falcon512, msg, malformedSig, kp.publicKey,
      falconScalar)
    malformedSig = sig
    malformedSig.add(0'u8)
    check not falconTyrVerify(falcon512, msg, malformedSig, kp.publicKey,
      falconScalar)

    malformedPk = kp.publicKey
    malformedPk.setLen(p.publicKeyBytes - 1)
    check not falconTyrVerify(falcon512, msg, sig, malformedPk, falconScalar)
    malformedPk = kp.publicKey
    malformedPk.add(0'u8)
    check not falconTyrVerify(falcon512, msg, sig, malformedPk, falconScalar)

    malformedSig = newSeq[byte](sig.len)
    malformedPk = newSeq[byte](p.publicKeyBytes)
    check not falconTyrVerify(falcon512, msg, malformedSig, kp.publicKey,
      falconScalar)
    check not falconTyrVerify(falcon512, msg, sig, malformedPk, falconScalar)
    i = 0
    while i < malformedSig.len:
      malformedSig[i] = 0xff'u8
      i = i + 1
    i = 0
    while i < malformedPk.len:
      malformedPk[i] = 0xff'u8
      i = i + 1
    check not falconTyrVerify(falcon512, msg, malformedSig, kp.publicKey,
      falconScalar)
    check not falconTyrVerify(falcon512, msg, sig, malformedPk, falconScalar)

    malformedSig = sig
    malformedSig[0] = malformedSig[0] xor 1'u8
    malformedPk = kp.publicKey
    malformedPk[0] = malformedPk[0] xor 1'u8
    check not falconTyrVerify(falcon512, msg, malformedSig, kp.publicKey,
      falconScalar)
    check not falconTyrVerify(falcon512, msg, sig, malformedPk, falconScalar)

  test "Falcon compressed decoder rejects negative zero and nonzero trailing padding":
    var
      p = params(falcon512)
      coefficients = newSeq[int16](1 shl p.logn)
      decoded = newSeq[int16](1 shl p.logn)
      encoded = newSeq[byte](p.signatureBytes)
      used: int = 0
    used = compEncode(encoded, coefficients, p.logn)
    require used > 0
    encoded.setLen(used)
    require compDecode(decoded, encoded, p.logn) == used
    ## Preserve canonical zero's magnitude and unary terminator, but set its sign.
    encoded[0] = encoded[0] or 0x80'u8
    check compDecode(decoded, encoded, p.logn) == 0

    ## Magnitude 128 adds one unary bit, leaving seven zero padding bits.
    coefficients[0] = 128'i16
    encoded = newSeq[byte](p.signatureBytes)
    used = compEncode(encoded, coefficients, p.logn)
    require used > 0
    encoded.setLen(used)
    require compDecode(decoded, encoded, p.logn) == used
    require (encoded[^1] and 1'u8) == 0'u8
    encoded[^1] = encoded[^1] or 1'u8
    check compDecode(decoded, encoded, p.logn) == 0

  falcon1024Test "falcon1024 scalar roundtrip succeeds":
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

  falcon512Test "falcon512 scalar prepared roundtrip succeeds":
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

  falcon1024Test "falcon1024 scalar prepared roundtrip succeeds":
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

  falcon512Test "pure Nim Falcon-512 verify accepts scalar signature":
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

  falcon1024Test "pure Nim Falcon-1024 verify accepts scalar signature":
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

  falcon512Test "pure Nim Falcon-512 prepared sign matches scalar prepared sign":
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

  falcon1024Test "pure Nim Falcon-1024 prepared sign matches scalar prepared sign":
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
    falcon512Test "scalar and simd outputs match under deterministic randomness":
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

    falcon512Test "scalar and simd prepared outputs match under deterministic randomness":
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

## ╭⟢ Cross-checking Falcon against the reference library
##
## Every test above compares Tyr's Falcon with itself: it signs, then
## verifies with its own verifier. A self-consistent mistake - a swapped
## constant, a differently ordered encoding - would pass all of them and
## still be unreadable to every other Falcon in the world.
##
## The tests below close that hole by making the two implementations
## check each other's work:
##
##   Tyr  --signs-->  signature  --checked by-->  liboqs
##   liboqs --signs-->  signature  --checked by-->  Tyr
##
## Both directions must hold. One direction alone would only prove that
## one side is lenient.

when defined(hasLibOqs):
  proc oqsFalconAlgId(v: FalconVariant): string {.role: {parser}.} =
    ## v: which Falcon size is being cross-checked.
    case v
    of falcon512:
      result = oqsSigFalcon512
    of falcon1024:
      result = oqsSigFalcon1024

  proc openOqsFalcon(v: FalconVariant): ptr OqsSig {.role: {dataFetcher}.} =
    ## v: which Falcon size is being cross-checked.
    ## Returns nil when this liboqs build left the algorithm out.
    if not ensureLibOqsLoaded():
      return nil
    result = OQS_SIG_new(oqsFalconAlgId(v).cstring)

  proc oqsAcceptsFalcon(S: ptr OqsSig, msg, sig, pk: openArray[byte]): bool
      {.role: {actor}.} =
    ## S: the opened liboqs Falcon handle.
    ## msg, sig, pk: the message, signature, and public key to check.
    var
      msgPtr: ptr uint8 = nil
    if msg.len > 0:
      msgPtr = cast[ptr uint8](unsafeAddr msg[0])
    result = OQS_SIG_verify(S, msgPtr, csize_t(msg.len),
      cast[ptr uint8](unsafeAddr sig[0]), csize_t(sig.len),
      cast[ptr uint8](unsafeAddr pk[0])) == oqsSuccess

  template falconInteropCase(v: FalconVariant) =
    ## v: the Falcon size under test.
    ## Signs on each side and hands the result to the other side.
    block:
      var
        p = params(v)
        msg = newSeq[byte](128)
        kp: FalconTyrKeypair
        sig: seq[byte] = @[]
        tampered: seq[byte] = @[]
        handle: ptr OqsSig = nil
        oqsPk: seq[byte] = @[]
        oqsSk: seq[byte] = @[]
        oqsSig: seq[byte] = @[]
        oqsSigLen: csize_t = 0
      fillPattern(msg, 0x5B)
      handle = openOqsFalcon(v)
      if handle == nil:
        checkpoint("liboqs " & oqsFalconAlgId(v) & " unavailable; skipping")
      else:
        defer:
          OQS_SIG_free(handle)
          falconTyrClearKeypair(kp)

        # The two sides must agree on sizes before they can agree on bytes.
        check int(handle[].length_public_key) == p.publicKeyBytes
        check int(handle[].length_secret_key) == p.secretKeyBytes
        check int(handle[].length_signature) == p.signatureBytes

        # Direction one: Tyr signs, liboqs checks.
        kp = falconTyrKeypair(v, falconScalar)
        sig = falconTyrSign(v, msg, kp.secretKey, falconScalar)
        check falconTyrVerify(v, msg, sig, kp.publicKey, falconScalar)
        check oqsAcceptsFalcon(handle, msg, sig, kp.publicKey)
        tampered = sig
        tampered[tampered.len - 1] = tampered[tampered.len - 1] xor 0x01'u8
        check not oqsAcceptsFalcon(handle, msg, tampered, kp.publicKey)

        # Direction two: liboqs signs, Tyr checks.
        oqsPk = newSeq[byte](p.publicKeyBytes)
        oqsSk = newSeq[byte](p.secretKeyBytes)
        oqsSig = newSeq[byte](p.signatureBytes)
        oqsSigLen = csize_t(oqsSig.len)
        requireSuccess(OQS_SIG_keypair(handle, addr oqsPk[0], addr oqsSk[0]),
          "OQS_SIG_keypair(" & oqsFalconAlgId(v) & ")")
        requireSuccess(OQS_SIG_sign(handle, addr oqsSig[0], addr oqsSigLen,
          addr msg[0], csize_t(msg.len), addr oqsSk[0]),
          "OQS_SIG_sign(" & oqsFalconAlgId(v) & ")")
        oqsSig.setLen(int(oqsSigLen))
        check falconTyrVerify(v, msg, oqsSig, oqsPk, falconScalar)
        tampered = oqsSig
        tampered[tampered.len - 1] = tampered[tampered.len - 1] xor 0x01'u8
        check not falconTyrVerify(v, msg, tampered, oqsPk, falconScalar)

  suite "falcon liboqs interop":
    # {.testKind: tkIntegration, covers: "falconTyrSign, falconTyrVerify".}
    falcon512Test "falcon512 signatures cross-verify with liboqs":
      falconInteropCase(falcon512)

    # {.testKind: tkIntegration, covers: "falconTyrSign, falconTyrVerify".}
    falcon1024Test "falcon1024 signatures cross-verify with liboqs":
      falconInteropCase(falcon1024)
