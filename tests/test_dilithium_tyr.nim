import std/unittest

import ../src/protocols/custom_crypto/dilithium as custom_dilithium
import ../src/protocols/wrapper/basic_api

when defined(hasLibOqs):
  import ../src/protocols/bindings/liboqs

proc fillDiliSeed(seed: var seq[byte], base: int) =
  var
    i: int = 0
  i = 0
  while i < seed.len:
    seed[i] = byte((base + i) mod 256)
    i = i + 1

when defined(hasLibOqs):
  var
    oqsDeterministicFeed: seq[uint8] = @[]
    oqsDeterministicOffset: int = 0

  proc oqsDeterministicCallback(random_array: ptr uint8, bytes_to_read: csize_t) {.cdecl.} =
    var
      outBytes = cast[ptr UncheckedArray[uint8]](random_array)
      i: int = 0
    i = 0
    while i < int(bytes_to_read):
      outBytes[i] = oqsDeterministicFeed[oqsDeterministicOffset + i]
      i = i + 1
    oqsDeterministicOffset = oqsDeterministicOffset + int(bytes_to_read)

  proc withDeterministicOqsRandom(feed: openArray[byte], body: proc ()) =
    oqsDeterministicFeed = newSeq[uint8](feed.len)
    for i in 0 ..< feed.len:
      oqsDeterministicFeed[i] = feed[i]
    oqsDeterministicOffset = 0
    OQS_randombytes_custom_algorithm(oqsDeterministicCallback)
    try:
      body()
    finally:
      discard OQS_randombytes_switch_algorithm(oqsRandAlgSystem.cstring)
      oqsDeterministicFeed.setLen(0)
      oqsDeterministicOffset = 0

proc methodName(v: custom_dilithium.DilithiumVariant): string =
  case v
  of custom_dilithium.dilithium44:
    result = "ML-DSA-44"
  of custom_dilithium.dilithium65:
    result = "ML-DSA-65"
  of custom_dilithium.dilithium87:
    result = "ML-DSA-87"

suite "dilithium tyr":
  test "poly add sub and shift match scalar reference":
    var
      a: custom_dilithium.DilithiumPoly
      b: custom_dilithium.DilithiumPoly
      addRes: custom_dilithium.DilithiumPoly
      subRes: custom_dilithium.DilithiumPoly
      shiftRes: custom_dilithium.DilithiumPoly
      i: int = 0
    i = 0
    while i < custom_dilithium.dilithiumN:
      a.coeffs[i] = int32((12345 * i) mod custom_dilithium.dilithiumQ)
      b.coeffs[i] = int32((23456 * i + 7) mod custom_dilithium.dilithiumQ)
      shiftRes.coeffs[i] = a.coeffs[i]
      i = i + 1
    custom_dilithium.polyAdd(addRes, a, b)
    custom_dilithium.polySub(subRes, a, b)
    custom_dilithium.polyShiftL(shiftRes)
    i = 0
    while i < custom_dilithium.dilithiumN:
      check addRes.coeffs[i] == a.coeffs[i] + b.coeffs[i]
      check subRes.coeffs[i] == a.coeffs[i] - b.coeffs[i]
      check shiftRes.coeffs[i] == (a.coeffs[i] shl custom_dilithium.dilithiumD)
      i = i + 1

  test "pure-nim Dilithium roundtrip works for all tiers":
    for v in [custom_dilithium.dilithium44, custom_dilithium.dilithium65, custom_dilithium.dilithium87]:
      var seed = newSeq[byte](32)
      fillDiliSeed(seed, 17)
      let kp = custom_dilithium.dilithiumTyrKeypair(v, seed)
      let msg = @[1'u8, 2'u8, 3'u8, 4'u8, 5'u8]
      let sig = custom_dilithium.dilithiumTyrSignDeterministic(v, msg, kp.secretKey)
      check custom_dilithium.dilithiumTyrVerify(v, msg, sig, kp.publicKey)

  test "pure-nim Dilithium into APIs match seq-returning APIs":
    for v in [custom_dilithium.dilithium44, custom_dilithium.dilithium65, custom_dilithium.dilithium87]:
      let p = custom_dilithium.dilithiumParamsTable[v]
      var
        seed = newSeq[byte](32)
        rnd = newSeq[byte](32)
        pk = newSeq[byte](p.publicKeyBytes)
        sk = newSeq[byte](p.secretKeyBytes)
        sig = newSeq[byte](p.signatureBytes)
      fillDiliSeed(seed, 61)
      fillDiliSeed(rnd, 87)
      let msg = @[1'u8, 3'u8, 3'u8, 7'u8, 9'u8]
      let kpRef = custom_dilithium.dilithiumTyrKeypair(v, seed)
      custom_dilithium.dilithiumTyrKeypairInto(v, pk, sk, seed)
      check pk == kpRef.publicKey
      check sk == kpRef.secretKey
      let sigRef = custom_dilithium.dilithiumTyrSignDerand(v, msg, sk, rnd)
      custom_dilithium.dilithiumTyrSignDerandInto(v, sig, msg, sk, rnd)
      check sig == sigRef
      check custom_dilithium.dilithiumTyrVerify(v, msg, sig, pk)

  test "basic_api Dilithium Tyr wrappers work":
    var
      seed = newSeq[byte](32)
      signM: dilithium0TyrSignM
      verifyM: dilithium0TyrVerifyM
      i: int = 0
    fillDiliSeed(seed, 29)
    let kp = custom_dilithium.dilithiumTyrKeypair(custom_dilithium.dilithium44, seed)
    i = 0
    while i < signM.secretKey.len:
      signM.secretKey[i] = kp.secretKey[i]
      i = i + 1
    i = 0
    while i < verifyM.publicKey.len:
      verifyM.publicKey[i] = kp.publicKey[i]
      i = i + 1
    let msg = @[9'u8, 8'u8, 7'u8]
    let sig = custom_dilithium.dilithiumTyrSignDeterministic(custom_dilithium.dilithium44, msg,
      signM.secretKey)
    i = 0
    while i < verifyM.signature.len:
      verifyM.signature[i] = sig[i]
      i = i + 1
    check msg.verify(verifyM)

  when defined(hasLibOqs) and defined(release):
    test "pure-nim Dilithium keypair and signature match liboqs for all tiers":
      for v in [custom_dilithium.dilithium44, custom_dilithium.dilithium65, custom_dilithium.dilithium87]:
        var seed = newSeq[byte](32)
        var rnd = newSeq[byte](32)
        fillDiliSeed(seed, 43)
        fillDiliSeed(rnd, 91)
        let kp = custom_dilithium.dilithiumTyrKeypair(v, seed)
        let msg = @[1'u8, 2'u8, 3'u8, 4'u8, 5'u8]
        let sig = custom_dilithium.dilithiumTyrSignDerand(v, msg, kp.secretKey, rnd)
        let oqs = OQS_SIG_new(methodName(v).cstring)
        if oqs == nil:
          checkpoint("liboqs " & methodName(v) & " unavailable; skipping exact comparison")
        else:
          defer:
            OQS_SIG_free(oqs)
          var pk = newSeq[uint8](int oqs[].length_public_key)
          var sk = newSeq[uint8](int oqs[].length_secret_key)
          withDeterministicOqsRandom(seed, proc () =
            requireSuccess(OQS_SIG_keypair(oqs, addr pk[0], addr sk[0]), "OQS_SIG_keypair(" & methodName(v) & ")")
          )
          check pk == kp.publicKey
          check sk == kp.secretKey
          var oqsSig = newSeq[uint8](int oqs[].length_signature)
          var sigLen: csize_t
          withDeterministicOqsRandom(rnd, proc () =
            requireSuccess(OQS_SIG_sign(oqs, addr oqsSig[0], addr sigLen, addr msg[0], csize_t(msg.len), addr sk[0]),
              "OQS_SIG_sign(" & methodName(v) & ")")
          )
          oqsSig.setLen(int(sigLen))
          check oqsSig == sig
          check OQS_SIG_verify(oqs, addr msg[0], csize_t(msg.len), addr sig[0], csize_t(sig.len), addr pk[0]) == oqsSuccess
          check custom_dilithium.dilithiumTyrVerify(v, msg, oqsSig, pk)
