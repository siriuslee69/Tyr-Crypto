import std/unittest

import ../src/protocols/custom_crypto/sphincs as custom_sphincs
import ../src/protocols/wrapper/basic_api

when defined(hasLibOqs):
  import ../src/protocols/bindings/liboqs

proc fillSphincsSeed(seed: var seq[byte], base: int) =
  for i in 0 ..< seed.len:
    seed[i] = byte((base + i) mod 256)

when defined(hasLibOqs):
  var
    oqsDeterministicFeed: seq[uint8] = @[]
    oqsDeterministicOffset: int = 0

  proc oqsDeterministicCallback(random_array: ptr uint8, bytes_to_read: csize_t) {.cdecl.} =
    let outBytes = cast[ptr UncheckedArray[uint8]](random_array)
    for i in 0 ..< int(bytes_to_read):
      outBytes[i] = oqsDeterministicFeed[oqsDeterministicOffset + i]
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

suite "sphincs tyr":
  test "pure-nim SPHINCS rejects a short secret key before dereferencing it":
    expect(ValueError):
      discard custom_sphincs.sphincsTyrSignDerand(
        custom_sphincs.sphincsShake128fSimple,
        @[1'u8],
        @[0'u8],
        newSeq[byte](16)
      )

  when not defined(release):
    test "pure-nim SPHINCS roundtrip is release-only due runtime cost":
      checkpoint("SPHINCS pure-Nim runtime checks are only enabled in release builds")
  else:
    test "pure-nim SPHINCS roundtrip works":
      var
        seed = newSeq[byte](48)
        optrand = newSeq[byte](16)
      fillSphincsSeed(seed, 11)
      fillSphincsSeed(optrand, 91)
      let kp = custom_sphincs.sphincsTyrSeedKeypair(custom_sphincs.sphincsShake128fSimple, seed)
      let msg = @[1'u8, 2'u8, 3'u8, 4'u8, 5'u8]
      let sig = custom_sphincs.sphincsTyrSignDerand(custom_sphincs.sphincsShake128fSimple, msg, kp.secretKey, optrand)
      check custom_sphincs.sphincsTyrVerify(custom_sphincs.sphincsShake128fSimple, msg, sig, kp.publicKey)
      check kp.publicKey.len == 32
      check kp.secretKey.len == 64
      check sig.len == 17088

    test "basic_api SPHINCS Tyr wrappers work":
      var
        seed = newSeq[byte](48)
        signM: sphincsHaraka128fSimpleTyrSignM
        verifyM: sphincsHaraka128fSimpleTyrVerifyM
      fillSphincsSeed(seed, 23)
      let kp = custom_sphincs.sphincsTyrSeedKeypair(custom_sphincs.sphincsShake128fSimple, seed)
      for i in 0 ..< signM.secretKey.len:
        signM.secretKey[i] = kp.secretKey[i]
      for i in 0 ..< verifyM.publicKey.len:
        verifyM.publicKey[i] = kp.publicKey[i]
      let msg = @[7'u8, 8'u8, 9'u8]
      let sig = custom_sphincs.sphincsTyrSignDerand(custom_sphincs.sphincsShake128fSimple, msg, kp.secretKey, @seed[0 ..< 16])
      for i in 0 ..< verifyM.signature.len:
        verifyM.signature[i] = sig[i]
      check msg.verify(verifyM)

    when defined(hasLibOqs):
      test "pure-nim SPHINCS keypair and signature match liboqs with deterministic RNG":
        var
          seed = newSeq[byte](48)
          optrand = newSeq[byte](16)
          feed: seq[byte] = @[]
        fillSphincsSeed(seed, 31)
        fillSphincsSeed(optrand, 57)
        let kp = custom_sphincs.sphincsTyrSeedKeypair(custom_sphincs.sphincsShake128fSimple, seed)
        let msg = @[1'u8, 2'u8, 3'u8, 4'u8, 5'u8]
        let sig = custom_sphincs.sphincsTyrSignDerand(custom_sphincs.sphincsShake128fSimple, msg, kp.secretKey, optrand)
        let oqs = OQS_SIG_new("SPHINCS+-SHAKE-128f-simple")
        if oqs == nil:
          checkpoint("liboqs SPHINCS+-SHAKE-128f-simple unavailable; skipping exact comparison")
        else:
          defer:
            OQS_SIG_free(oqs)
          feed = @seed & optrand
          withDeterministicOqsRandom(feed, proc () =
            var pk = newSeq[uint8](int oqs[].length_public_key)
            var sk = newSeq[uint8](int oqs[].length_secret_key)
            requireSuccess(OQS_SIG_keypair(oqs, addr pk[0], addr sk[0]), "OQS_SIG_keypair(SPHINCS)")
            check pk == kp.publicKey
            check sk == kp.secretKey
            var oqsSig = newSeq[uint8](int oqs[].length_signature)
            var sigLen: csize_t
            requireSuccess(OQS_SIG_sign(oqs, addr oqsSig[0], addr sigLen, addr msg[0], csize_t(msg.len), addr sk[0]),
              "OQS_SIG_sign(SPHINCS)")
            oqsSig.setLen(int(sigLen))
            check oqsSig == sig
            check custom_sphincs.sphincsTyrVerify(custom_sphincs.sphincsShake128fSimple, msg, oqsSig, pk)
          )
