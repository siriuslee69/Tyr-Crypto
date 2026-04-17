import std/unittest

import ../src/protocols/custom_crypto/frodo as custom_frodo
import ../src/protocols/wrapper/basic_api

when defined(hasLibOqs):
  import ../src/protocols/wrapper/helpers/algorithms
  import ../src/protocols/bindings/liboqs

proc fillSeed(seed: var seq[byte], base: int) =
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
    oqsDeterministicShortRead: bool = false

  proc oqsDeterministicCallback(random_array: ptr uint8,
      bytes_to_read: csize_t) {.cdecl.} =
    var
      outBytes = cast[ptr UncheckedArray[uint8]](random_array)
      n: int = int(bytes_to_read)
      i: int = 0
    i = 0
    while i < n:
      if oqsDeterministicOffset < oqsDeterministicFeed.len:
        outBytes[i] = oqsDeterministicFeed[oqsDeterministicOffset]
        oqsDeterministicOffset = oqsDeterministicOffset + 1
      else:
        outBytes[i] = 0'u8
        oqsDeterministicShortRead = true
      i = i + 1

  proc withDeterministicOqsRandom(feed: openArray[byte], body: proc ()) =
    oqsDeterministicFeed = newSeq[uint8](feed.len)
    for i in 0 ..< feed.len:
      oqsDeterministicFeed[i] = feed[i]
    oqsDeterministicOffset = 0
    oqsDeterministicShortRead = false
    OQS_randombytes_custom_algorithm(oqsDeterministicCallback)
    try:
      body()
    finally:
      discard OQS_randombytes_switch_algorithm(oqsRandAlgSystem.cstring)
      oqsDeterministicFeed.setLen(0)
      oqsDeterministicOffset = 0

suite "frodo tyr":
  when not defined(release):
    test "pure-nim Frodo roundtrip is release-only due runtime cost":
      checkpoint("Frodo pure-Nim runtime checks are only enabled in release builds")
  else:
    test "tier-0 pure-nim Frodo roundtrip matches shared secret":
      var
        keypairRandom = newSeq[byte](64)
        encapsRandom = newSeq[byte](24)
      fillSeed(keypairRandom, 13)
      fillSeed(encapsRandom, 77)
      let kp = custom_frodo.frodoTyrKeypairDerand(custom_frodo.frodo976aes, keypairRandom)
      let env = custom_frodo.frodoTyrEncapsDerand(custom_frodo.frodo976aes, kp.publicKey, encapsRandom)
      let shared = custom_frodo.frodoTyrDecaps(custom_frodo.frodo976aes, kp.secretKey, env.ciphertext)
      check shared == env.sharedSecret
      check kp.publicKey.len == 15632
      check kp.secretKey.len == 31296
      check env.ciphertext.len == 15744
      check env.sharedSecret.len == 24

    test "tier-0 basic_api Frodo Tyr roundtrip matches shared secret":
      var
        keypairRandom = newSeq[byte](64)
        encapsRandom = newSeq[byte](24)
        openM: frodo0TyrOpenM
        i: int = 0
      fillSeed(keypairRandom, 25)
      fillSeed(encapsRandom, 101)
      let kp = custom_frodo.frodoTyrKeypairDerand(custom_frodo.frodo976aes, keypairRandom)
      i = 0
      while i < openM.receiverSecretKey.len:
        openM.receiverSecretKey[i] = kp.secretKey[i]
        i = i + 1
      let env0 = custom_frodo.frodoTyrEncapsDerand(custom_frodo.frodo976aes, kp.publicKey, encapsRandom)
      let env = AsymCipher(ciphertext: env0.ciphertext, senderPublicKey: @[], sharedSecret: env0.sharedSecret)
      check open(env, openM) == env.sharedSecret

    when defined(hasLibOqs):
      test "tier-0 pure-nim Frodo keypair and encaps match liboqs with deterministic RNG":
        var
          keypairRandom = newSeq[byte](64)
          encapsRandom = newSeq[byte](24)
          kem: ptr OqsKem = nil
          pk: seq[uint8] = @[]
          sk: seq[uint8] = @[]
          ct: seq[uint8] = @[]
          shared: seq[uint8] = @[]
        fillSeed(keypairRandom, 41)
        fillSeed(encapsRandom, 99)
        kem = OQS_KEM_new(oqsAlgFrodoKEM976)
        if kem == nil:
          checkpoint("liboqs FrodoKEM-976-AES unavailable; skipping exact comparison")
        else:
          defer:
            OQS_KEM_free(kem)
          let nimKp = custom_frodo.frodoTyrKeypairDerand(custom_frodo.frodo976aes, keypairRandom)
          pk = newSeq[uint8](int kem[].length_public_key)
          sk = newSeq[uint8](int kem[].length_secret_key)
          withDeterministicOqsRandom(keypairRandom, proc () =
            requireSuccess(OQS_KEM_keypair(kem, addr pk[0], addr sk[0]), "OQS_KEM_keypair(Frodo)")
          )
          check not oqsDeterministicShortRead
          check pk == nimKp.publicKey
          check sk == nimKp.secretKey

          let nimEnv = custom_frodo.frodoTyrEncapsDerand(custom_frodo.frodo976aes, nimKp.publicKey, encapsRandom)
          ct = newSeq[uint8](int kem[].length_ciphertext)
          shared = newSeq[uint8](int kem[].length_shared_secret)
          withDeterministicOqsRandom(encapsRandom, proc () =
            requireSuccess(OQS_KEM_encaps(kem, addr ct[0], addr shared[0], addr pk[0]), "OQS_KEM_encaps(Frodo)")
          )
          check not oqsDeterministicShortRead
          check ct == nimEnv.ciphertext
          check shared == nimEnv.sharedSecret

      test "tier-0 pure-nim and liboqs Frodo interoperate both directions":
        var
          keypairRandom = newSeq[byte](64)
          encapsRandom = newSeq[byte](24)
          kem: ptr OqsKem = nil
          sendM: frodo0TyrSendM
          openM: frodo0TyrOpenM
          i: int = 0
        fillSeed(keypairRandom, 53)
        fillSeed(encapsRandom, 115)
        let nimKp = custom_frodo.frodoTyrKeypairDerand(custom_frodo.frodo976aes, keypairRandom)
        let nimEnv = custom_frodo.frodoTyrEncapsDerand(custom_frodo.frodo976aes, nimKp.publicKey, encapsRandom)
        check asymDec(kaFrodo0, nimKp.secretKey, AsymCipher(ciphertext: nimEnv.ciphertext, senderPublicKey: @[], sharedSecret: nimEnv.sharedSecret)) == nimEnv.sharedSecret

        kem = OQS_KEM_new(oqsAlgFrodoKEM976)
        if kem == nil:
          checkpoint("liboqs FrodoKEM-976-AES unavailable; skipping interop comparison")
        else:
          defer:
            OQS_KEM_free(kem)
          let oqsKp = asymKeypair(kaFrodo0)
          i = 0
          while i < openM.receiverSecretKey.len:
            openM.receiverSecretKey[i] = oqsKp.secretKey[i]
            i = i + 1
          let oqsEnv = asymEnc(kaFrodo0, oqsKp.publicKey)
          check open(oqsEnv, openM) == oqsEnv.sharedSecret
