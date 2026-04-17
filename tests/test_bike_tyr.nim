import std/unittest

import ../src/protocols/custom_crypto/bike as custom_bike
import ../src/protocols/wrapper/basic_api

when defined(hasLibOqs):
  import ../src/protocols/bindings/liboqs

proc fillBikeSeed(seed: var seq[byte], base: int) =
  var
    i: int = 0
  i = 0
  while i < seed.len:
    seed[i] = byte((base + i) mod 256)
    i = i + 1

when defined(hasLibOqs):
  var
    bikeOqsDeterministicFeed: seq[uint8] = @[]
    bikeOqsDeterministicOffset: int = 0
    bikeOqsDeterministicShortRead: bool = false

  proc bikeOqsDeterministicCallback(random_array: ptr uint8,
      bytes_to_read: csize_t) {.cdecl.} =
    var
      outBytes = cast[ptr UncheckedArray[uint8]](random_array)
      n: int = int(bytes_to_read)
      i: int = 0
    i = 0
    while i < n:
      if bikeOqsDeterministicOffset < bikeOqsDeterministicFeed.len:
        outBytes[i] = bikeOqsDeterministicFeed[bikeOqsDeterministicOffset]
        bikeOqsDeterministicOffset = bikeOqsDeterministicOffset + 1
      else:
        outBytes[i] = 0'u8
        bikeOqsDeterministicShortRead = true
      i = i + 1

  proc withBikeDeterministicOqsRandom(feed: openArray[byte], body: proc ()) =
    bikeOqsDeterministicFeed = newSeq[uint8](feed.len)
    for i in 0 ..< feed.len:
      bikeOqsDeterministicFeed[i] = feed[i]
    bikeOqsDeterministicOffset = 0
    bikeOqsDeterministicShortRead = false
    OQS_randombytes_custom_algorithm(bikeOqsDeterministicCallback)
    try:
      body()
    finally:
      discard OQS_randombytes_switch_algorithm(oqsRandAlgSystem.cstring)
      bikeOqsDeterministicFeed.setLen(0)
      bikeOqsDeterministicOffset = 0

suite "bike tyr":
  test "pure-nim BIKE roundtrip matches shared secret":
    var
      keypairRandom = newSeq[byte](64)
      encapsRandom = newSeq[byte](64)
    fillBikeSeed(keypairRandom, 17)
    fillBikeSeed(encapsRandom, 91)
    let kp = custom_bike.bikeTyrKeypairDerand(custom_bike.bikeL1, keypairRandom)
    let env = custom_bike.bikeTyrEncapsDerand(custom_bike.bikeL1, kp.publicKey, encapsRandom)
    let shared = custom_bike.bikeTyrDecaps(custom_bike.bikeL1, kp.secretKey, env.ciphertext)
    check shared == env.sharedSecret
    check kp.publicKey.len == 1541
    check kp.secretKey.len == 5223
    check env.ciphertext.len == 1573
    check env.sharedSecret.len == 32

  test "basic_api BIKE Tyr roundtrip matches shared secret":
    var
      keypairRandom = newSeq[byte](64)
      encapsRandom = newSeq[byte](64)
      sendM: bike0TyrSendM
      openM: bike0TyrOpenM
      i: int = 0
    fillBikeSeed(keypairRandom, 29)
    fillBikeSeed(encapsRandom, 117)
    let kp = custom_bike.bikeTyrKeypairDerand(custom_bike.bikeL1, keypairRandom)
    i = 0
    while i < sendM.receiverPublicKey.len:
      sendM.receiverPublicKey[i] = kp.publicKey[i]
      i = i + 1
    i = 0
    while i < openM.receiverSecretKey.len:
      openM.receiverSecretKey[i] = kp.secretKey[i]
      i = i + 1
    let env0 = custom_bike.bikeTyrEncapsDerand(custom_bike.bikeL1, kp.publicKey, encapsRandom)
    let env = AsymCipher(ciphertext: env0.ciphertext, senderPublicKey: @[], sharedSecret: env0.sharedSecret)
    check open(env, openM) == env.sharedSecret

  when defined(hasLibOqs):
    test "pure-nim BIKE keypair and encaps match liboqs with deterministic RNG":
      var
        keypairRandom = newSeq[byte](64)
        encapsRandom = newSeq[byte](64)
        kem: ptr OqsKem = nil
        pk: seq[uint8] = @[]
        sk: seq[uint8] = @[]
        ct: seq[uint8] = @[]
        shared: seq[uint8] = @[]
      fillBikeSeed(keypairRandom, 41)
      fillBikeSeed(encapsRandom, 133)
      kem = OQS_KEM_new(oqsAlgBike0)
      if kem == nil:
        checkpoint("liboqs BIKE-L1 unavailable; skipping exact comparison")
      else:
        defer:
          OQS_KEM_free(kem)
        let nimKp = custom_bike.bikeTyrKeypairDerand(custom_bike.bikeL1, keypairRandom)
        pk = newSeq[uint8](int kem[].length_public_key)
        sk = newSeq[uint8](int kem[].length_secret_key)
        withBikeDeterministicOqsRandom(keypairRandom, proc () =
          requireSuccess(OQS_KEM_keypair(kem, addr pk[0], addr sk[0]), "OQS_KEM_keypair(BIKE)")
        )
        check not bikeOqsDeterministicShortRead
        check pk == nimKp.publicKey
        check sk == nimKp.secretKey

        let nimEnv = custom_bike.bikeTyrEncapsDerand(custom_bike.bikeL1, nimKp.publicKey, encapsRandom)
        ct = newSeq[uint8](int kem[].length_ciphertext)
        shared = newSeq[uint8](int kem[].length_shared_secret)
        withBikeDeterministicOqsRandom(encapsRandom, proc () =
          requireSuccess(OQS_KEM_encaps(kem, addr ct[0], addr shared[0], addr pk[0]), "OQS_KEM_encaps(BIKE)")
        )
        check not bikeOqsDeterministicShortRead
        check ct == nimEnv.ciphertext
        check shared == nimEnv.sharedSecret

    test "pure-nim and liboqs BIKE interoperate both directions":
      var
        keypairRandom = newSeq[byte](64)
        encapsRandom = newSeq[byte](64)
        kem: ptr OqsKem = nil
        openM: bike0TyrOpenM
        pk: seq[uint8] = @[]
        sk: seq[uint8] = @[]
        ct: seq[uint8] = @[]
        shared: seq[uint8] = @[]
        i: int = 0
      fillBikeSeed(keypairRandom, 53)
      fillBikeSeed(encapsRandom, 149)
      let nimKp = custom_bike.bikeTyrKeypairDerand(custom_bike.bikeL1, keypairRandom)
      let nimEnv = custom_bike.bikeTyrEncapsDerand(custom_bike.bikeL1, nimKp.publicKey, encapsRandom)

      kem = OQS_KEM_new(oqsAlgBike0)
      if kem == nil:
        checkpoint("liboqs BIKE-L1 unavailable; skipping interop comparison")
      else:
        defer:
          OQS_KEM_free(kem)
        shared = newSeq[uint8](int kem[].length_shared_secret)
        ct = newSeq[uint8](int kem[].length_ciphertext)
        copyMem(addr ct[0], unsafeAddr nimEnv.ciphertext[0], ct.len)
        requireSuccess(OQS_KEM_decaps(kem, addr shared[0], addr ct[0], unsafeAddr nimKp.secretKey[0]),
          "OQS_KEM_decaps(BIKE)")
        check shared == nimEnv.sharedSecret

        pk = newSeq[uint8](int kem[].length_public_key)
        sk = newSeq[uint8](int kem[].length_secret_key)
        requireSuccess(OQS_KEM_keypair(kem, addr pk[0], addr sk[0]), "OQS_KEM_keypair(BIKE)")
        ct = newSeq[uint8](int kem[].length_ciphertext)
        shared = newSeq[uint8](int kem[].length_shared_secret)
        requireSuccess(OQS_KEM_encaps(kem, addr ct[0], addr shared[0], addr pk[0]), "OQS_KEM_encaps(BIKE)")
        i = 0
        while i < openM.receiverSecretKey.len:
          openM.receiverSecretKey[i] = sk[i]
          i = i + 1
        let oqsEnv = AsymCipher(ciphertext: ct, senderPublicKey: @[], sharedSecret: shared)
        check open(oqsEnv, openM) == oqsEnv.sharedSecret
