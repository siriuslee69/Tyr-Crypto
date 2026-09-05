{.define: tyrCryptoTestHooks.}

import std/unittest

import ../src/tyr/kems/bike as custom_bike
import ../src/tyr/hashes/sha3 as tyr_sha3
import ../src/tyr

when defined(hasLibOqs):
  import ../src/tyr/bindings/liboqs
  import ./oqs_random_hook

proc fillBikeSeed(seed: var seq[byte], base: int) =
  var
    i: int = 0
  i = 0
  while i < seed.len:
    seed[i] = byte((base + i) mod 256)
    i = i + 1

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

  test "typed material BIKE Tyr roundtrip matches shared secret":
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
    let env = initAsymCipher(env0.ciphertext, @[], env0.sharedSecret)
    check open(env, openM) == env.sharedSecret

  test "invalid BIKE ciphertext keeps diagnostic and fallback secret aligned":
    var
      keypairRandom = newSeq[byte](64)
      encapsRandom = newSeq[byte](64)
      kp: custom_bike.BikeTyrKeypair
      env: custom_bike.BikeTyrCipher
      good: tuple[sharedSecret: seq[byte], ok: bool]
      tampered: seq[byte] = @[]
      bad: tuple[sharedSecret: seq[byte], ok: bool]
      fallback: seq[byte] = @[]
      padded0: seq[byte] = @[]
      padded1: seq[byte] = @[]
      badPadding0: tuple[sharedSecret: seq[byte], ok: bool]
      badPadding1: tuple[sharedSecret: seq[byte], ok: bool]
      allZero: seq[byte] = @[]
      allFf: seq[byte] = @[]
      sigmaOff: int = 0
      fallbackInput: seq[byte] = @[]
      fallbackDigest: seq[byte] = @[]
      expectedZero: seq[byte] = @[]
      zero0: tuple[sharedSecret: seq[byte], ok: bool]
      zero1: tuple[sharedSecret: seq[byte], ok: bool]
      zeroFallback: seq[byte] = @[]
      ff0: tuple[sharedSecret: seq[byte], ok: bool]
      ff1: tuple[sharedSecret: seq[byte], ok: bool]
      ffFallback: seq[byte] = @[]
      i: int = 0
    fillBikeSeed(keypairRandom, 61)
    fillBikeSeed(encapsRandom, 173)
    kp = custom_bike.bikeTyrKeypairDerand(custom_bike.bikeL1,
      keypairRandom)
    env = custom_bike.bikeTyrEncapsDerand(custom_bike.bikeL1,
      kp.publicKey, encapsRandom)
    expect ValueError:
      discard custom_bike.bikeTyrDecaps(custom_bike.bikeL1, kp.secretKey, @[])
    expect ValueError:
      discard custom_bike.bikeTyrDecaps(custom_bike.bikeL1, kp.secretKey,
        newSeq[byte](env.ciphertext.len - 1))
    expect ValueError:
      discard custom_bike.bikeTyrDecaps(custom_bike.bikeL1, kp.secretKey,
        newSeq[byte](env.ciphertext.len + 1))
    good = custom_bike.bikeTyrTryDecaps(custom_bike.bikeL1,
      kp.secretKey, env.ciphertext)
    tampered = env.ciphertext
    tampered[0] = tampered[0] xor 1'u8
    bad = custom_bike.bikeTyrTryDecaps(custom_bike.bikeL1,
      kp.secretKey, tampered)
    fallback = custom_bike.bikeTyrDecaps(custom_bike.bikeL1,
      kp.secretKey, tampered)
    padded0 = env.ciphertext
    padded1 = env.ciphertext
    padded0[custom_bike.bikeRBytes - 1] =
      padded0[custom_bike.bikeRBytes - 1] or 0x80'u8
    padded1[custom_bike.bikeRBytes - 1] =
      padded1[custom_bike.bikeRBytes - 1] or 0x40'u8
    badPadding0 = custom_bike.bikeTyrTryDecaps(custom_bike.bikeL1,
      kp.secretKey, padded0)
    badPadding1 = custom_bike.bikeTyrTryDecaps(custom_bike.bikeL1,
      kp.secretKey, padded1)
    check good.ok
    check good.sharedSecret == env.sharedSecret
    check not bad.ok
    check bad.sharedSecret.len == env.sharedSecret.len
    check bad.sharedSecret != env.sharedSecret
    check fallback == bad.sharedSecret
    check not badPadding0.ok
    check not badPadding1.ok
    check badPadding0.sharedSecret != env.sharedSecret
    check badPadding0.sharedSecret != badPadding1.sharedSecret
    allZero = newSeq[byte](env.ciphertext.len)
    allFf = newSeq[byte](env.ciphertext.len)
    i = 0
    while i < allFf.len:
      allFf[i] = 0xff'u8
      i = i + 1
    sigmaOff = custom_bike.bikeSecretKeyBytes - custom_bike.bikeMessageBytes
    fallbackInput = newSeq[byte](custom_bike.bikeMessageBytes +
      custom_bike.bikeCiphertextBytes)
    i = 0
    while i < custom_bike.bikeMessageBytes:
      fallbackInput[i] = kp.secretKey[sigmaOff + i]
      i = i + 1
    i = 0
    while i < custom_bike.bikeCiphertextBytes:
      fallbackInput[custom_bike.bikeMessageBytes + i] = allZero[i]
      i = i + 1
    fallbackDigest = tyr_sha3.sha3_384(fallbackInput)
    expectedZero = newSeq[byte](custom_bike.bikeSharedSecretBytes)
    i = 0
    while i < expectedZero.len:
      expectedZero[i] = fallbackDigest[i]
      i = i + 1
    zero0 = custom_bike.bikeTyrTryDecaps(custom_bike.bikeL1,
      kp.secretKey, allZero)
    zero1 = custom_bike.bikeTyrTryDecaps(custom_bike.bikeL1,
      kp.secretKey, allZero)
    zeroFallback = custom_bike.bikeTyrDecaps(custom_bike.bikeL1,
      kp.secretKey, allZero)
    ff0 = custom_bike.bikeTyrTryDecaps(custom_bike.bikeL1,
      kp.secretKey, allFf)
    ff1 = custom_bike.bikeTyrTryDecaps(custom_bike.bikeL1,
      kp.secretKey, allFf)
    ffFallback = custom_bike.bikeTyrDecaps(custom_bike.bikeL1,
      kp.secretKey, allFf)
    check not zero0.ok
    check not zero1.ok
    check zero0.sharedSecret == zero1.sharedSecret
    check zeroFallback == zero0.sharedSecret
    check zeroFallback == expectedZero
    check zeroFallback != env.sharedSecret
    check not ff0.ok
    check not ff1.ok
    check ff0.sharedSecret == ff1.sharedSecret
    check ffFallback == ff0.sharedSecret
    check ffFallback != env.sharedSecret

  test "BIKE rejects non-canonical public and secret key encodings":
    var
      keypairRandom = newSeq[byte](64)
      encapsRandom = newSeq[byte](64)
      kp: custom_bike.BikeTyrKeypair
      env: custom_bike.BikeTyrCipher
      malformedPk: seq[byte] = @[]
      malformedSk: seq[byte] = @[]
    fillBikeSeed(keypairRandom, 83)
    fillBikeSeed(encapsRandom, 191)
    kp = custom_bike.bikeTyrKeypairDerand(custom_bike.bikeL1, keypairRandom)
    env = custom_bike.bikeTyrEncapsDerand(custom_bike.bikeL1, kp.publicKey,
      encapsRandom)
    malformedPk = kp.publicKey
    malformedPk[custom_bike.bikeRBytes - 1] =
      malformedPk[custom_bike.bikeRBytes - 1] or 0x80'u8
    expect ValueError:
      discard custom_bike.bikeTyrEncapsDerand(custom_bike.bikeL1,
        malformedPk, encapsRandom)
    malformedSk = kp.secretKey
    malformedSk[0] = byte(custom_bike.bikeRBits and 0xff)
    malformedSk[1] = byte((custom_bike.bikeRBits shr 8) and 0xff)
    malformedSk[2] = byte((custom_bike.bikeRBits shr 16) and 0xff)
    malformedSk[3] = byte((custom_bike.bikeRBits shr 24) and 0xff)
    expect ValueError:
      discard custom_bike.bikeTyrDecaps(custom_bike.bikeL1, malformedSk,
        env.ciphertext)

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
        withOqsFeed(keypairRandom, proc () =
          requireSuccess(OQS_KEM_keypair(kem, addr pk[0], addr sk[0]), "OQS_KEM_keypair(BIKE)")
        )
        check not oqsFeedRanShort()
        check pk == nimKp.publicKey
        check sk == nimKp.secretKey

        let nimEnv = custom_bike.bikeTyrEncapsDerand(custom_bike.bikeL1, nimKp.publicKey, encapsRandom)
        ct = newSeq[uint8](int kem[].length_ciphertext)
        shared = newSeq[uint8](int kem[].length_shared_secret)
        withOqsFeed(encapsRandom, proc () =
          requireSuccess(OQS_KEM_encaps(kem, addr ct[0], addr shared[0], addr pk[0]), "OQS_KEM_encaps(BIKE)")
        )
        check not oqsFeedRanShort()
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
        let oqsEnv = initAsymCipher(ct, @[], shared)
        check open(oqsEnv, openM) == oqsEnv.sharedSecret
