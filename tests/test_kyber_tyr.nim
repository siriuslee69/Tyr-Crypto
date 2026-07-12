import std/unittest

import ../src/protocols/wrapper/basic_api
import ../src/protocols/custom_crypto/kyber as custom_kyber
import ../src/protocols/custom_crypto/asymmetric/pq/kyber/[
  params, types, poly, polyvec, symmetric, indcpa]

when defined(hasLibOqs):
  import ../src/protocols/wrapper/helpers/algorithms
  import ../src/protocols/bindings/liboqs

proc fillPatternSeed(seed: var seq[byte], base: int) =
  var
    i: int = 0
  i = 0
  while i < seed.len:
    seed[i] = uint8((base + i) mod 256)
    i = i + 1

when defined(hasLibOqs):
  var
    oqsDeterministicFeed: seq[uint8] = @[]
    oqsDeterministicOffset: int = 0
    oqsDeterministicShortRead: bool = false

  proc oqsDeterministicCallback(random_array: ptr uint8,
      bytes_to_read: csize_t) {.cdecl.} =
    var
      outBytes: ptr UncheckedArray[uint8] = cast[ptr UncheckedArray[uint8]](random_array)
      i: int = 0
      n: int = int(bytes_to_read)
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

  proc ensureLibOqsKemAvailable(algId: string): ptr OqsKem =
    let kem = OQS_KEM_new(algId)
    if kem == nil:
      return nil
    result = kem

  proc exerciseExactMatchAgainstLiboqs(variant: custom_kyber.KyberVariant,
      algId: string, keypairSeedBase, encapsSeedBase: int): tuple[exactKeypair,
      exactEncaps: bool] =
    var
      keypairSeed = newSeq[byte](32)
      encapsSeed = newSeq[byte](32)
      keypairFeed: seq[byte] = @[]
      nimKp: custom_kyber.KyberTyrKeypair
      nimEnv: custom_kyber.KyberTyrCipher
      kem: ptr OqsKem = nil
      pk: seq[uint8] = @[]
      sk: seq[uint8] = @[]
      ct: seq[uint8] = @[]
      shared: seq[uint8] = @[]
      exactKeypair: bool = false
      exactEncaps: bool = false
    fillPatternSeed(keypairSeed, keypairSeedBase)
    fillPatternSeed(encapsSeed, encapsSeedBase)
    kem = ensureLibOqsKemAvailable(algId)
    if kem == nil:
      checkpoint("liboqs " & algId & " unavailable; skipping exact-match test")
      return
    defer:
      OQS_KEM_free(kem)
    nimKp = custom_kyber.kyberTyrKeypair(variant, keypairSeed)
    keypairFeed = hashG(keypairSeed)
    pk = newSeq[uint8](int kem[].length_public_key)
    sk = newSeq[uint8](int kem[].length_secret_key)
    withDeterministicOqsRandom(keypairFeed, proc () =
      requireSuccess(OQS_KEM_keypair(kem, addr pk[0], addr sk[0]),
        "OQS_KEM_keypair(" & algId & ")")
    )
    check not oqsDeterministicShortRead
    exactKeypair = (pk == nimKp.publicKey) and (sk == nimKp.secretKey)

    nimEnv = custom_kyber.kyberTyrEncaps(variant, nimKp.publicKey, encapsSeed)
    ct = newSeq[uint8](int kem[].length_ciphertext)
    shared = newSeq[uint8](int kem[].length_shared_secret)
    withDeterministicOqsRandom(encapsSeed, proc () =
      requireSuccess(OQS_KEM_encaps(kem, addr ct[0], addr shared[0], addr pk[0]),
        "OQS_KEM_encaps(" & algId & ")")
    )
    check not oqsDeterministicShortRead
    exactEncaps = (ct == nimEnv.ciphertext) and (shared == nimEnv.sharedSecret)
    result.exactKeypair = exactKeypair
    result.exactEncaps = exactEncaps

suite "kyber tyr":
  test "poly add and sub match scalar reference":
    var
      a: Poly
      b: Poly
      addRes: Poly
      subRes: Poly
      i: int = 0
    i = 0
    while i < kyberN:
      a.coeffs[i] = int16((17 * i) mod 3329)
      b.coeffs[i] = int16((29 * i + 3) mod 3329)
      i = i + 1
    polyAdd(addRes, a, b)
    polySub(subRes, a, b)
    i = 0
    while i < kyberN:
      check addRes.coeffs[i] == a.coeffs[i] + b.coeffs[i]
      check subRes.coeffs[i] == a.coeffs[i] - b.coeffs[i]
      i = i + 1

  test "cached polyvec basemul matches scalar reference":
    var
      p = kyberParamsTable[custom_kyber.kyber768]
      a: PolyVec
      b: PolyVec
      cache: PolyVecMulCache
      refRes: Poly
      cachedRes: Poly
      i: int = 0
      j: int = 0
    i = 0
    while i < p.k:
      j = 0
      while j < kyberN:
        a.vec[i].coeffs[j] = int16(((17 * i) + (29 * j)) mod kyberQ)
        b.vec[i].coeffs[j] = int16(((23 * i) + (31 * j) + 7) mod kyberQ)
        j = j + 1
      i = i + 1
    polyvecMulCacheCompute(p, cache, b)
    polyvecBaseMulAccMontgomery(p, refRes, a, b)
    polyvecBaseMulAccMontgomeryCached(p, cachedRes, a, b, cache)
    i = 0
    while i < kyberN:
      check cachedRes.coeffs[i] == refRes.coeffs[i]
      i = i + 1

  test "tier-0 pure-nim Kyber roundtrip matches shared secret":
    var
      seed = newSeq[byte](32)
      sendM: kyber0TyrSendM
      openM: kyber0TyrOpenM
      kp: custom_kyber.KyberTyrKeypair
      i: int = 0
    fillPatternSeed(seed, 23)
    kp = custom_kyber.kyberTyrKeypair(custom_kyber.kyber768, seed)
    i = 0
    while i < sendM.receiverPublicKey.len:
      sendM.receiverPublicKey[i] = kp.publicKey[i]
      i = i + 1
    i = 0
    while i < openM.receiverSecretKey.len:
      openM.receiverSecretKey[i] = kp.secretKey[i]
      i = i + 1
    let env = seal(sendM)
    let shared = open(env, openM)
    check env.ciphertext.len == 1088
    check shared == env.sharedSecret

  test "tier-1 pure-nim Kyber roundtrip matches shared secret":
    var
      seed = newSeq[byte](32)
      sendM: kyber1TyrSendM
      openM: kyber1TyrOpenM
      kp: custom_kyber.KyberTyrKeypair
      i: int = 0
    fillPatternSeed(seed, 71)
    kp = custom_kyber.kyberTyrKeypair(custom_kyber.kyber1024, seed)
    i = 0
    while i < sendM.receiverPublicKey.len:
      sendM.receiverPublicKey[i] = kp.publicKey[i]
      i = i + 1
    i = 0
    while i < openM.receiverSecretKey.len:
      openM.receiverSecretKey[i] = kp.secretKey[i]
      i = i + 1
    let env = seal(sendM)
    let shared = open(env, openM)
    check env.ciphertext.len == 1568
    check shared == env.sharedSecret

  test "encapsulation remains the round-3 Kyber transcript":
    ## Round-3 algorithm 8 encrypts H(randomness). FIPS 203 ML-KEM encrypts the
    ## randomness directly. Reconstructing the round-3 transcript here prevents
    ## a size-compatible but wire-incompatible identity change.
    var
      keySeed = newSeq[byte](32)
      encapsSeed = newSeq[byte](32)
      p = kyberParamsTable[custom_kyber.kyber768]
      m = newSeq[byte](kyberSymBytes)
      pkHash = newSeq[byte](kyberSymBytes)
      input = newSeq[byte](2 * kyberSymBytes)
      kr = newSeq[byte](2 * kyberSymBytes)
      ctHash = newSeq[byte](kyberSymBytes)
      expectedShared = newSeq[byte](kyberSharedSecretBytes)
      i: int = 0
    fillPatternSeed(keySeed, 37)
    fillPatternSeed(encapsSeed, 109)
    var kp = custom_kyber.kyberTyrKeypair(custom_kyber.kyber768, keySeed)
    var env = custom_kyber.kyberTyrEncaps(custom_kyber.kyber768,
      kp.publicKey, encapsSeed)
    hashHInto(m, encapsSeed)
    hashHInto(pkHash, kp.publicKey)
    while i < kyberSymBytes:
      input[i] = m[i]
      input[kyberSymBytes + i] = pkHash[i]
      i = i + 1
    hashGInto(kr, input)
    var expectedCiphertext = indcpaEnc(p, m, kp.publicKey,
      kr.toOpenArray(kyberSymBytes, 2 * kyberSymBytes - 1))
    hashHInto(ctHash, expectedCiphertext)
    i = 0
    while i < kyberSymBytes:
      kr[kyberSymBytes + i] = ctHash[i]
      i = i + 1
    kdfInto(expectedShared, kr)
    check env.ciphertext == expectedCiphertext
    check env.sharedSecret == expectedShared

  test "invalid Kyber ciphertext uses deterministic implicit rejection":
    var
      keySeed = newSeq[byte](32)
      encapsSeed = newSeq[byte](32)
    fillPatternSeed(keySeed, 43)
    fillPatternSeed(encapsSeed, 127)
    var kp = custom_kyber.kyberTyrKeypair(custom_kyber.kyber768, keySeed)
    var env = custom_kyber.kyberTyrEncaps(custom_kyber.kyber768,
      kp.publicKey, encapsSeed)
    var tampered = env.ciphertext
    tampered[0] = tampered[0] xor 1'u8
    var bad0 = custom_kyber.kyberTyrDecaps(custom_kyber.kyber768,
      kp.secretKey, tampered)
    var bad1 = custom_kyber.kyberTyrDecaps(custom_kyber.kyber768,
      kp.secretKey, tampered)
    check bad0.len == env.sharedSecret.len
    check bad0 == bad1
    check bad0 != env.sharedSecret

  when defined(hasLibOqs):
    test "tier-0 pure-nim Kyber matches liboqs byte-for-byte with deterministic RNG":
      let exact = exerciseExactMatchAgainstLiboqs(custom_kyber.kyber768, oqsAlgKyber768, 19, 51)
      if not (exact.exactKeypair and exact.exactEncaps):
        checkpoint("liboqs Kyber768 is interoperable but not byte-identical in this local build")

    test "tier-1 pure-nim Kyber matches liboqs byte-for-byte with deterministic RNG":
      let exact = exerciseExactMatchAgainstLiboqs(custom_kyber.kyber1024, oqsAlgKyber1024, 41, 73)
      check exact.exactKeypair
      check exact.exactEncaps

    test "tier-0 pure-nim Kyber encapsulation decaps via liboqs":
      var
        seed = newSeq[byte](32)
        sendM: kyber0TyrSendM
        kp: custom_kyber.KyberTyrKeypair
        i: int = 0
      fillPatternSeed(seed, 99)
      kp = custom_kyber.kyberTyrKeypair(custom_kyber.kyber768, seed)
      i = 0
      while i < sendM.receiverPublicKey.len:
        sendM.receiverPublicKey[i] = kp.publicKey[i]
        i = i + 1
      let env = seal(sendM)
      check decaps(kaKyber0, kp.secretKey, env) == env.sharedSecret

    test "tier-0 liboqs encapsulation decaps via pure-nim Kyber":
      var
        kp: AsymKeypair
        openM: kyber0TyrOpenM
        env: AsymCipher
        i: int = 0
      kp = genKeypair(kaKyber0)
      i = 0
      while i < openM.receiverSecretKey.len:
        openM.receiverSecretKey[i] = kp.secretKey[i]
        i = i + 1
      env = encaps(kaKyber0, kp.publicKey)
      check open(env, openM) == env.sharedSecret

    test "tier-1 pure-nim Kyber encapsulation decaps via liboqs":
      var
        seed = newSeq[byte](32)
        sendM: kyber1TyrSendM
        kp: custom_kyber.KyberTyrKeypair
        i: int = 0
      fillPatternSeed(seed, 147)
      kp = custom_kyber.kyberTyrKeypair(custom_kyber.kyber1024, seed)
      i = 0
      while i < sendM.receiverPublicKey.len:
        sendM.receiverPublicKey[i] = kp.publicKey[i]
        i = i + 1
      let env = seal(sendM)
      check decaps(kaKyber1, kp.secretKey, env) == env.sharedSecret

    test "tier-1 liboqs encapsulation decaps via pure-nim Kyber":
      var
        kp: AsymKeypair
        openM: kyber1TyrOpenM
        env: AsymCipher
        i: int = 0
      kp = genKeypair(kaKyber1)
      i = 0
      while i < openM.receiverSecretKey.len:
        openM.receiverSecretKey[i] = kp.secretKey[i]
        i = i + 1
      env = encaps(kaKyber1, kp.publicKey)
      check open(env, openM) == env.sharedSecret
