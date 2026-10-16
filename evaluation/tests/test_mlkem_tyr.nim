import std/unittest

import ../../src/tyr
import ../../src/tyr/kems/mlkem as custom_mlkem
import ../../src/tyr/kems/mlkem/[
  params, types, poly, polyvec, symmetric, indcpa]

when defined(hasLibOqs):
  import ../../src/tyr/helpers/tiers
  import ../../src/tyr/bindings/liboqs
  import ../oqs_random_hook

proc fillPatternSeed(seed: var seq[byte], base: int) =
  var
    i: int = 0
  i = 0
  while i < seed.len:
    seed[i] = uint8((base + i) mod 256)
    i = i + 1

when defined(hasLibOqs):
  proc ensureLibOqsKemAvailable(algId: string): ptr OqsKem =
    let kem = OQS_KEM_new(algId)
    if kem == nil:
      return nil
    result = kem

  proc exerciseExactMatchAgainstLiboqs(variant: custom_mlkem.MlKemVariant,
      algId: string, keypairSeedBase, encapsSeedBase: int): tuple[exactKeypair,
      exactEncaps: bool] =
    var
      keypairSeed = newSeq[byte](32)
      encapsSeed = newSeq[byte](32)
      keypairFeed: seq[byte] = @[]
      nimKp: custom_mlkem.MlKemTyrKeypair
      nimEnv: custom_mlkem.MlKemTyrCipher
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
    nimKp = custom_mlkem.mlkemTyrKeypair(variant, keypairSeed)
    keypairFeed = hashG(keypairSeed)
    pk = newSeq[uint8](int kem[].length_public_key)
    sk = newSeq[uint8](int kem[].length_secret_key)
    withOqsFeed(keypairFeed, proc () =
      requireSuccess(OQS_KEM_keypair(kem, addr pk[0], addr sk[0]),
        "OQS_KEM_keypair(" & algId & ")")
    )
    check not oqsFeedRanShort()
    exactKeypair = (pk == nimKp.publicKey) and (sk == nimKp.secretKey)

    nimEnv = custom_mlkem.mlkemTyrEncaps(variant, nimKp.publicKey, encapsSeed)
    ct = newSeq[uint8](int kem[].length_ciphertext)
    shared = newSeq[uint8](int kem[].length_shared_secret)
    withOqsFeed(encapsSeed, proc () =
      requireSuccess(OQS_KEM_encaps(kem, addr ct[0], addr shared[0], addr pk[0]),
        "OQS_KEM_encaps(" & algId & ")")
    )
    check not oqsFeedRanShort()
    exactEncaps = (ct == nimEnv.ciphertext) and (shared == nimEnv.sharedSecret)
    result.exactKeypair = exactKeypair
    result.exactEncaps = exactEncaps

suite "mlkem tyr":
  test "derandomized keypair validates material before slicing":
    expect ValueError:
      discard custom_mlkem.mlkemTyrKeypairDerand(custom_mlkem.mlkem768,
        newSeq[byte](63))
    expect ValueError:
      discard custom_mlkem.mlkemTyrKeypairDerand(custom_mlkem.mlkem768,
        newSeq[byte](65))

  test "poly add and sub match scalar reference":
    var
      a: Poly
      b: Poly
      addRes: Poly
      subRes: Poly
      i: int = 0
    i = 0
    while i < mlkemN:
      a.coeffs[i] = int16((17 * i) mod 3329)
      b.coeffs[i] = int16((29 * i + 3) mod 3329)
      i = i + 1
    polyAdd(addRes, a, b)
    polySub(subRes, a, b)
    i = 0
    while i < mlkemN:
      check addRes.coeffs[i] == a.coeffs[i] + b.coeffs[i]
      check subRes.coeffs[i] == a.coeffs[i] - b.coeffs[i]
      i = i + 1

  test "cached polyvec basemul matches scalar reference":
    var
      p = mlkemParamsTable[custom_mlkem.mlkem768]
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
      while j < mlkemN:
        a.vec[i].coeffs[j] = int16(((17 * i) + (29 * j)) mod mlkemQ)
        b.vec[i].coeffs[j] = int16(((23 * i) + (31 * j) + 7) mod mlkemQ)
        j = j + 1
      i = i + 1
    polyvecMulCacheCompute(p, cache, b)
    polyvecBaseMulAccMontgomery(p, refRes, a, b)
    polyvecBaseMulAccMontgomeryCached(p, cachedRes, a, b, cache)
    i = 0
    while i < mlkemN:
      check cachedRes.coeffs[i] == refRes.coeffs[i]
      i = i + 1

  test "tier-0 pure-nim ML-KEM roundtrip matches shared secret":
    var
      seed = newSeq[byte](32)
      sendM: mlkem0TyrSendM
      openM: mlkem0TyrOpenM
      kp: custom_mlkem.MlKemTyrKeypair
      i: int = 0
    fillPatternSeed(seed, 23)
    kp = custom_mlkem.mlkemTyrKeypair(custom_mlkem.mlkem768, seed)
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

  test "tier-1 pure-nim ML-KEM roundtrip matches shared secret":
    var
      seed = newSeq[byte](32)
      sendM: mlkem1TyrSendM
      openM: mlkem1TyrOpenM
      kp: custom_mlkem.MlKemTyrKeypair
      i: int = 0
    fillPatternSeed(seed, 71)
    kp = custom_mlkem.mlkemTyrKeypair(custom_mlkem.mlkem1024, seed)
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

  # {.testKind: tkRegression, covers: "mlkemTyrEncaps".}
  test "encapsulation follows the FIPS 203 transcript":
    ## FIPS 203 algorithm 17: (K, r) = G(m || H(pk)), ct = Encrypt(pk, m, r),
    ## and K is the shared secret as-is. Round-3 Kyber hashed m first and
    ## hashed the ciphertext into K; either step here would break this test.
    var
      keySeed = newSeq[byte](32)
      encapsSeed = newSeq[byte](32)
      p = mlkemParamsTable[custom_mlkem.mlkem768]
      pkHash = newSeq[byte](mlkemSymBytes)
      input = newSeq[byte](2 * mlkemSymBytes)
      kr = newSeq[byte](2 * mlkemSymBytes)
      kp: custom_mlkem.MlKemTyrKeypair
      env: custom_mlkem.MlKemTyrCipher
      expectedCiphertext: seq[byte] = @[]
      i: int = 0
    fillPatternSeed(keySeed, 37)
    fillPatternSeed(encapsSeed, 109)
    kp = custom_mlkem.mlkemTyrKeypair(custom_mlkem.mlkem768, keySeed)
    env = custom_mlkem.mlkemTyrEncaps(custom_mlkem.mlkem768,
      kp.publicKey, encapsSeed)
    hashHInto(pkHash, kp.publicKey)
    while i < mlkemSymBytes:
      input[i] = encapsSeed[i]
      input[mlkemSymBytes + i] = pkHash[i]
      i = i + 1
    hashGInto(kr, input)
    expectedCiphertext = indcpaEnc(p, encapsSeed, kp.publicKey,
      kr.toOpenArray(mlkemSymBytes, 2 * mlkemSymBytes - 1))
    check env.ciphertext == expectedCiphertext
    check env.sharedSecret == kr[0 ..< mlkemSymBytes]

  # {.testKind: tkEdgeCase, covers: "mlkemTyrEncaps, publicKeyIsReduced".}
  test "a public key holding a number >= q is refused":
    ## FIPS 203 section 7.2. 0xFF 0xFF packs the numbers 4095 and 4095.
    var
      kp = custom_mlkem.mlkemTyrKeypair(custom_mlkem.mlkem768, newSeq[byte](32))
      bad: seq[byte] = kp.publicKey
    bad[0] = 0xff'u8
    bad[1] = 0xff'u8
    check custom_mlkem.publicKeyIsReduced(mlkemParamsTable[custom_mlkem.mlkem768], kp.publicKey)
    check not custom_mlkem.publicKeyIsReduced(mlkemParamsTable[custom_mlkem.mlkem768], bad)
    expect ValueError:
      discard custom_mlkem.mlkemTyrEncaps(custom_mlkem.mlkem768, bad)

  # {.testKind: tkEdgeCase, covers: "mlkemTyrDecaps".}
  test "a secret key whose stored H(ek) does not match is refused":
    ## FIPS 203 section 7.3. Flip one bit of the stored hash.
    var
      kp = custom_mlkem.mlkemTyrKeypair(custom_mlkem.mlkem768, newSeq[byte](32))
      env = custom_mlkem.mlkemTyrEncaps(custom_mlkem.mlkem768, kp.publicKey)
      p = mlkemParamsTable[custom_mlkem.mlkem768]
      bad: seq[byte] = kp.secretKey
    bad[p.secretKeyBytes - 2 * mlkemSymBytes] = bad[p.secretKeyBytes - 2 * mlkemSymBytes] xor 1'u8
    expect ValueError:
      discard custom_mlkem.mlkemTyrDecaps(custom_mlkem.mlkem768, bad, env.ciphertext)

  test "invalid ML-KEM ciphertext uses deterministic implicit rejection":
    var
      keySeed = newSeq[byte](32)
      encapsSeed = newSeq[byte](32)
      p = mlkemParamsTable[custom_mlkem.mlkem768]
      kp: custom_mlkem.MlKemTyrKeypair
      env: custom_mlkem.MlKemTyrCipher
      tampered: seq[byte] = @[]
      allZero: seq[byte] = @[]
      allFf: seq[byte] = @[]
      fallbackMaterial: seq[byte] = @[]
      expectedZero: seq[byte] = @[]
      bad0: seq[byte] = @[]
      bad1: seq[byte] = @[]
      zero0: seq[byte] = @[]
      zero1: seq[byte] = @[]
      ff0: seq[byte] = @[]
      ff1: seq[byte] = @[]
      i: int = 0
    fillPatternSeed(keySeed, 43)
    fillPatternSeed(encapsSeed, 127)
    kp = custom_mlkem.mlkemTyrKeypair(custom_mlkem.mlkem768, keySeed)
    env = custom_mlkem.mlkemTyrEncaps(custom_mlkem.mlkem768,
      kp.publicKey, encapsSeed)
    expect ValueError:
      discard custom_mlkem.mlkemTyrDecaps(custom_mlkem.mlkem768,
        kp.secretKey, @[])
    expect ValueError:
      discard custom_mlkem.mlkemTyrDecaps(custom_mlkem.mlkem768,
        kp.secretKey, newSeq[byte](env.ciphertext.len - 1))
    expect ValueError:
      discard custom_mlkem.mlkemTyrDecaps(custom_mlkem.mlkem768,
        kp.secretKey, newSeq[byte](env.ciphertext.len + 1))
    tampered = env.ciphertext
    tampered[0] = tampered[0] xor 1'u8
    bad0 = custom_mlkem.mlkemTyrDecaps(custom_mlkem.mlkem768,
      kp.secretKey, tampered)
    bad1 = custom_mlkem.mlkemTyrDecaps(custom_mlkem.mlkem768,
      kp.secretKey, tampered)
    check bad0.len == env.sharedSecret.len
    check bad0 == bad1
    check bad0 != env.sharedSecret
    allZero = newSeq[byte](env.ciphertext.len)
    allFf = newSeq[byte](env.ciphertext.len)
    i = 0
    while i < allFf.len:
      allFf[i] = 0xff'u8
      i = i + 1
    # FIPS 203 implicit rejection: K = J(z || ct) = SHAKE256(z || ct)[0..31]
    fallbackMaterial = kp.secretKey[p.secretKeyBytes - mlkemSymBytes ..< p.secretKeyBytes] & allZero
    expectedZero = newSeq[byte](mlkemSharedSecretBytes)
    kdfInto(expectedZero, fallbackMaterial)
    zero0 = custom_mlkem.mlkemTyrDecaps(custom_mlkem.mlkem768,
      kp.secretKey, allZero)
    zero1 = custom_mlkem.mlkemTyrDecaps(custom_mlkem.mlkem768,
      kp.secretKey, allZero)
    ff0 = custom_mlkem.mlkemTyrDecaps(custom_mlkem.mlkem768,
      kp.secretKey, allFf)
    ff1 = custom_mlkem.mlkemTyrDecaps(custom_mlkem.mlkem768,
      kp.secretKey, allFf)
    check zero0 == zero1
    check zero0 == expectedZero
    check zero0 != env.sharedSecret
    check ff0 == ff1
    check ff0 != env.sharedSecret

  when defined(hasLibOqs):
    test "tier-0 pure-nim ML-KEM matches liboqs byte-for-byte with deterministic RNG":
      let exact = exerciseExactMatchAgainstLiboqs(custom_mlkem.mlkem768, oqsAlgMlKem768, 19, 51)
      check exact.exactKeypair
      check exact.exactEncaps

    test "tier-1 pure-nim ML-KEM matches liboqs byte-for-byte with deterministic RNG":
      let exact = exerciseExactMatchAgainstLiboqs(custom_mlkem.mlkem1024, oqsAlgMlKem1024, 41, 73)
      check exact.exactKeypair
      check exact.exactEncaps

    test "tier-0 pure-nim ML-KEM encapsulation decaps via liboqs":
      var
        seed = newSeq[byte](32)
        sendM: mlkem0TyrSendM
        kp: custom_mlkem.MlKemTyrKeypair
        i: int = 0
      fillPatternSeed(seed, 99)
      kp = custom_mlkem.mlkemTyrKeypair(custom_mlkem.mlkem768, seed)
      i = 0
      while i < sendM.receiverPublicKey.len:
        sendM.receiverPublicKey[i] = kp.publicKey[i]
        i = i + 1
      let env = seal(sendM)
      check decaps(kaMlKem0, kp.secretKey, env) == env.sharedSecret

    test "tier-0 liboqs encapsulation decaps via pure-nim ML-KEM":
      var
        kp: AsymKeypair
        openM: mlkem0TyrOpenM
        env: AsymCipher
        i: int = 0
      kp = genKeypair(kaMlKem0)
      i = 0
      while i < openM.receiverSecretKey.len:
        openM.receiverSecretKey[i] = kp.secretKey[i]
        i = i + 1
      env = encaps(kaMlKem0, kp.publicKey)
      check open(env, openM) == env.sharedSecret

    test "tier-1 pure-nim ML-KEM encapsulation decaps via liboqs":
      var
        seed = newSeq[byte](32)
        sendM: mlkem1TyrSendM
        kp: custom_mlkem.MlKemTyrKeypair
        i: int = 0
      fillPatternSeed(seed, 147)
      kp = custom_mlkem.mlkemTyrKeypair(custom_mlkem.mlkem1024, seed)
      i = 0
      while i < sendM.receiverPublicKey.len:
        sendM.receiverPublicKey[i] = kp.publicKey[i]
        i = i + 1
      let env = seal(sendM)
      check decaps(kaMlKem1, kp.secretKey, env) == env.sharedSecret

    test "tier-1 liboqs encapsulation decaps via pure-nim ML-KEM":
      var
        kp: AsymKeypair
        openM: mlkem1TyrOpenM
        env: AsymCipher
        i: int = 0
      kp = genKeypair(kaMlKem1)
      i = 0
      while i < openM.receiverSecretKey.len:
        openM.receiverSecretKey[i] = kp.secretKey[i]
        i = i + 1
      env = encaps(kaMlKem1, kp.publicKey)
      check open(env, openM) == env.sharedSecret
