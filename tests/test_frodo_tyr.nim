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

template runPureRoundtripCase(variant: untyped, keypairBase, encapsBase: int) =
  block:
    let p = custom_frodo.frodoParamsTable[variant]
    checkpoint("pure-nim " & p.name)
    var
      keypairRandom = newSeq[byte](p.keypairRandomBytes)
      encapsRandom = newSeq[byte](p.encapsRandomBytes)
    fillSeed(keypairRandom, keypairBase)
    fillSeed(encapsRandom, encapsBase)
    let kp = custom_frodo.frodoTyrKeypairDerand(variant, keypairRandom)
    let env = custom_frodo.frodoTyrEncapsDerand(variant, kp.publicKey, encapsRandom)
    let shared = custom_frodo.frodoTyrDecaps(variant, kp.secretKey, env.ciphertext)
    check shared == env.sharedSecret
    check kp.publicKey.len == p.publicKeyBytes
    check kp.secretKey.len == p.secretKeyBytes
    check env.ciphertext.len == p.ciphertextBytes
    check env.sharedSecret.len == p.sharedSecretBytes

template runTyrApiRoundtripCase(variant, SendType, OpenType: untyped,
    keypairBase: int) =
  block:
    let p = custom_frodo.frodoParamsTable[variant]
    checkpoint("basic_api typed " & p.name)
    var
      keypairRandom = newSeq[byte](p.keypairRandomBytes)
      sendM: SendType
      openM: OpenType
      i: int = 0
    fillSeed(keypairRandom, keypairBase)
    let kp = custom_frodo.frodoTyrKeypairDerand(variant, keypairRandom)
    i = 0
    while i < sendM.receiverPublicKey.len:
      sendM.receiverPublicKey[i] = kp.publicKey[i]
      i = i + 1
    i = 0
    while i < openM.receiverSecretKey.len:
      openM.receiverSecretKey[i] = kp.secretKey[i]
      i = i + 1
    let env = seal(sendM)
    check env.ciphertext.len == p.ciphertextBytes
    check env.sharedSecret.len == p.sharedSecretBytes
    check open(env, openM) == env.sharedSecret

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

  template runExactMatchCase(variant: untyped, oqsAlg: string, keypairBase,
      encapsBase: int) =
    block:
      let p = custom_frodo.frodoParamsTable[variant]
      checkpoint("liboqs exact " & p.name)
      var
        keypairRandom = newSeq[byte](p.keypairRandomBytes)
        encapsRandom = newSeq[byte](p.encapsRandomBytes)
        kem: ptr OqsKem = nil
        pk: seq[uint8] = @[]
        sk: seq[uint8] = @[]
        ct: seq[uint8] = @[]
        shared: seq[uint8] = @[]
      fillSeed(keypairRandom, keypairBase)
      fillSeed(encapsRandom, encapsBase)
      kem = OQS_KEM_new(oqsAlg.cstring)
      if kem == nil:
        checkpoint("liboqs missing KEM " & oqsAlg)
      else:
        defer:
          OQS_KEM_free(kem)
        let nimKp = custom_frodo.frodoTyrKeypairDerand(variant, keypairRandom)
        pk = newSeq[uint8](int kem[].length_public_key)
        sk = newSeq[uint8](int kem[].length_secret_key)
        withDeterministicOqsRandom(keypairRandom, proc () =
          requireSuccess(OQS_KEM_keypair(kem, addr pk[0], addr sk[0]),
            "OQS_KEM_keypair(" & oqsAlg & ")")
        )
        check not oqsDeterministicShortRead
        check pk == nimKp.publicKey
        check sk == nimKp.secretKey

        let nimEnv = custom_frodo.frodoTyrEncapsDerand(variant, nimKp.publicKey, encapsRandom)
        ct = newSeq[uint8](int kem[].length_ciphertext)
        shared = newSeq[uint8](int kem[].length_shared_secret)
        withDeterministicOqsRandom(encapsRandom, proc () =
          requireSuccess(OQS_KEM_encaps(kem, addr ct[0], addr shared[0], addr pk[0]),
            "OQS_KEM_encaps(" & oqsAlg & ")")
        )
        check not oqsDeterministicShortRead
        check ct == nimEnv.ciphertext
        check shared == nimEnv.sharedSecret

  template runInteropCase(variant: untyped, alg: KemAlgorithm, oqsAlg: string,
      keypairBase, encapsBase: int) =
    block:
      let p = custom_frodo.frodoParamsTable[variant]
      checkpoint("liboqs interop " & p.name)
      var
        keypairRandom = newSeq[byte](p.keypairRandomBytes)
        encapsRandom = newSeq[byte](p.encapsRandomBytes)
        kem: ptr OqsKem = nil
      fillSeed(keypairRandom, keypairBase)
      fillSeed(encapsRandom, encapsBase)
      let nimKp = custom_frodo.frodoTyrKeypairDerand(variant, keypairRandom)
      let nimEnv = custom_frodo.frodoTyrEncapsDerand(variant, nimKp.publicKey, encapsRandom)
      check decaps(alg, nimKp.secretKey,
        initAsymCipher(nimEnv.ciphertext, @[], nimEnv.sharedSecret)) == nimEnv.sharedSecret

      kem = OQS_KEM_new(oqsAlg.cstring)
      if kem == nil:
        checkpoint("liboqs missing KEM " & oqsAlg)
      else:
        defer:
          OQS_KEM_free(kem)
        let oqsKp = genKeypair(alg)
        let oqsEnv = encaps(alg, oqsKp.publicKey)
        check custom_frodo.frodoTyrDecaps(variant, oqsKp.secretKey,
          oqsEnv.ciphertext) == oqsEnv.sharedSecret

suite "frodo tyr":
  test "constant-time word verification returns full-byte masks":
    var
      equalA: array[3, uint16] = [1'u16, 2'u16, 3'u16]
      equalB: array[3, uint16] = [1'u16, 2'u16, 3'u16]
      changed: array[3, uint16] = [1'u16, 2'u16, 7'u16]
      selected: array[3, byte]
      accepted: array[3, byte] = [0x12'u8, 0x34'u8, 0x56'u8]
      rejected: array[3, byte] = [0xa1'u8, 0xb2'u8, 0xc3'u8]
      selector: int8 = 0
    check custom_frodo.ctVerifyWords(equalA, equalB) == 0'i8
    selector = custom_frodo.ctVerifyWords(equalA, changed)
    check selector == -1'i8
    custom_frodo.ctSelectBytes(selected, accepted, rejected, selector)
    check selected == rejected

  when not defined(release):
    test "pure-nim Frodo roundtrip is release-only due runtime cost":
      checkpoint("Frodo pure-Nim runtime checks are only enabled in release builds")
  else:
    test "pure-nim Frodo roundtrips match shared secrets for all variants":
      runPureRoundtripCase(custom_frodo.frodo640aes, 13, 77)
      runPureRoundtripCase(custom_frodo.frodo640shake, 17, 81)
      runPureRoundtripCase(custom_frodo.frodo976aes, 21, 85)
      runPureRoundtripCase(custom_frodo.frodo976shake, 25, 89)
      runPureRoundtripCase(custom_frodo.frodo1344aes, 29, 93)
      runPureRoundtripCase(custom_frodo.frodo1344shake, 33, 97)

    test "basic_api Frodo Tyr typed materials roundtrip for all variants":
      runTyrApiRoundtripCase(custom_frodo.frodo640aes, frodo0AesTyrSendM,
        frodo0AesTyrOpenM, 41)
      runTyrApiRoundtripCase(custom_frodo.frodo640shake, frodo0ShakeTyrSendM,
        frodo0ShakeTyrOpenM, 45)
      runTyrApiRoundtripCase(custom_frodo.frodo976aes, frodo1AesTyrSendM,
        frodo1AesTyrOpenM, 49)
      runTyrApiRoundtripCase(custom_frodo.frodo976shake, frodo1ShakeTyrSendM,
        frodo1ShakeTyrOpenM, 53)
      runTyrApiRoundtripCase(custom_frodo.frodo1344aes, frodo2AesTyrSendM,
        frodo2AesTyrOpenM, 57)
      runTyrApiRoundtripCase(custom_frodo.frodo1344shake, frodo2ShakeTyrSendM,
        frodo2ShakeTyrOpenM, 61)

    when defined(hasLibOqs):
      test "pure-nim Frodo keypair and encaps match liboqs for all variants":
        runExactMatchCase(custom_frodo.frodo640aes, oqsAlgFrodoKEM640Aes, 71, 131)
        runExactMatchCase(custom_frodo.frodo640shake, oqsAlgFrodoKEM640Shake, 75, 135)
        runExactMatchCase(custom_frodo.frodo976aes, oqsAlgFrodoKEM976Aes, 79, 139)
        runExactMatchCase(custom_frodo.frodo976shake, oqsAlgFrodoKEM976Shake, 83, 143)
        runExactMatchCase(custom_frodo.frodo1344aes, oqsAlgFrodoKEM1344Aes, 87, 147)
        runExactMatchCase(custom_frodo.frodo1344shake, oqsAlgFrodoKEM1344Shake, 91, 151)

      test "pure-nim and liboqs Frodo interoperate both directions for all variants":
        runInteropCase(custom_frodo.frodo640aes, kaFrodo0Aes, oqsAlgFrodoKEM640Aes, 101, 161)
        runInteropCase(custom_frodo.frodo640shake, kaFrodo0Shake, oqsAlgFrodoKEM640Shake, 105, 165)
        runInteropCase(custom_frodo.frodo976aes, kaFrodo1Aes, oqsAlgFrodoKEM976Aes, 109, 169)
        runInteropCase(custom_frodo.frodo976shake, kaFrodo1Shake, oqsAlgFrodoKEM976Shake, 113, 173)
        runInteropCase(custom_frodo.frodo1344aes, kaFrodo2Aes, oqsAlgFrodoKEM1344Aes, 117, 177)
        runInteropCase(custom_frodo.frodo1344shake, kaFrodo2Shake, oqsAlgFrodoKEM1344Shake, 121, 181)
