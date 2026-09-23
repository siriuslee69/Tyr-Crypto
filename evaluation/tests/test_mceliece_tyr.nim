{.define: tyrCryptoTestHooks.}

import std/unittest

import ../../src/tyr
import ../../src/tyr/kems/mceliece as custom_mceliece
import ../../src/tyr/kems/mceliece/encrypt as mceliece_encrypt
import ../../src/tyr/hashes/sha3 as tyr_sha3

when defined(hasLibOqs):
  import ../../src/tyr/bindings/liboqs
  import ../oqs_random_hook

proc buildSeed(start: int): seq[byte] =
  result = newSeq[byte](32)
  var i: int = 0
  while i < result.len:
    result[i] = uint8((start + i) mod 256)
    i = i + 1

proc buildEncapsRandom(v: custom_mceliece.McElieceVariant): seq[byte] =
  var
    p = custom_mceliece.mcParamsTable[v]
  result = newSeq[byte](mceliece_encrypt.mcelieceEncapsRandomBlockBytes(p))
  for i in 0 ..< p.sysT:
    result[2 * i] = byte(uint16(i) and 0xff'u16)
    result[2 * i + 1] = byte((uint16(i) shr 8) and 0xff'u16)

when defined(hasLibOqs):
  proc checkDerandEncapsMatchesLiboqs(v: custom_mceliece.McElieceVariant,
      algId: string, seedBase: int) =
    var
      kem = OQS_KEM_new(algId.cstring)
      kp: custom_mceliece.McElieceTyrKeypair
      randomness: seq[byte] = @[]
      nimEnv: custom_mceliece.McElieceTyrCipher
      ct: seq[uint8] = @[]
      shared: seq[uint8] = @[]
    if kem == nil:
      checkpoint("liboqs " & algId & " unavailable; skipping exact comparison")
      return
    defer:
      OQS_KEM_free(kem)
    kp = custom_mceliece.mcelieceTyrKeypair(v, buildSeed(seedBase))
    randomness = buildEncapsRandom(v)
    nimEnv = custom_mceliece.mcelieceTyrEncapsDerand(v, kp.publicKey, randomness)
    ct = newSeq[uint8](int kem[].length_ciphertext)
    shared = newSeq[uint8](int kem[].length_shared_secret)
    withOqsFeed(randomness, proc () =
      requireSuccess(OQS_KEM_encaps(kem, addr ct[0], addr shared[0],
        unsafeAddr kp.publicKey[0]), "OQS_KEM_encaps(" & algId & ")")
    )
    check not oqsFeedRanShort()
    check ct == nimEnv.ciphertext
    check shared == nimEnv.sharedSecret

  ## ╭⟢ Cross-checking McEliece against the reference library
  ##
  ## The tests above only ever ask Tyr to undo its own work. A key pair
  ## that is wrong in a self-consistent way would still round-trip.
  ## These two exchanges make each implementation consume the other's
  ## output, which is what proves the encodings and the decoder agree:
  ##
  ##   Tyr key    -> liboqs seals -> Tyr opens    -> same secret
  ##   liboqs key -> Tyr seals    -> liboqs opens -> same secret
  proc checkInteropBothDirections(v: custom_mceliece.McElieceVariant,
      algId: string, seedBase: int) =
    ## v: which McEliece size is being cross-checked.
    ## algId: the same size under the library's own name.
    ## seedBase: starting byte of the deterministic key seed.
    var
      kem = OQS_KEM_new(algId.cstring)
      kp: custom_mceliece.McElieceTyrKeypair
      ct: seq[uint8] = @[]
      shared: seq[uint8] = @[]
      opened: tuple[sharedSecret: seq[byte], ok: bool]
      oqsPk: seq[uint8] = @[]
      oqsSk: seq[uint8] = @[]
      oqsShared: seq[uint8] = @[]
      nimEnv: custom_mceliece.McElieceTyrCipher
    if kem == nil:
      checkpoint("liboqs " & algId & " unavailable; skipping interop")
      return
    defer:
      OQS_KEM_free(kem)

    # Direction one: Tyr owns the key pair, the library seals to it.
    kp = custom_mceliece.mcelieceTyrKeypair(v, buildSeed(seedBase))
    check kp.publicKey.len == int kem[].length_public_key
    check kp.secretKey.len == int kem[].length_secret_key
    ct = newSeq[uint8](int kem[].length_ciphertext)
    shared = newSeq[uint8](int kem[].length_shared_secret)
    requireSuccess(OQS_KEM_encaps(kem, addr ct[0], addr shared[0],
      unsafeAddr kp.publicKey[0]), "OQS_KEM_encaps(" & algId & ")")
    opened = custom_mceliece.mcelieceTyrTryDecaps(v, kp.secretKey, ct)
    check opened.ok
    check opened.sharedSecret == shared

    # Direction two: the library owns the key pair, Tyr seals to it.
    oqsPk = newSeq[uint8](int kem[].length_public_key)
    oqsSk = newSeq[uint8](int kem[].length_secret_key)
    oqsShared = newSeq[uint8](int kem[].length_shared_secret)
    requireSuccess(OQS_KEM_keypair(kem, addr oqsPk[0], addr oqsSk[0]),
      "OQS_KEM_keypair(" & algId & ")")
    nimEnv = custom_mceliece.mcelieceTyrEncaps(v, oqsPk)
    check nimEnv.ciphertext.len == int kem[].length_ciphertext
    requireSuccess(OQS_KEM_decaps(kem, addr oqsShared[0],
      unsafeAddr nimEnv.ciphertext[0], addr oqsSk[0]),
      "OQS_KEM_decaps(" & algId & ")")
    check oqsShared == nimEnv.sharedSecret

suite "mceliece tyr":
  test "tier-0 pure-nim McEliece roundtrip matches shared secret":
    var
      seed = buildSeed(17)
      sendM: mceliece0TyrSendM
      openM: mceliece0TyrOpenM
      i: int = 0
    let kp = custom_mceliece.mcelieceTyrKeypair(custom_mceliece.mceliece6688128f, seed)
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
    check env.ciphertext.len == 208
    check shared == env.sharedSecret

  test "tier-1 pure-nim McEliece seeded roundtrip matches shared secret":
    let seed = buildSeed(41)
    let kp = custom_mceliece.mcelieceTyrKeypair(custom_mceliece.mceliece6960119f, seed)
    let env = custom_mceliece.mcelieceTyrEncaps(custom_mceliece.mceliece6960119f, kp.publicKey)
    let dec = custom_mceliece.mcelieceTyrTryDecaps(custom_mceliece.mceliece6960119f,
      kp.secretKey, env.ciphertext)
    check dec.ok
    check dec.sharedSecret == env.sharedSecret

  test "tier-2 pure-nim McEliece seeded roundtrip matches shared secret":
    let seed = buildSeed(73)
    let kp = custom_mceliece.mcelieceTyrKeypair(custom_mceliece.mceliece8192128f, seed)
    let env = custom_mceliece.mcelieceTyrEncaps(custom_mceliece.mceliece8192128f, kp.publicKey)
    let dec = custom_mceliece.mcelieceTyrTryDecaps(custom_mceliece.mceliece8192128f,
      kp.secretKey, env.ciphertext)
    check dec.ok
    check dec.sharedSecret == env.sharedSecret

  test "pure-nim McEliece derand encaps is reproducible":
    var
      seed = buildSeed(89)
      kp = custom_mceliece.mcelieceTyrKeypair(custom_mceliece.mceliece6688128f, seed)
      randomness = buildEncapsRandom(custom_mceliece.mceliece6688128f)
      envA = custom_mceliece.mcelieceTyrEncapsDerand(custom_mceliece.mceliece6688128f,
        kp.publicKey, randomness)
      envB = custom_mceliece.mcelieceTyrEncapsDerand(custom_mceliece.mceliece6688128f,
        kp.publicKey, randomness)
      dec = custom_mceliece.mcelieceTyrTryDecaps(custom_mceliece.mceliece6688128f,
        kp.secretKey, envA.ciphertext)
    check envA.ciphertext == envB.ciphertext
    check envA.sharedSecret == envB.sharedSecret
    check dec.ok
    check dec.sharedSecret == envA.sharedSecret

  test "pure-nim McEliece public APIs reject invalid lengths":
    var
      seed = buildSeed(107)
      kp = custom_mceliece.mcelieceTyrKeypair(custom_mceliece.mceliece6688128f, seed)
      randomness = buildEncapsRandom(custom_mceliece.mceliece6688128f)
      ctLen = custom_mceliece.ciphertextBytes(
        custom_mceliece.mcParamsTable[custom_mceliece.mceliece6688128f])
    expect(ValueError):
      discard custom_mceliece.mcelieceTyrEncaps(custom_mceliece.mceliece6688128f, @[])
    expect(ValueError):
      discard custom_mceliece.mcelieceTyrEncapsDerand(custom_mceliece.mceliece6688128f,
        @[], randomness)
    expect(ValueError):
      discard custom_mceliece.mcelieceTyrEncapsDerand(custom_mceliece.mceliece6688128f,
        kp.publicKey, @[])
    expect(ValueError):
      discard custom_mceliece.mcelieceTyrTryDecaps(custom_mceliece.mceliece6688128f,
        kp.secretKey, @[])
    expect(ValueError):
      discard custom_mceliece.mcelieceTyrTryDecaps(custom_mceliece.mceliece6688128f,
        kp.secretKey, newSeq[byte](ctLen - 1))
    expect(ValueError):
      discard custom_mceliece.mcelieceTyrTryDecaps(custom_mceliece.mceliece6688128f,
        kp.secretKey, newSeq[byte](ctLen + 1))
    expect(ValueError):
      discard custom_mceliece.mcelieceTyrTryDecaps(custom_mceliece.mceliece6688128f,
        @[], newSeq[byte](custom_mceliece.ciphertextBytes(
          custom_mceliece.mcParamsTable[custom_mceliece.mceliece6688128f])))

  # {.testKind: tkRegression, covers: "mcelieceTyrEncaps, mcelieceTyrEncapsDerand, mcelieceTyrTryDecaps", pins: "6960119f accepted nonzero padding bits".}
  test "McEliece 6960119f refuses nonzero padding bits like the reference":
    ## 6960119f is the one size whose ciphertext (1547 bits in 194 bytes)
    ## and public-key rows (5413 bits in 677 bytes) leave bits unused.
    var
      v = custom_mceliece.mceliece6960119f
      p = custom_mceliece.mcParamsTable[v]
      kp = custom_mceliece.mcelieceTyrKeypair(v, buildSeed(139))
      env = custom_mceliece.mcelieceTyrEncaps(v, kp.publicKey)
      badCt: seq[byte] = env.ciphertext
      badPk: seq[byte] = kp.publicKey
      opened: tuple[sharedSecret: seq[byte], ok: bool] = (@[], false)
    check custom_mceliece.ciphertextPaddingIsZero(p, env.ciphertext)
    check custom_mceliece.publicKeyPaddingIsZero(p, kp.publicKey)
    opened = custom_mceliece.mcelieceTyrTryDecaps(v, kp.secretKey, env.ciphertext)
    check opened.ok
    check opened.sharedSecret == env.sharedSecret
    badCt[^1] = badCt[^1] or 0x80'u8
    expect(ValueError):
      discard custom_mceliece.mcelieceTyrTryDecaps(v, kp.secretKey, badCt)
    expect(ValueError):
      discard custom_mceliece.mcelieceTyrDecaps(v, kp.secretKey, badCt)
    badPk[p.pkRowBytes - 1] = badPk[p.pkRowBytes - 1] or 0x80'u8
    expect(ValueError):
      discard custom_mceliece.mcelieceTyrEncaps(v, badPk)
    expect(ValueError):
      discard custom_mceliece.mcelieceTyrEncapsDerand(v, badPk, buildEncapsRandom(v))
    badPk = kp.publicKey
    badPk[^1] = badPk[^1] or 0x20'u8
    expect(ValueError):
      discard custom_mceliece.mcelieceTyrEncaps(v, badPk)

  # {.testKind: tkEdgeCase, covers: "ciphertextPaddingIsZero, publicKeyPaddingIsZero".}
  test "McEliece sizes that fill every byte have no padding to refuse":
    var
      p = custom_mceliece.mcParamsTable[custom_mceliece.mceliece6688128f]
      ct = newSeq[byte](custom_mceliece.ciphertextBytes(p))
      pk = newSeq[byte](custom_mceliece.publicKeyBytes(p))
      i: int = 0
    while i < ct.len:
      ct[i] = 0xff'u8
      i = i + 1
    i = 0
    while i < pk.len:
      pk[i] = 0xff'u8
      i = i + 1
    check custom_mceliece.ciphertextPaddingIsZero(p, ct)
    check custom_mceliece.publicKeyPaddingIsZero(p, pk)

  test "invalid McEliece ciphertext keeps diagnostic and fallback secret aligned":
    var
      v = custom_mceliece.mceliece6688128f
      p = custom_mceliece.mcParamsTable[v]
      kp = custom_mceliece.mcelieceTyrKeypair(v, buildSeed(131))
      randomness = buildEncapsRandom(v)
      env = custom_mceliece.mcelieceTyrEncapsDerand(v, kp.publicKey,
        randomness)
      good = custom_mceliece.mcelieceTyrTryDecaps(v, kp.secretKey,
        env.ciphertext)
      tampered = env.ciphertext
      bad0: tuple[sharedSecret: seq[byte], ok: bool]
      bad1: tuple[sharedSecret: seq[byte], ok: bool]
      fallback: seq[byte] = @[]
      allZero: seq[byte] = @[]
      allFf: seq[byte] = @[]
      sOff: int = 0
      fallbackInput: seq[byte] = @[]
      expectedZero: seq[byte] = @[]
      zero0: tuple[sharedSecret: seq[byte], ok: bool]
      zero1: tuple[sharedSecret: seq[byte], ok: bool]
      zeroFallback: seq[byte] = @[]
      ff0: tuple[sharedSecret: seq[byte], ok: bool]
      ff1: tuple[sharedSecret: seq[byte], ok: bool]
      ffFallback: seq[byte] = @[]
      i: int = 0
    tampered[0] = tampered[0] xor 1'u8
    bad0 = custom_mceliece.mcelieceTyrTryDecaps(v, kp.secretKey, tampered)
    bad1 = custom_mceliece.mcelieceTyrTryDecaps(v, kp.secretKey, tampered)
    fallback = custom_mceliece.mcelieceTyrDecaps(v, kp.secretKey, tampered)
    check good.ok
    check good.sharedSecret == env.sharedSecret
    check not bad0.ok
    check not bad1.ok
    check bad0.sharedSecret.len == env.sharedSecret.len
    check bad0.sharedSecret == bad1.sharedSecret
    check bad0.sharedSecret != env.sharedSecret
    check fallback == bad0.sharedSecret
    allZero = newSeq[byte](env.ciphertext.len)
    allFf = newSeq[byte](env.ciphertext.len)
    i = 0
    while i < allFf.len:
      allFf[i] = 0xff'u8
      i = i + 1
    sOff = custom_mceliece.secretKeyBytes(p) - p.sysN div 8
    fallbackInput = newSeq[byte](1 + p.sysN div 8 + p.syndBytes)
    fallbackInput[0] = 0x00'u8
    i = 0
    while i < p.sysN div 8:
      fallbackInput[1 + i] = kp.secretKey[sOff + i]
      i = i + 1
    i = 0
    while i < p.syndBytes:
      fallbackInput[1 + p.sysN div 8 + i] = allZero[i]
      i = i + 1
    expectedZero = tyr_sha3.shake256(fallbackInput,
      custom_mceliece.sharedKeyBytes())
    zero0 = custom_mceliece.mcelieceTyrTryDecaps(v, kp.secretKey, allZero)
    zero1 = custom_mceliece.mcelieceTyrTryDecaps(v, kp.secretKey, allZero)
    zeroFallback = custom_mceliece.mcelieceTyrDecaps(v, kp.secretKey, allZero)
    ff0 = custom_mceliece.mcelieceTyrTryDecaps(v, kp.secretKey, allFf)
    ff1 = custom_mceliece.mcelieceTyrTryDecaps(v, kp.secretKey, allFf)
    ffFallback = custom_mceliece.mcelieceTyrDecaps(v, kp.secretKey, allFf)
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

  when defined(hasLibOqs):
    test "pure-nim McEliece derand encaps matches liboqs deterministic RNG":
      checkDerandEncapsMatchesLiboqs(custom_mceliece.mceliece6688128f,
        oqsAlgClassicMcEliece6688128f, 113)
      checkDerandEncapsMatchesLiboqs(custom_mceliece.mceliece6960119f,
        oqsAlgClassicMcEliece6960119f, 127)
      checkDerandEncapsMatchesLiboqs(custom_mceliece.mceliece8192128f,
        oqsAlgClassicMcEliece8192128f, 149)

  when defined(hasLibOqs):
    # {.testKind: tkIntegration, covers: "mcelieceTyrTryDecaps".}
    test "liboqs also refuses a 6960119f ciphertext with padding bits set":
      var
        v = custom_mceliece.mceliece6960119f
        kem = OQS_KEM_new(oqsAlgClassicMcEliece6960119f.cstring)
        kp = custom_mceliece.mcelieceTyrKeypair(v, buildSeed(151))
        badCt: seq[byte] = custom_mceliece.mcelieceTyrEncaps(v, kp.publicKey).ciphertext
        oqsOut = newSeq[byte](32)
        rc: int = 0
      if kem == nil:
        checkpoint("liboqs Classic-McEliece-6960119f unavailable; skipping")
      else:
        badCt[^1] = badCt[^1] or 0x80'u8
        rc = int(OQS_KEM_decaps(kem, addr oqsOut[0], addr badCt[0], addr kp.secretKey[0]))
        OQS_KEM_free(kem)
        check rc != 0
        expect(ValueError):
          discard custom_mceliece.mcelieceTyrDecaps(v, kp.secretKey, badCt)

  when defined(hasLibOqs):
    # {.testKind: tkIntegration, covers: "mcelieceTyrKeypair, mcelieceTyrEncaps, mcelieceTyrTryDecaps".}
    test "pure-nim and liboqs McEliece interoperate both directions":
      checkInteropBothDirections(custom_mceliece.mceliece6688128f,
        oqsAlgClassicMcEliece6688128f, 163)
      checkInteropBothDirections(custom_mceliece.mceliece6960119f,
        oqsAlgClassicMcEliece6960119f, 179)
      checkInteropBothDirections(custom_mceliece.mceliece8192128f,
        oqsAlgClassicMcEliece8192128f, 191)
