{.define: tyrCryptoTestHooks.}

import std/unittest

import ../src/protocols/wrapper/basic_api
import ../src/protocols/custom_crypto/mceliece as custom_mceliece
import ../src/protocols/custom_crypto/asymmetric/pq/mceliece/encrypt as mceliece_encrypt
import ../src/protocols/custom_crypto/symmetric/sha3/sha3 as tyr_sha3

when defined(hasLibOqs):
  import ../src/protocols/bindings/liboqs

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
  var
    mcelieceOqsDeterministicFeed: seq[uint8] = @[]
    mcelieceOqsDeterministicOffset: int = 0
    mcelieceOqsDeterministicShortRead: bool = false

  proc mcelieceOqsDeterministicCallback(random_array: ptr uint8,
      bytes_to_read: csize_t) {.cdecl.} =
    var
      outBytes = cast[ptr UncheckedArray[uint8]](random_array)
    for i in 0 ..< int(bytes_to_read):
      if mcelieceOqsDeterministicOffset < mcelieceOqsDeterministicFeed.len:
        outBytes[i] = mcelieceOqsDeterministicFeed[mcelieceOqsDeterministicOffset]
        mcelieceOqsDeterministicOffset = mcelieceOqsDeterministicOffset + 1
      else:
        outBytes[i] = 0'u8
        mcelieceOqsDeterministicShortRead = true

  proc withMcelieceDeterministicOqsRandom(feed: openArray[byte], body: proc ()) =
    mcelieceOqsDeterministicFeed = newSeq[uint8](feed.len)
    for i in 0 ..< feed.len:
      mcelieceOqsDeterministicFeed[i] = feed[i]
    mcelieceOqsDeterministicOffset = 0
    mcelieceOqsDeterministicShortRead = false
    OQS_randombytes_custom_algorithm(mcelieceOqsDeterministicCallback)
    try:
      body()
    finally:
      discard OQS_randombytes_switch_algorithm(oqsRandAlgSystem.cstring)
      mcelieceOqsDeterministicFeed.setLen(0)
      mcelieceOqsDeterministicOffset = 0

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
    withMcelieceDeterministicOqsRandom(randomness, proc () =
      requireSuccess(OQS_KEM_encaps(kem, addr ct[0], addr shared[0],
        unsafeAddr kp.publicKey[0]), "OQS_KEM_encaps(" & algId & ")")
    )
    check not mcelieceOqsDeterministicShortRead
    check ct == nimEnv.ciphertext
    check shared == nimEnv.sharedSecret

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
