import std/unittest

import ../src/protocols/wrapper/basic_api
import ../src/protocols/custom_crypto/mceliece as custom_mceliece

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
  result = newSeq[byte](custom_mceliece.mcelieceEncapsRandomBlockBytes(p))
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
        @[], newSeq[byte](custom_mceliece.ciphertextBytes(
          custom_mceliece.mcParamsTable[custom_mceliece.mceliece6688128f])))

  test "invalid McEliece ciphertext keeps diagnostic and fallback secret aligned":
    var
      v = custom_mceliece.mceliece6688128f
      kp = custom_mceliece.mcelieceTyrKeypair(v, buildSeed(131))
      randomness = buildEncapsRandom(v)
      env = custom_mceliece.mcelieceTyrEncapsDerand(v, kp.publicKey,
        randomness)
      good = custom_mceliece.mcelieceTyrTryDecaps(v, kp.secretKey,
        env.ciphertext)
      tampered = env.ciphertext
    tampered[0] = tampered[0] xor 1'u8
    var bad = custom_mceliece.mcelieceTyrTryDecaps(v, kp.secretKey, tampered)
    var fallback = custom_mceliece.mcelieceTyrDecaps(v, kp.secretKey, tampered)
    check good.ok
    check good.sharedSecret == env.sharedSecret
    check not bad.ok
    check bad.sharedSecret.len == env.sharedSecret.len
    check bad.sharedSecret != env.sharedSecret
    check fallback == bad.sharedSecret

  when defined(hasLibOqs):
    test "pure-nim McEliece derand encaps matches liboqs deterministic RNG":
      checkDerandEncapsMatchesLiboqs(custom_mceliece.mceliece6688128f,
        oqsAlgClassicMcEliece6688128f, 113)
      checkDerandEncapsMatchesLiboqs(custom_mceliece.mceliece6960119f,
        oqsAlgClassicMcEliece6960119f, 127)
      checkDerandEncapsMatchesLiboqs(custom_mceliece.mceliece8192128f,
        oqsAlgClassicMcEliece8192128f, 149)
