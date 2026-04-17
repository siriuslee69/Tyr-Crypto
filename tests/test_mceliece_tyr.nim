import std/unittest

import ../src/protocols/wrapper/basic_api
import ../src/protocols/custom_crypto/mceliece as custom_mceliece

proc buildSeed(start: int): seq[byte] =
  result = newSeq[byte](32)
  var i: int = 0
  while i < result.len:
    result[i] = uint8((start + i) mod 256)
    i = i + 1

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
