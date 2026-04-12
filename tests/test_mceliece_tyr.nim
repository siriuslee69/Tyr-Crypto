import std/unittest

import ../src/protocols/wrapper/basic_api
import ../src/protocols/custom_crypto/mceliece as custom_mceliece

suite "mceliece tyr":
  test "tier-0 pure-nim McEliece roundtrip matches shared secret":
    var
      seed = newSeq[byte](32)
      sendM: mceliece0TyrSendM
      openM: mceliece0TyrOpenM
      i: int = 0
    while i < seed.len:
      seed[i] = uint8((17 + i) mod 256)
      i = i + 1
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
