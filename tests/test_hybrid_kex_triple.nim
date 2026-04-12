import std/unittest
import ../src/protocols/wrapper/helpers/algorithms
import ../src/protocols/common
import ../src/protocols/wrapper/basic_api

suite "multi kex triple":
  when defined(hasLibOqs) and defined(hasLibsodium):
    test "Kyber + McEliece + X25519 shared secrets match via quick api":
      let receiverX = asymKeypair(kaX25519)
      let receiverK = asymKeypair(kaKyber1)
      let receiverM = asymKeypair(kaMcEliece2)
      var sendX: x25519SendM
      var openX: x25519OpenM
      var sendK: kyber1SendM
      var openK: kyber1OpenM
      var sendM: mceliece2SendM
      var openM: mceliece2OpenM
      for i in 0 ..< 32:
        sendX.receiverPublicKey[i] = receiverX.publicKey[i]
        openX.receiverSecretKey[i] = receiverX.secretKey[i]
      for i in 0 ..< 1568:
        sendK.receiverPublicKey[i] = receiverK.publicKey[i]
      for i in 0 ..< 3168:
        openK.receiverSecretKey[i] = receiverK.secretKey[i]
      for i in 0 ..< 1357824:
        sendM.receiverPublicKey[i] = receiverM.publicKey[i]
      for i in 0 ..< 14120:
        openM.receiverSecretKey[i] = receiverM.secretKey[i]
      let envs = seal(sendX, sendK, sendM)
      let shareds = open(envs, openX, openK, openM)
      check shareds[0] == envs[0].sharedSecret
      check shareds[1] == envs[1].sharedSecret
      check shareds[2] == envs[2].sharedSecret

    test "hybrid kex can still be composed without helper suites":
      let receiverX = asymKeypair(kaX25519)
      let receiverK = asymKeypair(kaKyber1)
      let receiverM = asymKeypair(kaMcEliece2)
      var sendX: x25519SendM
      var openX: x25519OpenM
      var sendK: kyber1SendM
      var openK: kyber1OpenM
      var sendM: mceliece2SendM
      var openM: mceliece2OpenM
      for i in 0 ..< 32:
        sendX.receiverPublicKey[i] = receiverX.publicKey[i]
        openX.receiverSecretKey[i] = receiverX.secretKey[i]
      for i in 0 ..< 1568:
        sendK.receiverPublicKey[i] = receiverK.publicKey[i]
      for i in 0 ..< 3168:
        openK.receiverSecretKey[i] = receiverK.secretKey[i]
      for i in 0 ..< 1357824:
        sendM.receiverPublicKey[i] = receiverM.publicKey[i]
      for i in 0 ..< 14120:
        openM.receiverSecretKey[i] = receiverM.secretKey[i]
      check open(seal(sendX), openX) != @[]
      check open(seal(sendK), openK) != @[]
      check open(seal(sendM), openM) != @[]

    test "custom hybrid variants roundtrip":
      let receiverX = asymKeypair(kaX25519)
      let receiverK = asymKeypair(kaKyber1)
      let receiverM = asymKeypair(kaMcEliece2)
      var sendX: x25519SendM
      var openX: x25519OpenM
      var sendK: kyber1SendM
      var openK: kyber1OpenM
      var sendM: mceliece2SendM
      var openM: mceliece2OpenM
      for i in 0 ..< 32:
        sendX.receiverPublicKey[i] = receiverX.publicKey[i]
        openX.receiverSecretKey[i] = receiverX.secretKey[i]
      for i in 0 ..< 1568:
        sendK.receiverPublicKey[i] = receiverK.publicKey[i]
      for i in 0 ..< 3168:
        openK.receiverSecretKey[i] = receiverK.secretKey[i]
      for i in 0 ..< 1357824:
        sendM.receiverPublicKey[i] = receiverM.publicKey[i]
      for i in 0 ..< 14120:
        openM.receiverSecretKey[i] = receiverM.secretKey[i]
      let envX = seal(sendX)
      let envK = seal(sendK)
      let envM = seal(sendM)
      check open(envX, openX) == envX.sharedSecret
      check open(envK, openK) == envK.sharedSecret
      check open(envM, openM) == envM.sharedSecret
  else:
    test "hybrid kex unavailable raises descriptive error":
      expect LibraryUnavailableError:
        discard asymKeypair(kaKyber0)
