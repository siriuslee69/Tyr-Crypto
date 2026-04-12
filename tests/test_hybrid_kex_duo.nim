import std/unittest
import ../src/protocols/wrapper/helpers/algorithms
import ../src/protocols/common
import ../src/protocols/wrapper/basic_api

suite "multi kex duo":
  when defined(hasLibOqs) and defined(hasLibsodium):
    test "Kyber + X25519 shared secrets match via quick api":
      let receiverX = asymKeypair(kaX25519)
      let receiverK = asymKeypair(kaKyber0)
      var sendX: x25519SendM
      var openX: x25519OpenM
      var sendK: kyber0SendM
      var openK: kyber0OpenM
      for i in 0 ..< 32:
        sendX.receiverPublicKey[i] = receiverX.publicKey[i]
        openX.receiverSecretKey[i] = receiverX.secretKey[i]
      for i in 0 ..< 1184:
        sendK.receiverPublicKey[i] = receiverK.publicKey[i]
      for i in 0 ..< 2400:
        openK.receiverSecretKey[i] = receiverK.secretKey[i]
      let envs = seal(sendX, sendK)
      let shareds = open(envs, openX, openK)
      check shareds[0] == envs[0].sharedSecret
      check shareds[1] == envs[1].sharedSecret
      check shareds[0].len == 32
      check shareds[1].len == 32

    test "Kyber + X25519 can still be composed without helper suites":
      let receiverX = asymKeypair(kaX25519)
      let receiverK = asymKeypair(kaKyber0)
      var sendX: x25519SendM
      var openX: x25519OpenM
      var sendK: kyber0SendM
      var openK: kyber0OpenM
      for i in 0 ..< 32:
        sendX.receiverPublicKey[i] = receiverX.publicKey[i]
        openX.receiverSecretKey[i] = receiverX.secretKey[i]
      for i in 0 ..< 1184:
        sendK.receiverPublicKey[i] = receiverK.publicKey[i]
      for i in 0 ..< 2400:
        openK.receiverSecretKey[i] = receiverK.secretKey[i]
      let envX = seal(sendX)
      let envK = seal(sendK)
      check open(envX, openX) == envX.sharedSecret
      check open(envK, openK) == envK.sharedSecret

    test "Kyber1024 + X25519 shared secrets match":
      let receiverX = asymKeypair(kaX25519)
      let receiverK = asymKeypair(kaKyber1)
      var sendX: x25519SendM
      var openX: x25519OpenM
      var sendK: kyber1SendM
      var openK: kyber1OpenM
      for i in 0 ..< 32:
        sendX.receiverPublicKey[i] = receiverX.publicKey[i]
        openX.receiverSecretKey[i] = receiverX.secretKey[i]
      for i in 0 ..< 1568:
        sendK.receiverPublicKey[i] = receiverK.publicKey[i]
      for i in 0 ..< 3168:
        openK.receiverSecretKey[i] = receiverK.secretKey[i]
      let envs = seal(sendX, sendK)
      let shareds = open(envs, openX, openK)
      check shareds[0] == envs[0].sharedSecret
      check shareds[1] == envs[1].sharedSecret

    test "McEliece + X25519 shared secrets match":
      let receiverX = asymKeypair(kaX25519)
      let receiverM = asymKeypair(kaMcEliece0)
      var sendX: x25519SendM
      var openX: x25519OpenM
      var sendM: mceliece0SendM
      var openM: mceliece0OpenM
      for i in 0 ..< 32:
        sendX.receiverPublicKey[i] = receiverX.publicKey[i]
        openX.receiverSecretKey[i] = receiverX.secretKey[i]
      for i in 0 ..< 1044992:
        sendM.receiverPublicKey[i] = receiverM.publicKey[i]
      for i in 0 ..< 13932:
        openM.receiverSecretKey[i] = receiverM.secretKey[i]
      let envs = seal(sendX, sendM)
      let shareds = open(envs, openX, openM)
      check shareds[0] == envs[0].sharedSecret
      check shareds[1] == envs[1].sharedSecret

    test "alternate McEliece variant can be selected":
      let receiverX = asymKeypair(kaX25519)
      let receiverM = asymKeypair(kaMcEliece1)
      var sendX: x25519SendM
      var openX: x25519OpenM
      var sendM: mceliece1SendM
      var openM: mceliece1OpenM
      for i in 0 ..< 32:
        sendX.receiverPublicKey[i] = receiverX.publicKey[i]
        openX.receiverSecretKey[i] = receiverX.secretKey[i]
      for i in 0 ..< 1047319:
        sendM.receiverPublicKey[i] = receiverM.publicKey[i]
      for i in 0 ..< 13948:
        openM.receiverSecretKey[i] = receiverM.secretKey[i]
      let envs = seal(sendX, sendM)
      let shareds = open(envs, openX, openM)
      check shareds[0] == envs[0].sharedSecret
      check shareds[1] == envs[1].sharedSecret
  else:
    test "hybrid kex unavailable raises descriptive error":
      expect LibraryUnavailableError:
        discard asymKeypair(kaKyber0)
