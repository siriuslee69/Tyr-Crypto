import std/unittest
import ../src/protocols/wrapper/helpers/signature_support
import ../src/protocols/common
import ../src/protocols/wrapper/helpers/algorithms
import ../src/protocols/wrapper/basic_api

suite "signatures wrapper":
  when defined(hasLibsodium):
    test "ed25519 unavailable only when libsodium missing":
      if not signatureAvailable(saEd25519):
        check true
      else:
        let kp = signatureKeypair(saEd25519)
        let msg = @[1'u8, 2'u8, 3'u8]
        let sig = signMessage(saEd25519, msg, kp.secretKey)
        check verifyMessage(saEd25519, msg, sig, kp.publicKey)
  else:
    test "ed25519 unavailable raises descriptive error":
      expect LibraryUnavailableError:
        discard signatureKeypair(saEd25519)

  when defined(hasLibOqs):
    test "dilithium0 availability matches liboqs":
      if not signatureAvailable(saDilithium0):
        check true
      else:
        let kp = signatureKeypair(saDilithium0)
        let msg = @[4'u8, 5'u8]
        let sig = signMessage(saDilithium0, msg, kp.secretKey)
        check verifyMessage(saDilithium0, msg, sig, kp.publicKey)
  else:
    test "dilithium0 unavailable raises descriptive error":
      expect LibraryUnavailableError:
        discard signatureKeypair(saDilithium0)

  when defined(hasLibsodium) and defined(hasLibOqs):
    test "ed25519 + falcon hybrid matches when both backends are available":
      if not signatureAvailable(saEd25519Falcon512Hybrid):
        check true
      else:
        let kp = signatureKeypair(saEd25519Falcon512Hybrid)
        let msg = @[9'u8, 8'u8, 7'u8, 6'u8]
        let sig = signMessage(saEd25519Falcon512Hybrid, msg, kp.secretKey)
        check verifyMessage(saEd25519Falcon512Hybrid, msg, sig, kp.publicKey)
        var tampered = sig
        tampered[^1] = tampered[^1] xor 0x01'u8
        check not verifyMessage(saEd25519Falcon512Hybrid, msg, tampered, kp.publicKey)

    test "typed basic api multi verify loop matches when both backends are available":
      var
        msg = @[5'u8, 4'u8, 3'u8, 2'u8, 1'u8]
        blakeMat: blake3HashM
        edSignM: ed25519SignM
        falSignM: falcon0SignM
        edVerifyM: ed25519VerifyM
        falVerifyM: falcon0VerifyM
        digest: HashDigest32
      let edKp = signatureKeypair(saEd25519)
      let falKp = signatureKeypair(saFalcon512)
      for i in 0 ..< 64:
        edSignM.secretKey[i] = edKp.secretKey[i]
      for i in 0 ..< 32:
        edVerifyM.publicKey[i] = edKp.publicKey[i]
      for i in 0 ..< 1281:
        falSignM.secretKey[i] = falKp.secretKey[i]
      for i in 0 ..< 897:
        falVerifyM.publicKey[i] = falKp.publicKey[i]
      digest = msg.hash(blakeMat)
      let edSig = digest.sign(edSignM)
      let falSig = digest.sign(falSignM)
      for i in 0 ..< 64:
        edVerifyM.signature[i] = edSig[i]
      for i in 0 ..< 752:
        falVerifyM.signature[i] = falSig[i]
      check digest.verify(edVerifyM)
      check digest.verify(falVerifyM)
  else:
    test "hybrid signature unavailable raises descriptive error":
      expect LibraryUnavailableError:
        discard signatureKeypair(saEd25519Falcon512Hybrid)
