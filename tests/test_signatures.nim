import std/unittest
import ../src/protocols/wrapper/helpers/signature_support
import ../src/protocols/common
import ../src/protocols/wrapper/helpers/algorithms
import ../src/protocols/wrapper/basic_api

suite "signatures wrapper":
  test "ed25519 pure Nim wrapper roundtrip works without libsodium":
    check signatureAvailable(saEd25519)
    let kp = signatureKeypair(saEd25519)
    let msg = @[1'u8, 2'u8, 3'u8]
    let sig = signMessage(saEd25519, msg, kp.secretKey)
    check verifyMessage(saEd25519, msg, sig, kp.publicKey)

  test "ed25519 seeded keypairs are deterministic":
    let seed = @[0'u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
      16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]
    let kp0 = signatureKeypair(saEd25519, seed)
    let kp1 = signatureKeypair(saEd25519, seed)
    check kp0.publicKey == kp1.publicKey
    check kp0.secretKey == kp1.secretKey

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
    test "dilithium0 custom backend roundtrip works without liboqs":
      let kp = signatureKeypair(saDilithium0)
      let msg = @[4'u8, 5'u8]
      let sig = signMessage(saDilithium0, msg, kp.secretKey)
      check verifyMessage(saDilithium0, msg, sig, kp.publicKey)

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
      falVerifyM.signature = falSig
      check digest.verify(edVerifyM)
      check digest.verify(falVerifyM)
  else:
    test "ed25519 + falcon hybrid custom backend roundtrip works without external libs":
      let kp = signatureKeypair(saEd25519Falcon512Hybrid)
      let msg = @[9'u8, 8'u8, 7'u8, 6'u8]
      let sig = signMessage(saEd25519Falcon512Hybrid, msg, kp.secretKey)
      check verifyMessage(saEd25519Falcon512Hybrid, msg, sig, kp.publicKey)
