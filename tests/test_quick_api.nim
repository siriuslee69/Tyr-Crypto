import std/unittest

import ../src/protocols/wrapper/basic_api
import ../src/protocols/wrapper/helpers/algorithms
import ../src/protocols/wrapper/helpers/signature_support

suite "quick api":
  test "algorithm layouts expose single-algorithm metadata":
    let layout = layoutOf(akXChaCha20Cipher)
    check layout.operationKind == okCipher
    check layout.keyLayoutCount == 2'u8
    check layout.keyLayouts[0].size == 32
    check layout.keyLayouts[1].size == 24
    check layoutOf(akKyber0Send).keyLayouts[0].size == 1184
    check layoutOf(akKyber1Open).keyLayouts[0].size == 3168
    check layoutOf(akMcEliece1Send).keyLayouts[0].size == 1047319
    check layoutOf(akMcEliece2Open).keyLayouts[0].size == 14120
    check layoutOf(akFrodo0Send).keyLayouts[0].size == 15632
    check layoutOf(akFrodo0Send).outputBytes == 24
    check layoutOf(akDilithium0Sign).keyLayouts[0].size == 2560
    check layoutOf(akDilithium0Sign).outputBytes == 2420
    check layoutOf(akDilithium1Verify).keyLayouts[0].size == 1952
    check layoutOf(akDilithium1Verify).keyLayouts[1].size == 3309
    check layoutOf(akDilithium2Verify).keyLayouts[0].size == 2592
    check layoutOf(akDilithium2Verify).keyLayouts[1].size == 4627
    check layoutOf(akEd448Sign).keyLayouts[0].size == 57
    check layoutOf(akEd448Sign).outputBytes == 114
    check layoutOf(akSphincsHaraka128fSimpleSign).keyLayouts[0].size == 64
    check layoutOf(akSphincsHaraka128fSimpleSign).outputBytes == 17088
    check layoutOf(akNtruPrime0Send).keyLayouts[0].size == 1158
    check layoutOf(akNtruPrime0Open).keyLayouts[0].size == 1763
    check layoutOf(akBike0Send).keyLayouts[0].size == 1541
    check layoutOf(akBike0Open).keyLayouts[0].size == 5223

  test "message hash works with typed material":
    var
      blakeMat: blake3M
      message = @[9'u8, 8'u8, 7'u8]
    let digest = message.hash(blakeMat)
    check digest.len == 32

  test "message hmac works with typed material":
    var
      hmacMat: blake3hmacM
      authMat: blake3hmacVerifyM
      message = @[5'u8, 4'u8, 3'u8, 2'u8]
      tag: seq[byte]
    for i in 0 ..< 32:
      hmacMat.key[i] = uint8((90 + i) mod 256)
      authMat.key[i] = hmacMat.key[i]
    tag = message.hmac(hmacMat)
    authMat.tag = tag
    authMat.outLen = hmacMat.outLen
    check message.authenticate(authMat)

  test "single cipher encrypt decrypt works":
    var
      cipherMat: xchacha20cipherM
      message = @[11'u8, 22'u8, 33'u8, 44'u8]
      cipher: seq[byte]
    for i in 0 ..< 32:
      cipherMat.key[i] = uint8((15 + i) mod 256)
    for i in 0 ..< 24:
      cipherMat.nonce[i] = uint8((45 + i) mod 256)
    cipher = message.encrypt(cipherMat)
    check cipher.decrypt(cipherMat) == message

  when defined(hasLibsodium):
    test "message hash verify works with typed material":
      var
        blakeMat: blake3M
        verifyMat: ed25519VerifyM
        message = @[3'u8, 1'u8, 4'u8]
      let digest = message.hash(blakeMat)
      let kp = signatureKeypair(saEd25519)
      let sig = signMessage(saEd25519, @digest, kp.secretKey)
      for i in 0 ..< 32:
        verifyMat.publicKey[i] = kp.publicKey[i]
      for i in 0 ..< 64:
        verifyMat.signature[i] = sig[i]
      check digest.verify(verifyMat)

    test "single signature sign verify works":
      var
        blakeMat: blake3M
        signMat: ed25519SignM
        verifyMat: ed25519VerifyM
        message = @[7'u8, 6'u8, 5'u8]
        digest: HashDigest32
        signature: seq[byte]
      let kp = signatureKeypair(saEd25519)
      for i in 0 ..< 64:
        signMat.secretKey[i] = kp.secretKey[i]
      for i in 0 ..< 32:
        verifyMat.publicKey[i] = kp.publicKey[i]
      digest = message.hash(blakeMat)
      signature = digest.sign(signMat)
      for i in 0 ..< 64:
        verifyMat.signature[i] = signature[i]
      check digest.verify(verifyMat)

    test "single kem seal open works":
      var
        sendMat: x25519SendM
        openMat: x25519OpenM
      let kp = asymKeypair(kaX25519)
      for i in 0 ..< 32:
        sendMat.receiverPublicKey[i] = kp.publicKey[i]
        openMat.receiverSecretKey[i] = kp.secretKey[i]
      let env = seal(sendMat)
      let shared = open(env, openMat)
      check shared == env.sharedSecret
