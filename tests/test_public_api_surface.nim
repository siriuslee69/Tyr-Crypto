import std/unittest

import ../src/tyr_crypto
import ./helpers

suite "public api surface":
  test "top-level module exports final basic api and custom modules":
    var
      msg = toBytes("public surface")
      key = hexToBytes("4242424242424242424242424242424242424242424242424242424242424242")
      polyTag: seq[byte] = @[]
      chaKey: seq[byte] = @[]
      chaNonce: seq[byte] = @[]
      chaCipher: seq[byte] = @[]
      blake: HashDigest32
      gimli: HashDigest32
      sha3Digest: seq[byte] = @[]
      argonParams: Argon2Params
      argonSalt: seq[byte] = @[]
      argonBlock: seq[byte] = @[]
      kdfBlock: seq[byte] = @[]
      kyberKp: KyberTyrKeypair
      kyberEnv: KyberTyrCipher
      kyberShared: seq[byte] = @[]
      diliKp: DilithiumTyrKeypair
      diliSig: seq[byte] = @[]
      sphincsKp: SphincsTyrKeypair
      sphincsSig: seq[byte] = @[]
    polyTag = hmacCreate(maPoly1305, key, msg, 16)
    check polyTag.len == 16
    check hmacAuth(maPoly1305, key, msg, polyTag, 16)
    chaKey = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    chaNonce = hexToBytes("000000090000004a00000000")
    chaCipher = chacha20TyrXor(chaKey, chaNonce, msg)
    check chacha20TyrXor(chaKey, chaNonce, chaCipher) == msg

    blake = hash(msg, blake3HashM())
    gimli = hash(msg, gimliHashM())
    sha3Digest = hash(msg, sha3HashM(outLen: 32))
    check blake.len == 32
    check gimli.len == 32
    check sha3Digest.len == 32
    argonParams = initArgon2Params(2, 4096, 1, 32)
    argonSalt = toBytes(">A 16-bytes salt")
    argonBlock = argon2idHash(msg, argonSalt, argonParams)
    check argonBlock.len == 32
    kdfBlock = deriveCustomKdf(msg, ckaGimli, 1, 512, 2, 8)
    check kdfBlock.len == 8

    kyberKp = kyberTyrKeypair(kyber768)
    kyberEnv = kyberTyrEncaps(kyber768, kyberKp.publicKey)
    kyberShared = kyberTyrDecaps(kyber768, kyberKp.secretKey, kyberEnv.ciphertext)
    check kyberShared == kyberEnv.sharedSecret

    diliKp = dilithiumTyrKeypair(dilithium65)
    diliSig = dilithiumTyrSign(dilithium65, msg, diliKp.secretKey)
    check dilithiumTyrVerify(dilithium65, msg, diliSig, diliKp.publicKey)

    sphincsKp = sphincsTyrKeypair(sphincsShake128fSimple)
    sphincsSig = sphincsTyrSign(sphincsShake128fSimple, msg, sphincsKp.secretKey)
    check sphincsTyrVerify(sphincsShake128fSimple, msg, sphincsSig, sphincsKp.publicKey)

  when defined(hasLibsodium):
    test "top-level module exports standard basic_api dispatch":
      var
        msg = toBytes("public surface standard dispatch")
        kp: AsymKeypair
        env: AsymCipher
        shared: seq[byte] = @[]
        sig: seq[byte] = @[]
      kp = genKeypair(kaX25519)
      env = encaps(kaX25519, kp.publicKey)
      shared = decaps(kaX25519, kp.secretKey, env)
      check shared == env.sharedSecret

      kp = genKeypair(saEd25519)
      sig = sign(saEd25519, msg, kp.secretKey)
      check verify(saEd25519, msg, sig, kp.publicKey)

  test "seeded Falcon and Dilithium wrapper keypairs are stable":
    var
      seedFalcon: seq[byte] = toBytes("falcon-seed-stable-0001")
      seedDili: seq[byte] = newSeq[byte](32)
      falcon0: AsymKeypair
      falcon1: AsymKeypair
      dili0: AsymKeypair
      dili1: AsymKeypair
      i: int = 0
    while i < seedDili.len:
      seedDili[i] = byte(i)
      i = i + 1
    falcon0 = genKeypair(saFalcon512, seedFalcon)
    falcon1 = genKeypair(saFalcon512, seedFalcon)
    check falcon0.publicKey == falcon1.publicKey
    check falcon0.secretKey == falcon1.secretKey
    dili0 = genKeypair(saDilithium1, seedDili)
    dili1 = genKeypair(saDilithium1, seedDili)
    check dili0.publicKey == dili1.publicKey
    check dili0.secretKey == dili1.secretKey
