import std/unittest

import ../src/tyr_crypto
import ./helpers

suite "public api surface":
  test "top-level module exports final basic api and custom modules":
    var
      msg = toBytes("public surface")
      key = hexToBytes("4242424242424242424242424242424242424242424242424242424242424242")
      polyTag: seq[byte] = @[]
      blake: HashDigest32
      gimli: HashDigest32
      sha3Digest: seq[byte] = @[]
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

    blake = hash(msg, blake3HashM())
    gimli = hash(msg, gimliHashM())
    sha3Digest = hash(msg, sha3HashM(outLen: 32))
    check blake.len == 32
    check gimli.len == 32
    check sha3Digest.len == 32

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
      kp = asymKeypair(kaX25519)
      env = asymEnc(kaX25519, kp.publicKey)
      shared = asymDec(kaX25519, kp.secretKey, env)
      check shared == env.sharedSecret

      kp = asymKeypair(saEd25519)
      sig = asymSign(saEd25519, msg, kp.secretKey)
      check asymVerify(saEd25519, msg, sig, kp.publicKey)
