## -----------------------------------------------------------------------
## Classical Asymmetric Boundaries <- RSA encodings and P-256 scalar ranges
## -----------------------------------------------------------------------

import std/unittest

import ../../src/tyr/helpers/bigint
import ../../src/tyr/signatures/ecdsa_p256
import ../../src/tyr/certs/rsa

proc identityRsaKeys(e: uint32 = 1'u32): tuple[
    publicKey: RsaPublicKey, privateKey: RsaPrivateKey] =
  var
    modulus: seq[byte] = newSeq[byte](128)
    i: int = 0
  while i < modulus.len:
    modulus[i] = 0xff'u8
    i = i + 1
  result.publicKey.n = bigFromBytesBe(modulus)
  result.publicKey.e = bigFromUint32(e)
  result.publicKey.bits = 1024
  result.privateKey.n = result.publicKey.n
  result.privateKey.e = result.publicKey.e
  result.privateKey.d = bigFromUint32(1'u32)
  result.privateKey.bits = 1024
  result.privateKey.hasCrt = false

suite "classical asymmetric boundaries":
  test "RSA PKCS1 verification rejects representative and padding boundaries":
    var
      K = identityRsaKeys()
      msg: seq[byte] = @[1'u8, 2, 3, 4]
      signed: RsaSignResult = rsaSignPkcs1v15Sha256(K.privateKey, msg)
      changed, shortSig, longSig: seq[byte] = @[]
      zeroSig: seq[byte] = newSeq[byte](128)
      oneSig: seq[byte] = newSeq[byte](128)
      nMinusOne: seq[byte] = newSeq[byte](128)
      nValue: seq[byte] = newSeq[byte](128)
      i: int = 0
    check signed.ok
    check rsaVerifyPkcs1v15Sha256(K.publicKey, msg, signed.signature)
    oneSig[^1] = 1'u8
    while i < nValue.len:
      nValue[i] = 0xff'u8
      nMinusOne[i] = 0xff'u8
      i = i + 1
    nMinusOne[^1] = 0xfe'u8
    check not rsaVerifyPkcs1v15Sha256(K.publicKey, msg, zeroSig)
    check not rsaVerifyPkcs1v15Sha256(K.publicKey, msg, oneSig)
    check not rsaVerifyPkcs1v15Sha256(K.publicKey, msg, nMinusOne)
    check not rsaVerifyPkcs1v15Sha256(K.publicKey, msg, nValue)
    shortSig = signed.signature[1 .. ^1]
    longSig = @[0'u8]
    longSig.add(signed.signature)
    check not rsaVerifyPkcs1v15Sha256(K.publicKey, msg, shortSig)
    check not rsaVerifyPkcs1v15Sha256(K.publicKey, msg, longSig)
    changed = signed.signature
    changed[10] = changed[10] xor 1'u8
    check not rsaVerifyPkcs1v15Sha256(K.publicKey, msg, changed)

  test "RSA PSS rejects forbidden top bits and invalid salt lengths":
    var
      K = identityRsaKeys()
      msg: seq[byte] = @[9'u8, 8, 7, 6]
      signed: RsaSignResult = rsaSignPssSha256(K.privateKey, msg, 0)
      forbidden: seq[byte] = @[]
      negative: RsaSignResult
    check signed.ok
    check rsaVerifyPssSha256(K.publicKey, msg, signed.signature, 0)
    forbidden = signed.signature
    forbidden[0] = forbidden[0] or 0x80'u8
    check not rsaVerifyPssSha256(K.publicKey, msg, forbidden, 0)
    check not rsaVerifyPssSha256(K.publicKey, msg, signed.signature, -1)
    negative = rsaSignPssSha256(K.privateKey, msg, -1)
    check not negative.ok
    expect ValueError:
      discard mgf1Sha256(@[], -1)

  test "RSA private operation self-check rejects an inconsistent exponent":
    var
      K = identityRsaKeys(3'u32)
      signed: RsaSignResult = rsaSignPkcs1v15Sha256(K.privateKey, @[1'u8])
    check not signed.ok

  test "P-256 rejects private scalar and signature range boundaries":
    var
      one: BigInt = bigFromUint32(1'u32)
      zero: BigInt = bigZero()
      msg: seq[byte] = @[4'u8, 5, 6]
      pub: P256AffinePoint = p256PublicFromScalar(one)
      signed: EcdsaSignResult = ecdsaSignP256(one, msg)
      changed: EcdsaSignature
      invalidPub: P256AffinePoint
    check pub.x == p256Gx
    check pub.y == p256Gy
    check signed.ok
    check ecdsaVerifyP256(pub, msg, signed.signature)
    changed = signed.signature
    changed.r = zero
    check not ecdsaVerifyP256(pub, msg, changed)
    changed = signed.signature
    changed.s = zero
    check not ecdsaVerifyP256(pub, msg, changed)
    changed = signed.signature
    changed.r = p256N
    check not ecdsaVerifyP256(pub, msg, changed)
    changed = signed.signature
    changed.s = p256N
    check not ecdsaVerifyP256(pub, msg, changed)
    invalidPub.infinity = true
    check not ecdsaVerifyP256(invalidPub, msg, signed.signature)
    invalidPub.infinity = false
    invalidPub.x = p256P
    invalidPub.y = zero
    check not ecdsaVerifyP256(invalidPub, msg, signed.signature)
    expect ValueError:
      discard p256PublicFromScalar(zero)
    expect ValueError:
      discard p256PublicFromScalar(p256N)
    check not p256Ecdh(zero, pub).ok
    check not p256Ecdh(p256N, pub).ok
