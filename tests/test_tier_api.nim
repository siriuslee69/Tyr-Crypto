## ---------------------------------------------------------------------
## | Tier API Tests <- the four call layers must agree with each other   |
## ---------------------------------------------------------------------
##
## Every module offers the same four ways to reach an algorithm:
##
##   default    digest(hfBlake3, data)        overload / family value
##   single     digestSingle(hfBlake3, data)  compile-time choice
##   dynamic    digestOf(hfBlake3, data)      runtime choice
##   direct     blake3Hash(data)              one algorithm by name
##
## Three of those are new surfaces over the fourth. If they ever disagree
## a caller gets different bytes depending only on which import they
## reached for, which is the worst kind of bug to find in production. This
## file pins them together, and covers the `types.nim` helpers that
## nothing else touched.

import std/unittest

import ../src/tyr/hashes
import ../src/tyr/hashes/dynamic as hashDyn
import ../src/tyr/hashes/single as hashSingle
import ../src/tyr/macs
import ../src/tyr/macs/dynamic as macDyn
import ../src/tyr/macs/single as macSingle
import ../src/tyr/kdfs
import ../src/tyr/kdfs/dynamic as kdfDyn
import ../src/tyr/kdfs/single as kdfSingle
import ../src/tyr/ciphers
import ../src/tyr/ciphers/single as cipherSingle
import ../src/tyr/kems
import ../src/tyr/kems/dynamic as kemDyn
import ../src/tyr/kems/single as kemSingle
import ../src/tyr/signatures
import ../src/tyr/signatures/dynamic as sigDyn

proc fill(n: int, seed: int): seq[byte] =
  var i: int = 0
  result = newSeq[byte](n)
  while i < n:
    result[i] = byte((i * 37 + seed * 11 + 3) and 0xff)
    i = i + 1

let
  key = fill(32, 1)
  msg = fill(128, 2)
  salt = fill(16, 3)

suite "hash tiers":

  test "default, dynamic and single agree for every family":
    for f in HashFamily:
      check digest(f, msg) == hashDyn.digestOf(f, msg)
    ## `single` needs a compile-time value, so each is named explicitly.
    check hashSingle.digestSingle(hfBlake3, msg) == digest(hfBlake3, msg)
    check hashSingle.digestSingle(hfSha256, msg) == digest(hfSha256, msg)
    check hashSingle.digestSingle(hfSha512, msg) == digest(hfSha512, msg)
    check hashSingle.digestSingle(hfSha3, msg) == digest(hfSha3, msg)

  test "the tiers agree with calling the algorithm directly":
    check digest(hfBlake3, msg) == blake3Hash(msg, 32)
    check digest(hfSha3, msg) == sha3Hash(msg, 32)
    check digest(hfSha256, msg) == @(sha256Hash(msg))
    check digest(hfSha512, msg) == @(sha512Hash(msg))

  test "natural digest lengths are what the table declares":
    for f in HashFamily:
      check digest(f, msg).len == defaultDigestBytes[f]
    check defaultDigestBytes[hfSha512] == 64

  test "a requested length is honoured where the family allows it":
    check digest(hfBlake3, msg, 64).len == 64
    check digest(hfSha3, msg, 64).len == 64

  test "names survive a write-then-read trip":
    for f in HashFamily:
      check parseHashFamily(familyName(f)) == f
    expect ValueError:
      discard parseHashFamily("no-such-hash")

  test "the public Tyr names reach the same code":
    check blake3TyrHash(msg) == blake3Hash(msg)
    check sha3TyrHash(msg) == sha3Hash(msg)
    check blake3TyrKeyedHash(key, msg) == blake3KeyedHash(key, msg)

suite "mac tiers":

  test "default, dynamic and single agree for every family":
    for f in MacFamily:
      check mac(f, key, msg) == macDyn.macOf(f, key, msg)
    check macSingle.macSingle(mfBlake3Keyed, key, msg) == mac(mfBlake3Keyed, key, msg)
    check macSingle.macSingle(mfGimli, key, msg) == mac(mfGimli, key, msg)
    check macSingle.macSingle(mfPoly1305, key, msg) == mac(mfPoly1305, key, msg)
    check macSingle.macSingle(mfHmacSha3, key, msg) == mac(mfHmacSha3, key, msg)

  test "a tag verifies and a changed message does not":
    var altered = fill(128, 2)
    altered[5] = altered[5] xor 0x01'u8
    for f in MacFamily:
      var tag = mac(f, key, msg)
      check macVerify(tag, mac(f, key, msg))
      check not macVerify(tag, mac(f, key, altered))

  test "only Poly1305 reports as one-time, and it ignores outLen":
    for f in MacFamily:
      check isOneTime(f) == (f == mfPoly1305)
    check mac(mfPoly1305, key, msg, 32).len == 16

  test "names survive a write-then-read trip":
    for f in MacFamily:
      check parseMacFamily(familyName(f)) == f
    expect ValueError:
      discard parseMacFamily("no-such-mac")

suite "kdf tiers":

  test "default, dynamic and single agree for every family":
    ## Argon2 cost knobs are kept tiny so this stays a correctness test
    ## rather than a benchmark.
    for f in KdfFamily:
      check deriveKey(f, key, salt, 32, 1, 64, 1) ==
        kdfDyn.deriveKeyOf(f, key, salt, 32, 1, 64, 1)
    check kdfSingle.deriveKeySingle(kdfArgon2i, key, salt, 32, 1, 64, 1) ==
      deriveKey(kdfArgon2i, key, salt, 32, 1, 64, 1)
    check kdfSingle.deriveKeySingle(kdfArgon2id, key, salt, 32, 1, 64, 1) ==
      deriveKey(kdfArgon2id, key, salt, 32, 1, 64, 1)
    check kdfSingle.deriveKeySingle(kdfBlake3Gimli, key, salt, 32, 1, 64, 1) ==
      deriveKey(kdfBlake3Gimli, key, salt, 32, 1, 64, 1)
    check kdfSingle.deriveKeySingle(kdfCustom, key, salt, 32, 1, 64, 1) ==
      deriveKey(kdfCustom, key, salt, 32, 1, 64, 1)

  test "derivation is deterministic and salt-separated":
    var other = fill(16, 99)
    for f in KdfFamily:
      var a = deriveKey(f, key, salt, 32, 1, 64, 1)
      check a == deriveKey(f, key, salt, 32, 1, 64, 1)
      check a.len == 32
      ## kdfCustom ignores the salt by construction; the rest must not.
      if f != kdfCustom:
        check a != deriveKey(f, key, other, 32, 1, 64, 1)

  test "a different secret gives a different key":
    var other = fill(32, 77)
    for f in KdfFamily:
      check deriveKey(f, key, salt, 32, 1, 64, 1) !=
        deriveKey(f, other, salt, 32, 1, 64, 1)

  test "only the Argon2 families are password-safe":
    for f in KdfFamily:
      check isPasswordSafe(f) == (f in {kdfArgon2i, kdfArgon2id})

  test "names survive a write-then-read trip":
    for f in KdfFamily:
      check parseKdfFamily(familyName(f)) == f
    expect ValueError:
      discard parseKdfFamily("no-such-kdf")

suite "cipher tiers":

  test "default and single agree for every family":
    for f in CipherFamily:
      var n = fill(nonceBytes(f), 4)
      check encrypt(f, key, n, msg) == decrypt(f, key, n, encrypt(f, key, n,
        encrypt(f, key, n, msg)))
    check cipherSingle.encryptSingle(cfXChaCha20, key, fill(24, 4), msg) ==
      encrypt(cfXChaCha20, key, fill(24, 4), msg)
    check cipherSingle.encryptSingle(cfChaCha20, key, fill(12, 4), msg) ==
      encrypt(cfChaCha20, key, fill(12, 4), msg)
    check cipherSingle.encryptSingle(cfAesCtr, key, fill(16, 4), msg) ==
      encrypt(cfAesCtr, key, fill(16, 4), msg)
    check cipherSingle.encryptSingle(cfGimliStream, key, fill(24, 4), msg) ==
      encrypt(cfGimliStream, key, fill(24, 4), msg)

  test "decryptSingle undoes encryptSingle":
    check cipherSingle.decryptSingle(cfXChaCha20, key, fill(24, 4),
      cipherSingle.encryptSingle(cfXChaCha20, key, fill(24, 4), msg)) == msg

suite "kem tiers":

  test "default, dynamic and single produce interoperable keys":
    ## Kyber is used as the representative family: it is the fastest, and
    ## the tier plumbing is identical for the rest.
    var
      viaDefault = keypair(kyber768)
      viaSingle = kemSingle.keypairSingle(kfKyber)
      viaDynamic = kemDyn.keypairOf(AnyKem(family: kfKyber, kyber: kyber768))
    check viaDefault.public.len == viaSingle.public.len
    check viaDefault.public.len == viaDynamic.public.len
    check viaDefault.family == kfKyber
    check viaSingle.family == kfKyber
    check viaDynamic.family == kfKyber
    ## A ciphertext made through one tier opens through another.
    var c = encaps(kyber768, viaDynamic.public)
    check kemDyn.decapsOf(AnyKem(family: kfKyber, kyber: kyber768),
      viaDynamic.secret, c.ciphertext) == c.shared
    check decaps(kyber768, viaDynamic.secret, c.ciphertext) == c.shared

  test "a seeded keypair is reproducible":
    var seed = fill(32, 8)
    check keypair(kyber768, seed).public == keypair(kyber768, seed).public

  test "names survive a write-then-read trip":
    for f in KemFamily:
      check parseKemFamily(familyName(f)) == f
    expect ValueError:
      discard parseKemFamily("no-such-kem")

suite "signature tiers":

  test "default and dynamic produce interoperable signatures":
    var
      viaDefault = keypair(dilithium65)
      viaDynamic = sigDyn.keypairOf(AnySig(family: sfDilithium,
        dilithium: dilithium65))
    check viaDefault.public.len == viaDynamic.public.len
    var sig = sign(dilithium65, msg, viaDynamic.secret)
    check verify(dilithium65, msg, sig, viaDynamic.public)
    check sigDyn.verifyOf(AnySig(family: sfDilithium, dilithium: dilithium65),
      msg, sig, viaDynamic.public)

  test "a changed message fails verification":
    var
      kp = keypair(dilithium65)
      sig = sign(dilithium65, msg, kp.secret)
      altered = fill(128, 2)
    altered[9] = altered[9] xor 0x01'u8
    check verify(dilithium65, msg, sig, kp.public)
    check not verify(dilithium65, altered, sig, kp.public)

  test "names survive a write-then-read trip":
    for f in SigFamily:
      check parseSigFamily(familyName(f)) == f
    expect ValueError:
      discard parseSigFamily("no-such-signature")
