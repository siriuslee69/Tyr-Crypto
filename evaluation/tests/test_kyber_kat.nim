## ---------------------------------------------------------------------
## | Kyber KAT <- round-3 Kyber against the published known answers    |
## ---------------------------------------------------------------------
##
## Record 0 of each size, built as `kem_kat_support.nim` describes.
## Kyber draws its randomness from the record generator in this order:
##
##   32 bytes  indcpa seed  --+
##   32 bytes  z            --+--> keypair
##   32 bytes  m            -----> encapsulation
##
## The list names are `Kyber512/768/1024`. Those are round-3 Kyber, which
## is what Tyr implements; `ML-KEM-*` is the FIPS 203 transcript and is
## not expected to match.

import std/unittest

import runePragmas
import ./kem_kat_support
import ../../src/tyr/kems/kyber as custom_kyber

proc kyberKatTranscript(v: custom_kyber.KyberVariant): string {.role: {orchestrator}.} =
  ## v: which Kyber size. Returns record 0 in the response-file layout.
  var
    seed48: seq[byte] = kemKatRootSeed()
    rec = default(PqNistDrbgState)
    indcpaSeed: seq[byte] = @[]
    zSeed: seq[byte] = @[]
    kp = default(custom_kyber.KyberTyrKeypair)
    env = default(custom_kyber.KyberTyrCipher)
  result.add("count = 0\n")
  appendKatField(result, "seed = ", seed48)
  rec = initNistDrbg(seed48)
  indcpaSeed = nistDrbgRandomBytes(rec, 32)
  zSeed = nistDrbgRandomBytes(rec, 32)
  kp = custom_kyber.kyberTyrKeypairFromParts(v, indcpaSeed, zSeed)
  appendKatField(result, "pk = ", kp.publicKey)
  appendKatField(result, "sk = ", kp.secretKey)
  env = custom_kyber.kyberTyrEncaps(v, kp.publicKey, nistDrbgRandomBytes(rec, 32))
  appendKatField(result, "ct = ", env.ciphertext)
  appendKatField(result, "ss = ", env.sharedSecret)
  check custom_kyber.kyberTyrDecaps(v, kp.secretKey, env.ciphertext) == env.sharedSecret

suite "kyber kat":
  # {.testKind: tkRegression, covers: "kyberTyrKeypairFromParts, kyberTyrEncaps, kyberTyrDecaps".}
  test "Kyber512 single KAT hash matches the published corpus":
    check kemKatTranscriptHash(kyberKatTranscript(custom_kyber.kyber512)) ==
      kemKatExpectedHash("Kyber512")

  # {.testKind: tkRegression, covers: "kyberTyrKeypairFromParts, kyberTyrEncaps, kyberTyrDecaps".}
  test "Kyber768 single KAT hash matches the published corpus":
    check kemKatTranscriptHash(kyberKatTranscript(custom_kyber.kyber768)) ==
      kemKatExpectedHash("Kyber768")

  # {.testKind: tkRegression, covers: "kyberTyrKeypairFromParts, kyberTyrEncaps, kyberTyrDecaps".}
  test "Kyber1024 single KAT hash matches the published corpus":
    check kemKatTranscriptHash(kyberKatTranscript(custom_kyber.kyber1024)) ==
      kemKatExpectedHash("Kyber1024")
