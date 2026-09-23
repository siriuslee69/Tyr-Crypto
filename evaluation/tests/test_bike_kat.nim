## ---------------------------------------------------------------------
## | BIKE KAT <- BIKE-L1 against the published known answers           |
## ---------------------------------------------------------------------
##
## Record 0, built as `kem_kat_support.nim` describes. BIKE draws its
## randomness from the record generator in this order:
##
##   64 bytes  seed for h0, h1 || sigma  -----> keypair
##   64 bytes  m (first 32 used)         -----> encapsulation
##
## Tyr implements BIKE-L1 only, so BIKE-L3 and BIKE-L5 are not checked.

import std/unittest

import runePragmas
import ./kem_kat_support
import ../../src/tyr/kems/bike as custom_bike

proc bikeKatTranscript(v: custom_bike.BikeVariant): string {.role: {orchestrator}.} =
  ## v: which BIKE level. Returns record 0 in the response-file layout.
  var
    seed48: seq[byte] = kemKatRootSeed()
    rec = default(PqNistDrbgState)
    kp = default(custom_bike.BikeTyrKeypair)
    env = default(custom_bike.BikeTyrCipher)
  result.add("count = 0\n")
  appendKatField(result, "seed = ", seed48)
  rec = initNistDrbg(seed48)
  kp = custom_bike.bikeTyrKeypairDerand(v, nistDrbgRandomBytes(rec, 64))
  appendKatField(result, "pk = ", kp.publicKey)
  appendKatField(result, "sk = ", kp.secretKey)
  env = custom_bike.bikeTyrEncapsDerand(v, kp.publicKey, nistDrbgRandomBytes(rec, 64))
  appendKatField(result, "ct = ", env.ciphertext)
  appendKatField(result, "ss = ", env.sharedSecret)
  check custom_bike.bikeTyrDecaps(v, kp.secretKey, env.ciphertext) == env.sharedSecret

suite "bike kat":
  # {.testKind: tkRegression, covers: "bikeTyrKeypairDerand, bikeTyrEncapsDerand, bikeTyrDecaps".}
  test "BIKE-L1 single KAT hash matches the published corpus":
    check kemKatTranscriptHash(bikeKatTranscript(custom_bike.bikeL1)) ==
      kemKatExpectedHash("BIKE-L1")
