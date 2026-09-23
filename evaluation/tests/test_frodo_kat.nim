## ---------------------------------------------------------------------
## | Frodo KAT <- unsalted FrodoKEM against the published known answers |
## ---------------------------------------------------------------------
##
## Record 0 of each variant, built as `kem_kat_support.nim` describes.
## Frodo draws its randomness from the record generator in this order:
##
##   keypairRandomBytes  (s || seedSE || z)  -----> keypair
##   encapsRandomBytes   (mu)                -----> encapsulation
##
##   variant      keypair  encaps
##   640          48       16
##   976          64       24
##   1344         80       32
##
## Tyr implements the unsalted FrodoKEM (9720-byte ciphertext at 640).
## liboqs 0.16 lists that as `eFrodoKEM-*`; its plain `FrodoKEM-*` is the
## salted ISO version and is not expected to match.

import std/unittest

import runePragmas
import ./kem_kat_support
import ../../src/tyr/kems/frodo as custom_frodo

const
  frodoKatNames: array[custom_frodo.FrodoVariant, string] = [
    custom_frodo.frodo640aes: "eFrodoKEM-640-AES",
    custom_frodo.frodo640shake: "eFrodoKEM-640-SHAKE",
    custom_frodo.frodo976aes: "eFrodoKEM-976-AES",
    custom_frodo.frodo976shake: "eFrodoKEM-976-SHAKE",
    custom_frodo.frodo1344aes: "eFrodoKEM-1344-AES",
    custom_frodo.frodo1344shake: "eFrodoKEM-1344-SHAKE"
  ]

proc frodoKatTranscript(v: custom_frodo.FrodoVariant): string {.role: {orchestrator}.} =
  ## v: which Frodo variant. Returns record 0 in the response-file layout.
  var
    p: custom_frodo.FrodoParams = params(v)
    seed48: seq[byte] = kemKatRootSeed()
    rec = default(PqNistDrbgState)
    kp = default(custom_frodo.FrodoTyrKeypair)
    env = default(custom_frodo.FrodoTyrCipher)
  result.add("count = 0\n")
  appendKatField(result, "seed = ", seed48)
  rec = initNistDrbg(seed48)
  kp = custom_frodo.frodoTyrKeypairDerand(v, nistDrbgRandomBytes(rec, p.keypairRandomBytes))
  appendKatField(result, "pk = ", kp.publicKey)
  appendKatField(result, "sk = ", kp.secretKey)
  env = custom_frodo.frodoTyrEncapsDerand(v, kp.publicKey,
    nistDrbgRandomBytes(rec, p.encapsRandomBytes))
  appendKatField(result, "ct = ", env.ciphertext)
  appendKatField(result, "ss = ", env.sharedSecret)
  check custom_frodo.frodoTyrDecaps(v, kp.secretKey, env.ciphertext) == env.sharedSecret

suite "frodo kat":
  for v in custom_frodo.FrodoVariant:
    # {.testKind: tkRegression, covers: "frodoTyrKeypairDerand, frodoTyrEncapsDerand, frodoTyrDecaps".}
    test frodoKatNames[v] & " single KAT hash matches the published corpus":
      check kemKatTranscriptHash(frodoKatTranscript(v)) == kemKatExpectedHash(frodoKatNames[v])
