## ---------------------------------------------------------------------
## | HQC Operations <- the key exchange built on top of the encryption  |
## ---------------------------------------------------------------------
##
## From encryption to key exchange
## -------------------------------
## The encryption underneath is only safe against somebody who watches.
## It is not safe against somebody who sends deliberately damaged
## ciphertexts and studies the answers. The wrapper here closes that gap
## with three moves:
##
##   1. Never encrypt a chosen message. Encrypt a fresh random one and
##      hash it into the shared secret.
##   2. Derive the encryption randomness from that message, so one
##      message can only ever produce one ciphertext.
##   3. On decryption, re-encrypt what came out and check it matches. If
##      it does not, hand back a key derived from a stored secret
##      instead of reporting an error.
##
## Move 3 is what "implicit rejection" means. A wrong ciphertext still
## yields 32 bytes that look perfectly normal, so an attacker learns
## nothing from the reply:
##
##   valid ciphertext    ->  K  = G(H(pk), m, salt)
##   invalid ciphertext  ->  K' = J(H(pk), sigma, ciphertext)
##                                        ^^^^^ only the key holder knows this
##
## What the byte strings look like
## -------------------------------
##   public key   [ seed_ek 32 ][ s               ]
##   secret key   [ public key ][ seed_dk 32 ][ sigma ][ seed_kem 32 ]
##   ciphertext   [ u          ][ v           ][ salt 16 ]
##
## `seed_kem` at the end of the secret key is the seed the whole key grew
## from. It is kept so a holder can regenerate the key, and it is never
## used by decapsulation.
##
## Reference: [HQC-20250822] HQC.KEM key generation, encapsulation and
## decapsulation; ported from the reference implementation's `kem.c`.

import runePragmas
import ../../helpers/otter_support
import ../../helpers/random
import ./params
export params
import ./types
export types
import ./parsing
import ./pke
import ./gf2x
import ./symmetric
import ./util

## Reference: [HQC-20250822] HQC.KEM key generation; deterministic keypair for `hqcTyrKeypairDerand`; pitfall: keep the order of seed_pke and sigma on the stream exact, and wipe every seed afterwards.
proc hqcTyrKeypairDerand*(v: HqcVariant, randomness: openArray[byte]):
    HqcTyrKeypair {.role: {orchestrator}, otterTrace.} =
  ## v/randomness: the parameter set, and exactly 32 bytes of randomness.
  ## Build a keypair from a caller-supplied seed, for tests and for
  ## reproducing published vectors.
  var
    p: HqcParams = params(v)
    X = default(HqcXof)
    seedPke = default(array[hqcSeedBytes, byte])
    sigma = default(array[hqcMaxMessageBytes, byte])
    ekPke: seq[byte] = @[]
    dkPke = default(array[hqcSeedBytes, byte])
    W: seq[uint64] = @[]
    i: int = 0
  if randomness.len != p.keypairRandomBytes:
    raise newException(ValueError,
      "HQC keypair randomness must be " & $p.keypairRandomBytes & " bytes")
  ekPke = newSeq[byte](p.publicKeyBytes)
  W = newHqcMulScratch(p)
  ## One 32-byte seed stretches into the encryption seed and sigma.
  xofInit(X, randomness)
  xofBytes(X, seedPke, 0, hqcSeedBytes)
  xofBytes(X, sigma, 0, p.messageBytes)
  xofClear(X)
  pkeKeygen(ekPke, dkPke, seedPke, p, W)
  result.variant = v
  result.publicKey = ekPke
  result.secretKey = newSeq[byte](p.secretKeyBytes)
  packSecretKey(result.secretKey, ekPke, dkPke, sigma, randomness, p)
  hqcWipeBytes(seedPke)
  hqcWipeBytes(sigma)
  hqcWipeBytes(dkPke)
  hqcWipeWords(W)

## Reference: [HQC-20250822] HQC.KEM key generation; keypair entry point for `hqcTyrKeypair`; pitfall: an empty seed must reach for system entropy, never for a default value.
proc hqcTyrKeypair*(v: HqcVariant, randomness: seq[byte] = @[]): HqcTyrKeypair
    {.role: {orchestrator}, otterTrace.} =
  ## v/randomness: the parameter set, and optionally exactly 32 bytes of
  ## fixed randomness. An empty sequence means "use system entropy".
  var
    p: HqcParams = params(v)
    material: seq[byte] = @[]
  if randomness.len > 0 and randomness.len != p.keypairRandomBytes:
    raise newException(ValueError,
      "HQC seeded keypair requires " & $p.keypairRandomBytes & " bytes")
  if randomness.len == 0:
    material = cryptoRandomBytes(p.keypairRandomBytes)
  else:
    material = randomness
  result = hqcTyrKeypairDerand(v, material)
  hqcWipeBytes(material)

## Reference: [HQC-20250822] HQC.KEM encapsulation; deterministic encapsulation for `hqcTyrEncapsDerand`; pitfall: the randomness is the message followed by the salt, in that order, and theta is the SECOND half of G's output.
include "operations_encapsulation.nim"
include "operations_decapsulation.nim"
include "operations_decapsulation_api.nim"
