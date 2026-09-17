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
proc hqcTyrEncapsDerand*(v: HqcVariant, pk: openArray[byte],
    randomness: openArray[byte]): HqcTyrCipher
    {.role: {encryptor}, otterTrace.} =
  ## v/pk/randomness: the parameter set, the recipient's public key, and
  ## exactly `messageBytes + 16` bytes of randomness.
  ## Encapsulate with caller-supplied randomness, for tests and vectors.
  var
    p: HqcParams = params(v)
    c = default(HqcPkeCipher)
    m = default(array[hqcMaxMessageBytes, byte])
    salt = default(array[hqcSaltBytes, byte])
    hashEk = default(array[hqcSharedSecretBytes, byte])
    kTheta = default(array[hqcSharedSecretBytes + hqcSeedBytes, byte])
    theta = default(array[hqcSeedBytes, byte])
    G: seq[uint16] = @[]
    W: seq[uint64] = @[]
    i: int = 0
  if pk.len != p.publicKeyBytes:
    raise newException(ValueError, "invalid HQC public key length")
  if randomness.len != p.encapsRandomBytes:
    raise newException(ValueError,
      "HQC encaps randomness must be " & $p.encapsRandomBytes & " bytes")
  i = 0
  while i < p.messageBytes:
    m[i] = randomness[i]
    i = i + 1
  i = 0
  while i < hqcSaltBytes:
    salt[i] = randomness[p.messageBytes + i]
    i = i + 1
  G = genPoly(v)
  W = newHqcMulScratch(p)
  c.u = newHqcVec(p.vecNWords)
  c.v = newHqcVec(p.vecNWords)
  ## K and theta both come out of one hash, so the shared secret and the
  ## ciphertext are locked to each other.
  hashH(hashEk, pk)
  hashG(kTheta, hashEk, m.toOpenArray(0, p.messageBytes - 1), salt)
  i = 0
  while i < hqcSeedBytes:
    theta[i] = kTheta[hqcSharedSecretBytes + i]
    i = i + 1
  pkeEncrypt(c, pk, m.toOpenArray(0, p.messageBytes - 1), theta, p, G, W)
  result.variant = v
  result.ciphertext = newSeq[byte](p.ciphertextBytes)
  packCiphertext(result.ciphertext, c, salt, p)
  result.sharedSecret = newSeq[byte](p.sharedSecretBytes)
  i = 0
  while i < p.sharedSecretBytes:
    result.sharedSecret[i] = kTheta[i]
    i = i + 1
  hqcWipeBytes(m)
  hqcWipeBytes(kTheta)
  hqcWipeBytes(theta)
  hqcWipeWords(W)

## Reference: [HQC-20250822] HQC.KEM encapsulation; encapsulation entry point for `hqcTyrEncaps`; pitfall: an empty seed must reach for system entropy, never for a default value.
proc hqcTyrEncaps*(v: HqcVariant, pk: openArray[byte],
    randomness: seq[byte] = @[]): HqcTyrCipher
    {.role: {encryptor}, otterTrace.} =
  ## v/pk/randomness: the parameter set, the recipient's public key, and
  ## optionally exactly `messageBytes + 16` bytes of fixed randomness.
  var
    p: HqcParams = params(v)
    material: seq[byte] = @[]
  if randomness.len > 0 and randomness.len != p.encapsRandomBytes:
    raise newException(ValueError,
      "HQC seeded encaps requires " & $p.encapsRandomBytes & " bytes")
  if randomness.len == 0:
    material = cryptoRandomBytes(p.encapsRandomBytes)
  else:
    material = randomness
  result = hqcTyrEncapsDerand(v, pk, material)
  hqcWipeBytes(material)

## Reference: [HQC-20250822] HQC.KEM decapsulation; implicit rejection for `hqcTyrTryDecapsInternal`; pitfall: the `ok` flag is diagnostic only, and exposing it to a peer turns decapsulation into a ciphertext-validity oracle.
proc hqcTyrTryDecapsInternal(v: HqcVariant, sk, ct: openArray[byte]):
    tuple[sharedSecret: seq[byte], ok: bool] {.role: {decryptor}.} =
  ## v/sk/ct: the parameter set, the secret key, the received ciphertext.
  ##
  ## Decrypt, then rebuild the ciphertext from what came out. Only an
  ## exact match yields the real shared secret; anything else yields the
  ## rejection key, with no branch anywhere between the two.
  var
    p: HqcParams = params(v)
    c = default(HqcPkeCipher)
    cPrime = default(HqcPkeCipher)
    mPrime = default(array[hqcMaxMessageBytes, byte])
    hashEk = default(array[hqcSharedSecretBytes, byte])
    kTheta = default(array[hqcSharedSecretBytes + hqcSeedBytes, byte])
    kBar = default(array[hqcSharedSecretBytes, byte])
    theta = default(array[hqcSeedBytes, byte])
    G: seq[uint16] = @[]
    W: seq[uint64] = @[]
    uBytes: seq[byte] = @[]
    vBytes: seq[byte] = @[]
    sigmaOffset: int = 0
    saltOffset: int = 0
    mismatch: byte = 0
    keepMask: byte = 0
    i: int = 0
  if sk.len != p.secretKeyBytes:
    raise newException(ValueError, "invalid HQC secret key length")
  if ct.len != p.ciphertextBytes:
    raise newException(ValueError, "invalid HQC ciphertext length")
  sigmaOffset = skSigmaOffset(p)
  saltOffset = ctSaltOffset(p)
  G = genPoly(v)
  W = newHqcMulScratch(p)
  c.u = newHqcVec(p.vecNWords)
  c.v = newHqcVec(p.vecNWords)
  cPrime.u = newHqcVec(p.vecNWords)
  cPrime.v = newHqcVec(p.vecNWords)
  unpackCiphertext(c, ct, p)
  pkeDecrypt(mPrime, sk.toOpenArray(skSeedOffset(p), sigmaOffset - 1), c, p, W)
  ## Rebuild the shared secret and the encryption randomness from what
  ## decryption produced. A wrong message gives a wrong theta, which
  ## gives a ciphertext that cannot match.
  hashH(hashEk, sk.toOpenArray(0, p.publicKeyBytes - 1))
  hashG(kTheta, hashEk, mPrime.toOpenArray(0, p.messageBytes - 1),
    ct.toOpenArray(saltOffset, saltOffset + hqcSaltBytes - 1))
  i = 0
  while i < hqcSeedBytes:
    theta[i] = kTheta[hqcSharedSecretBytes + i]
    i = i + 1
  pkeEncrypt(cPrime, sk.toOpenArray(0, p.publicKeyBytes - 1),
    mPrime.toOpenArray(0, p.messageBytes - 1), theta, p, G, W)
  uBytes = hqcVecToByteSeq(cPrime.u, p.vecNBytes)
  vBytes = hqcVecToByteSeq(cPrime.v, p.vecN1n2Bytes)
  ## The rejection key. It is built whether or not it is needed, so the
  ## work done never depends on whether the ciphertext was valid.
  hashJ(kBar, hashEk, sk.toOpenArray(sigmaOffset, sigmaOffset + p.messageBytes - 1),
    ct.toOpenArray(0, p.vecNBytes - 1),
    ct.toOpenArray(p.vecNBytes, saltOffset - 1),
    ct.toOpenArray(saltOffset, saltOffset + hqcSaltBytes - 1))
  mismatch = hqcVecCompare(ct, uBytes, p.vecNBytes)
  mismatch = mismatch or hqcVecCompare(ct.toOpenArray(p.vecNBytes, saltOffset - 1),
    vBytes, p.vecN1n2Bytes)
  ## keepMask is 0xff when everything matched and 0x00 when it did not.
  keepMask = mismatch - 1'u8
  result.sharedSecret = newSeq[byte](p.sharedSecretBytes)
  i = 0
  while i < p.sharedSecretBytes:
    result.sharedSecret[i] = (kTheta[i] and keepMask) or
      (kBar[i] and (not keepMask))
    i = i + 1
  result.ok = mismatch == 0'u8
  hqcWipeBytes(mPrime)
  hqcWipeBytes(kTheta)
  hqcWipeBytes(kBar)
  hqcWipeBytes(theta)
  hqcWipeWords(W)

## Reference: [HQC-20250822] HQC.KEM decapsulation; decapsulation entry point for `hqcTyrDecaps`; pitfall: callers must consume the returned secret uniformly, because a rejected ciphertext also returns 32 plausible bytes.
proc hqcTyrDecaps*(v: HqcVariant, sk, ct: openArray[byte]): seq[byte]
    {.role: {decryptor}, otterTrace.} =
  ## v/sk/ct: the parameter set, your secret key, the ciphertext received.
  ## Recover the shared secret. A damaged or forged ciphertext yields a
  ## different but equally normal-looking secret rather than an error.
  result = hqcTyrTryDecapsInternal(v, sk, ct).sharedSecret

when defined(tyrCryptoTestHooks):
  ## Reference: [HQC-20250822] HQC.KEM decapsulation; test-only validity flag for `hqcTyrTryDecaps`; pitfall: this must stay behind a build flag so no shipped build can expose the oracle.
  proc hqcTyrTryDecaps*(v: HqcVariant, sk, ct: openArray[byte]):
      tuple[sharedSecret: seq[byte], ok: bool] =
    ## v/sk/ct: the parameter set, the secret key, the ciphertext.
    ## Test-only view of whether the ciphertext was genuine.
    result = hqcTyrTryDecapsInternal(v, sk, ct)

