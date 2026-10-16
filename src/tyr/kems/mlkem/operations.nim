## ---------------------------------------------------------
## ML-KEM Operations <- KEM wrappers for the pure-Nim backend
## ---------------------------------------------------------

import ./params
import ../../helpers/secure_memory
export params
import ./util
import ./indcpa
import ./symmetric
import ./verify
import ../../helpers/otter_support
import ../../helpers/random

type
  ## Public/secret keypair emitted by the pure-Nim ML-KEM backend.
  MlKemTyrKeypair* = object
    variant*: MlKemVariant
    publicKey*: seq[byte]
    secretKey*: seq[byte]

  ## Detached ciphertext plus shared secret emitted by encapsulation.
  MlKemTyrCipher* = object
    variant*: MlKemVariant
    ciphertext*: seq[byte]
    sharedSecret*: seq[byte]

## Testing/reproducibility surface. Keep public during KAT and optimization
## work; tighten or remove this from the public API once ML-KEM stabilizes.
## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; key generation, encapsulation/signing, and decapsulation/verification algorithms for `mlkemTyrKeypairFromParts`; pitfall: keep transcript order, domain separation, sizes, and secret wiping exact.
proc mlkemTyrKeypairFromParts*(v: MlKemVariant, indcpaSeed, zSeed: openArray[byte]): MlKemTyrKeypair {.gcsafe.}

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; key generation, encapsulation/signing, and decapsulation/verification algorithms for `mlkemTyrKeypairDerand`; pitfall: keep transcript order, domain separation, sizes, and secret wiping exact.
proc mlkemTyrKeypairDerand*(v: MlKemVariant, seedMaterial: openArray[byte]): MlKemTyrKeypair =
  ## Generate a pure-Nim ML-KEM keypair from explicit 64-byte keypair material.
  ## Testing/reproducibility surface to narrow later.
  if seedMaterial.len != 2 * mlkemSymBytes:
    raise newException(ValueError, "ML-KEM keypair randomness must be 64 bytes")
  result = mlkemTyrKeypairFromParts(v,
    seedMaterial.toOpenArray(0, 31),
    seedMaterial.toOpenArray(32, 63))

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; key generation, encapsulation/signing, and decapsulation/verification algorithms for `mlkemTyrKeypairFromParts`; pitfall: keep transcript order, domain separation, sizes, and secret wiping exact.
proc mlkemTyrKeypairFromParts*(v: MlKemVariant, indcpaSeed, zSeed: openArray[byte]): MlKemTyrKeypair {.gcsafe.} =
  ## Generate a pure-Nim ML-KEM keypair from the two exact randomness draws used by the KEM.
  var
    p: MlKemParams = params(v)
    pkHash: array[mlkemSymBytes, byte] = default(array[mlkemSymBytes, byte])
  if indcpaSeed.len != 32:
    raise newException(ValueError, "ML-KEM indcpa keypair seed must be 32 bytes")
  if zSeed.len != 32:
    raise newException(ValueError, "ML-KEM fallback z seed must be 32 bytes")
  result.variant = v
  result.publicKey = newSeq[byte](p.publicKeyBytes)
  result.secretKey = newSeq[byte](p.secretKeyBytes)
  indcpaKeypairInto(p,
    result.publicKey,
    result.secretKey.toOpenArray(0, p.indcpaSecretKeyBytes - 1),
    indcpaSeed)
  hashHInto(pkHash, result.publicKey)
  copyBytes(result.secretKey, p.indcpaSecretKeyBytes, result.publicKey)
  copyBytes(result.secretKey, p.secretKeyBytes - 2 * mlkemSymBytes, pkHash)
  copyBytes(result.secretKey, p.secretKeyBytes - mlkemSymBytes, zSeed)
  clearBytes(pkHash)

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; key generation, encapsulation/signing, and decapsulation/verification algorithms for `mlkemTyrKeypair`; pitfall: keep transcript order, domain separation, sizes, and secret wiping exact.
proc mlkemTyrKeypair*(v: MlKemVariant, seed: seq[byte] = @[]): MlKemTyrKeypair {.otterTrace.} =
  ## Generate a pure-Nim ML-KEM keypair.
  var
    seedMaterial: seq[byte] = @[]
    seedMaterialBuf: array[2 * mlkemSymBytes, byte] = default(array[2 * mlkemSymBytes, byte])
  if seed.len > 0 and seed.len != mlkemSymBytes:
    raise newException(ValueError, "ML-KEM seeded keypair requires a 32-byte seed")
  if seed.len == 0:
    seedMaterial = cryptoRandomBytes(64)
    fillArray(seedMaterialBuf, seedMaterial)
    secureClearBytes(seedMaterial)
  else:
    hashGInto(seedMaterialBuf, seed)
  result = mlkemTyrKeypairDerand(v, seedMaterialBuf)
  secureClearBytes(seedMaterialBuf)

## Reference: [FIPS-203] section 7.2, encapsulation-key check; pitfall: reject before any secret is touched.
proc publicKeyIsReduced*(p: MlKemParams, pk: openArray[byte]): bool =
  ## pk: encoded public key. True when every 12-bit number in it is below q.
  ##
  ##   3 bytes  [b0][b1][b2]  ->  two numbers  a = b0 | (b1 & 0x0F) << 8
  ##                                          c = b1 >> 4 | b2 << 4
  ##   both must be < 3329, else the key is not a valid FIPS 203 key.
  var
    i: int = 0
    a: int = 0
    c: int = 0
    n: int = p.k * mlkemPolyBytes
  result = pk.len == p.publicKeyBytes
  while result and i < n:
    a = int(pk[i]) or ((int(pk[i + 1]) and 0x0f) shl 8)
    c = (int(pk[i + 1]) shr 4) or (int(pk[i + 2]) shl 4)
    result = a < mlkemQ and c < mlkemQ
    i = i + 3

## Reference: [FIPS-203] algorithms 17 and 20, ML-KEM.Encaps_internal; pitfall: keep transcript order, domain separation, sizes, and secret wiping exact.
proc mlkemTyrEncaps*(v: MlKemVariant, pk: openArray[byte], seed: seq[byte] = @[]): MlKemTyrCipher {.otterTrace.} =
  ## Encapsulate against an ML-KEM public key.
  ## v/pk: size and encapsulation key. seed: optional 32-byte m for tests.
  ##
  ##   m (32 random bytes)
  ##   (K, r) = G(m || H(pk))          <- K is the shared secret as-is
  ##   ct     = Encrypt(pk, m, r)
  var
    p: MlKemParams = params(v)
    entropy: seq[byte] = @[]
    buf: array[2 * mlkemSymBytes, byte] = default(array[2 * mlkemSymBytes, byte])
    kr: array[2 * mlkemSymBytes, byte] = default(array[2 * mlkemSymBytes, byte])
    pkHash: array[mlkemSymBytes, byte] = default(array[mlkemSymBytes, byte])
  if pk.len != p.publicKeyBytes:
    raise newException(ValueError, "invalid ML-KEM public key length")
  if not publicKeyIsReduced(p, pk):
    raise newException(ValueError, "ML-KEM public key is not reduced mod q")
  if seed.len > 0 and seed.len != mlkemSymBytes:
    raise newException(ValueError, "ML-KEM seeded encapsulation requires a 32-byte seed")
  if seed.len == 0:
    entropy = cryptoRandomBytes(mlkemSymBytes)
    copyBytes(buf, 0, entropy)
    secureClearBytes(entropy)
  else:
    copyBytes(buf, 0, seed)
  hashHInto(pkHash, pk)
  copyBytes(buf, mlkemSymBytes, pkHash)
  hashGInto(kr, buf)
  result.variant = v
  result.ciphertext = newSeq[byte](p.ciphertextBytes)
  indcpaEncInto(p, result.ciphertext, buf.toOpenArray(0, mlkemSymBytes - 1), pk,
    kr.toOpenArray(mlkemSymBytes, 2 * mlkemSymBytes - 1))
  result.sharedSecret = newSeq[byte](p.sharedSecretBytes)
  copyBytes(result.sharedSecret, 0, kr.toOpenArray(0, mlkemSymBytes - 1))
  secureClearBytes(buf)
  secureClearBytes(kr)
  clearBytes(pkHash)

## Reference: [FIPS-203] section 7.3 decapsulation-key check; pitfall: the stored H(ek) must match the stored ek.
proc secretKeyHashMatches(p: MlKemParams, sk: openArray[byte]): bool =
  ## sk: full decapsulation key  [ dk_pke | ek | H(ek) | z ].
  var
    h: array[mlkemSymBytes, byte] = default(array[mlkemSymBytes, byte])
    o: int = p.indcpaSecretKeyBytes
  hashHInto(h, sk.toOpenArray(o, o + p.indcpaPublicKeyBytes - 1))
  result = verifyBytes(h, sk.toOpenArray(p.secretKeyBytes - 2 * mlkemSymBytes,
    p.secretKeyBytes - mlkemSymBytes - 1)) == 0

## Reference: [FIPS-203] algorithms 18 and 21, ML-KEM.Decaps_internal; pitfall: preserve implicit rejection and never expose a secret-dependent validity oracle.
proc mlkemTyrTryDecaps(v: MlKemVariant, sk, ct: openArray[byte]): tuple[sharedSecret: seq[byte], ok: bool] =
  ## Internal decapsulation helper that keeps the re-encryption check private
  ## so callers cannot accidentally expose a validity oracle.
  ##
  ##   m'       = Decrypt(dk_pke, ct)
  ##   (K', r') = G(m' || h)
  ##   Kbad     = J(z || ct) = SHAKE256(z || ct)[0..31]
  ##   ct'      = Encrypt(ek, m', r')
  ##   result   = K' when ct == ct', else Kbad   (chosen without a branch)
  var
    p: MlKemParams = params(v)
    buf: array[2 * mlkemSymBytes, byte] = default(array[2 * mlkemSymBytes, byte])
    kr: array[2 * mlkemSymBytes, byte] = default(array[2 * mlkemSymBytes, byte])
    cmp: array[1568, byte] = default(array[1568, byte])
    kBad: array[mlkemSymBytes, byte] = default(array[mlkemSymBytes, byte])
    zc: seq[byte] = @[]
    fail: int = 0
  if sk.len != p.secretKeyBytes:
    raise newException(ValueError, "invalid ML-KEM secret key length")
  if ct.len != p.ciphertextBytes:
    raise newException(ValueError, "invalid ML-KEM ciphertext length")
  if not secretKeyHashMatches(p, sk):
    raise newException(ValueError, "ML-KEM secret key fails its H(ek) check")
  indcpaDecInto(p, buf.toOpenArray(0, mlkemSymBytes - 1), ct,
    sk.toOpenArray(0, p.indcpaSecretKeyBytes - 1))
  copyBytes(buf, mlkemSymBytes, sk.toOpenArray(p.secretKeyBytes - 2 * mlkemSymBytes,
    p.secretKeyBytes - mlkemSymBytes - 1))
  hashGInto(kr, buf)
  zc = newSeq[byte](mlkemSymBytes + ct.len)
  copyBytes(zc, 0, sk.toOpenArray(p.secretKeyBytes - mlkemSymBytes, p.secretKeyBytes - 1))
  copyBytes(zc, mlkemSymBytes, ct)
  kdfInto(kBad, zc)
  indcpaEncInto(p, cmp.toOpenArray(0, p.ciphertextBytes - 1), buf.toOpenArray(0, mlkemSymBytes - 1),
    sk.toOpenArray(p.indcpaSecretKeyBytes, p.indcpaSecretKeyBytes + p.indcpaPublicKeyBytes - 1),
    kr.toOpenArray(mlkemSymBytes, 2 * mlkemSymBytes - 1))
  fail = verifyBytes(ct, cmp.toOpenArray(0, p.ciphertextBytes - 1))
  cmovBytes(kr.toOpenArray(0, mlkemSymBytes - 1), kBad, uint8(fail))
  result.sharedSecret = newSeq[byte](p.sharedSecretBytes)
  copyBytes(result.sharedSecret, 0, kr.toOpenArray(0, mlkemSymBytes - 1))
  result.ok = fail == 0
  secureClearBytes(buf)
  secureClearBytes(kr)
  secureClearBytes(cmp)
  secureClearBytes(kBad)
  secureClearBytes(zc)

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; key generation, encapsulation/signing, and decapsulation/verification algorithms for `mlkemTyrDecaps`; pitfall: preserve implicit rejection and never expose a secret-dependent validity oracle.
proc mlkemTyrDecaps*(v: MlKemVariant, sk, ct: openArray[byte]): seq[byte] {.otterTrace.} =
  ## Decapsulate a ML-KEM ciphertext and return the derived shared secret
  ## without exposing the internal re-encryption check result.
  result = mlkemTyrTryDecaps(v, sk, ct).sharedSecret
