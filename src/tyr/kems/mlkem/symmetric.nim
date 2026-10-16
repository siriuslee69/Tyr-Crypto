## ---------------------------------------------------------
## ML-KEM Symmetric <- SHA3/SHAKE wrappers for ML-KEM internals
## ---------------------------------------------------------

import ./params
import ../../hashes/sha3

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; hash, XOF, and domain-separation rules for `hashHInto`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc hashHInto*(dst: var openArray[byte], A: openArray[byte]) =
  ## SHA3-256 wrapper used by ML-KEM into a fixed 32-byte buffer.
  if dst.len != mlkemSymBytes:
    raise newException(ValueError, "ML-KEM hashH output must be 32 bytes")
  sha3_256Into(dst, A)

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; hash, XOF, and domain-separation rules for `hashH`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc hashH*(A: openArray[byte]): seq[byte] =
  ## SHA3-256 wrapper used by ML-KEM.
  result = newSeq[byte](mlkemSymBytes)
  hashHInto(result, A)

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; hash, XOF, and domain-separation rules for `hashGInto`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc hashGInto*(dst: var openArray[byte], A: openArray[byte]) =
  ## SHA3-512 wrapper used by ML-KEM into a fixed 64-byte buffer.
  if dst.len != 2 * mlkemSymBytes:
    raise newException(ValueError, "ML-KEM hashG output must be 64 bytes")
  sha3_512Into(dst, A)

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; hash, XOF, and domain-separation rules for `hashG`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc hashG*(A: openArray[byte]): seq[byte] =
  ## SHA3-512 wrapper used by ML-KEM.
  result = newSeq[byte](2 * mlkemSymBytes)
  hashGInto(result, A)

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; hash, XOF, and domain-separation rules for `kdfInto`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc kdfInto*(dst: var openArray[byte], A: openArray[byte]) =
  ## SHAKE256-based KDF that fills a caller-provided shared-secret buffer.
  if dst.len != mlkemSharedSecretBytes:
    raise newException(ValueError, "ML-KEM KDF output must be 32 bytes")
  shake256Into(dst, A)

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; hash, XOF, and domain-separation rules for `kdf`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc kdf*(A: openArray[byte]): seq[byte] =
  ## SHAKE256-based KDF that returns a ML-KEM shared secret.
  result = newSeq[byte](mlkemSharedSecretBytes)
  kdfInto(result, A)

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; hash, XOF, and domain-separation rules for `prfInto`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc prfInto*(dst: var openArray[byte], key: openArray[byte], nonce: byte) =
  ## ML-KEM SHAKE256 PRF over `key || nonce` into a caller-provided buffer.
  var
    material: array[mlkemSymBytes + 1, byte] = default(array[mlkemSymBytes + 1, byte])
    i: int = 0
  if key.len != mlkemSymBytes:
    raise newException(ValueError, "ML-KEM PRF key must be 32 bytes")
  i = 0
  while i < mlkemSymBytes:
    material[i] = key[i]
    i = i + 1
  material[mlkemSymBytes] = nonce
  shake256Into(dst, material)

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; hash, XOF, and domain-separation rules for `prf`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc prf*(key: openArray[byte], nonce: byte, outLen: int): seq[byte] =
  ## ML-KEM SHAKE256 PRF over `key || nonce`.
  if outLen < 0:
    raise newException(ValueError, "ML-KEM PRF output length must be >= 0")
  result = newSeq[byte](outLen)
  prfInto(result, key, nonce)

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; hash, XOF, and domain-separation rules for `xofBytesInto`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc xofBytesInto*(dst: var openArray[byte], seed: openArray[byte], x, y: byte) =
  ## ML-KEM SHAKE128 XOF over `seed || x || y` into a caller-provided buffer.
  var
    material: array[mlkemSymBytes + 2, byte] = default(array[mlkemSymBytes + 2, byte])
    i: int = 0
  if seed.len != mlkemSymBytes:
    raise newException(ValueError, "ML-KEM XOF seed must be 32 bytes")
  i = 0
  while i < mlkemSymBytes:
    material[i] = seed[i]
    i = i + 1
  material[mlkemSymBytes + 0] = x
  material[mlkemSymBytes + 1] = y
  shake128Into(dst, material)

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; hash, XOF, and domain-separation rules for `xofBytes`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc xofBytes*(seed: openArray[byte], x, y: byte, outLen: int): seq[byte] =
  ## ML-KEM SHAKE128 XOF over `seed || x || y`.
  if outLen < 0:
    raise newException(ValueError, "ML-KEM XOF output length must be >= 0")
  result = newSeq[byte](outLen)
  xofBytesInto(result, seed, x, y)
