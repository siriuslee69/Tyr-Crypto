## ---------------------------------------------------------
## Kyber Symmetric <- SHA3/SHAKE wrappers for Kyber internals
## ---------------------------------------------------------

import ./params
import ../../../sha3

## Reference: [KYBER-R3-20210804] version 3.02 sections 1.3 and 4, algorithms 1-9; hash, XOF, and domain-separation rules for `hashHInto`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc hashHInto*(dst: var openArray[byte], A: openArray[byte]) =
  ## SHA3-256 wrapper used by Kyber into a fixed 32-byte buffer.
  if dst.len != kyberSymBytes:
    raise newException(ValueError, "Kyber hashH output must be 32 bytes")
  sha3_256Into(dst, A)

## Reference: [KYBER-R3-20210804] version 3.02 sections 1.3 and 4, algorithms 1-9; hash, XOF, and domain-separation rules for `hashH`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc hashH*(A: openArray[byte]): seq[byte] =
  ## SHA3-256 wrapper used by Kyber.
  result = newSeq[byte](kyberSymBytes)
  hashHInto(result, A)

## Reference: [KYBER-R3-20210804] version 3.02 sections 1.3 and 4, algorithms 1-9; hash, XOF, and domain-separation rules for `hashGInto`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc hashGInto*(dst: var openArray[byte], A: openArray[byte]) =
  ## SHA3-512 wrapper used by Kyber into a fixed 64-byte buffer.
  if dst.len != 2 * kyberSymBytes:
    raise newException(ValueError, "Kyber hashG output must be 64 bytes")
  sha3_512Into(dst, A)

## Reference: [KYBER-R3-20210804] version 3.02 sections 1.3 and 4, algorithms 1-9; hash, XOF, and domain-separation rules for `hashG`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc hashG*(A: openArray[byte]): seq[byte] =
  ## SHA3-512 wrapper used by Kyber.
  result = newSeq[byte](2 * kyberSymBytes)
  hashGInto(result, A)

## Reference: [KYBER-R3-20210804] version 3.02 sections 1.3 and 4, algorithms 1-9; hash, XOF, and domain-separation rules for `kdfInto`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc kdfInto*(dst: var openArray[byte], A: openArray[byte]) =
  ## SHAKE256-based KDF that fills a caller-provided shared-secret buffer.
  if dst.len != kyberSharedSecretBytes:
    raise newException(ValueError, "Kyber KDF output must be 32 bytes")
  shake256Into(dst, A)

## Reference: [KYBER-R3-20210804] version 3.02 sections 1.3 and 4, algorithms 1-9; hash, XOF, and domain-separation rules for `kdf`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc kdf*(A: openArray[byte]): seq[byte] =
  ## SHAKE256-based KDF that returns a Kyber shared secret.
  result = newSeq[byte](kyberSharedSecretBytes)
  kdfInto(result, A)

## Reference: [KYBER-R3-20210804] version 3.02 sections 1.3 and 4, algorithms 1-9; hash, XOF, and domain-separation rules for `prfInto`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc prfInto*(dst: var openArray[byte], key: openArray[byte], nonce: byte) =
  ## Kyber SHAKE256 PRF over `key || nonce` into a caller-provided buffer.
  var
    material: array[kyberSymBytes + 1, byte]
    i: int = 0
  if key.len != kyberSymBytes:
    raise newException(ValueError, "Kyber PRF key must be 32 bytes")
  i = 0
  while i < kyberSymBytes:
    material[i] = key[i]
    i = i + 1
  material[kyberSymBytes] = nonce
  shake256Into(dst, material)

## Reference: [KYBER-R3-20210804] version 3.02 sections 1.3 and 4, algorithms 1-9; hash, XOF, and domain-separation rules for `prf`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc prf*(key: openArray[byte], nonce: byte, outLen: int): seq[byte] =
  ## Kyber SHAKE256 PRF over `key || nonce`.
  if outLen < 0:
    raise newException(ValueError, "Kyber PRF output length must be >= 0")
  result = newSeq[byte](outLen)
  prfInto(result, key, nonce)

## Reference: [KYBER-R3-20210804] version 3.02 sections 1.3 and 4, algorithms 1-9; hash, XOF, and domain-separation rules for `xofBytesInto`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc xofBytesInto*(dst: var openArray[byte], seed: openArray[byte], x, y: byte) =
  ## Kyber SHAKE128 XOF over `seed || x || y` into a caller-provided buffer.
  var
    material: array[kyberSymBytes + 2, byte]
    i: int = 0
  if seed.len != kyberSymBytes:
    raise newException(ValueError, "Kyber XOF seed must be 32 bytes")
  i = 0
  while i < kyberSymBytes:
    material[i] = seed[i]
    i = i + 1
  material[kyberSymBytes + 0] = x
  material[kyberSymBytes + 1] = y
  shake128Into(dst, material)

## Reference: [KYBER-R3-20210804] version 3.02 sections 1.3 and 4, algorithms 1-9; hash, XOF, and domain-separation rules for `xofBytes`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc xofBytes*(seed: openArray[byte], x, y: byte, outLen: int): seq[byte] =
  ## Kyber SHAKE128 XOF over `seed || x || y`.
  if outLen < 0:
    raise newException(ValueError, "Kyber XOF output length must be >= 0")
  result = newSeq[byte](outLen)
  xofBytesInto(result, seed, x, y)
