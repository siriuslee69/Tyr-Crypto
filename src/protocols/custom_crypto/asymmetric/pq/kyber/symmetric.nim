## ---------------------------------------------------------
## Kyber Symmetric <- SHA3/SHAKE wrappers for Kyber internals
## ---------------------------------------------------------

import ./params
import ../../../sha3

proc hashHInto*(dst: var openArray[byte], A: openArray[byte]) =
  ## SHA3-256 wrapper used by Kyber into a fixed 32-byte buffer.
  if dst.len != kyberSymBytes:
    raise newException(ValueError, "Kyber hashH output must be 32 bytes")
  sha3_256Into(dst, A)

proc hashH*(A: openArray[byte]): seq[byte] =
  ## SHA3-256 wrapper used by Kyber.
  result = newSeq[byte](kyberSymBytes)
  hashHInto(result, A)

proc hashGInto*(dst: var openArray[byte], A: openArray[byte]) =
  ## SHA3-512 wrapper used by Kyber into a fixed 64-byte buffer.
  if dst.len != 2 * kyberSymBytes:
    raise newException(ValueError, "Kyber hashG output must be 64 bytes")
  sha3_512Into(dst, A)

proc hashG*(A: openArray[byte]): seq[byte] =
  ## SHA3-512 wrapper used by Kyber.
  result = newSeq[byte](2 * kyberSymBytes)
  hashGInto(result, A)

proc kdfInto*(dst: var openArray[byte], A: openArray[byte]) =
  ## SHAKE256-based KDF that fills a caller-provided shared-secret buffer.
  if dst.len != kyberSharedSecretBytes:
    raise newException(ValueError, "Kyber KDF output must be 32 bytes")
  shake256Into(dst, A)

proc kdf*(A: openArray[byte]): seq[byte] =
  ## SHAKE256-based KDF that returns a Kyber shared secret.
  result = newSeq[byte](kyberSharedSecretBytes)
  kdfInto(result, A)

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

proc prf*(key: openArray[byte], nonce: byte, outLen: int): seq[byte] =
  ## Kyber SHAKE256 PRF over `key || nonce`.
  if outLen < 0:
    raise newException(ValueError, "Kyber PRF output length must be >= 0")
  result = newSeq[byte](outLen)
  prfInto(result, key, nonce)

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

proc xofBytes*(seed: openArray[byte], x, y: byte, outLen: int): seq[byte] =
  ## Kyber SHAKE128 XOF over `seed || x || y`.
  if outLen < 0:
    raise newException(ValueError, "Kyber XOF output length must be >= 0")
  result = newSeq[byte](outLen)
  xofBytesInto(result, seed, x, y)
