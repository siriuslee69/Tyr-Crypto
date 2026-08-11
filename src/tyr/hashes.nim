## ---------------------------------------------------------------------
## | Hashes <- default tier: one `digest` name for every hash family    |
## ---------------------------------------------------------------------
##
##   import tyr/hashes            <- THIS FILE. digest(hfBlake3, data)
##   import tyr/hashes/blake3     <- one family: blake3Hash(data)
##   import tyr/hashes/dynamic    <- pick from a stored value at runtime
##   import tyr/hashes/single     <- one family by build flag, for devices
##   import tyr/hashes/material   <- typed material surface
##
## Unlike the KEM and signature tiers, hash families have no per-family
## variant type to overload on, so the family is named by its enum value.
##
## Each algorithm also answers to a `...Tyr...` public name, meaning "this
## repo's own version of it" - see the block at the bottom of this file.

import ./hashes/types
import ./hashes/blake3
import ./hashes/sha256
import ./hashes/sha512
import ./hashes/sha3
import ./hashes/material

export types
export blake3, sha256, sha512, sha3
export material

proc digest*(f: HashFamily, data: openArray[byte], outLen: int = 0): seq[byte] =
  ## f/data/outLen: family, bytes to fingerprint, and the wanted length.
  ## `outLen = 0` means "this family's natural length". SHA-256 and SHA-512
  ## have only one length and ignore any other request.
  var n: int = outLen
  if n <= 0:
    n = defaultDigestBytes[f]
  case f
  of hfBlake3: result = blake3Hash(data, n)
  of hfSha3:   result = sha3Hash(data, n)
  of hfSha256: result = @(sha256Hash(data))
  of hfSha512: result = @(sha512Hash(data))

## ╭⟢ Public names
##
## `blake3Hash` is what the implementation calls itself and what the rest
## of Tyr uses. `blake3TyrHash` is the same code under the name other
## repos call, chosen so it cannot collide with a library-backed BLAKE3
## imported alongside it.

proc blake3TyrHash*(input: openArray[byte],
    outLen: int = outLenDefault): seq[byte] {.inline.} =
  ## Public name for the local BLAKE3 hash.
  result = blake3Hash(input, outLen)

proc blake3TyrKeyedHash*(key, input: openArray[byte],
    outLen: int = outLenDefault): seq[byte] {.inline.} =
  ## Public name for the local keyed BLAKE3 hash.
  result = blake3KeyedHash(key, input, outLen)

proc sha3TyrHash*(input: openArray[byte],
    outLen: int = 32): seq[byte] {.inline.} =
  ## Public name for the local SHA3 hash.
  result = sha3Hash(input, outLen)

proc shake256Tyr*(input: openArray[byte], outLen: int): seq[byte] {.inline.} =
  ## Public name for the local SHAKE256 XOF.
  result = shake256(input, outLen)

proc shake128Tyr*(input: openArray[byte], outLen: int): seq[byte] {.inline.} =
  ## Public name for the local SHAKE128 XOF.
  result = shake128(input, outLen)
