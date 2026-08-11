## ---------------------------------------------------------------------
## | Hashes <- default tier: one `digest` name for every hash family    |
## ---------------------------------------------------------------------
##
##   import tyr/hashes            <- THIS FILE. digest(hfBlake3, data)
##   import tyr/hashes/blake3     <- one family: blake3Hash(data)
##   import tyr/hashes/dynamic    <- pick from a stored value at runtime
##   import tyr/hashes/single     <- one family by build flag, for devices
##
## Unlike the KEM and signature tiers, hash families have no per-family
## variant type to overload on, so the family is named by its enum value.

import ./hashes/types
import ./hashes/blake3
import ./hashes/sha256
import ./hashes/sha512
import ./hashes/sha3

export types
export blake3, sha256, sha512, sha3

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
