## ---------------------------------------------------------------------
## | Hash Dynamic <- pick the family from a VALUE while the program runs |
## ---------------------------------------------------------------------
##
## `digestOf` takes the family as data, so the choice can come from a
## config file or a message header. The name ends in `Of` so this tier can
## be imported alongside `tyr/hashes` without clashing.

import ./types
import ./blake3
import ./sha256
import ./sha512
import ./sha3

export types

proc digestOf*(f: HashFamily, data: openArray[byte], outLen: int = 0): seq[byte] =
  ## f/data/outLen: family read at runtime, bytes to fingerprint, wanted length.
  ## `outLen = 0` selects the family's natural length.
  var n: int = outLen
  if n <= 0:
    n = defaultDigestBytes[f]
  case f
  of hfBlake3: result = blake3Hash(data, n)
  of hfSha3:   result = sha3Hash(data, n)
  of hfSha256: result = @(sha256Hash(data))
  of hfSha512: result = @(sha512Hash(data))
