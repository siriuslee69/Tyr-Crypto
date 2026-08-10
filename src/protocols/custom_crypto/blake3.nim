## ------------------------------------------------
## Blake3 <- compatibility facade to blake3 folder
## ------------------------------------------------

import ./symmetric/blake3/blake3

export blake3

proc blake3TyrHash*(input: openArray[byte], outLen: int = outLenDefault): seq[byte] =
  ## Tyr-suffixed alias for the local BLAKE3 hash.
  result = blake3Hash(input, outLen)

proc blake3TyrKeyedHash*(key, input: openArray[byte],
    outLen: int = outLenDefault): seq[byte] =
  ## Tyr-suffixed alias for the local keyed BLAKE3 hash.
  result = blake3KeyedHash(key, input, outLen)
