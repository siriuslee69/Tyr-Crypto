## --------------------------------------------
## SHA3 <- compatibility facade to sha3 folder
## --------------------------------------------

import ./symmetric/sha3/sha3

export sha3

proc sha3TyrHash*(input: openArray[byte], outLen: int = 32): seq[byte] =
  ## Tyr-suffixed alias for the local SHA3 hash.
  result = sha3Hash(input, outLen)

proc shake256Tyr*(input: openArray[byte], outLen: int): seq[byte] =
  ## Tyr-suffixed alias for the local SHAKE256 XOF.
  result = shake256(input, outLen)

proc shake128Tyr*(input: openArray[byte], outLen: int): seq[byte] =
  ## Tyr-suffixed alias for the local SHAKE128 XOF.
  result = shake128(input, outLen)
