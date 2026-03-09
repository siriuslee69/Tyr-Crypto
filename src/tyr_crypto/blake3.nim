# ==============================================
# | BLAKE3 Bindings                             |
# |---------------------------------------------|
# | Optional wrapper around the local BLAKE3    |
# | implementation for the bindings layer.      |
# ==============================================

import ./common

when defined(hasBlake3):
  import ./custom_crypto/blake3 as blake3Impl

  proc blake3Hash*(input: openArray[byte]; outLen: int = outLenDefault): seq[byte] =
    ## input: data to hash.
    ## outLen: requested output length.
    blake3Impl.blake3Hash(input, outLen)
else:
  proc blake3Hash*(input: openArray[byte]; outLen: int = 32): seq[byte] =
    ## input: data to hash.
    ## outLen: requested output length.
    discard input
    discard outLen
    raiseUnavailable("blake3", "hasBlake3")
    return @[]
