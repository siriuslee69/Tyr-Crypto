## --------------------------------------------
## AES CTR <- compatibility facade to aes folder
## --------------------------------------------

import ./symmetric/aes/aes_ctr

export aes_ctr

proc aesCtrTyrXor*(k, n, ps: openArray[uint8], b: AesCtrBackend = acbAuto): seq[uint8] =
  ## Tyr-suffixed alias for the local AES-CTR xor helper.
  result = aesCtrXor(k, n, ps, b)

proc initAesCtrTyrState*(k, n: openArray[uint8]): AesCtrState =
  ## Tyr-suffixed alias for the local AES-CTR state initializer.
  result = initAesCtrState(k, n)
