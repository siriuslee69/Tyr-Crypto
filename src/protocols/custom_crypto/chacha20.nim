## ------------------------------------------------
## ChaCha20 <- compatibility facade to chacha folder
## ------------------------------------------------

import ./symmetric/chacha/chacha20

export chacha20

proc chacha20TyrXor*(key, nonce: openArray[byte], input: openArray[byte]): seq[byte] =
  ## Tyr-suffixed alias for the local ChaCha20 xor helper.
  result = chacha20Xor(key, nonce, input)

proc chacha20TyrStream*(key, nonce: openArray[byte], length: int,
    initialCounter: uint32 = 0'u32): seq[byte] =
  ## Tyr-suffixed alias for the local ChaCha20 keystream helper.
  result = chacha20Stream(key, nonce, length, initialCounter)
