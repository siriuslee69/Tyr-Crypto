## -------------------------------------------------
## XChaCha20 <- compatibility facade to chacha folder
## -------------------------------------------------

import ./symmetric/chacha/xchacha20

export xchacha20

proc hchacha20Tyr*(key, nonce: openArray[byte]): array[32, byte] =
  ## Tyr-suffixed alias for the local HChaCha20 core.
  result = hchacha20(key, nonce)

proc xchacha20TyrXor*(key, nonce: openArray[byte], input: openArray[byte]): seq[byte] =
  ## Tyr-suffixed alias for the local XChaCha20 xor helper.
  result = xchacha20Xor(key, nonce, input)

proc xchacha20TyrStream*(key, nonce: openArray[byte], length: int,
    initialCounter: uint32 = 0'u32): seq[byte] =
  ## Tyr-suffixed alias for the local XChaCha20 keystream helper.
  result = xchacha20Stream(key, nonce, length, initialCounter)
