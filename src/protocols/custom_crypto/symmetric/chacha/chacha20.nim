## -----------------------------------------------------------------
## ChaCha20 <- compile-time Tyr SIMD dispatch with a scalar fallback
## -----------------------------------------------------------------

import ./chacha20_scalar as scalar

when defined(sse2) or defined(avx2) or defined(neon) or defined(arm64) or
    defined(aarch64):
  import ./xchacha20_simd as simd

const
  chacha20BlockSize* = scalar.chacha20BlockSize

proc requireChaCha20BlockRange*(initialCounter: uint32, byteLen: int) =
  ## Validate the public IETF counter range.
  scalar.requireChaCha20BlockRange(initialCounter, byteLen)

proc chacha20Block*(key, nonce: openArray[byte],
    counter: uint32 = 0'u32): array[chacha20BlockSize, byte] =
  ## Generate one block; SIMD starts at four independent blocks.
  result = scalar.chacha20Block(key, nonce, counter)

proc chacha20Xor*(key, nonce: openArray[byte], initialCounter: uint32,
    input: openArray[byte]): seq[byte] =
  ## Transform input with the best Tyr-native implementation in this build.
  when defined(sse2) or defined(avx2) or defined(neon) or defined(arm64) or
      defined(aarch64):
    result = simd.chacha20XorSimd(key, nonce, initialCounter, input)
  else:
    result = scalar.chacha20Xor(key, nonce, initialCounter, input)

proc chacha20Xor*(key, nonce: openArray[byte], input: openArray[byte]): seq[byte] =
  ## Transform input starting from counter zero.
  result = chacha20Xor(key, nonce, 0'u32, input)

proc chacha20XorInPlace*(key, nonce: openArray[byte], initialCounter: uint32,
    buffer: var openArray[byte]) =
  ## Transform a caller-owned buffer with compile-time SIMD dispatch.
  when defined(sse2) or defined(avx2) or defined(neon) or defined(arm64) or
      defined(aarch64):
    simd.chacha20XorInPlaceSimd(key, nonce, initialCounter, buffer)
  else:
    scalar.chacha20XorInPlace(key, nonce, initialCounter, buffer)

proc chacha20Stream*(key, nonce: openArray[byte], length: int,
    initialCounter: uint32 = 0'u32): seq[byte] =
  ## Generate a stream with compile-time SIMD dispatch.
  when defined(sse2) or defined(avx2) or defined(neon) or defined(arm64) or
      defined(aarch64):
    result = simd.chacha20StreamSimd(key, nonce, length, initialCounter)
  else:
    result = scalar.chacha20Stream(key, nonce, length, initialCounter)
