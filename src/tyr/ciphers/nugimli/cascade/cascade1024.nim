## ----------------------------------------------------------------
## NuGimli Cascade-1024 <- 1024-bit overlapping-window permutation
## ----------------------------------------------------------------

import tyrPragmas
import ../types
import ../core

proc cascadePermute1024*(S: var NuGimli1024) {.role: {math}.} =
  ## S: 1024-bit state transformed in place.
  cascadePermuteCore(S, nugimli1024Rounds)

proc cascadeInvert1024*(S: var NuGimli1024) {.role: {math}.} =
  ## S: 1024-bit state whose Cascade permutation is undone in place.
  cascadeInvertCore(S, nugimli1024Rounds)

proc cascadeEncrypt1024*(X, K: NuGimli1024): NuGimli1024 {.role: {encryptor}.} =
  ## X: 1024-bit plaintext block. K: 1024-bit key.
  result = cascadeEncryptCore(X, K, nugimli1024Rounds)

proc cascadeDecrypt1024*(C, K: NuGimli1024): NuGimli1024 {.role: {decryptor}.} =
  ## C: 1024-bit ciphertext block. K: 1024-bit key.
  result = cascadeDecryptCore(C, K, nugimli1024Rounds)
