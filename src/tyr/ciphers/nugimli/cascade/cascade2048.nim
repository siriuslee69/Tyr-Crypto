## ----------------------------------------------------------------
## NuGimli Cascade-2048 <- 2048-bit overlapping-window permutation
## ----------------------------------------------------------------

import tyrPragmas
import ../types
import ../core

proc cascadePermute2048*(S: var NuGimli2048) {.role: {math}.} =
  ## S: 2048-bit state transformed in place.
  cascadePermuteCore(S, nugimli2048Rounds)

proc cascadeInvert2048*(S: var NuGimli2048) {.role: {math}.} =
  ## S: 2048-bit state whose Cascade permutation is undone in place.
  cascadeInvertCore(S, nugimli2048Rounds)

proc cascadeEncrypt2048*(X, K: NuGimli2048): NuGimli2048 {.role: {encryptor}.} =
  ## X: 2048-bit plaintext block. K: 2048-bit key.
  result = cascadeEncryptCore(X, K, nugimli2048Rounds)

proc cascadeDecrypt2048*(C, K: NuGimli2048): NuGimli2048 {.role: {decryptor}.} =
  ## C: 2048-bit ciphertext block. K: 2048-bit key.
  result = cascadeDecryptCore(C, K, nugimli2048Rounds)
