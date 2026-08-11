## --------------------------------------------------------------
## NuGimli Cascade-512 <- 512-bit overlapping-window permutation
## --------------------------------------------------------------

import metaPragmas
import ../types
import ../core

proc cascadePermute512*(S: var NuGimli512) {.role: {math}.} =
  ## S: 512-bit state transformed in place.
  cascadePermuteCore(S, nugimli512Rounds)

proc cascadeInvert512*(S: var NuGimli512) {.role: {math}.} =
  ## S: 512-bit state whose Cascade permutation is undone in place.
  cascadeInvertCore(S, nugimli512Rounds)

proc cascadeEncrypt512*(X, K: NuGimli512): NuGimli512 {.role: {encryptor}.} =
  ## X: 512-bit plaintext block. K: 512-bit key.
  result = cascadeEncryptCore(X, K, nugimli512Rounds)

proc cascadeDecrypt512*(C, K: NuGimli512): NuGimli512 {.role: {decryptor}.} =
  ## C: 512-bit ciphertext block. K: 512-bit key.
  result = cascadeDecryptCore(C, K, nugimli512Rounds)
