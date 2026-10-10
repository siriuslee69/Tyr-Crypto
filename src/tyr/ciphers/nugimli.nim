## ----------------------------------------------------------------
## | NuGimli Cascade <- public surface (EXPERIMENTAL)
## ----------------------------------------------------------------
##
## A wide, reversible scrambler built from the Gimli column box, in
## three sizes: 512, 1024 and 2048 bits.
##
##   state:    [chunk 0][chunk 1] ... [chunk n]     one chunk = 4 words = 128 bits
##   encrypt:  C = K xor P(X xor K)                  P = the Cascade scrambler
##   decrypt:  X = K xor P^-1(C xor K)
##
## ⚠ No published cryptanalysis exists. Do not protect real data with it
##   until an independent review says which uses are safe.
## ⚠ The key layer has a built-in relation for EVERY difference D:
##       encrypt(X xor D, K xor D) == encrypt(X, K) xor D
##   Never build keys by xoring a counter or a label into one master key.
##   Derive each key with `deriveCascade512/1024/2048` instead.
## ⚠ Decryption runs about 7-10x slower than encryption: undoing one
##   Gimli box takes 32 passes instead of one.
##
## The full implementation lives in `./nugimli/`. This file only lists
## what callers may use. The direct reference loops in
## `./nugimli/reference.nim` are a test oracle and stay out of it.
## Review and measurements: docs/NUGIMLI_REVIEW.md.

import ./nugimli/types
import ./nugimli/domain
import ./nugimli/cascade

export types, domain, cascade
