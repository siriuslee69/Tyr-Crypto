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
## Every call works on all three widths; the state type picks the width:
##
##   var S: NuGimli1024                   # or NuGimli512 / NuGimli2048
##   cascadePermute(S)                    # S = P(S)
##   cascadeInvert(S)                     # S = P^-1(S)
##   C = cascadeEncrypt(X, K)             # X, K, C: one width
##   X = cascadeDecrypt(C, K)
##   m = deriveCascade(NuGimli2048, S, tag)  # key + state for another width
##
## ⚠ No published cryptanalysis exists. Do not protect real data with it
##   until an independent review says which uses are safe.
## ⚠ The key layer has a built-in relation for EVERY difference D:
##       encrypt(X xor D, K xor D) == encrypt(X, K) xor D
##   Never build keys by xoring a counter or a label into one master key.
##   Derive each key with `deriveCascade` instead.
## ⚠ Decryption runs about 7-10x slower than encryption: undoing one
##   Gimli box takes 32 passes instead of one.
## ⚠ Design revision 2 (2026-10-11) changed every output: the lane swap
##   now hits every even chunk. Data from revision 1 does not decrypt.
##
## The implementation lives in `./nugimli/`:
##   types    widths, round counts, chunk swap
##   core     the round steps and the five calls above
##   domain   deriveCascade (tagged SHAKE256)
##   scalar_box / simd_box   the Gimli box, portable and SSE2/NEON
## Review and measurements: docs/NUGIMLI_REVIEW.md.

import ./nugimli/types
import ./nugimli/domain
import ./nugimli/core

export types, domain, core
