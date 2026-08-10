## -------------------------------------------------------
## NuGimli <- experimental reversible wide Gimli profiles
## -------------------------------------------------------
##
## State:   [128-bit chunk 0] ... [128-bit chunk n]
## Encrypt: K xor P(X xor K)
## Decrypt: K xor P^-1(C xor K)
##
## These novel profiles have no published cryptanalysis or security claim.
## Keep them experimental until independent analysis establishes safe uses.

import ./nugimli/types
import ./nugimli/domain
import ./nugimli/cascade
import ./nugimli/reference

export types
export domain
export cascade
export reference
