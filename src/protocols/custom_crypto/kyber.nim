## -----------------------------------------------------
## Kyber <- compatibility facade to the Kyber core folder
## -----------------------------------------------------

import ./kyber/params
import ./kyber/types
import ./kyber/util
import ./kyber/reduce
import ./kyber/verify
import ./kyber/ntt
import ./kyber/symmetric
import ./kyber/cbd
import ./kyber/poly
import ./kyber/polyvec
import ./kyber/indcpa
import ./kyber/operations

## Compatibility facade note:
## This currently re-exports the full Kyber internals to keep KAT, profiling,
## and optimization work easy. Trim this export surface once the polished
## public API is finalized.

export params
export types
export util
export reduce
export verify
export ntt
export symmetric
export cbd
export poly
export polyvec
export indcpa
export operations
