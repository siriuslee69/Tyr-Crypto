## -----------------------------------------------------
## Kyber <- compatibility facade to the Kyber core folder
## -----------------------------------------------------

import ./asymmetric/pq/kyber/params
import ./asymmetric/pq/kyber/types
import ./asymmetric/pq/kyber/util
import ./asymmetric/pq/kyber/reduce
import ./asymmetric/pq/kyber/verify
import ./asymmetric/pq/kyber/ntt
import ./asymmetric/pq/kyber/symmetric
import ./asymmetric/pq/kyber/cbd
import ./asymmetric/pq/kyber/poly
import ./asymmetric/pq/kyber/polyvec
import ./asymmetric/pq/kyber/indcpa
import ./asymmetric/pq/kyber/operations

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
