## -------------------------------------------
## | Dilithium <- public surface
## -------------------------------------------
##
## Post-quantum signatures on module lattices. Standardised as ML-DSA.
##
## The full implementation lives in `./dilithium/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./dilithium/operations

export operations
