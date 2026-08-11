## ---------------------------------------
## | SHA-3 <- public surface
## ---------------------------------------
##
## Keccak sponge hash, plus the SHAKE extendable-output functions.
##
## The full implementation lives in `./sha3/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./sha3/sha3

export sha3
