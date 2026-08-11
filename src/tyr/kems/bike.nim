## --------------------------------------
## | BIKE <- public surface
## --------------------------------------
##
## Bit-flipping key encapsulation. Post-quantum KEM built on quasi-cyclic codes.
##
## The full implementation lives in `./bike/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./bike/operations

export operations
