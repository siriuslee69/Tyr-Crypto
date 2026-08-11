## --------------------------------------
## | NTRU <- public surface
## --------------------------------------
##
## Post-quantum KEM built on polynomial rings.
##
## The full implementation lives in `./ntru/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./ntru/operations

export operations
