## ----------------------------------------
## | Falcon <- public surface
## ----------------------------------------
##
## Post-quantum signatures on NTRU lattices. Compact signatures, delicate floating-point core.
##
## The full implementation lives in `./falcon/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./falcon/operations

export operations
