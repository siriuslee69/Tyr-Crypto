## ---------------------------------------
## | Kyber <- public surface
## ---------------------------------------
##
## Post-quantum KEM built on module learning-with-errors. CRYSTALS round 3.
##
## The full implementation lives in `./kyber/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./kyber/operations

export operations
