## ---------------------------------------
## | SABER <- public surface
## ---------------------------------------
##
## Post-quantum KEM built on module learning-with-rounding.
##
## The full implementation lives in `./saber/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./saber/operations

export operations
