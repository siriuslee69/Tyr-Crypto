## --------------------------------------------
## | Custom KDF <- public surface
## --------------------------------------------
##
## Tyr's own configurable memory-hard derivation. Fast profile; not for raw passwords.
##
## The full implementation lives in `./kdf/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./kdf/kdf

export kdf
