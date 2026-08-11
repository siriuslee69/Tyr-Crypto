## --------------------------------------------------
## | BLAKE3+Gimli KDF <- public surface
## --------------------------------------------------
##
## Fast staged derivation for material that is already a strong secret.
##
## The full implementation lives in `./blake3_gimli_kdf/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./blake3_gimli_kdf/blake3_gimli_kdf

export blake3_gimli_kdf
