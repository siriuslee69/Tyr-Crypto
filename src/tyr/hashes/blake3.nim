## ----------------------------------------
## | BLAKE3 <- public surface
## ----------------------------------------
##
## Fast tree-based hash. Also does keyed mode and key derivation.
##
## The full implementation lives in `./blake3/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./blake3/blake3

export blake3
