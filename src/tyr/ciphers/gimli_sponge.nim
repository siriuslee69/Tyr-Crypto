## ----------------------------------------------
## | Gimli Sponge <- public surface
## ----------------------------------------------
##
## Gimli in sponge mode: stream encryption, hashing and tags.
##
## The full implementation lives in `./gimli/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./gimli/gimli_sponge

export gimli_sponge
