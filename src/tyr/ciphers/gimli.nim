## ---------------------------------------
## | Gimli <- public surface
## ---------------------------------------
##
## The Gimli permutation itself, the shared core under the sponge modes.
##
## The full implementation lives in `./gimli/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./gimli/gimli_types
import ./gimli/gimli

export gimli_types
export gimli
