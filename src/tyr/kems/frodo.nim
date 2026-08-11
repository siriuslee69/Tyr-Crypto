## ------------------------------------------
## | FrodoKEM <- public surface
## ------------------------------------------
##
## Post-quantum KEM built on plain (unstructured) learning-with-errors.
##
## The full implementation lives in `./frodo/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./frodo/operations

export operations
