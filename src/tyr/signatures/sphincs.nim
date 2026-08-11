## ------------------------------------------
## | SPHINCS+ <- public surface
## ------------------------------------------
##
## Post-quantum signatures built only from hashing. Large signatures, very conservative security.
##
## The full implementation lives in `./sphincs/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./sphincs/operations

export operations
