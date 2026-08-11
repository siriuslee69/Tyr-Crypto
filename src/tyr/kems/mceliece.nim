## --------------------------------------------------
## | Classic McEliece <- public surface
## --------------------------------------------------
##
## Post-quantum KEM built on binary Goppa codes. Very large public keys, very small ciphertexts.
##
## The full implementation lives in `./mceliece/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./mceliece/operations

export operations
