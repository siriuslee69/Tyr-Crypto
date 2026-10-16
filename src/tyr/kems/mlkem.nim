## ---------------------------------------
## | ML-KEM <- public surface
## ---------------------------------------
##
## Post-quantum KEM built on module learning-with-errors. FIPS 203 ML-KEM
## (the standardised CRYSTALS-Kyber; round-3 Kyber is no longer in Tyr).
##
## The full implementation lives in `./mlkem/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./mlkem/operations

export operations
