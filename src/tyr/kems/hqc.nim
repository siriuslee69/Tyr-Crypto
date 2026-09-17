## --------------------------------------
## | HQC <- public surface
## --------------------------------------
##
## Hamming Quasi-Cyclic. A post-quantum key exchange whose security rests
## on how hard it is to decode a random linear code - the oldest and most
## studied hard problem in the post-quantum set, and a completely
## different one from the lattice problems Kyber and Frodo rely on.
##
## The full implementation lives in `./hqc/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./hqc/operations

export operations
