## -------------------------------------
## | RSA <- public surface
## -------------------------------------
##
## RSA key parsing and digest helpers used when reading X.509 certificates.
##
## The full implementation lives in `./rsa/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./rsa/rsa

export rsa
