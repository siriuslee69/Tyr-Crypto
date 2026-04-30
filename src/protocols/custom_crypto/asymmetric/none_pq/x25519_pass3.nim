## ---------------------------------------------------------------
## X25519 Pass 3 <- refactored core plus paper-inspired fast path
## ---------------------------------------------------------------

const
  x25519BenchTag = "x25519.pass3"
  x25519SplitHelpers = true
  x25519BatchInversion = true
  x25519SecureWipe = false

include ./x25519_impl_template
