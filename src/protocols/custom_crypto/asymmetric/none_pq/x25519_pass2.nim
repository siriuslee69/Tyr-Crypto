## ----------------------------------------------------------------
## X25519 Pass 2 <- split long arithmetic into tiny inline helpers
## ----------------------------------------------------------------

const
  x25519BenchTag = "x25519.pass2"
  x25519SplitHelpers = true
  x25519BatchInversion = false
  x25519SecureWipe = false

include ./x25519_impl_template
