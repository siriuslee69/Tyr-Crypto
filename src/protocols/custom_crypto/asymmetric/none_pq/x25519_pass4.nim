## ----------------------------------------------------------
## X25519 Pass 4 <- pass 3 core with secret-lifetime hardening
## ----------------------------------------------------------

const
  x25519BenchTag = "x25519.pass4"
  x25519SplitHelpers = true
  x25519BatchInversion = true
  x25519SecureWipe = true

include ./x25519_impl_template
