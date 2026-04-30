## --------------------------------------------------------
## X25519 Pass 1 <- direct-ish libsodium ref10 scalar port
## --------------------------------------------------------

const
  x25519BenchTag = "x25519.pass1"
  x25519SplitHelpers = false
  x25519BatchInversion = false
  x25519SecureWipe = false

include ./x25519_impl_template
