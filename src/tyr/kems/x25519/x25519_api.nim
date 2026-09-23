## X25519 public API wrappers included by x25519_impl.nim.
##
## Keeping these wrappers in the implementation module lets them use its
## private scalar routines without exporting internal helpers.

## Reference: [RFC-7748] sections 5-6, X25519 and Diffie-Hellman; implementation support for the family algorithms for `x25519ScalarmultBaseRaw`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc x25519ScalarmultBaseRaw*(publicKey: var X25519Bytes32,
    secretKey: X25519Bytes32): bool =
  result = x25519ScalarmultRaw(publicKey, secretKey, x25519Basepoint)

## Reference: [RFC-7748] sections 5-6, X25519 and Diffie-Hellman; implementation support for the family algorithms for `x25519TyrShared`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc x25519TyrShared*(secretKey, publicKey: openArray[byte]): seq[byte] {.otterTrace.} =
  var
    sk = toFixed32(secretKey)
    pk = toFixed32(publicKey)
    shared: X25519Bytes32 = default(X25519Bytes32)
  defer:
    secureClearPod(sk)
    secureClearPod(pk)
    secureClearPod(shared)
  if not x25519ScalarmultRaw(shared, sk, pk):
    raise newException(ValueError, "X25519 shared secret derivation failed")
  result = toSeqBytes(shared)

## Reference: [RFC-7748] sections 5-6, X25519 and Diffie-Hellman; implementation support for the family algorithms for `x25519TyrPublicKey`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc x25519TyrPublicKey*(secretKey: openArray[byte]): seq[byte] {.otterTrace.} =
  var
    sk = toFixed32(secretKey)
    pk: X25519Bytes32 = default(X25519Bytes32)
  defer:
    secureClearPod(sk)
    secureClearPod(pk)
  if not x25519ScalarmultBaseRaw(pk, sk):
    raise newException(ValueError, "X25519 public key derivation failed")
  result = toSeqBytes(pk)

## Reference: [RFC-7748] sections 5-6, X25519 and Diffie-Hellman; implementation support for the family algorithms for `x25519TyrKeypair`; pitfall: keep transcript order, domain separation, sizes, and secret wiping exact.
proc x25519TyrKeypair*(): X25519TyrKeypair {.otterTrace.} =
  var
    sk = randomSecret32()
    pk: X25519Bytes32 = default(X25519Bytes32)
  defer:
    secureClearPod(sk)
    secureClearPod(pk)
  if not x25519ScalarmultBaseRaw(pk, sk):
    raise newException(ValueError, "X25519 public key derivation failed")
  result.publicKey = toSeqBytes(pk)
  result.secretKey = toSeqBytes(sk)

## Reference: [RFC-7748] sections 5-6, X25519 and Diffie-Hellman; implementation support for the family algorithms for `x25519TyrKeypairFromSeed`; pitfall: keep transcript order, domain separation, sizes, and secret wiping exact.
proc x25519TyrKeypairFromSeed*(seed: openArray[byte]): X25519TyrKeypair {.otterTrace.} =
  var
    sk = deriveSeedSecretCompat(seed)
    pk: X25519Bytes32 = default(X25519Bytes32)
  defer:
    secureClearPod(sk)
    secureClearPod(pk)
  if not x25519ScalarmultBaseRaw(pk, sk):
    raise newException(ValueError, "X25519 public key derivation failed")
  result.publicKey = toSeqBytes(pk)
  result.secretKey = toSeqBytes(sk)
