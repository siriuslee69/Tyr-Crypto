## --------------------------------------------------------
## X25519 <- custom Curve25519 facade for the hardened impl
## --------------------------------------------------------

import ./asymmetric/none_pq/[x25519_common, x25519_impl]
import ../helpers/otter_support

export x25519_common

proc x25519TyrShared*(secretKey, publicKey: openArray[byte]): seq[byte] {.otterTrace.} =
  result = x25519_impl.x25519TyrShared(secretKey, publicKey)

proc x25519TyrPublicKey*(secretKey: openArray[byte]): seq[byte] {.otterTrace.} =
  result = x25519_impl.x25519TyrPublicKey(secretKey)

proc x25519TyrKeypair*(): X25519TyrKeypair {.otterTrace.} =
  result = x25519_impl.x25519TyrKeypair()

proc x25519TyrKeypairFromSeed*(seed: openArray[byte]): X25519TyrKeypair {.otterTrace.} =
  result = x25519_impl.x25519TyrKeypairFromSeed(seed)

when defined(amd64) or defined(i386):
  proc x25519TyrSharedSse2x*(secretKeys, publicKeys: array[2, seq[byte]]): array[2, seq[byte]] =
    result = x25519_impl.x25519TyrSharedSse2x(secretKeys, publicKeys)

when defined(neon) or defined(arm64) or defined(aarch64):
  proc x25519TyrSharedNeon2x*(secretKeys, publicKeys: array[2, seq[byte]]): array[2, seq[byte]] =
    result = x25519_impl.x25519TyrSharedNeon2x(secretKeys, publicKeys)

when defined(avx2):
  proc x25519TyrSharedAvx4x*(secretKeys, publicKeys: array[4, seq[byte]]): array[4, seq[byte]] =
    result = x25519_impl.x25519TyrSharedAvx4x(secretKeys, publicKeys)
