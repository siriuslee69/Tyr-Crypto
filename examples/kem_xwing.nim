## X-Wing: ML-KEM-768 and X25519 in one KEM. An attacker must break both.

import std/strutils
import tyr

## std's toHex has no overload for byte sequences, so give it one.
proc toHex(b: openArray[byte]): string =
  for x in b:
    result.add strutils.toHex(x, 2)

var
  kp = xwingTyrKeypair()                                        # sk 32 B, pk 1216 B
  ct = xwingTyrEncaps(xwing768, kp.publicKey)                   # ct 1120 B
  shared = xwingTyrDecaps(xwing768, kp.secretKey, ct.ciphertext)

assert shared == ct.sharedSecret, "X-Wing decapsulation mismatch"
echo "X-Wing shared secret (first 8 bytes): ", shared[0..7].toHex
