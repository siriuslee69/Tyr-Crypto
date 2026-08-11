import std/strutils
import tyr

## std's toHex has no overload for byte sequences, so give it one.
proc toHex(b: openArray[byte]): string =
  for x in b:
    result.add strutils.toHex(x, 2)

let alice = x25519TyrKeypair()
let bob = x25519TyrKeypair()

let aliceShared = x25519TyrShared(alice.secretKey, bob.publicKey)
let bobShared = x25519TyrShared(bob.secretKey, alice.publicKey)

doAssert aliceShared == bobShared
echo "X25519 shared secret (first 8 bytes): ", aliceShared[0..7].toHex
