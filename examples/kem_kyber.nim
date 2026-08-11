import std/strutils
import tyr

## std's toHex has no overload for byte sequences, so give it one.
proc toHex(b: openArray[byte]): string =
  for x in b:
    result.add strutils.toHex(x, 2)

let kp = kyberTyrKeypair(kyber768)

let ct = kyberTyrEncaps(kyber768, kp.publicKey)

let shared = kyberTyrDecaps(kyber768, kp.secretKey, ct.ciphertext)

assert shared == ct.sharedSecret, "KEM decapsulation mismatch"
echo "Kyber768 shared secret (first 8 bytes): ", shared[0..7].toHex
