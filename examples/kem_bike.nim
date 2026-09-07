## BIKE-L1 <- keypair -> encapsulate -> decapsulate
##
## Same three steps as every KEM here. BIKE has one parameter set, so the
## variant name carries no size suffix to choose between.
import std/strutils
import tyr

## std's toHex has no overload for byte sequences, so give it one.
proc toHex(b: openArray[byte]): string =
  for x in b:
    result.add strutils.toHex(x, 2)

var
  kp: BikeTyrKeypair = bikeTyrKeypair(bikeL1)
  ct: BikeTyrCipher = bikeTyrEncaps(bikeL1, kp.publicKey)
  shared: seq[byte] = bikeTyrDecaps(bikeL1, kp.secretKey, ct.ciphertext)

assert shared == ct.sharedSecret, "KEM decapsulation mismatch"
echo "BIKE-L1 shared secret (first 8 bytes): ", shared[0..7].toHex
