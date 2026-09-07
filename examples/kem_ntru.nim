## NTRU-HPS-2048-509 <- keypair -> encapsulate -> decapsulate
##
## NTRU also reports which arithmetic backend ran. `ntruAuto` lets the
## library pick; the keypair carries back what it actually used, so a
## benchmark can say whether the AVX2 path was taken.
import std/strutils
import tyr

## std's toHex has no overload for byte sequences, so give it one.
proc toHex(b: openArray[byte]): string =
  for x in b:
    result.add strutils.toHex(x, 2)

var
  kp: NtruTyrKeypair = ntruTyrKeypair(ntruHps2048509)
  ct: NtruTyrCipher = ntruTyrEncaps(ntruHps2048509, kp.publicKey)
  shared: seq[byte] = ntruTyrDecaps(ntruHps2048509, kp.secretKey, ct.ciphertext)

assert shared == ct.sharedSecret, "KEM decapsulation mismatch"
echo "NTRU-HPS-2048-509 backend: ", kp.backend
echo "NTRU-HPS-2048-509 shared secret (first 8 bytes): ", shared[0..7].toHex
