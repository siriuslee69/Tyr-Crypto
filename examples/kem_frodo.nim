## FrodoKEM-976-AES <- keypair -> encapsulate -> decapsulate
##
## A KEM does not encrypt a message. It agrees on one shared secret:
##
##   sender                             receiver
##     |                                   |
##     |<--------- publicKey --------------| keypair()
##     | encaps(publicKey)                 |
##     |---------- ciphertext ------------>| decaps(secretKey, ciphertext)
##     |                                   |
##   sharedSecret                     sharedSecret   <- the same bytes
import std/strutils
import tyr

## std's toHex has no overload for byte sequences, so give it one.
proc toHex(b: openArray[byte]): string =
  for x in b:
    result.add strutils.toHex(x, 2)

var
  kp: FrodoTyrKeypair = frodoTyrKeypair(frodo976aes)
  ct: FrodoTyrCipher = frodoTyrEncaps(frodo976aes, kp.publicKey)
  shared: seq[byte] = frodoTyrDecaps(frodo976aes, kp.secretKey, ct.ciphertext)

assert shared == ct.sharedSecret, "KEM decapsulation mismatch"
echo "FrodoKEM-976-AES shared secret (first 8 bytes): ", shared[0..7].toHex
