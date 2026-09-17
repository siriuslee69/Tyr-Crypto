## HQC <- keypair -> encapsulate -> decapsulate
##
## Same three steps as every KEM here. HQC has three parameter sets,
## `hqc1`, `hqc3` and `hqc5`; the digit is the NIST security category,
## not a key length.
##
## HQC rests on a different hard problem from Kyber and Frodo: decoding a
## random linear code rather than anything about lattices. That makes it
## the sensible second half of a hybrid, because one advance in lattice
## cryptanalysis cannot take both halves at once.
import std/strutils
import tyr

## std's toHex has no overload for byte sequences, so give it one.
proc toHex(b: openArray[byte]): string =
  for x in b:
    result.add strutils.toHex(x, 2)

var
  kp: HqcTyrKeypair = hqcTyrKeypair(hqc1)
  ct: HqcTyrCipher = hqcTyrEncaps(hqc1, kp.publicKey)
  shared: seq[byte] = hqcTyrDecaps(hqc1, kp.secretKey, ct.ciphertext)

assert shared == ct.sharedSecret, "KEM decapsulation mismatch"
echo "HQC-1 public key is ", kp.publicKey.len, " bytes"
echo "HQC-1 ciphertext is ", ct.ciphertext.len, " bytes"
echo "HQC-1 shared secret, first 8 bytes ", shared[0..7].toHex

## A tampered ciphertext does NOT raise. It returns a different but
## equally normal-looking secret, so an attacker learns nothing from the
## reply. Both sides simply fail to agree, and the protocol above notices.
var damaged: seq[byte] = ct.ciphertext
damaged[0] = damaged[0] xor 1'u8
echo "tampered ciphertext still returns 32 bytes, and they differ: ",
  hqcTyrDecaps(hqc1, kp.secretKey, damaged) != shared
