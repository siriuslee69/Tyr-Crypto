import tyr_crypto

let kp = kyberTyrKeypair(kyber768)

let ct = kyberTyrEncaps(kyber768, kp.publicKey)

let shared = kyberTyrDecaps(kyber768, kp.secretKey, ct.ciphertext)

assert shared == ct.sharedSecret, "KEM decapsulation mismatch"
echo "Kyber768 shared secret (first 8 bytes): ", shared[0..7].toHex
