import tyr_crypto

let alice = x25519TyrKeypair()
let bob = x25519TyrKeypair()

let aliceShared = x25519TyrShared(alice.secretKey, bob.publicKey)
let bobShared = x25519TyrShared(bob.secretKey, alice.publicKey)

doAssert aliceShared == bobShared
echo "X25519 shared secret (first 8 bytes): ", aliceShared[0..7].toHex
