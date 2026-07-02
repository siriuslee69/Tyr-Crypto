import tyr_crypto

let kp = dilithiumTyrKeypair(dilithium65)

let msg = @[byte 'M', 'e', 's', 's', 'a', 'g', 'e']
let sig = dilithiumTyrSign(dilithium65, msg, kp.secretKey)

let ok = dilithiumTyrVerify(dilithium65, msg, sig, kp.publicKey)
assert ok, "signature validation failed"
echo "Dilithium65 signature valid: ", ok
