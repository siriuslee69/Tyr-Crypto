import tyr_crypto

let kp = falconTyrKeypair(falcon512)

let msg = @[byte 'M', 'e', 's', 's', 'a', 'g', 'e']
let sig = falconTyrSign(falcon512, msg, kp.secretKey)

let ok = falconTyrVerify(falcon512, msg, sig, kp.publicKey)
assert ok, "Falcon signature validation failed"
echo "Falcon-512 signature valid: ", ok
echo "Signature bytes: ", sig.len
