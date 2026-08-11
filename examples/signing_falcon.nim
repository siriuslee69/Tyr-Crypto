import std/strutils
import tyr

let kp = falconTyrKeypair(falcon512)

let msg = @[byte 'M', byte 'e', byte 's', byte 's', byte 'a', byte 'g', byte 'e']
let sig = falconTyrSign(falcon512, msg, kp.secretKey)

let ok = falconTyrVerify(falcon512, msg, sig, kp.publicKey)
assert ok, "Falcon signature validation failed"
echo "Falcon-512 signature valid: ", ok
echo "Signature bytes: ", sig.len
