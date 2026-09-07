## SPHINCS+ (SHAKE-128f-simple) <- keypair -> sign -> verify
##
## A signature scheme proves a message came from the secret key holder:
##
##   signer                              verifier
##     | keypair()                          |
##     |----------- publicKey ------------->|
##     | sign(msg, secretKey)               |
##     |----------- msg + sig ------------->| verify(msg, sig, publicKey)
##                                          v
##                                     true / false
##
## SPHINCS+ builds only on hashing, so its security rests on nothing but
## the hash function. The trade is size: signatures are far larger than
## Dilithium's or Falcon's.
import tyr

var
  kp: SphincsTyrKeypair = sphincsTyrKeypair(sphincsShake128fSimple)
  msg: seq[byte] = @[]
  sig: seq[byte] = @[]
  ok: bool = false

for ch in "Tyr signs with SPHINCS+":
  msg.add byte(ord(ch))

sig = sphincsTyrSign(sphincsShake128fSimple, msg, kp.secretKey)
ok = sphincsTyrVerify(sphincsShake128fSimple, msg, sig, kp.publicKey)

assert ok, "SPHINCS+ verification failed"
echo "SPHINCS+ signature bytes: ", sig.len
echo "SPHINCS+ verify: ", ok
