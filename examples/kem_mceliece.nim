import tyr_crypto

var kp = asymKeypair(mceliece0TyrSendM)

var
  sendM: mceliece0TyrSendM
  openM: mceliece0TyrOpenM

for i in 0 ..< sendM.receiverPublicKey.len:
  sendM.receiverPublicKey[i] = kp.publicKey[i]
for i in 0 ..< openM.receiverSecretKey.len:
  openM.receiverSecretKey[i] = kp.secretKey[i]

var env = seal(sendM)
var shared = open(env, openM)
doAssert shared == env.sharedSecret
echo "McEliece shared secret (first 8 bytes): ", shared[0..7].toHex
