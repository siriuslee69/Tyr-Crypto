import std/strutils
import tyr

## std's toHex has no overload for byte sequences, so give it one.
proc toHex(b: openArray[byte]): string =
  for x in b:
    result.add strutils.toHex(x, 2)

var kp = genKeypair(mceliece0TyrSendM)

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
