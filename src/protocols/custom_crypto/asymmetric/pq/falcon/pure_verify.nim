## ----------------------------------------------------------------
## Falcon Pure Verify <- end-to-end pure-Nim Falcon verification
## ----------------------------------------------------------------

import ./format
import ./params
import ./vrfy
import ../../../../helpers/otter_support

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; decoding, malformed-input rejection, and verification rules for `falconVerifyPure`; pitfall: fail closed and preserve canonical, constant-time comparison where secrets are involved.
proc falconVerifyPure*(v: FalconVariant, msg, sig, pk: openArray[byte]): bool {.otterBench.} =
  var
    decodedPk: FalconDecodedPublic
    decodedSig: FalconDecodedSignature
    hm: seq[uint16]
  if not decodePublicKeyToNtt(decodedPk, pk, v):
    return false
  if not decodeSignature(decodedSig, sig, v):
    return false
  hm = newSeq[uint16](1 shl decodedPk.logn)
  hashNonceMessageToPoint(hm, decodedSig.nonce, msg, decodedPk.logn)
  verifyRaw(hm, decodedSig.s2, decodedPk.h, decodedPk.logn)
