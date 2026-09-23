## ---------------------------------------------------------------------
## | KEM material (Tyr-only) <- NTRU, SABER and HQC on the typed tier    |
## ---------------------------------------------------------------------
##
## For each material pair this checks three things:
##
##   1. the byte sizes in the layout table equal the sizes in the type
##      and the sizes the family itself produces
##   2. genKeypair -> seal -> open gives the sender's shared secret back
##   3. a damaged ciphertext still opens, to a DIFFERENT 32-byte secret
##      (implicit rejection), rather than raising

import std/unittest

import runePragmas
import ../../src/tyr

proc copyInto[N: static[int]](dst: var array[N, byte], src: openArray[byte])
    {.role: {helper}.} =
  ## dst/src: fixed-size material slot, and key bytes of exactly N.
  var
    i: int = 0
  check src.len == N
  while i < N:
    dst[i] = src[i]
    i = i + 1

proc checkMaterialPair[S, O](sendT: typedesc[S], openT: typedesc[O])
    {.role: {orchestrator}.} =
  ## sendT/openT: one send/open material pair, e.g. hqc0TyrSendM/hqc0TyrOpenM.
  var
    s = default(S)
    o = default(O)
    kp = default(AsymKeypair)
    sealed = default(AsymCipher)
    bad = default(AsymEnvelope)
    sendLayout = layoutOf(algorithmOf(S))
    openLayout = layoutOf(algorithmOf(O))
  check sendLayout.keyLayouts[0].size == s.receiverPublicKey.len
  check openLayout.keyLayouts[0].size == o.receiverSecretKey.len
  check sendLayout.outputBytes == 32
  kp = genKeypair(S)
  check kp.publicKey.len == s.receiverPublicKey.len
  check kp.secretKey.len == o.receiverSecretKey.len
  copyInto(s.receiverPublicKey, kp.publicKey)
  copyInto(o.receiverSecretKey, kp.secretKey)
  sealed = seal(s)
  check sealed.sharedSecret.len == 32
  check sealed.envelope.senderPublicKey.len == 0
  check open(sealed.envelope, o) == sealed.sharedSecret
  check open(sealed, o) == sealed.sharedSecret
  bad = sealed.envelope
  bad.ciphertext[0] = bad.ciphertext[0] xor 0x01'u8
  check open(bad, o).len == 32
  check open(bad, o) != sealed.sharedSecret

suite "kem material tyr":
  # {.testKind: tkIntegration, covers: "genKeypair, seal, open".}
  test "NTRU typed materials round trip and reject a damaged ciphertext":
    checkMaterialPair(ntru0TyrSendM, ntru0TyrOpenM)
    checkMaterialPair(ntru1TyrSendM, ntru1TyrOpenM)
    checkMaterialPair(ntru2TyrSendM, ntru2TyrOpenM)
    checkMaterialPair(ntruHrss0TyrSendM, ntruHrss0TyrOpenM)

  # {.testKind: tkIntegration, covers: "genKeypair, seal, open".}
  test "SABER typed materials round trip and reject a damaged ciphertext":
    checkMaterialPair(saber0TyrSendM, saber0TyrOpenM)
    checkMaterialPair(saber1TyrSendM, saber1TyrOpenM)
    checkMaterialPair(saber2TyrSendM, saber2TyrOpenM)

  # {.testKind: tkIntegration, covers: "genKeypair, seal, open".}
  test "HQC typed materials round trip and reject a damaged ciphertext":
    checkMaterialPair(hqc0TyrSendM, hqc0TyrOpenM)
    checkMaterialPair(hqc1TyrSendM, hqc1TyrOpenM)
    checkMaterialPair(hqc2TyrSendM, hqc2TyrOpenM)
