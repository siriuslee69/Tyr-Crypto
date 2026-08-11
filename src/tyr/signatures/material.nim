## ---------------------------------------------------------------------
## | Signature Material <- typed signing material, sizes in the type    |
## ---------------------------------------------------------------------
##
##   var sig = sign(message, ed25519SignM(secretKey: sk))
##   var ok  = verify(message, ed25519VerifyM(publicKey: pk, signature: sig))
##
## Signing material and verifying material are different types, and only
## the signing one holds a secret key. Code that merely checks signatures
## cannot be handed a secret key by accident, because the type it needs
## has no field for one.
##
## The key sizes here are the real ones - Falcon-512's 1281-byte secret
## key, Dilithium5's 4896 - so a key from the wrong parameter set is a
## compile error rather than a failure at verify time.
##
## Two routes per algorithm
## ------------------------
##   falcon0SignM        the library-backed route (liboqs / PQClean)
##   dilithium0TyrSignM  Tyr's own pure-Nim implementation
##
## The `Tyr` in the middle means "this repo's own version of it", the same
## split the algorithm enums use.

import ../helpers/material
import ../helpers/tiers
import ../helpers/random
import ./registry as wrapSign
import ./dilithium as customDilithium
import ./sphincs as customSphincs

export material

type
  ## Material for Ed25519 signing.
  ed25519SignM* = object
    secretKey*: array[64, byte]
  ## Material for Ed25519 signature verification.
  ed25519VerifyM* = object
    publicKey*: array[32, byte]
    signature*: array[64, byte]
  ## Material for Falcon-512 signing.
  falcon0SignM* = object
    secretKey*: array[1281, byte]
  ## Material for Falcon-512 signature verification.
  falcon0VerifyM* = object
    publicKey*: array[897, byte]
    signature*: seq[byte]
  ## Material for Falcon-1024 signing.
  falcon1SignM* = object
    secretKey*: array[2305, byte]
  ## Material for Falcon-1024 signature verification.
  falcon1VerifyM* = object
    publicKey*: array[1793, byte]
    signature*: seq[byte]
  ## Material for tier-0 Dilithium signing.
  dilithium0SignM* = object
    ## original Dilithium2 / standardized ML-DSA-44
    secretKey*: array[2560, byte]
  ## Material for tier-0 Dilithium signature verification.
  dilithium0VerifyM* = object
    ## original Dilithium2 / standardized ML-DSA-44
    publicKey*: array[1312, byte]
    signature*: array[2420, byte]
  ## Material for tier-1 Dilithium signing.
  dilithium1SignM* = object
    ## original Dilithium3 / standardized ML-DSA-65
    secretKey*: array[4032, byte]
  ## Material for tier-1 Dilithium signature verification.
  dilithium1VerifyM* = object
    ## original Dilithium3 / standardized ML-DSA-65
    publicKey*: array[1952, byte]
    signature*: array[3309, byte]
  ## Material for tier-2 Dilithium signing.
  dilithium2SignM* = object
    ## original Dilithium5 / standardized ML-DSA-87
    secretKey*: array[4896, byte]
  ## Material for tier-2 Dilithium signature verification.
  dilithium2VerifyM* = object
    ## original Dilithium5 / standardized ML-DSA-87
    publicKey*: array[2592, byte]
    signature*: array[4627, byte]
  ## Material for the pure-Nim Tyr tier-0 Dilithium signing path.
  dilithium0TyrSignM* = object
    ## original Dilithium2 / standardized ML-DSA-44
    secretKey*: array[2560, byte]
  ## Material for the pure-Nim Tyr tier-0 Dilithium verification path.
  dilithium0TyrVerifyM* = object
    ## original Dilithium2 / standardized ML-DSA-44
    publicKey*: array[1312, byte]
    signature*: array[2420, byte]
  ## Material for the pure-Nim Tyr tier-1 Dilithium signing path.
  dilithium1TyrSignM* = object
    ## original Dilithium3 / standardized ML-DSA-65
    secretKey*: array[4032, byte]
  ## Material for the pure-Nim Tyr tier-1 Dilithium verification path.
  dilithium1TyrVerifyM* = object
    ## original Dilithium3 / standardized ML-DSA-65
    publicKey*: array[1952, byte]
    signature*: array[3309, byte]
  ## Material for the pure-Nim Tyr tier-2 Dilithium signing path.
  dilithium2TyrSignM* = object
    ## original Dilithium5 / standardized ML-DSA-87
    secretKey*: array[4896, byte]
  ## Material for the pure-Nim Tyr tier-2 Dilithium verification path.
  dilithium2TyrVerifyM* = object
    ## original Dilithium5 / standardized ML-DSA-87
    publicKey*: array[2592, byte]
    signature*: array[4627, byte]
  ## Material for Ed448 signing.
  ed448SignM* = object
    secretKey*: array[57, byte]
  ## Material for Ed448 signature verification.
  ed448VerifyM* = object
    publicKey*: array[57, byte]
    signature*: array[114, byte]
  ## Material for the SHAKE 128f SPHINCS+ signing surface.
  sphincsShake128fSimpleSignM* = object
    secretKey*: array[64, byte]
  ## Material for the SHAKE 128f SPHINCS+ verification surface.
  sphincsShake128fSimpleVerifyM* = object
    publicKey*: array[32, byte]
    signature*: array[17088, byte]
  ## Material for the pure-Nim Tyr SHAKE 128f simple SPHINCS+ signing path.
  sphincsShake128fSimpleTyrSignM* = object
    secretKey*: array[64, byte]
  ## Material for the pure-Nim Tyr SHAKE 128f simple SPHINCS+ verification path.
  sphincsShake128fSimpleTyrVerifyM* = object
    publicKey*: array[32, byte]
    signature*: array[17088, byte]
  ## Material for the Haraka 128f SPHINCS+ signing surface.
  ## Compatibility alias surface; the local backend binding is SHAKE-128f-simple.
  sphincsHaraka128fSimpleSignM* = object
    secretKey*: array[64, byte]
  ## Material for the Haraka 128f SPHINCS+ verification surface.
  ## Compatibility alias surface; the local backend binding is SHAKE-128f-simple.
  sphincsHaraka128fSimpleVerifyM* = object
    publicKey*: array[32, byte]
    signature*: array[17088, byte]
  ## Material for the pure-Nim Tyr 128f simple SPHINCS+ signing path.
  ## Compatibility alias surface for the SHAKE-128f-simple backend.
  sphincsHaraka128fSimpleTyrSignM* = object
    secretKey*: array[64, byte]
  ## Material for the pure-Nim Tyr 128f simple SPHINCS+ verification path.
  ## Compatibility alias surface for the SHAKE-128f-simple backend.
  sphincsHaraka128fSimpleTyrVerifyM* = object
    publicKey*: array[32, byte]
    signature*: array[17088, byte]

## ╭⟢ Which layout entry each material type names

proc algorithmOf*(T: typedesc[ed25519SignM]): AlgorithmKind = akEd25519Sign
proc algorithmOf*(T: typedesc[ed25519VerifyM]): AlgorithmKind = akEd25519Verify
proc algorithmOf*(T: typedesc[falcon0SignM]): AlgorithmKind = akFalcon0Sign
proc algorithmOf*(T: typedesc[falcon0VerifyM]): AlgorithmKind = akFalcon0Verify
proc algorithmOf*(T: typedesc[falcon1SignM]): AlgorithmKind = akFalcon1Sign
proc algorithmOf*(T: typedesc[falcon1VerifyM]): AlgorithmKind = akFalcon1Verify
proc algorithmOf*(T: typedesc[dilithium0SignM]): AlgorithmKind = akDilithium0Sign
proc algorithmOf*(T: typedesc[dilithium0VerifyM]): AlgorithmKind = akDilithium0Verify
proc algorithmOf*(T: typedesc[dilithium1SignM]): AlgorithmKind = akDilithium1Sign
proc algorithmOf*(T: typedesc[dilithium1VerifyM]): AlgorithmKind = akDilithium1Verify
proc algorithmOf*(T: typedesc[dilithium2SignM]): AlgorithmKind = akDilithium2Sign
proc algorithmOf*(T: typedesc[dilithium2VerifyM]): AlgorithmKind = akDilithium2Verify
proc algorithmOf*(T: typedesc[dilithium0TyrSignM]): AlgorithmKind = akDilithium0TyrSign
proc algorithmOf*(T: typedesc[dilithium0TyrVerifyM]): AlgorithmKind = akDilithium0TyrVerify
proc algorithmOf*(T: typedesc[dilithium1TyrSignM]): AlgorithmKind = akDilithium1TyrSign
proc algorithmOf*(T: typedesc[dilithium1TyrVerifyM]): AlgorithmKind = akDilithium1TyrVerify
proc algorithmOf*(T: typedesc[dilithium2TyrSignM]): AlgorithmKind = akDilithium2TyrSign
proc algorithmOf*(T: typedesc[dilithium2TyrVerifyM]): AlgorithmKind = akDilithium2TyrVerify
proc algorithmOf*(T: typedesc[ed448SignM]): AlgorithmKind = akEd448Sign
proc algorithmOf*(T: typedesc[ed448VerifyM]): AlgorithmKind = akEd448Verify
proc algorithmOf*(T: typedesc[sphincsShake128fSimpleSignM]): AlgorithmKind =
  akSphincsShake128fSimpleSign
proc algorithmOf*(T: typedesc[sphincsShake128fSimpleVerifyM]): AlgorithmKind =
  akSphincsShake128fSimpleVerify
proc algorithmOf*(T: typedesc[sphincsShake128fSimpleTyrSignM]): AlgorithmKind =
  akSphincsShake128fSimpleTyrSign
proc algorithmOf*(T: typedesc[sphincsShake128fSimpleTyrVerifyM]): AlgorithmKind =
  akSphincsShake128fSimpleTyrVerify
proc algorithmOf*(T: typedesc[sphincsHaraka128fSimpleSignM]): AlgorithmKind =
  akSphincsHaraka128fSimpleSign
proc algorithmOf*(T: typedesc[sphincsHaraka128fSimpleVerifyM]): AlgorithmKind =
  akSphincsHaraka128fSimpleVerify
proc algorithmOf*(T: typedesc[sphincsHaraka128fSimpleTyrSignM]): AlgorithmKind =
  akSphincsHaraka128fSimpleTyrSign
proc algorithmOf*(T: typedesc[sphincsHaraka128fSimpleTyrVerifyM]): AlgorithmKind =
  akSphincsHaraka128fSimpleTyrVerify

## ╭⟢ Pick the algorithm by its tier value

proc genKeypair*(alg: SignatureAlgorithm): AsymKeypair =
  ## Build a signature keypair for one non-hybrid signature algorithm.
  var
    kp0: wrapSign.SignatureKeypair
  if alg in {saEd25519Falcon512Hybrid, saEd25519Falcon1024Hybrid}:
    raise newException(ValueError, "hybrid signature combinations are not supported by the typed material surface")
  kp0 = signatureKeypair(alg)
  result.publicKey = kp0.publicKey
  result.secretKey = kp0.secretKey

proc genKeypair*(alg: SignatureAlgorithm, seed: seq[uint8]): AsymKeypair =
  ## Build a signature keypair using deterministic seed material where the
  ## backend supports it.
  var
    kp0: wrapSign.SignatureKeypair
  if alg in {saEd25519Falcon512Hybrid, saEd25519Falcon1024Hybrid}:
    raise newException(ValueError,
      "hybrid signature combinations are not supported by the typed material surface")
  kp0 = signatureKeypair(alg, seed)
  result.publicKey = kp0.publicKey
  result.secretKey = kp0.secretKey

proc sign*(alg: SignatureAlgorithm, msg, secretKey: seq[uint8]): seq[uint8] =
  ## Create a detached signature with the selected signature backend.
  if alg in {saEd25519Falcon512Hybrid, saEd25519Falcon1024Hybrid}:
    raise newException(ValueError, "hybrid signature combinations are not supported by the typed material surface")
  result = signMessage(alg, msg, secretKey)

proc verify*(alg: SignatureAlgorithm, msg, signature, publicKey: seq[uint8]): bool =
  ## Verify a detached signature with the selected signature backend.
  if alg in {saEd25519Falcon512Hybrid, saEd25519Falcon1024Hybrid}:
    raise newException(ValueError, "hybrid signature combinations are not supported by the typed material surface")
  result = verifyMessage(alg, msg, signature, publicKey)

## ╭⟢ Signing and verifying from typed material

proc sign*(message: openArray[byte], m: ed25519SignM): seq[byte] =
  ## Sign `message` with typed Ed25519 material.
  result = sign(saEd25519, toSeqBytes(message), toSeqBytes(m.secretKey))

proc verify*(message: openArray[byte], m: ed25519VerifyM): bool =
  ## Verify an Ed25519 signature with typed verification material.
  result = verify(saEd25519, toSeqBytes(message),
    toSeqBytes(m.signature), toSeqBytes(m.publicKey))

proc sign*(message: openArray[byte], m: falcon0SignM): seq[byte] =
  result = sign(saFalcon512, toSeqBytes(message), toSeqBytes(m.secretKey))

proc verify*(message: openArray[byte], m: falcon0VerifyM): bool =
  result = verify(saFalcon512, toSeqBytes(message), toSeqBytes(m.signature),
    toSeqBytes(m.publicKey))

proc sign*(message: openArray[byte], m: falcon1SignM): seq[byte] =
  result = sign(saFalcon1024, toSeqBytes(message), toSeqBytes(m.secretKey))

proc verify*(message: openArray[byte], m: falcon1VerifyM): bool =
  result = verify(saFalcon1024, toSeqBytes(message), toSeqBytes(m.signature),
    toSeqBytes(m.publicKey))

proc sign*(message: openArray[byte], m: dilithium0SignM): seq[byte] =
  result = sign(saDilithium0, toSeqBytes(message), toSeqBytes(m.secretKey))

proc verify*(message: openArray[byte], m: dilithium0VerifyM): bool =
  result = verify(saDilithium0, toSeqBytes(message),
    toSeqBytes(m.signature), toSeqBytes(m.publicKey))

proc sign*(message: openArray[byte], m: dilithium1SignM): seq[byte] =
  result = sign(saDilithium1, toSeqBytes(message), toSeqBytes(m.secretKey))

proc verify*(message: openArray[byte], m: dilithium1VerifyM): bool =
  result = verify(saDilithium1, toSeqBytes(message),
    toSeqBytes(m.signature), toSeqBytes(m.publicKey))

proc sign*(message: openArray[byte], m: dilithium2SignM): seq[byte] =
  result = sign(saDilithium2, toSeqBytes(message), toSeqBytes(m.secretKey))

proc verify*(message: openArray[byte], m: dilithium2VerifyM): bool =
  result = verify(saDilithium2, toSeqBytes(message),
    toSeqBytes(m.signature), toSeqBytes(m.publicKey))

proc sign*(message: openArray[byte], m: dilithium0TyrSignM): seq[byte] =
  result = customDilithium.dilithiumTyrSign(customDilithium.dilithium44,
    toSeqBytes(message), toSeqBytes(m.secretKey))

proc verify*(message: openArray[byte], m: dilithium0TyrVerifyM): bool =
  result = customDilithium.dilithiumTyrVerify(customDilithium.dilithium44,
    toSeqBytes(message), toSeqBytes(m.signature), toSeqBytes(m.publicKey))

proc sign*(message: openArray[byte], m: dilithium1TyrSignM): seq[byte] =
  result = customDilithium.dilithiumTyrSign(customDilithium.dilithium65,
    toSeqBytes(message), toSeqBytes(m.secretKey))

proc verify*(message: openArray[byte], m: dilithium1TyrVerifyM): bool =
  result = customDilithium.dilithiumTyrVerify(customDilithium.dilithium65,
    toSeqBytes(message), toSeqBytes(m.signature), toSeqBytes(m.publicKey))

proc sign*(message: openArray[byte], m: dilithium2TyrSignM): seq[byte] =
  result = customDilithium.dilithiumTyrSign(customDilithium.dilithium87,
    toSeqBytes(message), toSeqBytes(m.secretKey))

proc verify*(message: openArray[byte], m: dilithium2TyrVerifyM): bool =
  result = customDilithium.dilithiumTyrVerify(customDilithium.dilithium87,
    toSeqBytes(message), toSeqBytes(m.signature), toSeqBytes(m.publicKey))

proc sign*(message: openArray[byte], m: ed448SignM): seq[byte] =
  result = sign(saEd448, toSeqBytes(message), toSeqBytes(m.secretKey))

proc verify*(message: openArray[byte], m: ed448VerifyM): bool =
  result = verify(saEd448, toSeqBytes(message),
    toSeqBytes(m.signature), toSeqBytes(m.publicKey))

proc sign*(message: openArray[byte], m: sphincsShake128fSimpleSignM): seq[byte] =
  result = sign(saSPHINCSPlusShake128fSimple, toSeqBytes(message), toSeqBytes(m.secretKey))

proc verify*(message: openArray[byte], m: sphincsShake128fSimpleVerifyM): bool =
  result = verify(saSPHINCSPlusShake128fSimple, toSeqBytes(message),
    toSeqBytes(m.signature), toSeqBytes(m.publicKey))

proc sign*(message: openArray[byte], m: sphincsShake128fSimpleTyrSignM): seq[byte] =
  result = customSphincs.sphincsTyrSignDerand(customSphincs.sphincsShake128fSimple,
    toSeqBytes(message), toSeqBytes(m.secretKey), cryptoRandomBytes(16))

proc verify*(message: openArray[byte], m: sphincsShake128fSimpleTyrVerifyM): bool =
  result = customSphincs.sphincsTyrVerify(customSphincs.sphincsShake128fSimple,
    toSeqBytes(message), toSeqBytes(m.signature), toSeqBytes(m.publicKey))

proc sign*(message: openArray[byte], m: sphincsHaraka128fSimpleSignM): seq[byte] =
  result = sign(saSPHINCSPlusShake128fSimple, toSeqBytes(message), toSeqBytes(m.secretKey))

proc verify*(message: openArray[byte], m: sphincsHaraka128fSimpleVerifyM): bool =
  result = verify(saSPHINCSPlusShake128fSimple, toSeqBytes(message),
    toSeqBytes(m.signature), toSeqBytes(m.publicKey))

proc sign*(message: openArray[byte], m: sphincsHaraka128fSimpleTyrSignM): seq[byte] =
  result = customSphincs.sphincsTyrSignDerand(customSphincs.sphincsShake128fSimple,
    toSeqBytes(message), toSeqBytes(m.secretKey), cryptoRandomBytes(16))

proc verify*(message: openArray[byte], m: sphincsHaraka128fSimpleTyrVerifyM): bool =
  result = customSphincs.sphincsTyrVerify(customSphincs.sphincsShake128fSimple,
    toSeqBytes(message), toSeqBytes(m.signature), toSeqBytes(m.publicKey))
