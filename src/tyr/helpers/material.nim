## ---------------------------------------------------------------------
## | Material Core <- what every module's typed material surface shares  |
## | one AlgorithmKind list, one layout table, one envelope shape        |
## ---------------------------------------------------------------------
##
## What the material surface is
## ----------------------------
## Beside the family tiers (`keypair(kyber768)`, `digest(hfBlake3, data)`)
## Tyr offers a second, stricter way to name an algorithm: a MATERIAL
## TYPE that carries the exact key and nonce sizes in the type itself.
##
##   var m = xchacha20cipherM(key: k, nonce: n)   <- wrong size = won't compile
##   var ct = encrypt(msg, m)
##
## The family tiers take `openArray[byte]` and check lengths while running.
## The material types make a wrong length a compile error instead. Use the
## family tiers for ordinary code and the material types where a size
## mistake must be impossible.
##
## Each module owns its own material types, next to the algorithms they
## describe:
##
##   tyr/hashes/material       blake3HashM sha3HashM ...
##   tyr/macs/material         blake3hmacM poly1305hmacM ...
##   tyr/ciphers/material      xchacha20cipherM aesCtrcipherM ...
##   tyr/signatures/material   ed25519SignM falcon0VerifyM ...
##   tyr/kems/material         kyber0SendM mceliece0OpenM ...
##
## THIS FILE holds only what all five need in common, and nothing that
## belongs to one algorithm. It imports nothing.
##
## Three things live here
## ----------------------
##   AlgorithmKind      one flat list naming every typed entry in Tyr.
##                      It stays whole because `algorithmLayouts` below is
##                      indexed by it - splitting the list would split the
##                      table into five that no longer line up.
##   algorithmLayouts   the sizes each entry expects, as data. `layoutOf`
##                      reads it; nothing needs a `case` to answer "how
##                      long is this key".
##   AsymEnvelope &co   the shapes KEM results travel in, shared so that
##                      `seal` in one module and `open` in another agree.

const
  maxKeyLayouts* = 2
  digestBytes* = 32
  variableLayoutSize = -1

type
  ## High-level operation bucket for an exported algorithm entry.
  OperationKind* = enum
    okHash,
    okHmac,
    okVerify,
    okSign,
    okCipher,
    okKemSend,
    okKemOpen

  ## Concrete typed operation id used by the layout table and dispatch helpers.
  AlgorithmKind* = enum
    akBlake3Hash,
    akGimliHash,
    akSha3Hash,
    akBlake3KeyedHash,
    akBlake3Hmac,
    akGimliHmac,
    akPoly1305Hmac,
    akSha3Hmac,
    akXChaCha20Cipher,
    akAesCtrCipher,
    akGimliStreamCipher,
    akEd25519Sign,
    akEd25519Verify,
    akFalcon0Sign,
    akFalcon0Verify,
    akFalcon1Sign,
    akFalcon1Verify,
    akDilithium0Sign, ## original Dilithium2 / standardized ML-DSA-44
    akDilithium0Verify, ## original Dilithium2 / standardized ML-DSA-44
    akDilithium1Sign, ## original Dilithium3 / standardized ML-DSA-65
    akDilithium1Verify, ## original Dilithium3 / standardized ML-DSA-65
    akDilithium2Sign, ## original Dilithium5 / standardized ML-DSA-87
    akDilithium2Verify, ## original Dilithium5 / standardized ML-DSA-87
    akDilithium0TyrSign, ## original Dilithium2 / standardized ML-DSA-44
    akDilithium0TyrVerify, ## original Dilithium2 / standardized ML-DSA-44
    akDilithium1TyrSign, ## original Dilithium3 / standardized ML-DSA-65
    akDilithium1TyrVerify, ## original Dilithium3 / standardized ML-DSA-65
    akDilithium2TyrSign, ## original Dilithium5 / standardized ML-DSA-87
    akDilithium2TyrVerify, ## original Dilithium5 / standardized ML-DSA-87
    akEd448Sign,
    akEd448Verify,
    akSphincsShake128fSimpleSign,
    akSphincsShake128fSimpleVerify,
    akSphincsShake128fSimpleTyrSign,
    akSphincsShake128fSimpleTyrVerify,
    akSphincsHaraka128fSimpleSign,
    akSphincsHaraka128fSimpleVerify,
    akSphincsHaraka128fSimpleTyrSign,
    akSphincsHaraka128fSimpleTyrVerify,
    akX25519Send,
    akX25519Open,
    akKyber0Send,
    akKyber0Open,
    akKyber1Send,
    akKyber1Open,
    akKyber0TyrSend,
    akKyber0TyrOpen,
    akKyber1TyrSend,
    akKyber1TyrOpen,
    akMcEliece0Send,
    akMcEliece0Open,
    akMcEliece1Send,
    akMcEliece1Open,
    akMcEliece2Send,
    akMcEliece2Open,
    akMcEliece0TyrSend,
    akMcEliece0TyrOpen,
    akMcEliece1TyrSend,
    akMcEliece1TyrOpen,
    akMcEliece2TyrSend,
    akMcEliece2TyrOpen,
    akFrodo0AesSend,
    akFrodo0AesOpen,
    akFrodo0ShakeSend,
    akFrodo0ShakeOpen,
    akFrodo1AesSend,
    akFrodo1AesOpen,
    akFrodo1ShakeSend,
    akFrodo1ShakeOpen,
    akFrodo2AesSend,
    akFrodo2AesOpen,
    akFrodo2ShakeSend,
    akFrodo2ShakeOpen,
    akFrodo0AesTyrSend,
    akFrodo0AesTyrOpen,
    akFrodo0ShakeTyrSend,
    akFrodo0ShakeTyrOpen,
    akFrodo1AesTyrSend,
    akFrodo1AesTyrOpen,
    akFrodo1ShakeTyrSend,
    akFrodo1ShakeTyrOpen,
    akFrodo2AesTyrSend,
    akFrodo2AesTyrOpen,
    akFrodo2ShakeTyrSend,
    akFrodo2ShakeTyrOpen,
    akNtruPrime0Send,
    akNtruPrime0Open,
    akBike0TyrSend,
    akBike0TyrOpen,
    akBike0Send,
    akBike0Open,
    akChaCha20Cipher

  ## Role of one material slot inside an algorithm layout.
  KeyKind* = enum
    kkSym,
    kkNonce,
    kkPublicKey,
    kkSecretKey,
    kkSignature

  ## Fixed description of one expected key/nonce/signature slot.
  KeyLayout* = object
    keyKind*: KeyKind
    size*: int

  ## Static metadata for one typed algorithm surface entry.
  AlgorithmLayout* = object
    algorithmKind*: AlgorithmKind
    operationKind*: OperationKind
    keyLayoutCount*: uint8
    keyLayouts*: array[maxKeyLayouts, KeyLayout]
    outputBytes*: int

  ## Public asymmetric/KEM envelope that is safe to serialize or send.
  AsymEnvelope* = object
    ciphertext*: seq[uint8]
    senderPublicKey*: seq[uint8]

  ## Local asymmetric/KEM result returned by `seal` and `encaps`.
  AsymCipher* = object
    envelope*: AsymEnvelope
    sharedSecret*: seq[uint8]

  ## Generic public/secret keypair returned by `genKeypair`.
  AsymKeypair* = object
    publicKey*: seq[uint8]
    secretKey*: seq[uint8]

  ## Fixed 32-byte digest used by BLAKE3 and Gimli hash surfaces.
  HashDigest32* = array[digestBytes, byte]

const
  zeroKeyLayout = KeyLayout(keyKind: kkSym, size: 0)

template `->`*(kindArg: KeyKind, keySize: static[int]): untyped =
  KeyLayout(keyKind: kindArg, size: keySize)

template buildLayout(kindArg: AlgorithmKind, opArg: OperationKind,
    outBytes: static[int], k0: KeyLayout = zeroKeyLayout,
    k1: KeyLayout = zeroKeyLayout): untyped =
  AlgorithmLayout(
    algorithmKind: kindArg,
    operationKind: opArg,
    keyLayoutCount: (if k1.size != 0: 2'u8 elif k0.size != 0: 1'u8 else: 0'u8),
    keyLayouts: [k0, k1],
    outputBytes: outBytes
  )

const algorithmLayouts*: array[AlgorithmKind, AlgorithmLayout] = [
  buildLayout(akBlake3Hash, okHash, digestBytes),
  buildLayout(akGimliHash, okHash, digestBytes),
  buildLayout(akSha3Hash, okHash, variableLayoutSize),
  buildLayout(akBlake3KeyedHash, okHash, variableLayoutSize, kkSym -> 32),
  buildLayout(akBlake3Hmac, okHmac, digestBytes, kkSym -> 32),
  buildLayout(akGimliHmac, okHmac, digestBytes, kkSym -> 32),
  buildLayout(akPoly1305Hmac, okHmac, 16, kkSym -> 32),
  buildLayout(akSha3Hmac, okHmac, digestBytes, kkSym -> 32),
  buildLayout(akXChaCha20Cipher, okCipher, variableLayoutSize, kkSym -> 32, kkNonce -> 24),
  buildLayout(akAesCtrCipher, okCipher, variableLayoutSize, kkSym -> 32, kkNonce -> 16),
  buildLayout(akGimliStreamCipher, okCipher, variableLayoutSize, kkSym -> 32, kkNonce -> 24),
  buildLayout(akEd25519Sign, okSign, 64, kkSecretKey -> 64),
  buildLayout(akEd25519Verify, okVerify, 1, kkPublicKey -> 32, kkSignature -> 64),
  buildLayout(akFalcon0Sign, okSign, variableLayoutSize, kkSecretKey -> 1281),
  buildLayout(akFalcon0Verify, okVerify, 1, kkPublicKey -> 897, kkSignature -> variableLayoutSize),
  buildLayout(akFalcon1Sign, okSign, variableLayoutSize, kkSecretKey -> 2305),
  buildLayout(akFalcon1Verify, okVerify, 1, kkPublicKey -> 1793, kkSignature -> variableLayoutSize),
  buildLayout(akDilithium0Sign, okSign, 2420, kkSecretKey -> 2560),
  buildLayout(akDilithium0Verify, okVerify, 1, kkPublicKey -> 1312, kkSignature -> 2420),
  buildLayout(akDilithium1Sign, okSign, 3309, kkSecretKey -> 4032),
  buildLayout(akDilithium1Verify, okVerify, 1, kkPublicKey -> 1952, kkSignature -> 3309),
  buildLayout(akDilithium2Sign, okSign, 4627, kkSecretKey -> 4896),
  buildLayout(akDilithium2Verify, okVerify, 1, kkPublicKey -> 2592, kkSignature -> 4627),
  buildLayout(akDilithium0TyrSign, okSign, 2420, kkSecretKey -> 2560),
  buildLayout(akDilithium0TyrVerify, okVerify, 1, kkPublicKey -> 1312, kkSignature -> 2420),
  buildLayout(akDilithium1TyrSign, okSign, 3309, kkSecretKey -> 4032),
  buildLayout(akDilithium1TyrVerify, okVerify, 1, kkPublicKey -> 1952, kkSignature -> 3309),
  buildLayout(akDilithium2TyrSign, okSign, 4627, kkSecretKey -> 4896),
  buildLayout(akDilithium2TyrVerify, okVerify, 1, kkPublicKey -> 2592, kkSignature -> 4627),
  buildLayout(akEd448Sign, okSign, 114, kkSecretKey -> 57),
  buildLayout(akEd448Verify, okVerify, 1, kkPublicKey -> 57, kkSignature -> 114),
  buildLayout(akSphincsShake128fSimpleSign, okSign, 17088, kkSecretKey -> 64),
  buildLayout(akSphincsShake128fSimpleVerify, okVerify, 1, kkPublicKey -> 32, kkSignature -> 17088),
  buildLayout(akSphincsShake128fSimpleTyrSign, okSign, 17088, kkSecretKey -> 64),
  buildLayout(akSphincsShake128fSimpleTyrVerify, okVerify, 1, kkPublicKey -> 32, kkSignature -> 17088),
  buildLayout(akSphincsHaraka128fSimpleSign, okSign, 17088, kkSecretKey -> 64),
  buildLayout(akSphincsHaraka128fSimpleVerify, okVerify, 1, kkPublicKey -> 32, kkSignature -> 17088),
  buildLayout(akSphincsHaraka128fSimpleTyrSign, okSign, 17088, kkSecretKey -> 64),
  buildLayout(akSphincsHaraka128fSimpleTyrVerify, okVerify, 1, kkPublicKey -> 32, kkSignature -> 17088),
  buildLayout(akX25519Send, okKemSend, 32, kkPublicKey -> 32),
  buildLayout(akX25519Open, okKemOpen, 32, kkSecretKey -> 32),
  buildLayout(akKyber0Send, okKemSend, 32, kkPublicKey -> 1184),
  buildLayout(akKyber0Open, okKemOpen, 32, kkSecretKey -> 2400),
  buildLayout(akKyber1Send, okKemSend, 32, kkPublicKey -> 1568),
  buildLayout(akKyber1Open, okKemOpen, 32, kkSecretKey -> 3168),
  buildLayout(akKyber0TyrSend, okKemSend, 32, kkPublicKey -> 1184),
  buildLayout(akKyber0TyrOpen, okKemOpen, 32, kkSecretKey -> 2400),
  buildLayout(akKyber1TyrSend, okKemSend, 32, kkPublicKey -> 1568),
  buildLayout(akKyber1TyrOpen, okKemOpen, 32, kkSecretKey -> 3168),
  buildLayout(akMcEliece0Send, okKemSend, 32, kkPublicKey -> 1044992),
  buildLayout(akMcEliece0Open, okKemOpen, 32, kkSecretKey -> 13932),
  buildLayout(akMcEliece1Send, okKemSend, 32, kkPublicKey -> 1047319),
  buildLayout(akMcEliece1Open, okKemOpen, 32, kkSecretKey -> 13948),
  buildLayout(akMcEliece2Send, okKemSend, 32, kkPublicKey -> 1357824),
  buildLayout(akMcEliece2Open, okKemOpen, 32, kkSecretKey -> 14120),
  buildLayout(akMcEliece0TyrSend, okKemSend, 32, kkPublicKey -> 1044992),
  buildLayout(akMcEliece0TyrOpen, okKemOpen, 32, kkSecretKey -> 13932),
  buildLayout(akMcEliece1TyrSend, okKemSend, 32, kkPublicKey -> 1047319),
  buildLayout(akMcEliece1TyrOpen, okKemOpen, 32, kkSecretKey -> 13948),
  buildLayout(akMcEliece2TyrSend, okKemSend, 32, kkPublicKey -> 1357824),
  buildLayout(akMcEliece2TyrOpen, okKemOpen, 32, kkSecretKey -> 14120),
  buildLayout(akFrodo0AesSend, okKemSend, 16, kkPublicKey -> 9616),
  buildLayout(akFrodo0AesOpen, okKemOpen, 16, kkSecretKey -> 19888),
  buildLayout(akFrodo0ShakeSend, okKemSend, 16, kkPublicKey -> 9616),
  buildLayout(akFrodo0ShakeOpen, okKemOpen, 16, kkSecretKey -> 19888),
  buildLayout(akFrodo1AesSend, okKemSend, 24, kkPublicKey -> 15632),
  buildLayout(akFrodo1AesOpen, okKemOpen, 24, kkSecretKey -> 31296),
  buildLayout(akFrodo1ShakeSend, okKemSend, 24, kkPublicKey -> 15632),
  buildLayout(akFrodo1ShakeOpen, okKemOpen, 24, kkSecretKey -> 31296),
  buildLayout(akFrodo2AesSend, okKemSend, 32, kkPublicKey -> 21520),
  buildLayout(akFrodo2AesOpen, okKemOpen, 32, kkSecretKey -> 43088),
  buildLayout(akFrodo2ShakeSend, okKemSend, 32, kkPublicKey -> 21520),
  buildLayout(akFrodo2ShakeOpen, okKemOpen, 32, kkSecretKey -> 43088),
  buildLayout(akFrodo0AesTyrSend, okKemSend, 16, kkPublicKey -> 9616),
  buildLayout(akFrodo0AesTyrOpen, okKemOpen, 16, kkSecretKey -> 19888),
  buildLayout(akFrodo0ShakeTyrSend, okKemSend, 16, kkPublicKey -> 9616),
  buildLayout(akFrodo0ShakeTyrOpen, okKemOpen, 16, kkSecretKey -> 19888),
  buildLayout(akFrodo1AesTyrSend, okKemSend, 24, kkPublicKey -> 15632),
  buildLayout(akFrodo1AesTyrOpen, okKemOpen, 24, kkSecretKey -> 31296),
  buildLayout(akFrodo1ShakeTyrSend, okKemSend, 24, kkPublicKey -> 15632),
  buildLayout(akFrodo1ShakeTyrOpen, okKemOpen, 24, kkSecretKey -> 31296),
  buildLayout(akFrodo2AesTyrSend, okKemSend, 32, kkPublicKey -> 21520),
  buildLayout(akFrodo2AesTyrOpen, okKemOpen, 32, kkSecretKey -> 43088),
  buildLayout(akFrodo2ShakeTyrSend, okKemSend, 32, kkPublicKey -> 21520),
  buildLayout(akFrodo2ShakeTyrOpen, okKemOpen, 32, kkSecretKey -> 43088),
  buildLayout(akNtruPrime0Send, okKemSend, 32, kkPublicKey -> 1158),
  buildLayout(akNtruPrime0Open, okKemOpen, 32, kkSecretKey -> 1763),
  buildLayout(akBike0TyrSend, okKemSend, 32, kkPublicKey -> 1541),
  buildLayout(akBike0TyrOpen, okKemOpen, 32, kkSecretKey -> 5223),
  buildLayout(akBike0Send, okKemSend, 32, kkPublicKey -> 1541),
  buildLayout(akBike0Open, okKemOpen, 32, kkSecretKey -> 5223),
  buildLayout(akChaCha20Cipher, okCipher, variableLayoutSize, kkSym -> 32, kkNonce -> 12)
]

proc layoutOf*(kind: AlgorithmKind): AlgorithmLayout =
  ## Return the static slot and output metadata for one typed algorithm entry.
  result = algorithmLayouts[kind]

## ╭⟢ Shared plumbing
##
## Small helpers the five material surfaces all reach for. They are
## exported because the surfaces live in different modules now, not
## because callers are expected to need them.

proc toSeqBytes*(input: openArray[byte]): seq[byte] =
  result = newSeq[byte](input.len)
  for i in 0 ..< input.len:
    result[i] = input[i]

proc toDigest32*(input: openArray[byte]): HashDigest32 =
  if input.len != digestBytes:
    raise newException(ValueError, "digest must be 32 bytes")
  for i in 0 ..< digestBytes:
    result[i] = input[i]

proc initAsymEnvelope*(ciphertext, senderPublicKey: seq[uint8]): AsymEnvelope =
  result.ciphertext = ciphertext
  result.senderPublicKey = senderPublicKey

proc initAsymCipher*(ciphertext, senderPublicKey, sharedSecret: seq[uint8]): AsymCipher =
  result.envelope = initAsymEnvelope(ciphertext, senderPublicKey)
  result.sharedSecret = sharedSecret

proc ciphertext*(cipher: AsymCipher): seq[uint8] {.inline.} =
  ## Compatibility accessor for code that reads `cipher.ciphertext`.
  result = cipher.envelope.ciphertext

proc senderPublicKey*(cipher: AsymCipher): seq[uint8] {.inline.} =
  ## Compatibility accessor for code that reads `cipher.senderPublicKey`.
  result = cipher.envelope.senderPublicKey

proc constantTimeEqual*(a, b: openArray[uint8]): bool =
  var
    diff: uint = if a.len == b.len: 0'u else: 1'u
    i: int = 0
    bByte: uint8 = 0
  i = 0
  while i < a.len:
    bByte = if i < b.len: b[i] else: 0'u8
    diff = diff or uint(a[i] xor bByte)
    i = i + 1
  result = diff == 0'u
