## -------------------------------------------------------------
## Basic API <- single-algorithm typed material surface for callers
## -------------------------------------------------------------

import std/[locks, monotimes, os, times]

import ../common
import ./helpers/algorithms
import ../custom_crypto/random
import ../bindings/liboqs
import ../bindings/libsodium
import ../custom_crypto/[xchacha20, aes_ctr, hmac]
import ../custom_crypto/blake3
import ../custom_crypto/gimli_sponge
import ../custom_crypto/mceliece as customMcEliece
import ./helpers/signature_support as wrapSign

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
    akEd448Sign,
    akEd448Verify,
    akSphincsHaraka128fSimpleSign,
    akSphincsHaraka128fSimpleVerify,
    akX25519Send,
    akX25519Open,
    akKyber0Send,
    akKyber0Open,
    akKyber1Send,
    akKyber1Open,
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
    akFrodo0Send,
    akFrodo0Open,
    akNtruPrime0Send,
    akNtruPrime0Open,
    akBike0Send,
    akBike0Open

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

  ## Generic asymmetric/KEM envelope returned by `seal` and `asymEnc`.
  AsymCipher* = object
    ciphertext*: seq[uint8]
    senderPublicKey*: seq[uint8]
    sharedSecret*: seq[uint8]

  ## Generic public/secret keypair returned by `asymKeypair`.
  AsymKeypair* = object
    publicKey*: seq[uint8]
    secretKey*: seq[uint8]

  ## Fixed 32-byte digest used by BLAKE3 and Gimli hash surfaces.
  HashDigest32* = array[digestBytes, byte]

  ## Material for plain BLAKE3 hashing.
  blake3HashM* = object
  ## Material for plain Gimli sponge hashing.
  gimliHashM* = object
  ## Material for SHA3 hashing with optional custom output length.
  sha3HashM* = object
    outLen*: uint16
  ## Material for keyed BLAKE3 hashing.
  blake3KeyedHashM* = object
    key*: array[32, byte]
    outLen*: uint16
  blake3M* = blake3HashM
  ## Material for BLAKE3-backed HMAC creation.
  blake3hmacM* = object
    key*: array[32, byte]
    outLen*: uint16
  ## Material for Gimli-backed HMAC creation.
  gimlihmacM* = object
    key*: array[32, byte]
    outLen*: uint16
  ## Material for Poly1305-backed HMAC creation.
  poly1305hmacM* = object
    key*: array[32, byte]
    outLen*: uint16
  ## Material for SHA3-backed HMAC creation.
  sha3hmacM* = object
    key*: array[32, byte]
    outLen*: uint16
  ## Material for BLAKE3-backed HMAC verification.
  blake3hmacVerifyM* = object
    key*: array[32, byte]
    tag*: seq[byte]
    outLen*: uint16
  ## Material for Gimli-backed HMAC verification.
  gimlihmacVerifyM* = object
    key*: array[32, byte]
    tag*: seq[byte]
    outLen*: uint16
  ## Material for Poly1305-backed HMAC verification.
  poly1305hmacVerifyM* = object
    key*: array[32, byte]
    tag*: seq[byte]
    outLen*: uint16
  ## Material for SHA3-backed HMAC verification.
  sha3hmacVerifyM* = object
    key*: array[32, byte]
    tag*: seq[byte]
    outLen*: uint16
  ## Material for XChaCha20 encryption and decryption.
  xchacha20cipherM* = object
    key*: array[32, byte]
    nonce*: array[24, byte]
  ## Material for AES-256-CTR encryption and decryption.
  aesCtrcipherM* = object
    key*: array[32, byte]
    nonce*: array[16, byte]
  ## Material for Gimli stream-cipher encryption and decryption.
  gimliStreamCipherM* = object
    key*: array[32, byte]
    nonce*: array[24, byte]
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
    signature*: array[752, byte]
  ## Material for Falcon-1024 signing.
  falcon1SignM* = object
    secretKey*: array[2305, byte]
  ## Material for Falcon-1024 signature verification.
  falcon1VerifyM* = object
    publicKey*: array[1793, byte]
    signature*: array[1462, byte]
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
  ## Material for Ed448 signing.
  ed448SignM* = object
    secretKey*: array[57, byte]
  ## Material for Ed448 signature verification.
  ed448VerifyM* = object
    publicKey*: array[57, byte]
    signature*: array[114, byte]
  ## Material for the Haraka 128f SPHINCS+ signing surface.
  sphincsHaraka128fSimpleSignM* = object
    ## The Haraka 128f simple parameter set uses the same fixed key/signature
    ## lengths as the other SPHINCS+ 128f simple backends.
    secretKey*: array[64, byte]
  ## Material for the Haraka 128f SPHINCS+ verification surface.
  sphincsHaraka128fSimpleVerifyM* = object
    publicKey*: array[32, byte]
    signature*: array[17088, byte]
  ## Material for sending an X25519-derived shared secret.
  x25519SendM* = object
    receiverPublicKey*: array[32, byte]
  ## Material for opening an X25519-derived shared secret.
  x25519OpenM* = object
    receiverSecretKey*: array[32, byte]
  ## Material for Kyber tier-0 encapsulation.
  kyber0SendM* = object
    receiverPublicKey*: array[1184, byte]
  ## Material for Kyber tier-0 decapsulation.
  kyber0OpenM* = object
    receiverSecretKey*: array[2400, byte]
  ## Material for Kyber tier-1 encapsulation.
  kyber1SendM* = object
    receiverPublicKey*: array[1568, byte]
  ## Material for Kyber tier-1 decapsulation.
  kyber1OpenM* = object
    receiverSecretKey*: array[3168, byte]
  ## Material for McEliece tier-0 encapsulation.
  mceliece0SendM* = object
    receiverPublicKey*: array[1044992, byte]
  ## Material for McEliece tier-0 decapsulation.
  mceliece0OpenM* = object
    receiverSecretKey*: array[13932, byte]
  ## Material for McEliece tier-1 encapsulation.
  mceliece1SendM* = object
    receiverPublicKey*: array[1047319, byte]
  ## Material for McEliece tier-1 decapsulation.
  mceliece1OpenM* = object
    receiverSecretKey*: array[13948, byte]
  ## Material for McEliece tier-2 encapsulation.
  mceliece2SendM* = object
    receiverPublicKey*: array[1357824, byte]
  ## Material for McEliece tier-2 decapsulation.
  mceliece2OpenM* = object
    receiverSecretKey*: array[14120, byte]
  ## Material for the pure-Nim Tyr McEliece tier-0 encapsulation path.
  mceliece0TyrSendM* = object
    receiverPublicKey*: array[1044992, byte]
  ## Material for the pure-Nim Tyr McEliece tier-0 decapsulation path.
  mceliece0TyrOpenM* = object
    receiverSecretKey*: array[13932, byte]
  ## Material for the pure-Nim Tyr McEliece tier-1 encapsulation path.
  mceliece1TyrSendM* = object
    receiverPublicKey*: array[1047319, byte]
  ## Material for the pure-Nim Tyr McEliece tier-1 decapsulation path.
  mceliece1TyrOpenM* = object
    receiverSecretKey*: array[13948, byte]
  ## Material for the pure-Nim Tyr McEliece tier-2 encapsulation path.
  mceliece2TyrSendM* = object
    receiverPublicKey*: array[1357824, byte]
  ## Material for the pure-Nim Tyr McEliece tier-2 decapsulation path.
  mceliece2TyrOpenM* = object
    receiverSecretKey*: array[14120, byte]
  ## Material for Frodo tier-0 encapsulation.
  frodo0SendM* = object
    receiverPublicKey*: array[15632, byte]
  ## Material for Frodo tier-0 decapsulation.
  frodo0OpenM* = object
    receiverSecretKey*: array[31296, byte]
  ## Material for NTRU Prime tier-0 encapsulation.
  ntruprime0SendM* = object
    ## ntruprime0 is currently bound to sntrup761 in the checked-out liboqs tree.
    receiverPublicKey*: array[1158, byte]
  ## Material for NTRU Prime tier-0 decapsulation.
  ntruprime0OpenM* = object
    receiverSecretKey*: array[1763, byte]
  ## Material for BIKE tier-0 encapsulation.
  bike0SendM* = object
    ## bike0 is currently bound to BIKE-L1 in the checked-out liboqs tree.
    receiverPublicKey*: array[1541, byte]
  ## Material for BIKE tier-0 decapsulation.
  bike0OpenM* = object
    receiverSecretKey*: array[5223, byte]

const
  zeroKeyLayout = KeyLayout(keyKind: kkSym, size: 0)
  x25519KeyBytes = 32

var
  oqsEntropyLock: Lock
  oqsEntropyExtra: seq[uint8] = @[]
  oqsEntropyCounter: uint64 = 0

discard block:
  initLock(oqsEntropyLock)
  true

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
  buildLayout(akPoly1305Hmac, okHmac, digestBytes, kkSym -> 32),
  buildLayout(akSha3Hmac, okHmac, digestBytes, kkSym -> 32),
  buildLayout(akXChaCha20Cipher, okCipher, variableLayoutSize, kkSym -> 32, kkNonce -> 24),
  buildLayout(akAesCtrCipher, okCipher, variableLayoutSize, kkSym -> 32, kkNonce -> 16),
  buildLayout(akGimliStreamCipher, okCipher, variableLayoutSize, kkSym -> 32, kkNonce -> 24),
  buildLayout(akEd25519Sign, okSign, 64, kkSecretKey -> 64),
  buildLayout(akEd25519Verify, okVerify, 1, kkPublicKey -> 32, kkSignature -> 64),
  buildLayout(akFalcon0Sign, okSign, 752, kkSecretKey -> 1281),
  buildLayout(akFalcon0Verify, okVerify, 1, kkPublicKey -> 897, kkSignature -> 752),
  buildLayout(akFalcon1Sign, okSign, 1462, kkSecretKey -> 2305),
  buildLayout(akFalcon1Verify, okVerify, 1, kkPublicKey -> 1793, kkSignature -> 1462),
  buildLayout(akDilithium0Sign, okSign, 2420, kkSecretKey -> 2560),
  buildLayout(akDilithium0Verify, okVerify, 1, kkPublicKey -> 1312, kkSignature -> 2420),
  buildLayout(akDilithium1Sign, okSign, 3309, kkSecretKey -> 4032),
  buildLayout(akDilithium1Verify, okVerify, 1, kkPublicKey -> 1952, kkSignature -> 3309),
  buildLayout(akDilithium2Sign, okSign, 4627, kkSecretKey -> 4896),
  buildLayout(akDilithium2Verify, okVerify, 1, kkPublicKey -> 2592, kkSignature -> 4627),
  buildLayout(akEd448Sign, okSign, 114, kkSecretKey -> 57),
  buildLayout(akEd448Verify, okVerify, 1, kkPublicKey -> 57, kkSignature -> 114),
  buildLayout(akSphincsHaraka128fSimpleSign, okSign, 17088, kkSecretKey -> 64),
  buildLayout(akSphincsHaraka128fSimpleVerify, okVerify, 1, kkPublicKey -> 32, kkSignature -> 17088),
  buildLayout(akX25519Send, okKemSend, 32, kkPublicKey -> 32),
  buildLayout(akX25519Open, okKemOpen, 32, kkSecretKey -> 32),
  buildLayout(akKyber0Send, okKemSend, 32, kkPublicKey -> 1184),
  buildLayout(akKyber0Open, okKemOpen, 32, kkSecretKey -> 2400),
  buildLayout(akKyber1Send, okKemSend, 32, kkPublicKey -> 1568),
  buildLayout(akKyber1Open, okKemOpen, 32, kkSecretKey -> 3168),
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
  buildLayout(akFrodo0Send, okKemSend, 24, kkPublicKey -> 15632),
  buildLayout(akFrodo0Open, okKemOpen, 24, kkSecretKey -> 31296),
  buildLayout(akNtruPrime0Send, okKemSend, 32, kkPublicKey -> 1158),
  buildLayout(akNtruPrime0Open, okKemOpen, 32, kkSecretKey -> 1763),
  buildLayout(akBike0Send, okKemSend, 32, kkPublicKey -> 1541),
  buildLayout(akBike0Open, okKemOpen, 32, kkSecretKey -> 5223)
]

proc layoutOf*(kind: AlgorithmKind): AlgorithmLayout =
  ## Return the static slot and output metadata for one typed algorithm entry.
  result = algorithmLayouts[kind]

proc algorithmOf*(T: typedesc[blake3HashM]): AlgorithmKind = akBlake3Hash
proc algorithmOf*(T: typedesc[gimliHashM]): AlgorithmKind = akGimliHash
proc algorithmOf*(T: typedesc[sha3HashM]): AlgorithmKind = akSha3Hash
proc algorithmOf*(T: typedesc[blake3KeyedHashM]): AlgorithmKind = akBlake3KeyedHash
proc algorithmOf*(T: typedesc[blake3hmacM]): AlgorithmKind = akBlake3Hmac
proc algorithmOf*(T: typedesc[gimlihmacM]): AlgorithmKind = akGimliHmac
proc algorithmOf*(T: typedesc[poly1305hmacM]): AlgorithmKind = akPoly1305Hmac
proc algorithmOf*(T: typedesc[sha3hmacM]): AlgorithmKind = akSha3Hmac
proc algorithmOf*(T: typedesc[blake3hmacVerifyM]): AlgorithmKind = akBlake3Hmac
proc algorithmOf*(T: typedesc[gimlihmacVerifyM]): AlgorithmKind = akGimliHmac
proc algorithmOf*(T: typedesc[poly1305hmacVerifyM]): AlgorithmKind = akPoly1305Hmac
proc algorithmOf*(T: typedesc[sha3hmacVerifyM]): AlgorithmKind = akSha3Hmac
proc algorithmOf*(T: typedesc[xchacha20cipherM]): AlgorithmKind = akXChaCha20Cipher
proc algorithmOf*(T: typedesc[aesCtrcipherM]): AlgorithmKind = akAesCtrCipher
proc algorithmOf*(T: typedesc[gimliStreamCipherM]): AlgorithmKind = akGimliStreamCipher
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
proc algorithmOf*(T: typedesc[ed448SignM]): AlgorithmKind = akEd448Sign
proc algorithmOf*(T: typedesc[ed448VerifyM]): AlgorithmKind = akEd448Verify
proc algorithmOf*(T: typedesc[sphincsHaraka128fSimpleSignM]): AlgorithmKind =
  akSphincsHaraka128fSimpleSign
proc algorithmOf*(T: typedesc[sphincsHaraka128fSimpleVerifyM]): AlgorithmKind =
  akSphincsHaraka128fSimpleVerify
proc algorithmOf*(T: typedesc[x25519SendM]): AlgorithmKind = akX25519Send
proc algorithmOf*(T: typedesc[x25519OpenM]): AlgorithmKind = akX25519Open
proc algorithmOf*(T: typedesc[kyber0SendM]): AlgorithmKind = akKyber0Send
proc algorithmOf*(T: typedesc[kyber0OpenM]): AlgorithmKind = akKyber0Open
proc algorithmOf*(T: typedesc[kyber1SendM]): AlgorithmKind = akKyber1Send
proc algorithmOf*(T: typedesc[kyber1OpenM]): AlgorithmKind = akKyber1Open
proc algorithmOf*(T: typedesc[mceliece0SendM]): AlgorithmKind = akMcEliece0Send
proc algorithmOf*(T: typedesc[mceliece0OpenM]): AlgorithmKind = akMcEliece0Open
proc algorithmOf*(T: typedesc[mceliece1SendM]): AlgorithmKind = akMcEliece1Send
proc algorithmOf*(T: typedesc[mceliece1OpenM]): AlgorithmKind = akMcEliece1Open
proc algorithmOf*(T: typedesc[mceliece2SendM]): AlgorithmKind = akMcEliece2Send
proc algorithmOf*(T: typedesc[mceliece2OpenM]): AlgorithmKind = akMcEliece2Open
proc algorithmOf*(T: typedesc[mceliece0TyrSendM]): AlgorithmKind = akMcEliece0TyrSend
proc algorithmOf*(T: typedesc[mceliece0TyrOpenM]): AlgorithmKind = akMcEliece0TyrOpen
proc algorithmOf*(T: typedesc[mceliece1TyrSendM]): AlgorithmKind = akMcEliece1TyrSend
proc algorithmOf*(T: typedesc[mceliece1TyrOpenM]): AlgorithmKind = akMcEliece1TyrOpen
proc algorithmOf*(T: typedesc[mceliece2TyrSendM]): AlgorithmKind = akMcEliece2TyrSend
proc algorithmOf*(T: typedesc[mceliece2TyrOpenM]): AlgorithmKind = akMcEliece2TyrOpen
proc algorithmOf*(T: typedesc[frodo0SendM]): AlgorithmKind = akFrodo0Send
proc algorithmOf*(T: typedesc[frodo0OpenM]): AlgorithmKind = akFrodo0Open
proc algorithmOf*(T: typedesc[ntruprime0SendM]): AlgorithmKind = akNtruPrime0Send
proc algorithmOf*(T: typedesc[ntruprime0OpenM]): AlgorithmKind = akNtruPrime0Open
proc algorithmOf*(T: typedesc[bike0SendM]): AlgorithmKind = akBike0Send
proc algorithmOf*(T: typedesc[bike0OpenM]): AlgorithmKind = akBike0Open

proc toSeqBytes(input: openArray[byte]): seq[byte] =
  result = newSeq[byte](input.len)
  for i in 0 ..< input.len:
    result[i] = input[i]

proc toDigest32(input: openArray[byte]): HashDigest32 =
  if input.len != digestBytes:
    raise newException(ValueError, "digest must be 32 bytes")
  for i in 0 ..< digestBytes:
    result[i] = input[i]

proc hmacLen(outLen: uint16): int =
  if outLen == 0'u16:
    result = digestBytes
  else:
    result = int(outLen)

proc constantTimeEqual(a, b: openArray[uint8]): bool =
  var
    diff: uint8 = 0
    i: int = 0
  if a.len != b.len:
    return false
  i = 0
  while i < a.len:
    diff = diff or (a[i] xor b[i])
    i = i + 1
  result = diff == 0'u8

proc kyberAlgId(variant: KyberTier): string =
  case variant
  of kyber0:
    result = oqsAlgKyber768
  of kyber1:
    result = oqsAlgKyber1024

proc mcElieceAlgId(variant: McElieceTier): string =
  case variant
  of mceliece0:
    result = oqsAlgClassicMcEliece6688128f
  of mceliece1:
    result = oqsAlgClassicMcEliece6960119f
  of mceliece2:
    result = oqsAlgClassicMcEliece8192128f

proc stringToBytes(s: string): seq[uint8] =
  result = newSeq[uint8](s.len)
  for i, ch in s:
    result[i] = uint8(ord(ch))

proc appendU64(buf: var seq[uint8], value: uint64) =
  for i in 0 ..< 8:
    buf.add(uint8((value shr (i * 8)) and 0xff'u64))

proc buildOqsEntropyMaterial(extraEntropy: openArray[uint8], bytesToRead: int,
    counter: uint64): seq[uint8] =
  const oqsEntropyContext = "tyr-crypto-oqs-rng-v1"
  var localMarker: uint64 = counter xor uint64(bytesToRead)
  result = newSeqOfCap[uint8](oqsEntropyContext.len + extraEntropy.len + 64)
  result.add(stringToBytes(oqsEntropyContext))
  appendU64(result, uint64(bytesToRead))
  appendU64(result, counter)
  appendU64(result, uint64(getCurrentProcessId()))
  appendU64(result, uint64(getMonoTime().ticks))
  appendU64(result, uint64(getTime().toUnix))
  appendU64(result, uint64(epochTime() * 1_000_000_000.0))
  appendU64(result, uint64(cpuTime() * 1_000_000_000.0))
  appendU64(result, cast[uint64](addr localMarker))
  result.add(extraEntropy)

proc oqsHybridRandomCallback(random_array: ptr uint8,
    bytes_to_read: csize_t) {.cdecl.} =
  try:
    let counter = oqsEntropyCounter
    inc oqsEntropyCounter
    let mixMaterial = buildOqsEntropyMaterial(oqsEntropyExtra, int(bytes_to_read),
      counter)
    let randomBytes = cryptoRandomBytes(int(bytes_to_read), mixMaterial)
    if random_array != nil and randomBytes.len > 0:
      copyMem(random_array, unsafeAddr randomBytes[0], randomBytes.len)
  except CatchableError:
    quit(1)

proc withOqsHybridEntropy[T](extraEntropy: openArray[uint8],
    body: proc (): T): T =
  acquire(oqsEntropyLock)
  oqsEntropyExtra = @extraEntropy
  oqsEntropyCounter = 0
  OQS_randombytes_custom_algorithm(oqsHybridRandomCallback)
  try:
    result = body()
  finally:
    discard OQS_randombytes_switch_algorithm(oqsRandAlgSystem.cstring)
    oqsEntropyExtra.setLen(0)
    oqsEntropyCounter = 0
    release(oqsEntropyLock)

when defined(hasLibOqs):
  proc newKem(algId: string): ptr OqsKem =
    let kem = OQS_KEM_new(algId.cstring)
    if kem == nil:
      raiseOperation("liboqs", "KEM " & algId & " unavailable")
    result = kem

proc kemKeypair(algId: string,
    extraEntropy: openArray[uint8]): tuple[pk, sk: seq[uint8]] =
  when defined(hasLibOqs):
    result = withOqsHybridEntropy(extraEntropy, proc (): tuple[pk, sk: seq[uint8]] =
      let kem = newKem(algId)
      defer:
        OQS_KEM_free(kem)
      var pk = newSeq[uint8](int kem[].length_public_key)
      var sk = newSeq[uint8](int kem[].length_secret_key)
      requireSuccess(OQS_KEM_keypair(kem, addr pk[0], addr sk[0]),
        "OQS_KEM_keypair(" & algId & ")")
      result = (pk: pk, sk: sk)
    )
  else:
    discard algId
    discard extraEntropy
    raiseUnavailable("liboqs", "hasLibOqs")
    result = (pk: @[], sk: @[])

proc kemKeypair(algId: string): tuple[pk, sk: seq[uint8]] =
  result = kemKeypair(algId, newSeq[uint8](0))

proc kemEncaps(algId: string,
    publicKey, extraEntropy: openArray[uint8]): tuple[ciphertext, shared: seq[uint8]] =
  when defined(hasLibOqs):
    let publicKeyBytes = @publicKey
    result = withOqsHybridEntropy(extraEntropy, proc (): tuple[ciphertext, shared: seq[uint8]] =
      let kem = newKem(algId)
      defer:
        OQS_KEM_free(kem)
      if publicKeyBytes.len != int kem[].length_public_key:
        raise newException(ValueError, "invalid " & algId & " public key length")
      var ciphertext = newSeq[uint8](int kem[].length_ciphertext)
      var shared = newSeq[uint8](int kem[].length_shared_secret)
      requireSuccess(
        OQS_KEM_encaps(
          kem,
          addr ciphertext[0],
          addr shared[0],
          if publicKeyBytes.len > 0: unsafeAddr publicKeyBytes[0] else: nil
        ),
        "OQS_KEM_encaps(" & algId & ")"
      )
      result = (ciphertext: ciphertext, shared: shared)
    )
  else:
    discard algId
    discard publicKey
    discard extraEntropy
    raiseUnavailable("liboqs", "hasLibOqs")
    result = (ciphertext: @[], shared: @[])

proc kemEncaps(algId: string,
    publicKey: openArray[uint8]): tuple[ciphertext, shared: seq[uint8]] =
  result = kemEncaps(algId, publicKey, newSeq[uint8](0))

proc kemDecaps(algId: string, ciphertext,
    secretKey: openArray[uint8]): seq[uint8] =
  when defined(hasLibOqs):
    let kem = newKem(algId)
    defer:
      OQS_KEM_free(kem)
    if secretKey.len != int kem[].length_secret_key:
      raise newException(ValueError, "invalid " & algId & " secret key length")
    if ciphertext.len != int kem[].length_ciphertext:
      raise newException(ValueError, "invalid " & algId & " ciphertext length")
    var shared = newSeq[uint8](int kem[].length_shared_secret)
    requireSuccess(
      OQS_KEM_decaps(
        kem,
        addr shared[0],
        if ciphertext.len > 0: unsafeAddr ciphertext[0] else: nil,
        if secretKey.len > 0: unsafeAddr secretKey[0] else: nil
      ),
      "OQS_KEM_decaps(" & algId & ")"
    )
    result = shared
  else:
    discard algId
    discard ciphertext
    discard secretKey
    raiseUnavailable("liboqs", "hasLibOqs")
    result = @[]

proc x25519Keypair(): tuple[pk, sk: seq[uint8]] =
  var pk = newSeq[uint8](x25519KeyBytes)
  var sk = newSeq[uint8](x25519KeyBytes)
  if crypto_kx_keypair(addr pk[0], addr sk[0]) != 0:
    raiseOperation("libsodium", "crypto_kx_keypair failed")
  result = (pk: pk, sk: sk)

proc x25519SeedLen(): int =
  let l = int(crypto_kx_seedbytes())
  if l <= 0:
    raiseOperation("libsodium", "crypto_kx_seedbytes returned invalid length")
  result = l

proc x25519KeypairFromSeed(seed: openArray[uint8]): tuple[pk, sk: seq[uint8]] =
  let seedLen = x25519SeedLen()
  if seed.len != seedLen:
    raise newException(ValueError, "invalid X25519 seed length")
  var pk = newSeq[uint8](x25519KeyBytes)
  var sk = newSeq[uint8](x25519KeyBytes)
  if crypto_kx_seed_keypair(
      addr pk[0], addr sk[0],
      if seed.len > 0: unsafeAddr seed[0] else: nil) != 0:
    raiseOperation("libsodium", "crypto_kx_seed_keypair failed")
  result = (pk: pk, sk: sk)

proc x25519Shared(secretKey, publicKey: openArray[uint8]): seq[uint8] =
  if secretKey.len != x25519KeyBytes or publicKey.len != x25519KeyBytes:
    raise newException(ValueError, "invalid X25519 key length")
  var shared = newSeq[uint8](x25519KeyBytes)
  if crypto_scalarmult_curve25519(
      addr shared[0],
      if secretKey.len > 0: unsafeAddr secretKey[0] else: nil,
      if publicKey.len > 0: unsafeAddr publicKey[0] else: nil) != 0:
    raiseOperation("libsodium", "crypto_scalarmult_curve25519 failed")
  result = shared

proc kyberVariantForTier(alg: KemAlgorithm): KyberTier =
  case alg
  of kaKyber0:
    result = kyber0
  of kaKyber1:
    result = kyber1
  else:
    raise newException(ValueError, "algorithm is not a kyber tier")

proc mcElieceVariantForTier(alg: KemAlgorithm): McElieceTier =
  case alg
  of kaMcEliece0:
    result = mceliece0
  of kaMcEliece1:
    result = mceliece1
  of kaMcEliece2:
    result = mceliece2
  else:
    raise newException(ValueError, "algorithm is not a mceliece tier")

proc kemAlgIdForDispatch(alg: KemAlgorithm): string =
  case alg
  of kaKyber0, kaKyber1:
    result = kyberAlgId(kyberVariantForTier(alg))
  of kaMcEliece0, kaMcEliece1, kaMcEliece2:
    result = mcElieceAlgId(mcElieceVariantForTier(alg))
  of kaFrodo0:
    result = oqsAlgFrodoKEM976
  of kaNtruPrime0:
    result = oqsAlgNtruPrime0
  of kaBike0:
    result = oqsAlgBike0
  else:
    raise newException(ValueError, "algorithm is not a KEM tier")

proc asymKeypair*(alg: KemAlgorithm, seed: seq[uint8] = @[]): AsymKeypair =
  ## Build a KEM/X25519 keypair using the selected backend tier.
  ## When `seed` is non-empty, the backend's deterministic seeded path is used.
  var
    kp0: tuple[pk, sk: seq[uint8]]
    algId: string = ""
  case alg
  of kaX25519:
    if seed.len > 0:
      kp0 = x25519KeypairFromSeed(seed)
    else:
      kp0 = x25519Keypair()
    result.publicKey = kp0.pk
    result.secretKey = kp0.sk
  of kaKyber0, kaKyber1, kaMcEliece0, kaMcEliece1, kaMcEliece2,
      kaFrodo0, kaNtruPrime0, kaBike0:
    algId = kemAlgIdForDispatch(alg)
    if seed.len > 0:
      kp0 = kemKeypair(algId, seed)
    else:
      kp0 = kemKeypair(algId)
    result.publicKey = kp0.pk
    result.secretKey = kp0.sk

proc asymKeypair*(alg: SignatureAlgorithm): AsymKeypair =
  ## Build a signature keypair for one non-hybrid signature algorithm.
  var
    kp0: wrapSign.SignatureKeypair
  if alg in {saEd25519Falcon512Hybrid, saEd25519Falcon1024Hybrid}:
    raise newException(ValueError, "hybrid signature combinations are not supported by basic_api")
  kp0 = signatureKeypair(alg)
  result.publicKey = kp0.publicKey
  result.secretKey = kp0.secretKey

proc asymKeypair*(T: typedesc[mceliece0TyrSendM]): AsymKeypair =
  ## Build a pure-Nim Tyr McEliece tier-0 keypair.
  var kp = customMcEliece.mcelieceTyrKeypair(customMcEliece.mceliece6688128f)
  result.publicKey = kp.publicKey
  result.secretKey = kp.secretKey

proc asymKeypair*(T: typedesc[mceliece0TyrOpenM]): AsymKeypair =
  ## Build a pure-Nim Tyr McEliece tier-0 keypair.
  result = asymKeypair(mceliece0TyrSendM)

proc asymKeypair*(T: typedesc[mceliece1TyrSendM]): AsymKeypair =
  ## Build a pure-Nim Tyr McEliece tier-1 keypair.
  var kp = customMcEliece.mcelieceTyrKeypair(customMcEliece.mceliece6960119f)
  result.publicKey = kp.publicKey
  result.secretKey = kp.secretKey

proc asymKeypair*(T: typedesc[mceliece1TyrOpenM]): AsymKeypair =
  ## Build a pure-Nim Tyr McEliece tier-1 keypair.
  result = asymKeypair(mceliece1TyrSendM)

proc asymKeypair*(T: typedesc[mceliece2TyrSendM]): AsymKeypair =
  ## Build a pure-Nim Tyr McEliece tier-2 keypair.
  var kp = customMcEliece.mcelieceTyrKeypair(customMcEliece.mceliece8192128f)
  result.publicKey = kp.publicKey
  result.secretKey = kp.secretKey

proc asymKeypair*(T: typedesc[mceliece2TyrOpenM]): AsymKeypair =
  ## Build a pure-Nim Tyr McEliece tier-2 keypair.
  result = asymKeypair(mceliece2TyrSendM)

proc symEnc*(alg: StreamCipherAlgorithm, key, nonce, msg: seq[uint8]): seq[uint8] =
  ## Encrypt or stream-XOR `msg` with the selected primitive cipher.
  case alg
  of scaXChaCha20:
    result = xchacha20Xor(key, nonce, msg)
  of scaAesCtr:
    result = aesCtrXor(key, nonce, msg, acbAuto)
  of scaGimliStream:
    result = gimliStreamXor(key, nonce, msg)

proc symDec*(alg: StreamCipherAlgorithm, key, nonce, cipher: seq[uint8]): seq[uint8] =
  ## Decrypt or stream-XOR `cipher` with the selected primitive cipher.
  result = symEnc(alg, key, nonce, cipher)

proc hmacCreate*(alg: MacAlgorithm, key, msg: seq[uint8], outLen: int = 32): seq[uint8] =
  ## Create a detached MAC/tag with the selected keyed hash backend.
  case alg
  of maBlake3:
    result = blake3CustomHmac(key, msg, outLen)
  of maGimli:
    result = gimliCustomHmac(key, msg, outLen)
  of maPoly1305:
    result = poly1305CustomHmac(key, msg, outLen)
  of maSha3:
    result = sha3CustomHmac(key, msg, outLen)

proc hmacAuth*(alg: MacAlgorithm, key, msg, tag: seq[uint8], outLen: int = 32): bool =
  ## Verify a detached MAC/tag with the selected keyed hash backend.
  var expected: seq[uint8] = @[]
  expected = hmacCreate(alg, key, msg, outLen)
  result = constantTimeEqual(expected, tag)

proc asymEnc*(alg: KemAlgorithm, receiverPublicKey: seq[uint8],
    senderPublicKey: seq[uint8] = @[], senderSecretKey: seq[uint8] = @[],
    seed: seq[uint8] = @[]): AsymCipher =
  ## Encapsulate or derive a shared secret for the selected KEM/X25519 backend.
  ## X25519 may either generate an ephemeral sender keypair or reuse the provided one.
  var
    kp0: tuple[pk, sk: seq[uint8]]
    kem0: tuple[ciphertext, shared: seq[uint8]]
    algId: string = ""
  case alg
  of kaX25519:
    if senderPublicKey.len == 0 and senderSecretKey.len == 0:
      if seed.len > 0:
        kp0 = x25519KeypairFromSeed(seed)
      else:
        kp0 = x25519Keypair()
    elif senderPublicKey.len > 0 and senderSecretKey.len > 0:
      kp0 = (pk: senderPublicKey, sk: senderSecretKey)
    else:
      raise newException(ValueError,
        "x25519 dispatch requires both senderPublicKey and senderSecretKey, or neither")
    result.senderPublicKey = kp0.pk
    result.ciphertext = @[]
    result.sharedSecret = x25519Shared(kp0.sk, receiverPublicKey)
  of kaKyber0, kaKyber1, kaMcEliece0, kaMcEliece1, kaMcEliece2,
      kaFrodo0, kaNtruPrime0, kaBike0:
    algId = kemAlgIdForDispatch(alg)
    if seed.len > 0:
      kem0 = kemEncaps(algId, receiverPublicKey, seed)
    else:
      kem0 = kemEncaps(algId, receiverPublicKey)
    result.ciphertext = kem0.ciphertext
    result.senderPublicKey = @[]
    result.sharedSecret = kem0.shared

proc asymDec*(alg: KemAlgorithm, receiverSecretKey: seq[uint8],
    cipher: AsymCipher): seq[uint8] =
  ## Recover the shared secret from a previously returned asymmetric envelope.
  var algId: string = ""
  case alg
  of kaX25519:
    result = x25519Shared(receiverSecretKey, cipher.senderPublicKey)
  of kaKyber0, kaKyber1, kaMcEliece0, kaMcEliece1, kaMcEliece2,
      kaFrodo0, kaNtruPrime0, kaBike0:
    algId = kemAlgIdForDispatch(alg)
    result = kemDecaps(algId, cipher.ciphertext, receiverSecretKey)

proc asymSign*(alg: SignatureAlgorithm, msg, secretKey: seq[uint8]): seq[uint8] =
  ## Create a detached signature with the selected signature backend.
  if alg in {saEd25519Falcon512Hybrid, saEd25519Falcon1024Hybrid}:
    raise newException(ValueError, "hybrid signature combinations are not supported by basic_api")
  result = signMessage(alg, msg, secretKey)

proc asymVerify*(alg: SignatureAlgorithm, msg, signature, publicKey: seq[uint8]): bool =
  ## Verify a detached signature with the selected signature backend.
  if alg in {saEd25519Falcon512Hybrid, saEd25519Falcon1024Hybrid}:
    raise newException(ValueError, "hybrid signature combinations are not supported by basic_api")
  result = verifyMessage(alg, msg, signature, publicKey)

proc crypoRand*(alg: algorithms.RandomAlgorithm, length: int,
    extraEntropy: seq[uint8] = @[]): seq[uint8] =
  ## Return cryptographically strong random bytes using the selected randomness mode.
  case alg
  of raSystem:
    result = cryptoRandomBytes(length)
  of raSystemMixed:
    result = cryptoRandomBytes(length, extraEntropy)

proc cryptoRand*(alg: algorithms.RandomAlgorithm, length: int,
    extraEntropy: seq[uint8] = @[]): seq[uint8] =
  ## Alias of `crypoRand` with the corrected public spelling.
  result = crypoRand(alg, length, extraEntropy)

proc hash*(message: openArray[byte], _: blake3HashM): HashDigest32 =
  ## Hash `message` with plain BLAKE3 and return the fixed 32-byte digest type.
  result = toDigest32(blake3Hash(message, digestBytes))

proc hash*(message: openArray[byte], _: gimliHashM): HashDigest32 =
  ## Hash `message` with the Gimli sponge and return the fixed 32-byte digest type.
  result = toDigest32(gimliXof(@[], @[], message, digestBytes))

proc hash*(message: openArray[byte], m: sha3HashM): seq[byte] =
  ## Hash `message` with SHA3 and optional variable output length.
  let outLen =
    if m.outLen == 0'u16: digestBytes
    else: int(m.outLen)
  result = sha3Hash(message, outLen)

proc hash*(message: openArray[byte], m: blake3KeyedHashM): seq[byte] =
  ## Hash `message` with keyed BLAKE3 and optional variable output length.
  let outLen =
    if m.outLen == 0'u16: digestBytes
    else: int(m.outLen)
  result = blake3KeyedHash(toSeqBytes(m.key), toSeqBytes(message), outLen)

proc hmac*(message: openArray[byte], m: blake3hmacM): seq[byte] =
  ## Create a detached BLAKE3-backed HMAC tag from typed material.
  result = hmacCreate(maBlake3, toSeqBytes(m.key), toSeqBytes(message), hmacLen(m.outLen))

proc hmac*(message: openArray[byte], m: gimlihmacM): seq[byte] =
  result = hmacCreate(maGimli, toSeqBytes(m.key), toSeqBytes(message), hmacLen(m.outLen))

proc hmac*(message: openArray[byte], m: poly1305hmacM): seq[byte] =
  result = hmacCreate(maPoly1305, toSeqBytes(m.key), toSeqBytes(message), hmacLen(m.outLen))

proc hmac*(message: openArray[byte], m: sha3hmacM): seq[byte] =
  result = hmacCreate(maSha3, toSeqBytes(m.key), toSeqBytes(message), hmacLen(m.outLen))

proc authenticate*(message: openArray[byte], m: blake3hmacVerifyM): bool =
  ## Verify a detached BLAKE3-backed HMAC tag from typed material.
  result = hmacAuth(maBlake3, toSeqBytes(m.key), toSeqBytes(message), m.tag, hmacLen(m.outLen))

proc authenticate*(message: openArray[byte], m: gimlihmacVerifyM): bool =
  result = hmacAuth(maGimli, toSeqBytes(m.key), toSeqBytes(message), m.tag, hmacLen(m.outLen))

proc authenticate*(message: openArray[byte], m: poly1305hmacVerifyM): bool =
  result = hmacAuth(maPoly1305, toSeqBytes(m.key), toSeqBytes(message), m.tag, hmacLen(m.outLen))

proc authenticate*(message: openArray[byte], m: sha3hmacVerifyM): bool =
  result = hmacAuth(maSha3, toSeqBytes(m.key), toSeqBytes(message), m.tag, hmacLen(m.outLen))

proc sign*(message: openArray[byte], m: ed25519SignM): seq[byte] =
  ## Sign `message` with typed Ed25519 material.
  result = asymSign(saEd25519, toSeqBytes(message), toSeqBytes(m.secretKey))

proc verify*(message: openArray[byte], m: ed25519VerifyM): bool =
  ## Verify an Ed25519 signature with typed verification material.
  result = asymVerify(saEd25519, toSeqBytes(message),
    toSeqBytes(m.signature), toSeqBytes(m.publicKey))

proc sign*(message: openArray[byte], m: falcon0SignM): seq[byte] =
  result = asymSign(saFalcon512, toSeqBytes(message), toSeqBytes(m.secretKey))

proc verify*(message: openArray[byte], m: falcon0VerifyM): bool =
  result = asymVerify(saFalcon512, toSeqBytes(message), toSeqBytes(m.signature),
    toSeqBytes(m.publicKey))

proc sign*(message: openArray[byte], m: falcon1SignM): seq[byte] =
  result = asymSign(saFalcon1024, toSeqBytes(message), toSeqBytes(m.secretKey))

proc verify*(message: openArray[byte], m: falcon1VerifyM): bool =
  result = asymVerify(saFalcon1024, toSeqBytes(message), toSeqBytes(m.signature),
    toSeqBytes(m.publicKey))

proc sign*(message: openArray[byte], m: dilithium0SignM): seq[byte] =
  result = asymSign(saDilithium0, toSeqBytes(message), toSeqBytes(m.secretKey))

proc verify*(message: openArray[byte], m: dilithium0VerifyM): bool =
  result = asymVerify(saDilithium0, toSeqBytes(message),
    toSeqBytes(m.signature), toSeqBytes(m.publicKey))

proc sign*(message: openArray[byte], m: dilithium1SignM): seq[byte] =
  result = asymSign(saDilithium1, toSeqBytes(message), toSeqBytes(m.secretKey))

proc verify*(message: openArray[byte], m: dilithium1VerifyM): bool =
  result = asymVerify(saDilithium1, toSeqBytes(message),
    toSeqBytes(m.signature), toSeqBytes(m.publicKey))

proc sign*(message: openArray[byte], m: dilithium2SignM): seq[byte] =
  result = asymSign(saDilithium2, toSeqBytes(message), toSeqBytes(m.secretKey))

proc verify*(message: openArray[byte], m: dilithium2VerifyM): bool =
  result = asymVerify(saDilithium2, toSeqBytes(message),
    toSeqBytes(m.signature), toSeqBytes(m.publicKey))

proc sign*(message: openArray[byte], m: ed448SignM): seq[byte] =
  result = asymSign(saEd448, toSeqBytes(message), toSeqBytes(m.secretKey))

proc verify*(message: openArray[byte], m: ed448VerifyM): bool =
  result = asymVerify(saEd448, toSeqBytes(message),
    toSeqBytes(m.signature), toSeqBytes(m.publicKey))

proc sign*(message: openArray[byte], m: sphincsHaraka128fSimpleSignM): seq[byte] =
  result = asymSign(saSPHINCSPlusHaraka128fSimple, toSeqBytes(message), toSeqBytes(m.secretKey))

proc verify*(message: openArray[byte], m: sphincsHaraka128fSimpleVerifyM): bool =
  result = asymVerify(saSPHINCSPlusHaraka128fSimple, toSeqBytes(message),
    toSeqBytes(m.signature), toSeqBytes(m.publicKey))

proc encrypt*(message: openArray[byte], m: xchacha20cipherM): seq[byte] =
  ## Encrypt or stream-XOR `message` with typed XChaCha20 material.
  result = symEnc(scaXChaCha20, toSeqBytes(m.key), toSeqBytes(m.nonce), toSeqBytes(message))

proc decrypt*(payload: openArray[byte], m: xchacha20cipherM): seq[byte] =
  ## Decrypt or stream-XOR `payload` with typed XChaCha20 material.
  result = symDec(scaXChaCha20, toSeqBytes(m.key), toSeqBytes(m.nonce), toSeqBytes(payload))

proc encrypt*(message: openArray[byte], m: aesCtrcipherM): seq[byte] =
  result = symEnc(scaAesCtr, toSeqBytes(m.key), toSeqBytes(m.nonce), toSeqBytes(message))

proc decrypt*(payload: openArray[byte], m: aesCtrcipherM): seq[byte] =
  result = symDec(scaAesCtr, toSeqBytes(m.key), toSeqBytes(m.nonce), toSeqBytes(payload))

proc encrypt*(message: openArray[byte], m: gimliStreamCipherM): seq[byte] =
  result = symEnc(scaGimliStream, toSeqBytes(m.key), toSeqBytes(m.nonce), toSeqBytes(message))

proc decrypt*(payload: openArray[byte], m: gimliStreamCipherM): seq[byte] =
  result = symDec(scaGimliStream, toSeqBytes(m.key), toSeqBytes(m.nonce), toSeqBytes(payload))

proc seal*(m: x25519SendM): AsymCipher =
  ## Encapsulate or derive a shared secret using typed X25519 send material.
  result = asymEnc(kaX25519, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymCipher, m: x25519OpenM): seq[byte] =
  ## Recover a shared secret using typed X25519 open material.
  result = asymDec(kaX25519, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: kyber0SendM): AsymCipher =
  result = asymEnc(kaKyber0, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymCipher, m: kyber0OpenM): seq[byte] =
  result = asymDec(kaKyber0, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: kyber1SendM): AsymCipher =
  result = asymEnc(kaKyber1, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymCipher, m: kyber1OpenM): seq[byte] =
  result = asymDec(kaKyber1, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: mceliece0SendM): AsymCipher =
  result = asymEnc(kaMcEliece0, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymCipher, m: mceliece0OpenM): seq[byte] =
  result = asymDec(kaMcEliece0, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: mceliece1SendM): AsymCipher =
  result = asymEnc(kaMcEliece1, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymCipher, m: mceliece1OpenM): seq[byte] =
  result = asymDec(kaMcEliece1, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: mceliece2SendM): AsymCipher =
  result = asymEnc(kaMcEliece2, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymCipher, m: mceliece2OpenM): seq[byte] =
  result = asymDec(kaMcEliece2, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: mceliece0TyrSendM): AsymCipher =
  ## Encapsulate with the pure-Nim Tyr McEliece tier-0 backend.
  var env = customMcEliece.mcelieceTyrEncaps(customMcEliece.mceliece6688128f,
    toSeqBytes(m.receiverPublicKey))
  result.ciphertext = env.ciphertext
  result.senderPublicKey = @[]
  result.sharedSecret = env.sharedSecret

proc open*(env: AsymCipher, m: mceliece0TyrOpenM): seq[byte] =
  ## Decapsulate with the pure-Nim Tyr McEliece tier-0 backend.
  result = customMcEliece.mcelieceTyrDecaps(customMcEliece.mceliece6688128f,
    toSeqBytes(m.receiverSecretKey), env.ciphertext)

proc seal*(m: mceliece1TyrSendM): AsymCipher =
  ## Encapsulate with the pure-Nim Tyr McEliece tier-1 backend.
  var env = customMcEliece.mcelieceTyrEncaps(customMcEliece.mceliece6960119f,
    toSeqBytes(m.receiverPublicKey))
  result.ciphertext = env.ciphertext
  result.senderPublicKey = @[]
  result.sharedSecret = env.sharedSecret

proc open*(env: AsymCipher, m: mceliece1TyrOpenM): seq[byte] =
  ## Decapsulate with the pure-Nim Tyr McEliece tier-1 backend.
  result = customMcEliece.mcelieceTyrDecaps(customMcEliece.mceliece6960119f,
    toSeqBytes(m.receiverSecretKey), env.ciphertext)

proc seal*(m: mceliece2TyrSendM): AsymCipher =
  ## Encapsulate with the pure-Nim Tyr McEliece tier-2 backend.
  var env = customMcEliece.mcelieceTyrEncaps(customMcEliece.mceliece8192128f,
    toSeqBytes(m.receiverPublicKey))
  result.ciphertext = env.ciphertext
  result.senderPublicKey = @[]
  result.sharedSecret = env.sharedSecret

proc open*(env: AsymCipher, m: mceliece2TyrOpenM): seq[byte] =
  ## Decapsulate with the pure-Nim Tyr McEliece tier-2 backend.
  result = customMcEliece.mcelieceTyrDecaps(customMcEliece.mceliece8192128f,
    toSeqBytes(m.receiverSecretKey), env.ciphertext)

proc seal*(m: frodo0SendM): AsymCipher =
  result = asymEnc(kaFrodo0, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymCipher, m: frodo0OpenM): seq[byte] =
  result = asymDec(kaFrodo0, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: ntruprime0SendM): AsymCipher =
  result = asymEnc(kaNtruPrime0, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymCipher, m: ntruprime0OpenM): seq[byte] =
  result = asymDec(kaNtruPrime0, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: bike0SendM): AsymCipher =
  result = asymEnc(kaBike0, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymCipher, m: bike0OpenM): seq[byte] =
  result = asymDec(kaBike0, toSeqBytes(m.receiverSecretKey), env)
