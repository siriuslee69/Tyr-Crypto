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
import ../custom_crypto/dilithium as customDilithium
import ../custom_crypto/gimli_sponge
import ../custom_crypto/bike as customBike
import ../custom_crypto/frodo as customFrodo
import ../custom_crypto/kyber as customKyber
import ../custom_crypto/mceliece as customMcEliece
import ../custom_crypto/sphincs as customSphincs
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

  ## Public asymmetric/KEM envelope that is safe to serialize or send.
  AsymEnvelope* = object
    ciphertext*: seq[uint8]
    senderPublicKey*: seq[uint8]

  ## Local asymmetric/KEM result returned by `seal` and `asymEnc`.
  AsymCipher* = object
    envelope*: AsymEnvelope
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
  ## Material for Poly1305 one-time tag creation.
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
  ## Material for Poly1305 one-time tag verification.
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
  ## Material for the pure-Nim Tyr Kyber tier-0 encapsulation path.
  kyber0TyrSendM* = object
    receiverPublicKey*: array[1184, byte]
  ## Material for the pure-Nim Tyr Kyber tier-0 decapsulation path.
  kyber0TyrOpenM* = object
    receiverSecretKey*: array[2400, byte]
  ## Material for the pure-Nim Tyr Kyber tier-1 encapsulation path.
  kyber1TyrSendM* = object
    receiverPublicKey*: array[1568, byte]
  ## Material for the pure-Nim Tyr Kyber tier-1 decapsulation path.
  kyber1TyrOpenM* = object
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
  ## Material for Frodo tier-0 AES encapsulation.
  frodo0AesSendM* = object
    receiverPublicKey*: array[9616, byte]
  ## Material for Frodo tier-0 AES decapsulation.
  frodo0AesOpenM* = object
    receiverSecretKey*: array[19888, byte]
  ## Material for Frodo tier-0 SHAKE encapsulation.
  frodo0ShakeSendM* = object
    receiverPublicKey*: array[9616, byte]
  ## Material for Frodo tier-0 SHAKE decapsulation.
  frodo0ShakeOpenM* = object
    receiverSecretKey*: array[19888, byte]
  ## Material for Frodo tier-1 AES encapsulation.
  frodo1AesSendM* = object
    receiverPublicKey*: array[15632, byte]
  ## Material for Frodo tier-1 AES decapsulation.
  frodo1AesOpenM* = object
    receiverSecretKey*: array[31296, byte]
  ## Material for Frodo tier-1 SHAKE encapsulation.
  frodo1ShakeSendM* = object
    receiverPublicKey*: array[15632, byte]
  ## Material for Frodo tier-1 SHAKE decapsulation.
  frodo1ShakeOpenM* = object
    receiverSecretKey*: array[31296, byte]
  ## Material for Frodo tier-2 AES encapsulation.
  frodo2AesSendM* = object
    receiverPublicKey*: array[21520, byte]
  ## Material for Frodo tier-2 AES decapsulation.
  frodo2AesOpenM* = object
    receiverSecretKey*: array[43088, byte]
  ## Material for Frodo tier-2 SHAKE encapsulation.
  frodo2ShakeSendM* = object
    receiverPublicKey*: array[21520, byte]
  ## Material for Frodo tier-2 SHAKE decapsulation.
  frodo2ShakeOpenM* = object
    receiverSecretKey*: array[43088, byte]
  ## Material for the pure-Nim Tyr Frodo tier-0 AES encapsulation path.
  frodo0AesTyrSendM* = object
    receiverPublicKey*: array[9616, byte]
  ## Material for the pure-Nim Tyr Frodo tier-0 AES decapsulation path.
  frodo0AesTyrOpenM* = object
    receiverSecretKey*: array[19888, byte]
  ## Material for the pure-Nim Tyr Frodo tier-0 SHAKE encapsulation path.
  frodo0ShakeTyrSendM* = object
    receiverPublicKey*: array[9616, byte]
  ## Material for the pure-Nim Tyr Frodo tier-0 SHAKE decapsulation path.
  frodo0ShakeTyrOpenM* = object
    receiverSecretKey*: array[19888, byte]
  ## Material for the pure-Nim Tyr Frodo tier-1 AES encapsulation path.
  frodo1AesTyrSendM* = object
    receiverPublicKey*: array[15632, byte]
  ## Material for the pure-Nim Tyr Frodo tier-1 AES decapsulation path.
  frodo1AesTyrOpenM* = object
    receiverSecretKey*: array[31296, byte]
  ## Material for the pure-Nim Tyr Frodo tier-1 SHAKE encapsulation path.
  frodo1ShakeTyrSendM* = object
    receiverPublicKey*: array[15632, byte]
  ## Material for the pure-Nim Tyr Frodo tier-1 SHAKE decapsulation path.
  frodo1ShakeTyrOpenM* = object
    receiverSecretKey*: array[31296, byte]
  ## Material for the pure-Nim Tyr Frodo tier-2 AES encapsulation path.
  frodo2AesTyrSendM* = object
    receiverPublicKey*: array[21520, byte]
  ## Material for the pure-Nim Tyr Frodo tier-2 AES decapsulation path.
  frodo2AesTyrOpenM* = object
    receiverSecretKey*: array[43088, byte]
  ## Material for the pure-Nim Tyr Frodo tier-2 SHAKE encapsulation path.
  frodo2ShakeTyrSendM* = object
    receiverPublicKey*: array[21520, byte]
  ## Material for the pure-Nim Tyr Frodo tier-2 SHAKE decapsulation path.
  frodo2ShakeTyrOpenM* = object
    receiverSecretKey*: array[43088, byte]
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
  ## Material for the pure-Nim Tyr BIKE tier-0 encapsulation path.
  bike0TyrSendM* = object
    receiverPublicKey*: array[1541, byte]
  ## Material for the pure-Nim Tyr BIKE tier-0 decapsulation path.
  bike0TyrOpenM* = object
    receiverSecretKey*: array[5223, byte]

  ## Tyr-suffixed alias for the local BLAKE3 hash material.
  blake3TyrHashM* = blake3HashM
  ## Tyr-suffixed alias for the local Gimli hash material.
  gimliTyrHashM* = gimliHashM
  ## Tyr-suffixed alias for the local SHA3 hash material.
  sha3TyrHashM* = sha3HashM
  ## Tyr-suffixed alias for the local keyed BLAKE3 material.
  blake3TyrKeyedHashM* = blake3KeyedHashM
  ## Tyr-suffixed alias for the local BLAKE3 HMAC material.
  blake3TyrHmacM* = blake3hmacM
  ## Tyr-suffixed alias for the local Gimli HMAC material.
  gimliTyrHmacM* = gimlihmacM
  ## Tyr-suffixed alias for the local Poly1305 HMAC material.
  poly1305TyrHmacM* = poly1305hmacM
  ## Tyr-suffixed alias for the local SHA3 HMAC material.
  sha3TyrHmacM* = sha3hmacM
  ## Tyr-suffixed alias for the local BLAKE3 HMAC verification material.
  blake3TyrHmacVerifyM* = blake3hmacVerifyM
  ## Tyr-suffixed alias for the local Gimli HMAC verification material.
  gimliTyrHmacVerifyM* = gimlihmacVerifyM
  ## Tyr-suffixed alias for the local Poly1305 HMAC verification material.
  poly1305TyrHmacVerifyM* = poly1305hmacVerifyM
  ## Tyr-suffixed alias for the local SHA3 HMAC verification material.
  sha3TyrHmacVerifyM* = sha3hmacVerifyM
  ## Tyr-suffixed alias for the local XChaCha20 cipher material.
  xchacha20TyrCipherM* = xchacha20cipherM
  ## Tyr-suffixed alias for the local AES-CTR cipher material.
  aesCtrTyrCipherM* = aesCtrcipherM
  ## Tyr-suffixed alias for the local Gimli stream-cipher material.
  gimliStreamTyrCipherM* = gimliStreamCipherM

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
proc algorithmOf*(T: typedesc[x25519SendM]): AlgorithmKind = akX25519Send
proc algorithmOf*(T: typedesc[x25519OpenM]): AlgorithmKind = akX25519Open
proc algorithmOf*(T: typedesc[kyber0SendM]): AlgorithmKind = akKyber0Send
proc algorithmOf*(T: typedesc[kyber0OpenM]): AlgorithmKind = akKyber0Open
proc algorithmOf*(T: typedesc[kyber1SendM]): AlgorithmKind = akKyber1Send
proc algorithmOf*(T: typedesc[kyber1OpenM]): AlgorithmKind = akKyber1Open
proc algorithmOf*(T: typedesc[kyber0TyrSendM]): AlgorithmKind = akKyber0TyrSend
proc algorithmOf*(T: typedesc[kyber0TyrOpenM]): AlgorithmKind = akKyber0TyrOpen
proc algorithmOf*(T: typedesc[kyber1TyrSendM]): AlgorithmKind = akKyber1TyrSend
proc algorithmOf*(T: typedesc[kyber1TyrOpenM]): AlgorithmKind = akKyber1TyrOpen
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
proc algorithmOf*(T: typedesc[frodo0AesSendM]): AlgorithmKind = akFrodo0AesSend
proc algorithmOf*(T: typedesc[frodo0AesOpenM]): AlgorithmKind = akFrodo0AesOpen
proc algorithmOf*(T: typedesc[frodo0ShakeSendM]): AlgorithmKind = akFrodo0ShakeSend
proc algorithmOf*(T: typedesc[frodo0ShakeOpenM]): AlgorithmKind = akFrodo0ShakeOpen
proc algorithmOf*(T: typedesc[frodo1AesSendM]): AlgorithmKind = akFrodo1AesSend
proc algorithmOf*(T: typedesc[frodo1AesOpenM]): AlgorithmKind = akFrodo1AesOpen
proc algorithmOf*(T: typedesc[frodo1ShakeSendM]): AlgorithmKind = akFrodo1ShakeSend
proc algorithmOf*(T: typedesc[frodo1ShakeOpenM]): AlgorithmKind = akFrodo1ShakeOpen
proc algorithmOf*(T: typedesc[frodo2AesSendM]): AlgorithmKind = akFrodo2AesSend
proc algorithmOf*(T: typedesc[frodo2AesOpenM]): AlgorithmKind = akFrodo2AesOpen
proc algorithmOf*(T: typedesc[frodo2ShakeSendM]): AlgorithmKind = akFrodo2ShakeSend
proc algorithmOf*(T: typedesc[frodo2ShakeOpenM]): AlgorithmKind = akFrodo2ShakeOpen
proc algorithmOf*(T: typedesc[frodo0AesTyrSendM]): AlgorithmKind = akFrodo0AesTyrSend
proc algorithmOf*(T: typedesc[frodo0AesTyrOpenM]): AlgorithmKind = akFrodo0AesTyrOpen
proc algorithmOf*(T: typedesc[frodo0ShakeTyrSendM]): AlgorithmKind = akFrodo0ShakeTyrSend
proc algorithmOf*(T: typedesc[frodo0ShakeTyrOpenM]): AlgorithmKind = akFrodo0ShakeTyrOpen
proc algorithmOf*(T: typedesc[frodo1AesTyrSendM]): AlgorithmKind = akFrodo1AesTyrSend
proc algorithmOf*(T: typedesc[frodo1AesTyrOpenM]): AlgorithmKind = akFrodo1AesTyrOpen
proc algorithmOf*(T: typedesc[frodo1ShakeTyrSendM]): AlgorithmKind = akFrodo1ShakeTyrSend
proc algorithmOf*(T: typedesc[frodo1ShakeTyrOpenM]): AlgorithmKind = akFrodo1ShakeTyrOpen
proc algorithmOf*(T: typedesc[frodo2AesTyrSendM]): AlgorithmKind = akFrodo2AesTyrSend
proc algorithmOf*(T: typedesc[frodo2AesTyrOpenM]): AlgorithmKind = akFrodo2AesTyrOpen
proc algorithmOf*(T: typedesc[frodo2ShakeTyrSendM]): AlgorithmKind = akFrodo2ShakeTyrSend
proc algorithmOf*(T: typedesc[frodo2ShakeTyrOpenM]): AlgorithmKind = akFrodo2ShakeTyrOpen
proc algorithmOf*(T: typedesc[ntruprime0SendM]): AlgorithmKind = akNtruPrime0Send
proc algorithmOf*(T: typedesc[ntruprime0OpenM]): AlgorithmKind = akNtruPrime0Open
proc algorithmOf*(T: typedesc[bike0TyrSendM]): AlgorithmKind = akBike0TyrSend
proc algorithmOf*(T: typedesc[bike0TyrOpenM]): AlgorithmKind = akBike0TyrOpen
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

proc hmacLen(outLen: uint16): int =
  if outLen == 0'u16:
    result = digestBytes
  else:
    result = int(outLen)

proc poly1305Len(outLen: uint16): int =
  if outLen == 0'u16:
    result = 16
  else:
    result = int(outLen)

proc constantTimeEqual(a, b: openArray[uint8]): bool =
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

proc x25519PublicKeyFromSecret(secretKey: openArray[uint8]): seq[uint8] =
  if secretKey.len != x25519KeyBytes:
    raise newException(ValueError, "invalid X25519 secret key length")
  result = newSeq[uint8](x25519KeyBytes)
  if crypto_scalarmult_curve25519_base(
      addr result[0],
      if secretKey.len > 0: unsafeAddr secretKey[0] else: nil) != 0:
    raiseOperation("libsodium", "crypto_scalarmult_curve25519_base failed")

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

proc frodoAlgIdForTier(alg: KemAlgorithm): string =
  case alg
  of kaFrodo0Aes:
    result = oqsAlgFrodoKEM640Aes
  of kaFrodo0Shake:
    result = oqsAlgFrodoKEM640Shake
  of kaFrodo1Aes:
    result = oqsAlgFrodoKEM976Aes
  of kaFrodo1Shake:
    result = oqsAlgFrodoKEM976Shake
  of kaFrodo2Aes:
    result = oqsAlgFrodoKEM1344Aes
  of kaFrodo2Shake:
    result = oqsAlgFrodoKEM1344Shake
  else:
    raise newException(ValueError, "algorithm is not a frodo tier")

proc kemAlgIdForDispatch(alg: KemAlgorithm): string =
  case alg
  of kaKyber0, kaKyber1:
    result = kyberAlgId(kyberVariantForTier(alg))
  of kaMcEliece0, kaMcEliece1, kaMcEliece2:
    result = mcElieceAlgId(mcElieceVariantForTier(alg))
  of kaFrodo0Aes, kaFrodo0Shake, kaFrodo1Aes, kaFrodo1Shake, kaFrodo2Aes, kaFrodo2Shake:
    result = frodoAlgIdForTier(alg)
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
      kaFrodo0Aes, kaFrodo0Shake, kaFrodo1Aes, kaFrodo1Shake, kaFrodo2Aes,
      kaFrodo2Shake, kaNtruPrime0, kaBike0:
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

proc asymKeypair*(T: typedesc[kyber0TyrSendM]): AsymKeypair =
  ## Build a pure-Nim Tyr Kyber tier-0 keypair.
  var kp = customKyber.kyberTyrKeypair(customKyber.kyber768)
  result.publicKey = kp.publicKey
  result.secretKey = kp.secretKey

proc asymKeypair*(T: typedesc[kyber0TyrOpenM]): AsymKeypair =
  ## Build a pure-Nim Tyr Kyber tier-0 keypair.
  result = asymKeypair(kyber0TyrSendM)

proc asymKeypair*(T: typedesc[kyber1TyrSendM]): AsymKeypair =
  ## Build a pure-Nim Tyr Kyber tier-1 keypair.
  var kp = customKyber.kyberTyrKeypair(customKyber.kyber1024)
  result.publicKey = kp.publicKey
  result.secretKey = kp.secretKey

proc asymKeypair*(T: typedesc[kyber1TyrOpenM]): AsymKeypair =
  ## Build a pure-Nim Tyr Kyber tier-1 keypair.
  result = asymKeypair(kyber1TyrSendM)

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

proc buildFrodoTyrKeypair(v: customFrodo.FrodoVariant): AsymKeypair =
  var kp = customFrodo.frodoTyrKeypair(v)
  result.publicKey = kp.publicKey
  result.secretKey = kp.secretKey

proc asymKeypair*(T: typedesc[frodo0AesTyrSendM]): AsymKeypair =
  result = buildFrodoTyrKeypair(customFrodo.frodo640aes)

proc asymKeypair*(T: typedesc[frodo0AesTyrOpenM]): AsymKeypair =
  result = asymKeypair(frodo0AesTyrSendM)

proc asymKeypair*(T: typedesc[frodo0ShakeTyrSendM]): AsymKeypair =
  result = buildFrodoTyrKeypair(customFrodo.frodo640shake)

proc asymKeypair*(T: typedesc[frodo0ShakeTyrOpenM]): AsymKeypair =
  result = asymKeypair(frodo0ShakeTyrSendM)

proc asymKeypair*(T: typedesc[frodo1AesTyrSendM]): AsymKeypair =
  result = buildFrodoTyrKeypair(customFrodo.frodo976aes)

proc asymKeypair*(T: typedesc[frodo1AesTyrOpenM]): AsymKeypair =
  result = asymKeypair(frodo1AesTyrSendM)

proc asymKeypair*(T: typedesc[frodo1ShakeTyrSendM]): AsymKeypair =
  result = buildFrodoTyrKeypair(customFrodo.frodo976shake)

proc asymKeypair*(T: typedesc[frodo1ShakeTyrOpenM]): AsymKeypair =
  result = asymKeypair(frodo1ShakeTyrSendM)

proc asymKeypair*(T: typedesc[frodo2AesTyrSendM]): AsymKeypair =
  result = buildFrodoTyrKeypair(customFrodo.frodo1344aes)

proc asymKeypair*(T: typedesc[frodo2AesTyrOpenM]): AsymKeypair =
  result = asymKeypair(frodo2AesTyrSendM)

proc asymKeypair*(T: typedesc[frodo2ShakeTyrSendM]): AsymKeypair =
  result = buildFrodoTyrKeypair(customFrodo.frodo1344shake)

proc asymKeypair*(T: typedesc[frodo2ShakeTyrOpenM]): AsymKeypair =
  result = asymKeypair(frodo2ShakeTyrSendM)

proc asymKeypair*(T: typedesc[bike0TyrSendM]): AsymKeypair =
  ## Build a pure-Nim Tyr BIKE tier-0 keypair.
  var kp = customBike.bikeTyrKeypair(customBike.bikeL1)
  result.publicKey = kp.publicKey
  result.secretKey = kp.secretKey

proc asymKeypair*(T: typedesc[bike0TyrOpenM]): AsymKeypair =
  ## Build a pure-Nim Tyr BIKE tier-0 keypair.
  result = asymKeypair(bike0TyrSendM)

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

proc macOutLen(alg: MacAlgorithm, outLen: int): int =
  if outLen > 0:
    return outLen
  case alg
  of maPoly1305:
    result = 16
  else:
    result = digestBytes

proc hmacCreate*(alg: MacAlgorithm, key, msg: seq[uint8], outLen: int = 0): seq[uint8] =
  ## Create a detached MAC/tag with the selected keyed hash backend.
  let resolvedOutLen = macOutLen(alg, outLen)
  case alg
  of maBlake3:
    result = blake3CustomHmac(key, msg, resolvedOutLen)
  of maGimli:
    result = gimliCustomHmac(key, msg, resolvedOutLen)
  of maPoly1305:
    result = poly1305CustomHmac(key, msg, resolvedOutLen)
  of maSha3:
    result = sha3CustomHmac(key, msg, resolvedOutLen)

proc hmacAuth*(alg: MacAlgorithm, key, msg, tag: seq[uint8], outLen: int = 0): bool =
  ## Verify a detached MAC/tag with the selected keyed hash backend.
  var expected: seq[uint8] = @[]
  expected = hmacCreate(alg, key, msg, macOutLen(alg, outLen))
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
      let derivedPublicKey = x25519PublicKeyFromSecret(senderSecretKey)
      if not constantTimeEqual(derivedPublicKey, senderPublicKey):
        raise newException(ValueError,
          "x25519 senderPublicKey does not match senderSecretKey")
      kp0 = (pk: senderPublicKey, sk: senderSecretKey)
    else:
      raise newException(ValueError,
        "x25519 dispatch requires both senderPublicKey and senderSecretKey, or neither")
    result = initAsymCipher(@[], kp0.pk, x25519Shared(kp0.sk, receiverPublicKey))
  of kaKyber0, kaKyber1, kaMcEliece0, kaMcEliece1, kaMcEliece2,
      kaFrodo0Aes, kaFrodo0Shake, kaFrodo1Aes, kaFrodo1Shake, kaFrodo2Aes,
      kaFrodo2Shake, kaNtruPrime0, kaBike0:
    algId = kemAlgIdForDispatch(alg)
    if seed.len > 0:
      kem0 = kemEncaps(algId, receiverPublicKey, seed)
    else:
      kem0 = kemEncaps(algId, receiverPublicKey)
    result = initAsymCipher(kem0.ciphertext, @[], kem0.shared)

proc asymDec*(alg: KemAlgorithm, receiverSecretKey: seq[uint8],
    cipher: AsymEnvelope): seq[uint8] =
  ## Recover the shared secret from a previously returned asymmetric envelope.
  var algId: string = ""
  case alg
  of kaX25519:
    result = x25519Shared(receiverSecretKey, cipher.senderPublicKey)
  of kaKyber0, kaKyber1, kaMcEliece0, kaMcEliece1, kaMcEliece2,
      kaFrodo0Aes, kaFrodo0Shake, kaFrodo1Aes, kaFrodo1Shake, kaFrodo2Aes,
      kaFrodo2Shake, kaNtruPrime0, kaBike0:
    algId = kemAlgIdForDispatch(alg)
    result = kemDecaps(algId, cipher.ciphertext, receiverSecretKey)

proc asymDec*(alg: KemAlgorithm, receiverSecretKey: seq[uint8],
    cipher: AsymCipher): seq[uint8] =
  ## Recover the shared secret using a local `AsymCipher` result.
  result = asymDec(alg, receiverSecretKey, cipher.envelope)

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
  result = hmacCreate(maPoly1305, toSeqBytes(m.key), toSeqBytes(message), poly1305Len(m.outLen))

proc hmac*(message: openArray[byte], m: sha3hmacM): seq[byte] =
  result = hmacCreate(maSha3, toSeqBytes(m.key), toSeqBytes(message), hmacLen(m.outLen))

proc authenticate*(message: openArray[byte], m: blake3hmacVerifyM): bool =
  ## Verify a detached BLAKE3-backed HMAC tag from typed material.
  result = hmacAuth(maBlake3, toSeqBytes(m.key), toSeqBytes(message), m.tag, hmacLen(m.outLen))

proc authenticate*(message: openArray[byte], m: gimlihmacVerifyM): bool =
  result = hmacAuth(maGimli, toSeqBytes(m.key), toSeqBytes(message), m.tag, hmacLen(m.outLen))

proc authenticate*(message: openArray[byte], m: poly1305hmacVerifyM): bool =
  result = hmacAuth(maPoly1305, toSeqBytes(m.key), toSeqBytes(message), m.tag, poly1305Len(m.outLen))

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
  result = asymSign(saEd448, toSeqBytes(message), toSeqBytes(m.secretKey))

proc verify*(message: openArray[byte], m: ed448VerifyM): bool =
  result = asymVerify(saEd448, toSeqBytes(message),
    toSeqBytes(m.signature), toSeqBytes(m.publicKey))

proc sign*(message: openArray[byte], m: sphincsShake128fSimpleSignM): seq[byte] =
  result = asymSign(saSPHINCSPlusShake128fSimple, toSeqBytes(message), toSeqBytes(m.secretKey))

proc verify*(message: openArray[byte], m: sphincsShake128fSimpleVerifyM): bool =
  result = asymVerify(saSPHINCSPlusShake128fSimple, toSeqBytes(message),
    toSeqBytes(m.signature), toSeqBytes(m.publicKey))

proc sign*(message: openArray[byte], m: sphincsShake128fSimpleTyrSignM): seq[byte] =
  result = customSphincs.sphincsTyrSignDerand(customSphincs.sphincsShake128fSimple,
    toSeqBytes(message), toSeqBytes(m.secretKey), cryptoRandomBytes(16))

proc verify*(message: openArray[byte], m: sphincsShake128fSimpleTyrVerifyM): bool =
  result = customSphincs.sphincsTyrVerify(customSphincs.sphincsShake128fSimple,
    toSeqBytes(message), toSeqBytes(m.signature), toSeqBytes(m.publicKey))

proc sign*(message: openArray[byte], m: sphincsHaraka128fSimpleSignM): seq[byte] =
  result = asymSign(saSPHINCSPlusShake128fSimple, toSeqBytes(message), toSeqBytes(m.secretKey))

proc verify*(message: openArray[byte], m: sphincsHaraka128fSimpleVerifyM): bool =
  result = asymVerify(saSPHINCSPlusShake128fSimple, toSeqBytes(message),
    toSeqBytes(m.signature), toSeqBytes(m.publicKey))

proc sign*(message: openArray[byte], m: sphincsHaraka128fSimpleTyrSignM): seq[byte] =
  result = customSphincs.sphincsTyrSignDerand(customSphincs.sphincsShake128fSimple,
    toSeqBytes(message), toSeqBytes(m.secretKey), cryptoRandomBytes(16))

proc verify*(message: openArray[byte], m: sphincsHaraka128fSimpleTyrVerifyM): bool =
  result = customSphincs.sphincsTyrVerify(customSphincs.sphincsShake128fSimple,
    toSeqBytes(message), toSeqBytes(m.signature), toSeqBytes(m.publicKey))

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

proc open*(env: AsymEnvelope, m: x25519OpenM): seq[byte] =
  ## Recover a shared secret using typed X25519 open material.
  result = asymDec(kaX25519, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: kyber0SendM): AsymCipher =
  result = asymEnc(kaKyber0, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: kyber0OpenM): seq[byte] =
  result = asymDec(kaKyber0, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: kyber1SendM): AsymCipher =
  result = asymEnc(kaKyber1, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: kyber1OpenM): seq[byte] =
  result = asymDec(kaKyber1, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: kyber0TyrSendM): AsymCipher =
  ## Encapsulate with the pure-Nim Tyr Kyber tier-0 backend.
  var env = customKyber.kyberTyrEncaps(customKyber.kyber768, toSeqBytes(m.receiverPublicKey))
  result.envelope.ciphertext = env.ciphertext
  result.envelope.senderPublicKey = @[]
  result.sharedSecret = env.sharedSecret

proc open*(env: AsymEnvelope, m: kyber0TyrOpenM): seq[byte] =
  ## Decapsulate with the pure-Nim Tyr Kyber tier-0 backend.
  result = customKyber.kyberTyrDecaps(customKyber.kyber768,
    toSeqBytes(m.receiverSecretKey), env.ciphertext)

proc seal*(m: kyber1TyrSendM): AsymCipher =
  ## Encapsulate with the pure-Nim Tyr Kyber tier-1 backend.
  var env = customKyber.kyberTyrEncaps(customKyber.kyber1024, toSeqBytes(m.receiverPublicKey))
  result.envelope.ciphertext = env.ciphertext
  result.envelope.senderPublicKey = @[]
  result.sharedSecret = env.sharedSecret

proc open*(env: AsymEnvelope, m: kyber1TyrOpenM): seq[byte] =
  ## Decapsulate with the pure-Nim Tyr Kyber tier-1 backend.
  result = customKyber.kyberTyrDecaps(customKyber.kyber1024,
    toSeqBytes(m.receiverSecretKey), env.ciphertext)

proc seal*(m: mceliece0SendM): AsymCipher =
  result = asymEnc(kaMcEliece0, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: mceliece0OpenM): seq[byte] =
  result = asymDec(kaMcEliece0, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: mceliece1SendM): AsymCipher =
  result = asymEnc(kaMcEliece1, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: mceliece1OpenM): seq[byte] =
  result = asymDec(kaMcEliece1, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: mceliece2SendM): AsymCipher =
  result = asymEnc(kaMcEliece2, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: mceliece2OpenM): seq[byte] =
  result = asymDec(kaMcEliece2, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: mceliece0TyrSendM): AsymCipher =
  ## Encapsulate with the pure-Nim Tyr McEliece tier-0 backend.
  var env = customMcEliece.mcelieceTyrEncaps(customMcEliece.mceliece6688128f,
    toSeqBytes(m.receiverPublicKey))
  result.envelope.ciphertext = env.ciphertext
  result.envelope.senderPublicKey = @[]
  result.sharedSecret = env.sharedSecret

proc open*(env: AsymEnvelope, m: mceliece0TyrOpenM): seq[byte] =
  ## Decapsulate with the pure-Nim Tyr McEliece tier-0 backend.
  result = customMcEliece.mcelieceTyrDecaps(customMcEliece.mceliece6688128f,
    toSeqBytes(m.receiverSecretKey), env.ciphertext)

proc seal*(m: mceliece1TyrSendM): AsymCipher =
  ## Encapsulate with the pure-Nim Tyr McEliece tier-1 backend.
  var env = customMcEliece.mcelieceTyrEncaps(customMcEliece.mceliece6960119f,
    toSeqBytes(m.receiverPublicKey))
  result.envelope.ciphertext = env.ciphertext
  result.envelope.senderPublicKey = @[]
  result.sharedSecret = env.sharedSecret

proc open*(env: AsymEnvelope, m: mceliece1TyrOpenM): seq[byte] =
  ## Decapsulate with the pure-Nim Tyr McEliece tier-1 backend.
  result = customMcEliece.mcelieceTyrDecaps(customMcEliece.mceliece6960119f,
    toSeqBytes(m.receiverSecretKey), env.ciphertext)

proc seal*(m: mceliece2TyrSendM): AsymCipher =
  ## Encapsulate with the pure-Nim Tyr McEliece tier-2 backend.
  var env = customMcEliece.mcelieceTyrEncaps(customMcEliece.mceliece8192128f,
    toSeqBytes(m.receiverPublicKey))
  result.envelope.ciphertext = env.ciphertext
  result.envelope.senderPublicKey = @[]
  result.sharedSecret = env.sharedSecret

proc open*(env: AsymEnvelope, m: mceliece2TyrOpenM): seq[byte] =
  ## Decapsulate with the pure-Nim Tyr McEliece tier-2 backend.
  result = customMcEliece.mcelieceTyrDecaps(customMcEliece.mceliece8192128f,
    toSeqBytes(m.receiverSecretKey), env.ciphertext)

proc buildFrodoTyrSeal(v: customFrodo.FrodoVariant, pk: openArray[byte]): AsymCipher =
  var env = customFrodo.frodoTyrEncaps(v, toSeqBytes(pk))
  result.envelope.ciphertext = env.ciphertext
  result.envelope.senderPublicKey = @[]
  result.sharedSecret = env.sharedSecret

proc buildFrodoTyrOpen(v: customFrodo.FrodoVariant, sk: openArray[byte],
    env: AsymEnvelope): seq[byte] =
  result = customFrodo.frodoTyrDecaps(v, toSeqBytes(sk), env.ciphertext)

proc seal*(m: frodo0AesSendM): AsymCipher =
  result = asymEnc(kaFrodo0Aes, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: frodo0AesOpenM): seq[byte] =
  result = asymDec(kaFrodo0Aes, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: frodo0ShakeSendM): AsymCipher =
  result = asymEnc(kaFrodo0Shake, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: frodo0ShakeOpenM): seq[byte] =
  result = asymDec(kaFrodo0Shake, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: frodo1AesSendM): AsymCipher =
  result = asymEnc(kaFrodo1Aes, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: frodo1AesOpenM): seq[byte] =
  result = asymDec(kaFrodo1Aes, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: frodo1ShakeSendM): AsymCipher =
  result = asymEnc(kaFrodo1Shake, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: frodo1ShakeOpenM): seq[byte] =
  result = asymDec(kaFrodo1Shake, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: frodo2AesSendM): AsymCipher =
  result = asymEnc(kaFrodo2Aes, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: frodo2AesOpenM): seq[byte] =
  result = asymDec(kaFrodo2Aes, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: frodo2ShakeSendM): AsymCipher =
  result = asymEnc(kaFrodo2Shake, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: frodo2ShakeOpenM): seq[byte] =
  result = asymDec(kaFrodo2Shake, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: frodo0AesTyrSendM): AsymCipher =
  result = buildFrodoTyrSeal(customFrodo.frodo640aes, m.receiverPublicKey)

proc open*(env: AsymEnvelope, m: frodo0AesTyrOpenM): seq[byte] =
  result = buildFrodoTyrOpen(customFrodo.frodo640aes, m.receiverSecretKey, env)

proc seal*(m: frodo0ShakeTyrSendM): AsymCipher =
  result = buildFrodoTyrSeal(customFrodo.frodo640shake, m.receiverPublicKey)

proc open*(env: AsymEnvelope, m: frodo0ShakeTyrOpenM): seq[byte] =
  result = buildFrodoTyrOpen(customFrodo.frodo640shake, m.receiverSecretKey, env)

proc seal*(m: frodo1AesTyrSendM): AsymCipher =
  result = buildFrodoTyrSeal(customFrodo.frodo976aes, m.receiverPublicKey)

proc open*(env: AsymEnvelope, m: frodo1AesTyrOpenM): seq[byte] =
  result = buildFrodoTyrOpen(customFrodo.frodo976aes, m.receiverSecretKey, env)

proc seal*(m: frodo1ShakeTyrSendM): AsymCipher =
  result = buildFrodoTyrSeal(customFrodo.frodo976shake, m.receiverPublicKey)

proc open*(env: AsymEnvelope, m: frodo1ShakeTyrOpenM): seq[byte] =
  result = buildFrodoTyrOpen(customFrodo.frodo976shake, m.receiverSecretKey, env)

proc seal*(m: frodo2AesTyrSendM): AsymCipher =
  result = buildFrodoTyrSeal(customFrodo.frodo1344aes, m.receiverPublicKey)

proc open*(env: AsymEnvelope, m: frodo2AesTyrOpenM): seq[byte] =
  result = buildFrodoTyrOpen(customFrodo.frodo1344aes, m.receiverSecretKey, env)

proc seal*(m: frodo2ShakeTyrSendM): AsymCipher =
  result = buildFrodoTyrSeal(customFrodo.frodo1344shake, m.receiverPublicKey)

proc open*(env: AsymEnvelope, m: frodo2ShakeTyrOpenM): seq[byte] =
  result = buildFrodoTyrOpen(customFrodo.frodo1344shake, m.receiverSecretKey, env)

proc seal*(m: ntruprime0SendM): AsymCipher =
  result = asymEnc(kaNtruPrime0, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: ntruprime0OpenM): seq[byte] =
  result = asymDec(kaNtruPrime0, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: bike0SendM): AsymCipher =
  result = asymEnc(kaBike0, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: bike0OpenM): seq[byte] =
  result = asymDec(kaBike0, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: bike0TyrSendM): AsymCipher =
  ## Encapsulate with the pure-Nim Tyr BIKE tier-0 backend.
  var env = customBike.bikeTyrEncaps(customBike.bikeL1, toSeqBytes(m.receiverPublicKey))
  result.envelope.ciphertext = env.ciphertext
  result.envelope.senderPublicKey = @[]
  result.sharedSecret = env.sharedSecret

proc open*(env: AsymEnvelope, m: bike0TyrOpenM): seq[byte] =
  ## Decapsulate with the pure-Nim Tyr BIKE tier-0 backend.
  result = customBike.bikeTyrDecaps(customBike.bikeL1,
    toSeqBytes(m.receiverSecretKey), env.ciphertext)

proc open*[T](cipher: AsymCipher, m: T): seq[byte] =
  ## Recover a shared secret from the public envelope inside a local result.
  result = open(cipher.envelope, m)

proc seal*[A, B](a: A, b: B): array[2, AsymCipher] =
  ## Convenience helper for composing two independent KEM/ECDH sends.
  result[0] = seal(a)
  result[1] = seal(b)

proc seal*[A, B, C](a: A, b: B, c: C): array[3, AsymCipher] =
  ## Convenience helper for composing three independent KEM/ECDH sends.
  result[0] = seal(a)
  result[1] = seal(b)
  result[2] = seal(c)

proc open*[A, B](envs: array[2, AsymEnvelope], a: A, b: B): array[2, seq[byte]] =
  ## Convenience helper for opening two public KEM/ECDH envelopes.
  result[0] = open(envs[0], a)
  result[1] = open(envs[1], b)

proc open*[A, B](ciphers: array[2, AsymCipher], a: A, b: B): array[2, seq[byte]] =
  ## Convenience helper for opening two local KEM/ECDH results.
  result[0] = open(ciphers[0], a)
  result[1] = open(ciphers[1], b)

proc open*[A, B, C](envs: array[3, AsymEnvelope], a: A, b: B,
    c: C): array[3, seq[byte]] =
  ## Convenience helper for opening three public KEM/ECDH envelopes.
  result[0] = open(envs[0], a)
  result[1] = open(envs[1], b)
  result[2] = open(envs[2], c)

proc open*[A, B, C](ciphers: array[3, AsymCipher], a: A, b: B,
    c: C): array[3, seq[byte]] =
  ## Convenience helper for opening three local KEM/ECDH results.
  result[0] = open(ciphers[0], a)
  result[1] = open(ciphers[1], b)
  result[2] = open(ciphers[2], c)
