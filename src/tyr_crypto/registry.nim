import ./algorithms
import ./bindings/liboqs
type
  AlgoInfo* = object
    provider*: string
    source*: string
    algorithmId*: string
    notes*: string
    requiresFlag*: string

proc algo*(alg: AlgoCombo): seq[AlgoInfo] =
  case alg
  of meaNone:
    @[]
  of meaCurve25519XChaCha20Poly1305:
    @[
      AlgoInfo(
        provider: "libsodium",
        source: "https://github.com/status-im/nim-sodium",
        algorithmId: "crypto_aead_xchacha20poly1305_ietf_*",
        notes: "Use libsodium AEAD with a Curve25519-derived key. Requires ensureSodiumInitialised before use.",
        requiresFlag: "hasLibsodium"
      )
    ]
  of meaRSAOAEPWithAESGCM:
    @[
      AlgoInfo(
        provider: "nimcrypto",
        source: "https://github.com/status-im/nimcrypto",
        algorithmId: "rsa/oaep + aes/gcm",
        notes: "Hybrid RSA-OAEP key wrapping combined with AES-256-GCM payload encryption.",
        requiresFlag: "hasNimcrypto"
      ),
      AlgoInfo(
        provider: "OpenSSL",
        source: "https://github.com/openssl/openssl",
        algorithmId: "EVP_PKEY_RSA + EVP_aes_256_gcm",
        notes: "Alternative OpenSSL-based implementation for RSA-OAEP and AES-GCM.",
        requiresFlag: "hasOpenSSL3"
      )
    ]
  of meaKyber768XChaCha20Poly1305:
    @[
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsAlgKyber768,
        notes: "Post-quantum KEM providing the shared secret.",
        requiresFlag: "hasLibOqs"
      ),
      AlgoInfo(
        provider: "libsodium",
        source: "https://github.com/status-im/nim-sodium",
        algorithmId: "crypto_aead_xchacha20poly1305_ietf_*",
        notes: "Symmetric channel for the encapsulated secret.",
        requiresFlag: "hasLibsodium"
      )
    ]
  of meaKyber1024AES256GCM:
    @[
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsAlgKyber1024,
        notes: "Kyber1024 KEM for enhanced security levels.",
        requiresFlag: "hasLibOqs"
      ),
      AlgoInfo(
        provider: "nimcrypto",
        source: "https://github.com/status-im/nimcrypto",
        algorithmId: "AES-256-GCM",
        notes: "Payload encryption using nimcrypto's AES-GCM implementation.",
        requiresFlag: "hasNimcrypto"
      )
    ]
  of meaFrodoKEM976AES256GCM:
    @[
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsAlgFrodoKEM976,
        notes: "FrodoKEM-976 AES variant.",
        requiresFlag: "hasLibOqs"
      ),
      AlgoInfo(
        provider: "nimcrypto",
        source: "https://github.com/status-im/nimcrypto",
        algorithmId: "AES-256-GCM",
        notes: "Authenticated encryption for payloads.",
        requiresFlag: "hasNimcrypto"
      )
    ]
  of meaClassicMcElieceAES256GCM:
    @[
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsAlgClassicMcEliece6688128f,
        notes: "Classic McEliece KEM for long-term security.",
        requiresFlag: "hasLibOqs"
      ),
      AlgoInfo(
        provider: "nimcrypto",
        source: "https://github.com/status-im/nimcrypto",
        algorithmId: "AES-256-GCM",
        notes: "Symmetric payload protection.",
        requiresFlag: "hasNimcrypto"
      )
    ]

proc cipherSuiteBackends*(suite: CipherSuite): seq[AlgoInfo] =
  case suite
  of csXChaCha20Poly1305:
    @[
      AlgoInfo(
        provider: "libsodium",
        source: "https://github.com/status-im/nim-sodium",
        algorithmId: "crypto_aead_xchacha20poly1305_ietf_*",
        notes: "XChaCha20-Poly1305 AEAD implementation.",
        requiresFlag: "hasLibsodium"
      )
    ]
  of csXChaCha20Gimli:
    @[
      AlgoInfo(
        provider: "custom",
        source: "Tyr-Crypto",
        algorithmId: "xchacha20 + gimli tag",
        notes: "XChaCha20 stream cipher with a Gimli sponge layer and Gimli tag.",
        requiresFlag: ""
      )
    ]
  of csAesGimli:
    @[
      AlgoInfo(
        provider: "custom",
        source: "Tyr-Crypto",
        algorithmId: "aes256-ctr + gimli stream + gimli tag",
        notes: "AES-256-CTR protected by a Gimli stream layer and Gimli authentication tag.",
        requiresFlag: ""
      )
    ]
  of csXChaCha20AesGimli:
    @[
      AlgoInfo(
        provider: "custom",
        source: "Tyr-Crypto",
        algorithmId: "xchacha20 + aes256-ctr + gimli stream + gimli tag",
        notes: "XChaCha20 stream cipher with AES-256-CTR, Gimli stream layer, and Gimli tag.",
        requiresFlag: ""
      )
    ]
  of csXChaCha20AesGimliPoly1305:
    @[
      AlgoInfo(
        provider: "custom",
        source: "Tyr-Crypto",
        algorithmId: "xchacha20 + aes256-ctr + gimli stream + gimli tag + poly1305",
        notes: "Layered stream construction with Gimli encryption plus dual Gimli and Poly1305 authentication.",
        requiresFlag: "hasLibsodium"
      )
    ]
  of csAes256Gcm:
    @[
      AlgoInfo(
        provider: "nimcrypto",
        source: "https://github.com/status-im/nimcrypto",
        algorithmId: "AES-256-GCM",
        notes: "Pure Nim AES-GCM implementation.",
        requiresFlag: "hasNimcrypto"
      ),
      AlgoInfo(
        provider: "OpenSSL",
        source: "https://github.com/openssl/openssl",
        algorithmId: "EVP_aes_256_gcm",
        notes: "EVP-based AES-GCM for hardware-accelerated workloads.",
        requiresFlag: "hasOpenSSL3"
      )
    ]
  of csAes256GcmSha384:
    @[
      AlgoInfo(
        provider: "nimcrypto",
        source: "https://github.com/status-im/nimcrypto",
        algorithmId: "AES-256-GCM + SHA-384",
        notes: "Combined AEAD and hashing suite.",
        requiresFlag: "hasNimcrypto"
      )
    ]
  of csKyber768XChaCha20Poly1305:
    @[
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsAlgKyber768,
        notes: "Kyber768 KEM.",
        requiresFlag: "hasLibOqs"
      ),
      AlgoInfo(
        provider: "libsodium",
        source: "https://github.com/status-im/nim-sodium",
        algorithmId: "crypto_aead_xchacha20poly1305_ietf_*",
        notes: "Symmetric channel using libsodium.",
        requiresFlag: "hasLibsodium"
      )
    ]
  of csKyber1024Aes256Gcm:
    @[
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsAlgKyber1024,
        notes: "Kyber1024 KEM.",
        requiresFlag: "hasLibOqs"
      ),
      AlgoInfo(
        provider: "nimcrypto",
        source: "https://github.com/status-im/nimcrypto",
        algorithmId: "AES-256-GCM",
        notes: "Symmetric encryption via nimcrypto.",
        requiresFlag: "hasNimcrypto"
      )
    ]
  of csFrodoKEM976Aes256GcmSha384:
    @[
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsAlgFrodoKEM976,
        notes: "FrodoKEM-976 AES implementation.",
        requiresFlag: "hasLibOqs"
      ),
      AlgoInfo(
        provider: "nimcrypto",
        source: "https://github.com/status-im/nimcrypto",
        algorithmId: "AES-256-GCM + SHA-384",
        notes: "Symmetric encryption plus hash binding.",
        requiresFlag: "hasNimcrypto"
      )
    ]

proc keyExchangeBackends*(kem: KeyExchangeMethod): seq[AlgoInfo] =
  case kem
  of kemCurve25519:
    @[
      AlgoInfo(
        provider: "libsodium",
        source: "https://github.com/status-im/nim-sodium",
        algorithmId: "crypto_kx_* / crypto_scalarmult_curve25519",
        notes: "Curve25519/X25519 key agreement.",
        requiresFlag: "hasLibsodium"
      )
    ]
  of kemX25519KyberHybrid:
    @[
      AlgoInfo(
        provider: "libsodium",
        source: "https://github.com/status-im/nim-sodium",
        algorithmId: "crypto_kx_*",
        notes: "Classical X25519 share.",
        requiresFlag: "hasLibsodium"
      ),
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsAlgKyber768,
        notes: "Kyber component for the hybrid exchange.",
        requiresFlag: "hasLibOqs"
      )
    ]
  of kemX25519McElieceHybrid:
    @[
      AlgoInfo(
        provider: "libsodium",
        source: "https://github.com/status-im/nim-sodium",
        algorithmId: "crypto_kx_*",
        notes: "Classical X25519 share.",
        requiresFlag: "hasLibsodium"
      ),
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsAlgClassicMcEliece6688128f,
        notes: "Classic McEliece component for the hybrid exchange. Variant selection happens in the wrapper API.",
        requiresFlag: "hasLibOqs"
      )
    ]
  of kemKyber768:
    @[
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsAlgKyber768,
        notes: "Pure Kyber768 key encapsulation.",
        requiresFlag: "hasLibOqs"
      )
    ]
  of kemKyber1024:
    @[
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsAlgKyber1024,
        notes: "Pure Kyber1024 key encapsulation.",
        requiresFlag: "hasLibOqs"
      )
    ]
  of kemFrodoKEM976:
    @[
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsAlgFrodoKEM976,
        notes: "FrodoKEM-976 AES variant.",
        requiresFlag: "hasLibOqs"
      )
    ]
  of kemClassicMcEliece6688128:
    @[
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsAlgClassicMcEliece6688128f,
        notes: "Classic McEliece KEM. Wrapper APIs also support the 6960119 and 8192128 families.",
        requiresFlag: "hasLibOqs"
      )
    ]
  of kemNTRULPrime653:
    @[
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsAlgNtruPrimeSntrup653,
        notes: "NTRU LPRime sntrup653 key encapsulation.",
        requiresFlag: "hasLibOqs"
      )
    ]
  of kemBIKEL2:
    @[
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsAlgBIKEL2,
        notes: "BIKE Level 2 KEM.",
        requiresFlag: "hasLibOqs"
      )
    ]

proc signatureBackends*(alg: SignatureAlgorithm): seq[AlgoInfo] =
  case alg
  of saEd25519:
    @[
      AlgoInfo(
        provider: "libsodium",
        source: "https://github.com/status-im/nim-sodium",
        algorithmId: "crypto_sign_ed25519_*",
        notes: "Deterministic Ed25519 signatures.",
        requiresFlag: "hasLibsodium"
      )
    ]
  of saEd448:
    @[
      AlgoInfo(
        provider: "OpenSSL",
        source: "https://github.com/openssl/openssl",
        algorithmId: "EVP_PKEY_ED448",
        notes: "Ed448 signatures via OpenSSL 3.x EVP interface.",
        requiresFlag: "hasOpenSSL3"
      )
    ]
  of saEd25519Falcon512Hybrid:
    @[
      AlgoInfo(
        provider: "libsodium",
        source: "https://github.com/status-im/nim-sodium",
        algorithmId: "crypto_sign_ed25519_*",
        notes: "Classical Ed25519 half of the hybrid signature.",
        requiresFlag: "hasLibsodium"
      ),
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsSigFalcon512,
        notes: "Falcon-512 half of the hybrid signature. Both signatures must verify.",
        requiresFlag: "hasLibOqs"
      )
    ]
  of saEd25519Falcon1024Hybrid:
    @[
      AlgoInfo(
        provider: "libsodium",
        source: "https://github.com/status-im/nim-sodium",
        algorithmId: "crypto_sign_ed25519_*",
        notes: "Classical Ed25519 half of the hybrid signature.",
        requiresFlag: "hasLibsodium"
      ),
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsSigFalcon1024,
        notes: "Falcon-1024 half of the hybrid signature. Both signatures must verify.",
        requiresFlag: "hasLibOqs"
      )
    ]
  of saDilithium2:
    @[
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsSigDilithium2,
        notes: "Dilithium level 2 signature scheme.",
        requiresFlag: "hasLibOqs"
      )
    ]
  of saDilithium3:
    @[
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsSigDilithium3,
        notes: "Dilithium level 3 signature scheme.",
        requiresFlag: "hasLibOqs"
      )
    ]
  of saDilithium5:
    @[
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsSigDilithium5,
        notes: "Dilithium level 5 signature scheme.",
        requiresFlag: "hasLibOqs"
      )
    ]
  of saFalcon512:
    @[
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsSigFalcon512,
        notes: "Falcon level 1 signature scheme.",
        requiresFlag: "hasLibOqs"
      )
    ]
  of saFalcon1024:
    @[
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsSigFalcon1024,
        notes: "Falcon level 5 signature scheme.",
        requiresFlag: "hasLibOqs"
      )
    ]
  of saSPHINCSPlusHaraka128fSimple:
    @[
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsSigSphincsHaraka128fSimple,
        notes: "SPHINCS+-Haraka 128f simple (stateless hash-based).",
        requiresFlag: "hasLibOqs"
      )
    ]
