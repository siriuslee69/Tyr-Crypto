import protocols/wrapper/helpers/algorithms
import protocols/bindings/liboqs

type
  AlgoInfo* = object
    provider*: string
    source*: string
    algorithmId*: string
    notes*: string
    requiresFlag*: string

proc cipherBackends*(alg: StreamCipherAlgorithm): seq[AlgoInfo] =
  case alg
  of scaXChaCha20:
    result = @[
      AlgoInfo(
        provider: "custom",
        source: "Tyr-Crypto",
        algorithmId: "xchacha20",
        notes: "XChaCha20 stream cipher with explicit 24-byte nonce handling.",
        requiresFlag: ""
      )
    ]
  of scaAesCtr:
    result = @[
      AlgoInfo(
        provider: "custom",
        source: "Tyr-Crypto",
        algorithmId: "aes256-ctr",
        notes: "AES-256-CTR stream transform with explicit big-endian counter increment.",
        requiresFlag: ""
      )
    ]
  of scaGimliStream:
    result = @[
      AlgoInfo(
        provider: "custom",
        source: "Tyr-Crypto",
        algorithmId: "gimli-stream",
        notes: "Gimli XOF-derived stream cipher with explicit little-endian absorb/squeeze.",
        requiresFlag: ""
      )
    ]

proc macBackends*(alg: MacAlgorithm): seq[AlgoInfo] =
  case alg
  of maBlake3:
    result = @[
      AlgoInfo(
        provider: "custom",
        source: "Tyr-Crypto",
        algorithmId: "blake3-custom-hmac",
        notes: "Two-pass custom HMAC over BLAKE3.",
        requiresFlag: ""
      )
    ]
  of maGimli:
    result = @[
      AlgoInfo(
        provider: "custom",
        source: "Tyr-Crypto",
        algorithmId: "gimli-custom-hmac",
        notes: "Two-pass custom HMAC over Gimli sponge output.",
        requiresFlag: ""
      )
    ]
  of maPoly1305:
    result = @[
      AlgoInfo(
        provider: "custom",
        source: "Tyr-Crypto",
        algorithmId: "poly1305-custom-hmac",
        notes: "Two-pass custom HMAC over the local Poly1305 implementation.",
        requiresFlag: ""
      )
    ]
  of maSha3:
    result = @[
      AlgoInfo(
        provider: "custom",
        source: "Tyr-Crypto",
        algorithmId: "sha3-custom-hmac",
        notes: "Two-pass custom HMAC over the local SHA3 implementation.",
        requiresFlag: ""
      )
    ]

proc kemBackends*(alg: KemAlgorithm): seq[AlgoInfo] =
  case alg
  of kaX25519:
    result = @[
      AlgoInfo(
        provider: "libsodium",
        source: "https://github.com/status-im/nim-sodium",
        algorithmId: "crypto_kx_* / crypto_scalarmult_curve25519",
        notes: "Curve25519/X25519 key agreement.",
        requiresFlag: "hasLibsodium"
      )
    ]
  of kaKyber0:
    result = @[
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsAlgKyber768,
        notes: "Kyber768 KEM.",
        requiresFlag: "hasLibOqs"
      )
    ]
  of kaKyber1:
    result = @[
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsAlgKyber1024,
        notes: "Kyber1024 KEM.",
        requiresFlag: "hasLibOqs"
      )
    ]
  of kaMcEliece0:
    result = @[
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsAlgClassicMcEliece6688128f,
        notes: "Classic McEliece 6688128 KEM.",
        requiresFlag: "hasLibOqs"
      )
    ]
  of kaMcEliece1:
    result = @[
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsAlgClassicMcEliece6960119f,
        notes: "Classic McEliece 6960119 KEM.",
        requiresFlag: "hasLibOqs"
      )
    ]
  of kaMcEliece2:
    result = @[
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsAlgClassicMcEliece8192128f,
        notes: "Classic McEliece 8192128 KEM.",
        requiresFlag: "hasLibOqs"
      )
    ]
  of kaFrodo0:
    result = @[
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsAlgFrodoKEM976,
        notes: "FrodoKEM-976 AES KEM.",
        requiresFlag: "hasLibOqs"
      )
    ]
  of kaNtruPrime0:
    result = @[
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsAlgNtruPrime0,
        notes: "NTRU Prime sntrup761 KEM for tier 0.",
        requiresFlag: "hasLibOqs"
      )
    ]
  of kaBike0:
    result = @[
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsAlgBike0,
        notes: "BIKE Level 1 KEM for tier 0.",
        requiresFlag: "hasLibOqs"
      )
    ]

proc signatureBackends*(alg: SignatureAlgorithm): seq[AlgoInfo] =
  case alg
  of saEd25519:
    result = @[
      AlgoInfo(
        provider: "libsodium",
        source: "https://github.com/status-im/nim-sodium",
        algorithmId: "crypto_sign_ed25519_*",
        notes: "Deterministic Ed25519 signatures.",
        requiresFlag: "hasLibsodium"
      )
    ]
  of saEd448:
    result = @[
      AlgoInfo(
        provider: "OpenSSL",
        source: "https://github.com/openssl/openssl",
        algorithmId: "EVP_PKEY_ED448",
        notes: "Ed448 signatures via OpenSSL 3.x EVP.",
        requiresFlag: "hasOpenSSL3"
      )
    ]
  of saDilithium0:
    result = @[
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsSigDilithium0,
        notes: "Dilithium tier 0 signature scheme (original Dilithium2 / standardized ML-DSA-44).",
        requiresFlag: "hasLibOqs"
      )
    ]
  of saDilithium1:
    result = @[
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsSigDilithium1,
        notes: "Dilithium tier 1 signature scheme (original Dilithium3 / standardized ML-DSA-65).",
        requiresFlag: "hasLibOqs"
      )
    ]
  of saDilithium2:
    result = @[
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsSigDilithium2,
        notes: "Dilithium tier 2 signature scheme (original Dilithium5 / standardized ML-DSA-87).",
        requiresFlag: "hasLibOqs"
      )
    ]
  of saFalcon512:
    result = @[
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsSigFalcon512,
        notes: "Falcon-512 signature scheme.",
        requiresFlag: "hasLibOqs"
      )
    ]
  of saFalcon1024:
    result = @[
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsSigFalcon1024,
        notes: "Falcon-1024 signature scheme.",
        requiresFlag: "hasLibOqs"
      )
    ]
  of saSPHINCSPlusHaraka128fSimple:
    result = @[
      AlgoInfo(
        provider: "liboqs",
        source: "https://github.com/open-quantum-safe/liboqs",
        algorithmId: oqsSigSphincsHaraka128fSimple,
        notes: "SPHINCS+-Haraka-128f-simple signature scheme.",
        requiresFlag: "hasLibOqs"
      )
    ]
  else:
    raise newException(ValueError,
      "registry metadata only exists for primitive signature algorithms")
