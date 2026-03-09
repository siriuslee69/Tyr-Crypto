type
  KyberVariant* = enum
    kvKyber768
    kvKyber1024

  McElieceVariant* = enum
    mvClassicMcEliece6688128
    mvClassicMcEliece6960119
    mvClassicMcEliece8192128

  AlgoCombo* = enum
    meaNone
    meaCurve25519XChaCha20Poly1305
    meaRSAOAEPWithAESGCM
    meaKyber768XChaCha20Poly1305
    meaKyber1024AES256GCM
    meaFrodoKEM976AES256GCM
    meaClassicMcElieceAES256GCM

  KeyExchangeMethod* = enum
    kemCurve25519
    kemX25519KyberHybrid
    kemX25519McElieceHybrid
    kemKyber768
    kemKyber1024
    kemFrodoKEM976
    kemClassicMcEliece6688128
    kemNTRULPrime653
    kemBIKEL2

  CipherSuite* = enum
    csXChaCha20Poly1305
    csXChaCha20Gimli
    csAesGimli
    csXChaCha20AesGimli
    csXChaCha20AesGimliPoly1305
    csAes256Gcm
    csAes256GcmSha384
    csKyber768XChaCha20Poly1305
    csKyber1024Aes256Gcm
    csFrodoKEM976Aes256GcmSha384

  SignatureAlgorithm* = enum
    saEd25519
    saEd448
    saEd25519Falcon512Hybrid
    saEd25519Falcon1024Hybrid
    saDilithium2
    saDilithium3
    saDilithium5
    saFalcon512
    saFalcon1024
    saSPHINCSPlusHaraka128fSimple
