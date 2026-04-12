## ------------------------------------------------
## Algorithms <- primitive enum definitions
## ------------------------------------------------

type
  ## KyberTier: concrete Kyber variant tier.
  KyberTier* = enum
    kyber0
    kyber1

  ## McElieceTier: concrete McEliece variant tier.
  McElieceTier* = enum
    mceliece0
    mceliece1
    mceliece2

  ## StreamCipherAlgorithm: primitive symmetric cipher/stream transform.
  StreamCipherAlgorithm* = enum
    scaXChaCha20
    scaAesCtr
    scaGimliStream

  ## MacAlgorithm: primitive hash/HMAC family selection.
  MacAlgorithm* = enum
    maBlake3
    maGimli
    maPoly1305
    maSha3

  ## RandomAlgorithm: primitive RNG selection.
  RandomAlgorithm* = enum
    raSystem
    raSystemMixed

  ## KemAlgorithm: primitive KEM or ECDH selection.
  KemAlgorithm* = enum
    kaX25519
    kaKyber0
    kaKyber1
    kaMcEliece0
    kaMcEliece1
    kaMcEliece2
    kaFrodo0
    kaNtruPrime0
    kaBike0

  ## SignatureAlgorithm: primitive signature selection plus kept compatibility hybrids.
  SignatureAlgorithm* = enum
    saEd25519
    saEd448
    saEd25519Falcon512Hybrid
    saEd25519Falcon1024Hybrid
    saDilithium0 ## original Dilithium2 / standardized ML-DSA-44
    saDilithium1 ## original Dilithium3 / standardized ML-DSA-65
    saDilithium2 ## original Dilithium5 / standardized ML-DSA-87
    saFalcon512
    saFalcon1024
    saSPHINCSPlusHaraka128fSimple
