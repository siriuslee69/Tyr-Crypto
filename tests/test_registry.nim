import std/unittest
import ../src/tyr_crypto/[registry, algorithms]

suite "registry helpers":
  test "mail encryption backends are defined":
    check algo(meaCurve25519XChaCha20Poly1305).len >= 1
    check algo(meaRSAOAEPWithAESGCM).len >= 1
    check algo(meaKyber768XChaCha20Poly1305).len == 2

  test "cipher suite backends include metadata":
    let info = cipherSuiteBackends(csAes256Gcm)
    check info.len >= 1
    for entry in info:
      check entry.provider.len > 0
      check entry.requiresFlag.len > 0
    check cipherSuiteBackends(csAesGimli).len == 1
    check cipherSuiteBackends(csXChaCha20AesGimliPoly1305).len == 1

  test "key exchange mapping covers PQ algorithms":
    check keyExchangeBackends(kemKyber768).len == 1
    check keyExchangeBackends(kemX25519KyberHybrid).len == 2
    check keyExchangeBackends(kemX25519McElieceHybrid).len == 2

  test "signature backend metadata exists":
    for alg in [saEd25519, saDilithium2, saFalcon512]:
      check signatureBackends(alg).len >= 1
    check signatureBackends(saEd25519Falcon512Hybrid).len == 2
