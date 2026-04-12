import std/unittest
import registry
import ../src/protocols/wrapper/helpers/algorithms

suite "registry helpers":
  test "cipher backends include metadata":
    let info = cipherBackends(scaAesCtr)
    check info.len >= 1
    for entry in info:
      check entry.provider.len > 0
    check cipherBackends(scaXChaCha20).len == 1
    check cipherBackends(scaGimliStream).len == 1

  test "mac backends include metadata":
    check macBackends(maBlake3).len == 1
    check macBackends(maGimli).len == 1
    check macBackends(maPoly1305).len == 1
    check macBackends(maSha3).len == 1

  test "kem metadata covers PQ algorithms":
    check kemBackends(kaX25519).len == 1
    check kemBackends(kaKyber0).len == 1
    check kemBackends(kaKyber1).len == 1
    check kemBackends(kaMcEliece2).len == 1
    check kemBackends(kaBike0).len == 1

  test "signature backend metadata exists":
    for alg in [saEd25519, saDilithium0, saFalcon512]:
      check signatureBackends(alg).len >= 1
