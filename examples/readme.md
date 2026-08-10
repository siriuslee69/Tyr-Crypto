# Examples

| File | What it shows |
|------|---------------|
| [basic_hash.nim](basic_hash.nim) | BLAKE3 (hash, keyed, KDF), SHA3, Poly1305 |
| [kem_kyber.nim](kem_kyber.nim) | Kyber KEM keypair / encaps / decaps |
| [kem_mceliece.nim](kem_mceliece.nim) | Classic McEliece KEM via typed materials |
| [kem_frodo.nim](kem_frodo.nim) | FrodoKEM-976-AES keypair / encaps / decaps |
| [kem_bike.nim](kem_bike.nim) | BIKE-L1 KEM keypair / encaps / decaps |
| [kem_ntru.nim](kem_ntru.nim) | NTRU-HPS-2048-509 KEM |
| [signal_dilithium.nim](signing_dilithium.nim) | ML-DSA sign / verify |
| [signing_falcon.nim](signing_falcon.nim) | Falcon sign / verify |
| [signing_sphincs.nim](signing_sphincs.nim) | SPHINCS+ sign / verify |
| [aead_xchacha20.nim](aead_xchacha20.nim) | XChaCha20-Poly1305 seal / open |
| [x25519_ecdh.nim](x25519_ecdh.nim) | X25519 key agreement |
| [wrapper.nim](wrapper.nim) | Typed material wrapper (encrypt/decrypt/sign/verify) |

See [tests/](../tests/) for KAT (Known-Answer Test) vectors and [tools/bench_custom_crypto_table.nim](../tools/bench_custom_crypto_table.nim) for benchmark scripts.
