# Code Layout

## Repo Map

```
Path                             Responsibility
src/                             Source tree
  tyr_crypto.nim                 Public export facade (import this)
  protocols/
    custom_crypto/               Pure-Nim primitive implementations
      symmetric/                 Hashes, MACs, RNG, stream ciphers, KDFs, OTP
        aes/                     AES-CTR (core + SIMD)
        argon2/                  Argon2 memory-hard KDF
        blake3/                  BLAKE3 hash (scalar + SIMD)
        chacha/                  ChaCha20 / XChaCha20 (scalar + SIMD)
        gimli/                   Gimli permutation, sponge, SSE
        poly1305/                Poly1305 MAC (scalar + SIMD)
        sha3/                    SHA3/SHAKE (scalar + SIMD)
        hmac.nim                 HMAC
        kdf.nim                  Custom memory-hard KDF
        otp.nim                  One-time pad helpers
        random.nim               CSPRNG
      asymmetric/
        none_pq/                 Non-PQ asymmetric
          x25519_impl.nim        X25519 hardened Montgomery ladder
          x25519_common.nim      Shared X25519 helpers
          ed25519_impl.nim       Ed25519 (RFC 8032) with embedded SHA-512
        pq/                      Post-quantum asymmetric
          bike/                  BIKE QC-MDPC KEM
          common/                ct_compare.nim, pq_rng.nim
          dilithium/             ML-DSA (Dilithium)
          falcon/                Falcon (scalar + SIMD backends)
          frodo/                 FrodoKEM (LWE-based)
          kyber/                 ML-KEM (Kyber)
          mceliece/              Classic McEliece code-based KEM
          ntru/                  NTRU HPS/HRSS KEM
          saber/                 SABER Module-LWR KEM
          sphincs/              SPHINCS+ hash-based sig
      <top-level facades>        Compatibility re-exports (e.g. kyber.nim → asymmetric/pq/kyber/)
    wrapper/                     Typed public operation API
      basic_api.nim              Canonical wrapper (encrypt/decrypt/sign/verify/seal/open)
      helpers/                   algorithms.nim, signature_support.nim
      wasm/                      Wasm/JS bridge
    bindings/                    Optional native ABI bindings (libsodium, liboqs, OpenSSL)
    builders/                    Native dependency build helpers
    helpers/                     otter_support.nim, etc.
bindings/
  js/                            Wasm loader and TypeScript declarations
tests/                           Unit, vector, parity, and harness tests
tools/                           Bench, harness, and report scripts
submodules/                      Pinned upstream source dependencies
docs/                            Documentation
  benchmarks/                    Curated benchmark JSON snapshots
  research/                      Paper indices and optimization notes
.iron/                           Repo coordination and conventions
build/                           Generated build artifacts (ignored)
nimcache/                        Nim compilation cache (ignored)
```

## Dependency Flow

```
User code
   |
   v
src/tyr_crypto.nim
   |
   +--> wrapper/basic_api.nim
   |       |
   |       +--> wrapper/helpers/algorithms.nim
   |       +--> custom_crypto/* (symmetric and asymmetric facades)
   |       +--> custom_crypto/symmetric/*  (implementation)
   |       +--> custom_crypto/asymmetric/* (implementation)
   |       +--> bindings/* when enabled by -d:has*
   |
   +--> custom_crypto/* compatibility facades
   +--> custom_crypto/asymmetric/pq/*  (direct access for advanced use)
```

## Primitive Layout

```
custom_crypto/
   |
   +--> symmetric/
   |       +--> aes, argon2, blake3, chacha, gimli, hmac, kdf, otp, poly1305, random, sha3
   |
   +--> asymmetric/
            +--> none_pq/
            |       +--> x25519_common.nim, x25519_impl.nim, ed25519_impl.nim
            |
            +--> pq/
                    common/      ct_compare.nim, pq_rng.nim
                    bike/        GF2X mul, black-gray decoder, sampling
                    dilithium/    NTT poly, polyvec, rejection sampling
                    falcon/      FFT, Gaussian sampling, FPR, sign, verify
                    frodo/       AES/SHAKE matrix, noise, encode/decode
                    kyber/       NTT, indcpa, polyvec, KEM FO transform
                    mceliece/    Goppa code: keygen, encrypt, decrypt, GF(2^13)
                    ntru/        NTT-unfriendly poly mul, fixed-weight sampling
                    saber/       Schoolbook poly mul, SHAKE noise gen
                    sphincs/     WOTS+, FORS, Merkle tree, SHAKE hash
```

Top-level facades (e.g. `custom_crypto/kyber.nim`) re-export the `asymmetric/pq/kyber/` implementation so existing imports keep working. New code should import from class-specific folders.

## Data Flow

```
raw bytes or typed crypto material
   |
   v
sanitize/validate (check sizes, reject invalid inputs)
   |
   v
typed crypto material (KyberSendM, DilithiumSignM, etc.)
   |
   v
actor operation: hash / encrypt / sign / encapsulate
   |
   v
typed output: bytes, tag, signature, KEM envelope
```

## Naming Rules

| Name shape     | Meaning                                       |
|----------------|-----------------------------------------------|
| `*Tyr*`        | Local pure-Nim implementation path            |
| unsuffixed     | Optional native backend path                  |
| `*M`           | Typed material object for basic_api           |
| `*SendM/*OpenM`| KEM sender/opening material                   |
| `*SignM/*VerifyM` | Signature material                        |
| `*Pass1-4`     | Competing X25519 arithmetic optimization pass |

## Test Group Mapping

| Group | Source path |
|-------|-------------|
| core | wrapper/basic_api.nim, helpers |
| custom_crypto | custom_crypto/symmetric/ + argon2 + kdf |
| sha3/poly1305/aes | custom_crypto/symmetric/sha3/, poly1305/, aes/ |
| gimli/blake3 | custom_crypto/symmetric/gimli/, blake3/ |
| x25519 | custom_crypto/asymmetric/none_pq/x25519* |
| kyber/frodo/bike | custom_crypto/asymmetric/pq/{kyber,frodo,bike}/ |
| ntru/saber | custom_crypto/asymmetric/pq/{ntru,saber}/ |
| dilithium/falcon | custom_crypto/asymmetric/pq/{dilithium,falcon}/ |
| sphincs/mceliece | custom_crypto/asymmetric/pq/{sphincs,mceliece}/ |
