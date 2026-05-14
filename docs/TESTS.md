# Tyr-Crypto Tests

## Test Groups

```text
+----------------------+------------------------------------------------------+
| Group                | Coverage                                              |
+----------------------+------------------------------------------------------+
| core                 | shared errors, config, registry, public typed API     |
| custom_crypto        | aggregate pure-Nim symmetric/custom checks            |
| sha3/poly1305/aes    | focused symmetric primitive vectors and parity        |
| gimli/blake3         | hash/sponge/vector and SIMD parity checks             |
| random/hmac/otp      | utility primitive behavior                            |
| x25519               | pure-Nim X25519 passes and SIMD batches               |
| kyber/frodo/bike     | PQ KEM roundtrips and KAT coverage                    |
| ntru/saber           | PQ KEM KAT and multiplier variant coverage            |
| dilithium/falcon     | PQ signature roundtrips, KATs, and variant splits     |
| sphincs/mceliece     | PQ signature/KEM roundtrips and KAT checks            |
+----------------------+------------------------------------------------------+
```

## Normal Flow

```text
edit code
   |
   v
nimble check_core
nimble check
   |
   v
nimble test_config or focused test file
   |
   v
nimble test
   |
   v
nimble test_all / Android harness when native backends or mobile paths changed
```

## Common Commands

```bash
nimble check
nimble test
nimble test_config
nimble test_wasm
nimble test_neon_checks
nimble test_simd_matrix
nimble test_ntru_saber
nimble test_ntru_saber_avx2
```

The parallel desktop runner is implemented in Nim:

```bash
nim r tools/run_desktop_tests_parallel.nim -- --only:core,x25519 --maxParallel:2
```

## Native Backend Defines

```text
+----------------+--------------------------------------------+
| Define         | Enables                                    |
+----------------+--------------------------------------------+
| -d:hasLibsodium| libsodium-backed X25519/Ed25519 helpers    |
| -d:hasLibOqs   | liboqs-backed PQ algorithms and comparisons|
| -d:hasOpenSSL3 | OpenSSL Ed448 and OpenSSL-dependent checks |
| -d:sse2/-d:avx2| x86 SIMD compile/runtime paths             |
| -d:neon        | ARM64 NEON compile paths                   |
+----------------+--------------------------------------------+
```

## Android Harness

```text
nimble build_android_harness_asymmetric_fast
   |
   v
APK + native test binary under ignored build paths
   |
   v
nim r tools/run_android_harness.nim -- --serial:<device> --timeoutSeconds:900
   |
   v
captured native test output
```

Generated `.bin`, `.so`, Gradle, and app build outputs are ignored. The Gradle wrapper JAR is the only tracked binary artifact.
