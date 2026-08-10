# Tyr-Crypto Tests

## Test Groups

```text
+----------------------+------------------------------------------------------+
| Group                | Coverage                                              |
+----------------------+------------------------------------------------------+
| core                 | shared errors, registry, public typed API             |
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
focused test file
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
| -d:aesni       | x86 AES instruction path                   |
| -d:neon        | ARM64 NEON compile paths                   |
+----------------+--------------------------------------------+
```

## Default Optimization Policy

`config.nims` applies `--opt:speed` to ordinary builds and tests. This optimizes
generated C without enabling `-d:release`, so assertions, bounds checks, overflow
checks, and the configured ARC/ORC memory manager remain unchanged.

Native x86 builds probe the selected C compiler's `-march=native` macros and
enable supported `sse2`, `avx2`, and `aesni` symbols with matching C flags.
AMD64 always receives its baseline SSE2 path. ARM64 receives NEON, which is a
required part of that architecture. WASM/JS targets receive no host SIMD symbol.

Use this explicit override for a portable scalar control build:

```bash
nim c -d:tyrExplicitCapabilities -u:sse2 -u:avx2 -u:aesni -u:neon tests/test_falcon_tyr.nim
```

Otter uses the same override before adding the capabilities selected in its
flag menu. Tyr's `tests/.otter/config.toml` selects all safe capabilities that
Otter detects by default, so general Test UI runs use the optimized paths too.

External backends such as `hasLibOqs` and unsafe experiments such as
`unsafeFastAes` or `falconUnsafeNativeFloatSimd` are never enabled by this
policy. Measured trial switches such as `frodoAvx2SaStripeSse` also remain off.

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
