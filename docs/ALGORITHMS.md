# Algorithm Reference

## Table of Contents

1. [Symmetric Primitives](#symmetric-primitives)
2. [Key Encapsulation Mechanisms (KEMs)](#key-encapsulation-mechanisms-kems)
3. [Signature Schemes](#signature-schemes)
4. [Key Agreement](#key-agreement)
5. [Constant-Time & Side-Channel Notes](#constant-time--side-channel-notes)
6. [Threshold / Security Comparison](#threshold--security-comparison)

---

## Symmetric Primitives

All symmetric primitives are **pure Nim** implementations under `src/protocols/custom_crypto/symmetric/`.

| Primitive | Block / Rate | Digest | SSE | AVX | NEON | Notes |
|-----------|-------------|--------|-----|-----|------|-------|
| **BLAKE3** | 1024-bit state | 256-bit (extendable) | yes | yes | yes | Keyed/derive-key modes, XOF |
| **SHA3-224/256/384/512** | 1600-bit sponge | 224/256/384/512 | yes | yes | yes | FIPS 202 |
| **SHAKE128/256** | 1600-bit sponge | arbitrary | yes | yes | yes | XOF |
| **Gimli** | 384-bit sponge | arbitrary | yes | yes | yes | Lightweight sponge |
| **ChaCha20** | 512-bit block | stream | no | no | no | IETF RFC 8439 scalar primitive |
| **XChaCha20** | 512-bit block | stream | yes | yes | yes | Extended (192-bit) nonce via HChaCha20 |
| **Poly1305** | 16-byte blocks | 128-bit tag | yes | yes | yes | RFC 8439 MAC |
| **AES-CTR** | 128-bit block | stream | yes | yes | yes | Constant-time core plus SIMD XOR path |
| **HMAC** | — | variable | no | no | no | Generic over BLAKE3/SHA3/Gimli |
| **Argon2id/i** | 1024 KB blocks | variable | yes | yes | yes | Memory-hard KDF (RFC 9106) |
| **Custom KDF** | tail-indexed xor rounds | variable | yes | yes | yes | Generator-dependent; mixing loop is scalar |

---

## Key Encapsulation Mechanisms (KEMs)

### Kyber (ML-KEM)

**Files:** `src/protocols/custom_crypto/kyber.nim`, `asymmetric/pq/kyber/`

| Variant | NIST Level | PK bytes | SK bytes | CT bytes | Shared Secret |
|---------|-----------|----------|----------|----------|---------------|
| Kyber512 (ML-KEM-512) | 1 | 800 | 1,632 | 768 | 32 |
| Kyber768 (ML-KEM-768) | 3 | 1,184 | 2,400 | 1,088 | 32 |
| Kyber1024 (ML-KEM-1024) | 5 | 1,568 | 3,168 | 1,568 | 32 |

- **Security foundation:** Module-LWE
- **NTT:** Scalar + optional SSE2/AVX2
- **Decaps:** Fujisaki-Okamoto transform with constant-time re-encryption check
- **KAT validated:** Against liboqs and local NIST KAT vectors

### FrodoKEM

**Files:** `src/protocols/custom_crypto/frodo.nim`, `asymmetric/pq/frodo/`

| Variant | NIST Level | PK bytes | SK bytes | CT bytes | Shared Secret |
|---------|-----------|----------|----------|----------|---------------|
| Frodo-640-AES | 1 | 9,616 | 19,888 | 9,720 | 16 |
| Frodo-640-SHAKE | 1 | 9,616 | 19,888 | 9,720 | 16 |
| Frodo-976-AES | 3 | 15,632 | 31,296 | 15,744 | 24 |
| Frodo-976-SHAKE | 3 | 15,632 | 31,296 | 15,744 | 24 |
| Frodo-1344-AES | 5 | 21,520 | 43,088 | 21,632 | 32 |
| Frodo-1344-SHAKE | 5 | 21,520 | 43,088 | 21,632 | 32 |

- **Security foundation:** Standard LWE (no structured lattice)
- **Largest bandwidth** of all KEMs here, but **most conservative** hardness assumption
- **Matrix generation:** Streamed AES-128 (or SHAKE-128) — full matrix is never materialized
- **SIMD:** SSE2/AVX2 for 16-bit multiply-low helpers

### BIKE

**Files:** `src/protocols/custom_crypto/bike.nim`, `asymmetric/pq/bike/`

| Variant | NIST Level | PK bytes | SK bytes | CT bytes | Shared Secret |
|---------|-----------|----------|----------|----------|---------------|
| BIKE-L1 | 1 | 1,540 | 4,958 | 1,572 | 32 |

- **Security foundation:** QC-MDPC codes
- **Decoder:** Constant-time black-gray decoder (BGF)
- **GF(2) multiplication:** Karatsuba + 128-bit word helpers

### NTRU

**Files:** `src/protocols/custom_crypto/ntru.nim`, `asymmetric/pq/ntru/`

| Variant | NIST Level | PK bytes | SK bytes | CT bytes | Shared Secret |
|---------|-----------|----------|----------|----------|---------------|
| NTRU-HPS-2048-509 | 1 | 699 | 935 | 699 | 32 |
| NTRU-HPS-2048-677 | 3 | 930 | 1,234 | 930 | 32 |
| NTRU-HPS-4096-821 | 5 | 1,230 | 1,590 | 1,230 | 32 |
| NTRU-HRSS-701 | 3 | 1,138 | 1,450 | 1,138 | 32 |

- **Security foundation:** NTRU (ring LWE variant)
- **Polynomial mul:** Default: Toom-4 + 2-level Karatsuba (K2). Alternative: coefficient, row, Toom-4 flags
- **Sampling:** The variable-work ISO rejection sampler is not selected; the
  fixed-work sort sampler is the default
- **KAT validated:** NIST DRBG replay + liboqs/PQClean hash

### SABER

**Files:** `src/protocols/custom_crypto/saber.nim`, `asymmetric/pq/saber/`

| Variant | NIST Level | PK bytes | SK bytes | CT bytes | Shared Secret |
|---------|-----------|----------|----------|----------|---------------|
| LightSaber | 1 | 672 | 1,568 | 736 | 32 |
| Saber | 3 | 992 | 2,304 | 1,088 | 32 |
| FireSaber | 5 | 1,312 | 3,040 | 1,472 | 32 |

- **Security foundation:** Module-LWR (learning with rounding)
- **Polynomial mul:** Scalar temp/reduce schoolbook; AVX2 uses 16 coefficient lanes and NEON uses 8 coefficient lanes for fixed-schedule negacyclic schoolbook multiplication
- **SSE2:** Reduction-only SIMD; it does not vectorize the multiplication core
- **Backend label:** `saberClean` / `saberAvx2` is compatibility/reporting metadata; arithmetic is compile-time selected and does not dispatch to PQClean at runtime
- **Decaps:** Constant-time FO with cmov

### Classic McEliece

**Files:** `src/protocols/custom_crypto/mceliece.nim`, `asymmetric/pq/mceliece/`

| Variant | NIST Level | PK bytes | SK bytes | CT bytes | Shared Secret |
|---------|-----------|----------|----------|----------|---------------|
| mceliece-6688128f | 3 | 524,928 | 13,892 | 224 | 32 |
| mceliece-6960119f | 3 | 524,928 | 13,948 | 226 | 32 |
| mceliece-8192128f | 5 | 1,357,576 | 14,468 | 240 | 32 |

- **Security foundation:** Goppa code-based cryptography
- **Largest public keys** (~0.5–1.3 MB) but **smallest ciphertexts** of any PQ KEM
- **Key generation** is the bottleneck (Goppa code selection)
- **SIMD:** AVX2 matrix fill plus AVX2/SSE2/NEON masked row XOR during public-key generation; decoding remains scalar
- **Optimized:** 64×64 bit-matrix transpose, masked row XOR, public syndrome bit limit

---

## Signature Schemes

### Dilithium (ML-DSA)

**Files:** `src/protocols/custom_crypto/dilithium.nim`, `asymmetric/pq/dilithium/`

| Variant | NIST Level | PK bytes | SK bytes | Signature bytes |
|---------|-----------|----------|----------|-----------------|
| ML-DSA-44 (Dilithium2) | 2 | 1,312 | 2,560 | 2,420 |
| ML-DSA-65 (Dilithium3) | 3 | 1,952 | 4,032 | 3,309 |
| ML-DSA-87 (Dilithium5) | 5 | 2,592 | 4,896 | 4,627 |

- **Security foundation:** Module-LWE / Module-SIS (Fiat-Shamir with aborts)
- **NTT:** Scalar + optional SSE2/AVX2 coefficient lanes
- **SIMD:** Add/sub/shift/pointwise accumulation batched via SIMD-Nexus
- **⚠️ Known timing caveat:** Rejection loop iteration count varies with secret key — see [Constant-Time Notes](#constant-time--side-channel-notes)
- **KAT validated:** liboqs and local KAT vectors

### Falcon

**Files:** `src/protocols/custom_crypto/falcon.nim`, `asymmetric/pq/falcon/`

| Variant | NIST Level | PK bytes | SK bytes | Signature bytes |
|---------|-----------|----------|----------|-----------------|
| Falcon-512 | 1 | 897 | 1,281 | 752 |
| Falcon-1024 | 5 | 1,793 | 2,305 | 1,462 |

- **Security foundation:** NTRU lattice (GPV framework)
- **Smallest signature + key sizes** of all PQ signatures
- **Gaussian sampling** is inherently variable-time
- **SIMD:** Two-lane FalconFpr helper (SSE2/NEON) for FFT, keygen norm accumulation
- **Dual backends:** `falconScalar` / `falconSimd` (compile-time + runtime selectable)
- **Current benchmark profile:** sign/verify are low-ms to sub-ms, but the current pure-Nim keygen path is still seconds-scale and dominates Falcon totals in the curated snapshots

### SPHINCS+

**Files:** `src/protocols/custom_crypto/sphincs.nim`, `asymmetric/pq/sphincs/`

| Variant | NIST Level | PK bytes | SK bytes | Signature bytes |
|---------|-----------|----------|----------|-----------------|
| SPHINCS+-SHAKE-128f-simple | 1 | 32 | 64 | 17,088 |

- **Security foundation:** Stateless hash-based (XMSS + FORS)
- **Largest signature size** (~17 KB) but **smallest keys** (32/64 bytes)
- **No rejection sampling** — fully deterministic, no secret-dependent branches
- **SIMD:** SSE2/NEON two-way and AVX2 four-way SHAKE/WOTS batching
- **Optimized:** Fixed one-block SHAKE fast paths plus batched WOTS/Merkle work

---

## Key Agreement

### X25519

**Files:** `src/protocols/custom_crypto/x25519.nim`, `asymmetric/none_pq/x25519_pass[1-4].nim`

| Parameter | Value |
|-----------|-------|
| Key bytes | 32 |
| Shared secret | 32 |
| Security level | 128-bit (Curve25519) |

- **Ladder:** Montgomery ladder, branch-free using `feCswap`
- **SIMD:** SSE2/NEON 2× batches, AVX2 4× batches
- **Constant-time:** Yes — fully audited
- **5 passes:** Competing arithmetic optimization strategies; pass 4 is the default

---

## Approximate Speed Ranking

Sorted by encaps/decaps or sign/verify cycles on a desktop Skylake-class CPU (release build, no SIMD bias):

### KEMs (fastest → slowest per keypair+encaps+decaps)

```
Kyber512      ~0.05 ms  │  PK: 800 B   CT: 768 B    Level 1
NTRU 509      ~2.5  ms  │  PK: 699 B   CT: 699 B    Level 1
SABER         ~0.15 ms  │  PK: 672 B   CT: 736 B    Level 1
BIKE-L1       ~3.0  ms  │  PK: 1.5 KB  CT: 1.5 KB   Level 1
Frodo-640     ~8.0  ms  │  PK: 9.4 KB  CT: 9.5 KB   Level 1
McEliece      ~40   ms  │  PK: ~0.5 MB CT: 224 B    Level 3 (keygen dominates)
```

### Signatures (current curated profile)

```
Dilithium-44  keygen ~0.08 ms   sign ~0.19 ms   verify ~0.09 ms   │  fast balanced profile
Falcon-512    keygen ~12.09 s   sign ~1.37 ms   verify ~0.03 ms   │  current pure-Nim total dominated by keygen
SPHINCS+      combined sign+verify ~20.9 ms                         │  current curated snapshot is not phase-split
```

---

## Constant-Time & Side-Channel Notes

This is an implementation review, not a formal side-channel proof. “Reviewed”
means the current path was inspected for obvious secret-dependent branches and
table lookups; it does not make a pure-Nim implementation suitable for every
co-resident or microarchitectural threat model. Public lengths, parameter sets,
and malformed-input rejection can still change runtime.

| Algorithm | Status | Notes |
|-----------|--------|-------|
| X25519 / Ed25519 | reviewed | Branch-free ladder/scalar path; transient secrets use volatile wiping helpers |
| ChaCha20 / Poly1305 | reviewed | Word-level arithmetic; Poly1305 keys are wiped after use |
| BLAKE3 / SHA3 / Gimli | reviewed | Permutation paths do not branch on secret contents; Gimli uses a 16-byte-rate sponge with separate XOF/tag/stream domains |
| AES-CTR | reviewed by default | The default S-box path is constant-time; `-d:unsafeFastAes` deliberately enables unsafe secret-indexed lookup tables |
| HMAC | reviewed | Constant-time verification; long keys are reduced correctly; the Poly1305 adapter derives a distinct one-time key per message |
| Custom KDF | reviewed | Memory schedule is driven by public parameters; selected generators determine available SIMD paths |
| Argon2i | reviewed with algorithm caveat | Data-independent addressing, but use only the standard parameter constraints |
| **Argon2id** | **not constant-time by design** | Later passes use data-dependent memory addressing; this is part of Argon2id's tradeoff, not a suitable primitive for a strict CT claim |
| Kyber / SABER / Frodo | reviewed | FO checks use masks; no newly identified secret-dependent branch in the reviewed KEM paths |
| NTRU | reviewed with sampler caveat | The default is fixed-work sort sampling; do not re-enable the ISO rejection sampler for secret material |
| BIKE | reviewed with decoder caveat | GF(2) multiplication no longer branches on secret bits; the decoder still needs dedicated timing measurement on each target |
| McEliece / SPHINCS+ | reviewed | Masked helpers / deterministic hash-based paths; not formally verified |
| **Dilithium signing** | **not constant-time** | Fiat-Shamir-with-aborts rejection count remains observable; do not use where signing timing is attacker-observable |
| **Falcon signing/keygen** | **not constant-time** | Gaussian sampling is variable-time; default FPR code avoids native floating point, but this does not make the scheme CT |

---

## Key Size / Bandwidth Comparison

```
KEM public key sizes (smallest → largest):

NTRU 509        699 B
SABER           672 B   (LightSaber)
Kyber512        800 B
BIKE-L1       1,540 B
NTRU 677        930 B
Frodo-640     9,616 B
McEliece      ~525 KB

Signature public key + signature sizes (smallest → largest combined):

Falcon-512      897 + 752   = 1,649 B    │ smallest PQC sig
Dilithium-44  1,312 + 2,420 = 3,732 B
SPHINCS+         32 + 17,088 = 17,120 B  │ smallest PK
```

---

## Research & Reference Documents

- `docs/research/pq_non_ntru_saber/README.md` — Paper index for Kyber, Dilithium, Falcon, Frodo, BIKE, McEliece, SPHINCS+
- `docs/research/ntru_saber/README.md` — Paper index for NTRU and SABER, optimization history, benchmark tables
- `docs/benchmarks/` — Curated benchmark JSON snapshots (desktop + 3 phones)
- `.iron/PROGRESS.md` — Full implementation history: what was implemented, bugs found/fixed, performance changes
