## PQ Research Notes: non-NTRU/SABER

Date: 2026-05-01

Scope: pure-Nim PQ implementations under `src/protocols/custom_crypto/asymmetric/pq`,
excluding `ntru` and `saber`.

### Research Document Manifest

Paper lifecycle is controlled by `papers.lock.json`. PDFs with explicit
redistribution terms stay tracked; PDFs without clear redistribution terms are
ignored local-cache files and can be restored with `download_papers.nim`.
License notes are in `LICENSES.md`.

Restore ignored cache files on Windows with:
`nim r docs/research/pq_non_ntru_saber/download_papers.nim`.

### Reference Sources

Falcon's previous tracked C snapshot under
`src/protocols/custom_crypto/asymmetric/pq/falcon/upstream/pqclean_falcon-*`
has been replaced by the `submodules/pqclean_falcon_ref_sources` submodule.
That submodule points at `https://github.com/PQClean/PQClean.git` and is pinned
to commit `f81bd579`, the exact upstream commit that matched the removed copied
files. The relevant upstream paths are `crypto_sign/falcon-512/{clean,avx2}` and
`crypto_sign/falcon-1024/{clean,avx2}`.

These Falcon sources are reference and porting material only. Tyr's active
Falcon backend is the pure-Nim implementation in
`src/protocols/custom_crypto/asymmetric/pq/falcon`, and the current comparison
benchmarks use liboqs rather than compiling this Falcon reference submodule.

### Papers

| Area | Paper / spec | Local copy | Upstream |
| --- | --- | --- | --- |
| Frodo | Frodo: Take off the ring! Practical, quantum-secure key exchange from LWE | [2016-0659_frodo_take_off_the_ring.pdf](papers/2016-0659_frodo_take_off_the_ring.pdf) | https://eprint.iacr.org/2016/659 |
| Dilithium | CRYSTALS-Dilithium original design paper | [2017-0633_crystals_dilithium.pdf](papers/2017-0633_crystals_dilithium.pdf) | https://eprint.iacr.org/2017/633 |
| Kyber | CRYSTALS-Kyber original design paper | [2017-0634_crystals_kyber.pdf](papers/2017-0634_crystals_kyber.pdf) | https://eprint.iacr.org/2017/634 |
| Kyber/Dilithium | Faster AVX2 optimized NTT implementations | [2018-0039_vectorized_ntt_implementations.pdf](papers/2018-0039_vectorized_ntt_implementations.pdf) | https://eprint.iacr.org/2018/039 |
| Falcon | Falcon Gaussian sampling and precision analysis | [2019-0267_falcon_gaussian_sampling_precision.pdf](papers/2019-0267_falcon_gaussian_sampling_precision.pdf) | https://eprint.iacr.org/2019/267 |
| BIKE | BIKE constant-time decoder work | [2020-0117_bike_constant_time_decoder.pdf](papers/2020-0117_bike_constant_time_decoder.pdf) | https://eprint.iacr.org/2020/117 |
| Kyber/Dilithium/SABER | Neon NTT: Faster Dilithium, Kyber, and Saber | [2021-0986_neon_ntt_dilithium_kyber_saber.pdf](papers/2021-0986_neon_ntt_dilithium_kyber_saber.pdf) | https://eprint.iacr.org/2021/986 |
| Kyber/Dilithium | Speed and memory optimizations on Cortex-M4 | [2022-0112_kyber_dilithium_speed_memory_cortex_m4.pdf](papers/2022-0112_kyber_dilithium_speed_memory_cortex_m4.pdf) | https://eprint.iacr.org/2022/112 |
| SPHINCS+ | Optimization for SPHINCS+ using Intel SHA extensions | [2022-1726_sphincs_sha_extensions.pdf](papers/2022-1726_sphincs_sha_extensions.pdf) | https://eprint.iacr.org/2022/1726 |
| SPHINCS+ | Multi-Armed SPHINCS+ | [2023-0636_multi_armed_sphincs.pdf](papers/2023-0636_multi_armed_sphincs.pdf) | https://eprint.iacr.org/2023/636 |
| NTT survey | Polynomial multiplication implementation design space | [2023-1962_ntt_multiplication_survey.pdf](papers/2023-1962_ntt_multiplication_survey.pdf) | https://eprint.iacr.org/2023/1962 |
| SLH-DSA | Accelerating SLH-DSA by two orders of magnitude | [2024-0367_accelerating_slh_dsa_hash_unit.pdf](papers/2024-0367_accelerating_slh_dsa_hash_unit.pdf) | https://eprint.iacr.org/2024/367 |
| SPHINCS+ | Side Channel Resistant SPHINCS+ | [2024-0500_side_channel_resistant_sphincs.pdf](papers/2024-0500_side_channel_resistant_sphincs.pdf) | https://eprint.iacr.org/2024/500 |
| Dilithium | Dilithium sampling implementation and leakage analysis | [2024-1149_dilithium_sampling_implementation_analysis.pdf](papers/2024-1149_dilithium_sampling_implementation_analysis.pdf) | https://eprint.iacr.org/2024/1149 |
| Dilithium | Recent rejection-sampling side-channel work | [2025-0214_dilithium_rejection_sampling_side_channel.pdf](papers/2025-0214_dilithium_rejection_sampling_side_channel.pdf) | https://eprint.iacr.org/2025/214 |
| BIKE | BIKE specification v5.2 | cache only, ignored | https://bikesuite.org/files/v5.2/BIKE_Spec.2024.10.10.1.pdf |
| Frodo | FrodoKEM standard proposal | cache only, ignored | https://frodokem.org/files/FrodoKEM_standard_proposal_20250929.pdf |
| Falcon | Falcon specification | cache only, ignored | https://falcon-sign.info/falcon.pdf |
| Classic McEliece | Classic McEliece specification | cache only, ignored | https://classic.mceliece.org/mceliece-spec-20221023.pdf |
| Classic McEliece | Classic McEliece implementation guide | cache only, ignored | https://classic.mceliece.org/mceliece-impl-20221023.pdf |

### Applied Mapping

Kyber differs from a minimal clean reference mainly by caching twiddle-scaled odd
coefficients for base multiplication and by using SIMD coefficient lanes for
add/sub/reduction and cached polyvec accumulation. Those comments are in
`kyber/poly.nim`, `kyber/polyvec.nim`, and `kyber/reduce.nim`.

Dilithium keeps the reference arithmetic structure but adds fixed-width SIMD
lanes for add/sub/shift/pointwise accumulation and batched SHAKE sampling paths.
The eta sampler also includes a fixed-work prefix and explicit wipes; comments
mark both the applied batching and the side-channel papers that constrain it.

Frodo follows the FrodoKEM matrix equations, but the hot AES variants stream
four public rows or eight public columns at a time instead of materializing the
full public matrix. Comments mark the direct transposed decode, SIMD dot kernels,
OpenSSL/AES-NI bulk paths, and streamed `A*s+e` / `s*A+e` calls.

BIKE uses the BIKE decoder structure, Karatsuba GF(2) multiplication, and 128-bit
word helpers for XOR and bit-sliced decoder updates. The code comments mark
where the constant-time decoder paper and current BIKE spec are relevant.

Falcon is not a full AVX2 Falcon rewrite. The current applied optimization is a
portable two-lane `FalconFpr` helper used in FFT polynomial helper loops and keygen
norm accumulation. Comments mark those shared SSE2/NEON-style lanes.

Classic McEliece keeps the spec/PQClean flow but accelerates public-key generation
with 64x64 bit-matrix transpose and masked row XOR lanes, plus a public syndrome
bit limit that avoids scanning zero-padded ciphertext tail bits.

SPHINCS+ stays spec-compatible and focuses optimization on hash batching: fixed
one-block SHAKE fast paths and 2/4-lane WOTS hash batches where lane activity is
public or masked. Comments also mark where side-channel-resistant SPHINCS+ papers
were reviewed but not adopted because they change the signer design.
