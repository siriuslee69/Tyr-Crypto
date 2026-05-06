## NTRU/SABER Security And Optimization Research

Date: 2026-05-01

Scope: pure-Nim NTRU and SABER implementations in `src/protocols/custom_crypto/asymmetric/pq`.

### Research Document Manifest

Paper lifecycle is now controlled by `papers.lock.json`. PDFs with explicit
redistribution terms stay tracked; PDFs without clear redistribution terms are
ignored local-cache files and can be restored with `download_papers.ps1`.
License notes are in `LICENSES.md`.

Restore ignored cache files on Windows with:
`powershell -ExecutionPolicy Bypass -File docs/research/ntru_saber/download_papers.ps1`.

### Papers

| Area | Paper | Local copy | Upstream |
| --- | --- | --- | --- |
| NTRU performance | High-speed key encapsulation from NTRU | [2017-0667_high_speed_key_encapsulation_from_ntru.pdf](papers/2017-0667_high_speed_key_encapsulation_from_ntru.pdf) | https://eprint.iacr.org/2017/667 |
| NTRU/SABER performance | Faster multiplication in Z_2^m[x] on Cortex-M4 to speed up NIST PQC candidates | [2018-1018_faster_multiplication_z2m_cortex_m4.pdf](papers/2018-1018_faster_multiplication_z2m_cortex_m4.pdf) | https://eprint.iacr.org/2018/1018 |
| SABER throughput | SaberX4: High-throughput Software Implementation of Saber Key Encapsulation Mechanism | [2019-1309_saberx4_high_throughput_software.pdf](papers/2019-1309_saberx4_high_throughput_software.pdf) | https://eprint.iacr.org/2019/1309 |
| SABER side channels | A Side-Channel Resistant Implementation of SABER | [2020-0733_saber_side_channel_resistant_implementation.pdf](papers/2020-0733_saber_side_channel_resistant_implementation.pdf) | https://eprint.iacr.org/2020/733 |
| KEM message encoding | Single-Trace Attacks on the Message Encoding of Lattice-Based KEMs | [2020-0992_single_trace_message_encoding_lattice_kems.pdf](papers/2020-0992_single_trace_message_encoding_lattice_kems.pdf) | https://eprint.iacr.org/2020/992 |
| NTRU/SABER performance | NTT Multiplication for NTT-unfriendly Rings | [2020-1397_ntt_multiplication_ntt_unfriendly_rings.pdf](papers/2020-1397_ntt_multiplication_ntt_unfriendly_rings.pdf) | https://eprint.iacr.org/2020/1397 |
| SABER side channels | A Side-Channel Attack on a Masked IND-CCA Secure Saber KEM | [2021-0079_masked_ind_cca_secure_saber_attack.pdf](papers/2021-0079_masked_ind_cca_secure_saber_attack.pdf) | https://eprint.iacr.org/2021/079 |
| Masked FO comparison | Attacking and Defending Masked Polynomial Comparison for Lattice-Based Cryptography | [2021-0104_attacking_defending_masked_poly_comparison.pdf](papers/2021-0104_attacking_defending_masked_poly_comparison.pdf) | https://eprint.iacr.org/2021/104 |
| NTRU chosen-ciphertext side channels | Will You Cross the Threshold for Me? Generic Side-Channel Assisted Chosen-Ciphertext Attacks on NTRU-based KEMs | [2021-0718_generic_sca_cca_attacks_ntru_kems.pdf](papers/2021-0718_generic_sca_cca_attacks_ntru_kems.pdf) | https://eprint.iacr.org/2021/718 |
| NTRU side channels | A Side-Channel Assisted Attack on NTRU | [2021-0790_side_channel_assisted_attack_on_ntru.pdf](papers/2021-0790_side_channel_assisted_attack_on_ntru.pdf) | https://eprint.iacr.org/2021/790 |
| ARM64 performance | Neon NTT: Faster Dilithium, Kyber, and Saber on Cortex-A72 and Apple M1 | [2021-0986_neon_ntt_faster_dilithium_kyber_saber.pdf](papers/2021-0986_neon_ntt_faster_dilithium_kyber_saber.pdf) | https://eprint.iacr.org/2021/986 |
| SABER side channels | Lightweight Implementation of Saber Resistant Against Side-Channel Attacks | [2021-1452_lightweight_sca_resistant_saber.pdf](papers/2021-1452_lightweight_sca_resistant_saber.pdf) | https://eprint.iacr.org/2021/1452 |
| ARM64 performance | Optimized Software Implementations Using NEON-Based Special Instructions of ARMv8 | cache only, ignored | https://csrc.nist.gov/CSRC/media/Events/third-pqc-standardization-conference/documents/accepted-papers/nguyen-optimized-software-gmu-pqc2021.pdf |
| ARM64 performance | Fast NEON-Based Multiplication for Lattice-Based NIST Post-Quantum Cryptography Finalists | cache only, ignored | https://people-ece.vse.gmu.edu/~kgaj/publications/conferences/GMU_PQCrypto_2021_NEON.pdf |
| NTRU sampling side channels | Single-Trace Side-Channel Attacks on omega-Small Polynomial Sampling | [2022-0494_single_trace_omega_small_sampling_ntru.pdf](papers/2022-0494_single_trace_omega_small_sampling_ntru.pdf) | https://eprint.iacr.org/2022/494 |
| SABER side channels | Side-Channel Attacks on Lattice-Based KEMs Are Not Prevented by Higher-Order Masking | [2022-0919_side_channel_attacks_lattice_kems.pdf](papers/2022-0919_side_channel_attacks_lattice_kems.pdf) | https://eprint.iacr.org/2022/919 |
| Verified NTT kernels | Verified NTT Multiplications for NISTPQC KEM Lattice Finalists: Kyber, SABER, and NTRU | [2022_tches_verified_ntt_multiplications_ntru_saber.pdf](papers/2022_tches_verified_ntt_multiplications_ntru_saber.pdf) | https://tches.iacr.org/index.php/TCHES/article/view/9838 |
| NTRU sampling performance | Efficient isochronous fixed-weight sampling with applications to NTRU | [2024-0548_isochronous_fixed_weight_sampling_ntru.pdf](papers/2024-0548_isochronous_fixed_weight_sampling_ntru.pdf) | https://eprint.iacr.org/2024/548 |

### Supporting Material

| Material | Local copy | Upstream |
| --- | --- | --- |
| NTRU specification | cache only, ignored | https://ntru.org/f/ntru-20190330.pdf |
| SABER round-3 specification | cache only, ignored | https://www.esat.kuleuven.be/cosic/pqcrypto/saber/files/saberspecround3.pdf |
| NIST PQC round-3 report | [nist_ir_8413_upd1_pqc_round3_report.pdf](supporting/nist_ir_8413_upd1_pqc_round3_report.pdf) | https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8413-upd1.pdf |

### Reference Source Submodule

The NTRU fixed-weight sampling follow-up is linked as the `submodules/ntru_sampling_ref_sources` submodule, pointing at `https://github.com/dgazzoni/NTRU-sampling.git` on `main`. The full upstream repository contains Windows-incompatible filenames in historical speed-result paths, so this Windows workspace materializes only the source files needed for review and porting:

- `shuffling/ref/ntruhps*/sample.c`
- `shuffling/opt_neon/ntruhps*/sample.c`
- `speed/speed_sample_fixed_type.c`
- `vector-polymul-ntru-ntrup/sort/crypto_sort.c`

The submodule is configured with `update = none` in `.gitmodules` to avoid accidental full checkout of the invalid speed-result paths on Windows.

### Findings

NTRU has one concrete low-risk hardening item already applied: `mod3` and `mod3Small` now use the lower-leakage branchless reduction shape recommended by the NTRU side-channel paper instead of the subtract-and-mask form. This maps directly to secret-key unpacking and avoids the high Hamming-weight contrast highlighted in the paper.

The shared PQ byte wipe helper now uses volatile stores. This does not make heap lifetime perfect in Nim, but it prevents the most obvious dead-store elimination of the explicit short-lived secret wipes already present in NTRU/SABER keygen, encapsulation, and decapsulation.

NTRU fixed-weight sampling is the most important next security/performance item. The current HPS sampler follows a fixed sorting schedule, but the 2022 sampling paper shows that fixed-weight assignment can still leak on power traces, and the 2024 isochronous sampler gives a linear-time, timing-resistant replacement with large ARM speedups. This is a good next implementation target because it improves security posture and speed without adding a new cryptographic assumption.

NTRU/SABER polynomial multiplication is the main performance target. The current pure-Nim kernels are fixed-schedule schoolbook multipliers with SIMD only on the reduction pass. The NTT-unfriendly-rings paper, Neon NTT paper, and verified-NTT paper point to a better path: implement fixed-size scalar NTT kernels first, then AVX2/NEON backends, and keep all transform tables public and fixed. This should be guarded by KATs, differential tests against the current scalar path, OtterBench runs, and range/overflow tests.

SABER's unmasked branch-level behavior is acceptable for regular remote timing: decapsulation re-encrypts, verifies, and uses constant-time conditional move. That does not make it side-channel hardened on a device an attacker can physically measure. The SABER papers show attacks against message encoding, masked logical shifts, masked FO comparison, and even higher-order masked variants. Masking should not be added casually; it needs to follow patched designs and be validated with leakage tests.

Batching ideas such as SaberX4 are not appropriate as the default single-operation API. They may be useful as an explicit batch API later, but batching keeps more secret material live at once and complicates wipe boundaries. Prefer single-operation NTT and sampler improvements first.

### Optimization Pass: 2026-05-01

Experimental desktop AVX2 OtterBench JSON files are stored under `docs/research/ntru_saber/benchmarks`. The promoted final desktop and phone benchmark JSON files are in `docs/benchmarks`, and the focused HTML report is `docs/benchmarks/ntru_saber_bench_report.html`.

NTRU multiplication variants tested:

| Build | 509 ms | 677 ms | 821 ms | HRSS701 ms | Decision |
| --- | ---: | ---: | ---: | ---: | --- |
| baseline temp/reduce | 3.380 | 5.382 | 7.460 | 5.245 | replaced |
| row accumulator | 3.336 | 5.552 | 7.523 | 4.529 | kept behind `-d:ntruMulRows` |
| row accumulator unroll4 | 3.151 | 4.959 | 6.927 | 4.239 | kept behind `-d:ntruMulRowsUnroll4` |
| coefficient-oriented | 2.848 | 4.162 | 5.863 | 4.138 | kept behind `-d:ntruMulCoeff` |
| exact int64 Toom-4 | 2.286 | 3.567 | 4.910 | 2.615 | kept behind `-d:ntruMulToom4` |
| Toom-4 + 2-level Karatsuba | 2.328 | 3.569 | 4.902 | 2.585 | promoted as default |
| isochronous sampler only | 3.001 | 4.656 | 6.372 | 4.253 | experimental `-d:ntruIsoSample` |

The exact-int64 Toom-4 implementation was the first large paper-inspired win. The later K2 port follows the PQClean Toom-4 plus two-layer Karatsuba schedule, stayed KAT-compatible, and was stronger on scaled desktop repeats and all connected ARM64 phones. The promoted K2 path uses fixed public loop bounds, no secret-dependent branches, no secret-indexed tables, and stack-scoped scratch arrays. Rollback flags are preserved for every previous multiplier.

The isochronous fixed-weight sampler port is not the default. It greatly reduces the `sampleFixedType` hotspot in isolated benchmarking, but it changes the official deterministic HPS KAT transcripts and uses the reference rejection loop. It stays behind `-d:ntruIsoSample` until deterministic transcript compatibility and leakage behavior are reviewed more deeply.

SABER multiplication variants tested:

| Build | LightSaber ms | Saber ms | FireSaber ms | Decision |
| --- | ---: | ---: | ---: | --- |
| baseline temp/reduce | 0.154 | 0.192 | 0.258 | kept |
| row accumulator | 0.651 | 1.233 | 1.913 | rejected |
| row accumulator unroll4 | 0.537 | 0.961 | 1.520 | rejected |
| coefficient-oriented | 0.538 | 0.919 | 1.476 | rejected |
| exact int64 Toom-4 | 0.351 | 0.574 | 0.900 | rejected |
| modular Toom-4/Karatsuba | 0.215 | 0.328 | 0.414 | rejected |
| cached modular Toom-4/Karatsuba | 0.208 | 0.299 | 0.412 | rejected |
| scalar CRT/NTT, two NTT primes | 1.710 | 3.293 | 5.420 | rejected, kept behind `-d:saberMulNttScalar` |
| stack SHAKE buffers | 0.148 | 0.194 | 0.258 | promoted |

SABER's current temp-buffer schoolbook polynomial multiply plus fixed reduction pass remains the default multiplication path. The tested split-loop, Toom, and scalar NTT variants were KAT/vector-correct but slower on desktop. The scalar NTT uses two NTT-friendly primes and CRT reconstruction, avoids secret-dependent branches, and is useful as a correctness experiment, but it is not close to the schoolbook path without a much more specialized SIMD design.

The only SABER change promoted in this pass is replacing the heap-allocated SHAKE output buffers in `genMatrix` and `genSecret` with fixed stack buffers. This is a small speed win and a security cleanup: the secret noise buffer stays short-lived, is volatile-wiped, and does not require allocator traffic. `-d:saberHeapBuffers` is retained as the rollback build. On same-device SABER-only phone comparisons, stack buffers improved LightSaber/Saber/FireSaber by 1.3/2.1/2.4% on Infinix X6871, 0.8/3.3/4.1% on motorola edge 50 fusion, and 2.1/2.6/2.9% on moto g56 5G.

Final refreshed benchmark coverage:

| Device | Backend | NTRU 509 | NTRU 677 | NTRU 821 | HRSS701 | LightSaber | Saber | FireSaber |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Windows workstation | AVX2 | 2.340 | 3.642 | 4.573 | 2.552 | 0.141 | 0.194 | 0.268 |
| Infinix X6871 | NEON | 6.543 | 10.675 | 14.766 | 8.652 | 0.290 | 0.389 | 0.530 |
| motorola edge 50 fusion | NEON | 8.494 | 13.807 | 19.041 | 11.167 | 0.372 | 0.503 | 0.684 |
| moto g56 5G | NEON | 9.289 | 15.147 | 20.853 | 12.221 | 0.410 | 0.554 | 0.753 |

Compared with the previous coefficient-default run, the final NTRU desktop roundtrips improved by roughly 16-26% depending on variant. On the three connected phones, the same variants improved by roughly 29-39%, with the largest gains on HRSS701. SABER is now stack-buffer-default for matrix and secret generation; the phone SABER rows in the focused report were collected in same-binary SABER-only passes to avoid thermal/order skew after the heavier NTRU measurements.

### Implementation Guidance

Recommended next changes:

1. Replace NTRU HPS fixed-weight sampling with the 2024 isochronous sampler, keeping deterministic KAT replay intact.
2. Do not promote SABER NTT from the current scalar experiment; only revisit it with a SIMD design that removes the two-prime transform overhead and wins against the current small-secret schoolbook path.
3. Keep NTRU K2 as the rollback default while any future NTT work is validated on both desktop and phones.
4. Add a small leakage-audit checklist for PQ KEM changes: no secret-dependent branches, no secret-indexed tables, fixed loop bounds, volatile wipe for transient secret buffers, and FO failure handling only via constant-time selection.

Items to avoid:

1. Variable-time early exits in sampling, decoding, comparison, or decapsulation.
2. Secret-indexed lookup tables in SIMD kernels.
3. Masking changes copied from older SABER papers without also applying the later attack papers' fixes.
4. Batch APIs that reuse scratch buffers across unrelated key exchanges unless they have explicit lifetime and wipe semantics.
