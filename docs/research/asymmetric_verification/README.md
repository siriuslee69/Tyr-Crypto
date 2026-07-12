# Asymmetric Cryptography Verification

Date: 2026-07-12

This folder records the normative sources and the limits of the pure-Nim
asymmetric review. It does not claim that tests or source inspection are a
formal proof, a side-channel evaluation, or an independent cryptographic
certification.

The source lock is `references.lock.json`. Tracked copies are limited to
documents with clear redistribution terms. Candidate specifications without a
clear grant remain ignored local caches in the older research folders and are
identified by URL and SHA-256 there.

## Identity Map

| Tyr family | Implemented identity | Normative baseline | Status |
| --- | --- | --- | --- |
| X25519 | X25519 | RFC 7748 sections 5 and 6 | RFC vectors and invalid-peer tests pass |
| Ed25519 | PureEd25519 with strict prime-subgroup verification | RFC 8032 sections 5.1.1-5.1.7; strict policy from *Taming the many EdDSAs* section 3 | RFC vectors pass; identity-key forgery rejected |
| `kyber*` | CRYSTALS-Kyber round 3 | Kyber v3.02 round-3 specification | Legacy format; not FIPS 203 ML-KEM |
| `dilithium*` | ML-DSA-44/65/87 | FIPS 204 | Standardized format; canonical hint regression added |
| `sphincs*` | SPHINCS+-SHAKE-128f-simple v3.1 raw-message API | SPHINCS+ v3.1 specification | Legacy API; not FIPS 205 SLH-DSA |
| Falcon | Falcon-512/1024 round 3 | Falcon specification and PQClean round-3 source | Candidate format; KAT/differential evidence only |
| FrodoKEM | FrodoKEM 640/976/1344 AES/SHAKE | pinned FrodoKEM proposal | Candidate format; KAT/differential evidence only |
| BIKE | BIKE-L1 | pinned BIKE v5.2 specification | Candidate format; KAT/differential evidence only |
| Classic McEliece | 6688128f/6960119f/8192128f | pinned 2022 specification and implementation guide | Candidate format; KAT/differential evidence only |
| NTRU | HPS 2048-509/677, HPS 4096-821, HRSS-701 | pinned 2019 NTRU specification | Round-3 candidate format; official KAT replay passes |
| SABER | LightSaber/Saber/FireSaber | pinned SABER round-3 specification | Round-3 candidate format; official KAT replay passes |

## Concrete Findings

1. ML-DSA hint decoding already used the required strict ordering test. A
   duplicate-index mutation now locks this behavior against the non-canonical
   signature class described in the linked PQC assay.
2. Ed25519 verification accepted the identity public key with `R = B, S = 1`
   for every message. Verification now requires both decoded points to be
   non-identity members of the prime-order subgroup before applying the group
   equation.
3. Kyber encapsulation hashes its random message before the Fujisaki-Okamoto
   transform. That is round-3 Kyber algorithm 8 and is not wire-compatible with
   FIPS 203 ML-KEM algorithm 20.
4. SPHINCS+ signs the raw caller message. FIPS 205 SLH-DSA signs an externally
   framed message containing a domain byte and context length, so the existing
   API must not be labeled SLH-DSA.
5. BIKE and Classic McEliece expose diagnostic decapsulation validity flags.
   Normal wrappers use implicit rejection, but application code must not branch
   on those flags. Removing or test-gating those exported diagnostics is a
   release-boundary API change.

## Verification Limits

- KAT replay checks exact deterministic transcripts, but does not cover every
  malformed encoding or arithmetic input.
- Differential tests can reproduce the same defect when both implementations
  share ancestry.
- Source review cannot establish constant-time behavior after every compiler,
  target, and optimization choice. Physical leakage testing was not performed.
- FIPS 203 and FIPS 204 have active NIST errata notices. The files and hashes in
  this folder identify the exact review baseline and must be refreshed when a
  revised publication is released.
- Falcon, FrodoKEM, BIKE, Classic McEliece, NTRU, and SABER are not claimed to
  be current NIST standards by this audit.
- The local liboqs-dependent KAT programs compiled but did not compare their
  corpora because this build did not provide the liboqs runtime. Their skip
  messages are not counted as KAT passes. NTRU and SABER replayed their
  independent official response files; the other candidate families passed
  their available pure-Nim round-trip, malformed-input, or focused tests.

## Verification Record

| Evidence | Result | What it establishes |
| --- | --- | --- |
| Citation and source-lock gate | Pass, 84 modules checked and 1,374 declarations across 79 declaration-bearing modules | Every function-like declaration has an immediate known source ID; tracked reference bytes match locked size and SHA-256 |
| Public library compile | Pass | The annotated default public surface parses and compiles |
| ARM64/NEON compile matrix | Pass for ML-DSA, FrodoKEM, and Classic McEliece audit targets | Conditional SIMD declarations remain valid on the checked ARM64 target |
| X25519 and Ed25519 focused tests | Pass | RFC vectors, invalid peers, tampering, and the identity-key Ed25519 forgery regression |
| ML-DSA focused tests | Pass | Sign/verify behavior and duplicate hint-index rejection |
| Kyber and SPHINCS+ focused tests | Pass | Legacy round-3 round trips and rejection behavior, not ML-KEM or SLH-DSA conformance |
| Falcon, FrodoKEM, BIKE, and Classic McEliece focused tests | Pass | Available local round trips and malformed-input checks |
| NTRU and SABER official KAT replay | Pass | Exact deterministic response-file behavior for the covered parameter sets |
| liboqs corpus comparisons | Not run | Build lacked the required liboqs runtime; the tests reported a skip |
| Motorola ARM64/NEON release harness | Pass, `motorola_edge_50_fusion`, exit 0 | All asymmetric families plus certificate codec edge tests completed on the connected Android device |

The audit found no source basis for calling the existing Kyber API ML-KEM or
the existing SPHINCS+ API SLH-DSA. Those names remain deliberately legacy and
must not be changed without implementing the standardized transcript and adding
independent vectors for the new wire format.

The permanent negative regressions cover Ed25519 identity and mixed-order
forgeries, malformed ML-DSA hints, the legacy Kyber transcript, KEM implicit
rejection, and strict certificate parsing. The Android harness embeds its real
Ed25519 PKCS#8/X.509 fixture at compile time, so those checks cannot silently
skip because repository files are absent on the device.

## Reproduction

Run `nimble check_asymmetric_references` to verify that every asymmetric
function declaration has an immediately preceding `Reference:` comment, that
every cited source ID exists in `references.lock.json`, and that every tracked
reference still matches its locked byte size and SHA-256.

Run the focused correctness tests with `nimble test_asymmetric_audit`.
