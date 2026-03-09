Commit Message: add chunkyCrypto wrapper, AES-CTR streaming, and hybrid kex renames

Features to implement:
- Stable high-level crypto wrapper API with predictable inputs/outputs.
- Pure Nim implementations for common primitives (XChaCha20, BLAKE3, etc.).
- Native bindings for libsodium, OpenSSL, and liboqs.
- Test vectors and regression tests for all supported primitives.
- Build and test nimble tasks for daily use and CI.
- Chunked file encryption + hashing wrapper for large files.

Implemented:
- libsodium bindings for AEAD, XChaCha20 stream, and Argon2 APIs.
- nimcrypto binding for AES-256-GCM.
- Pure Nim BLAKE3 and XChaCha20 (with HChaCha20) implementations.
- Wrapper-level encrypt/decrypt with tag verification.
- Unit tests for bindings, custom crypto, and wrapper API.
- Kyber+X25519 hybrid KEX variant and tests.
- Signature wrapper for Ed25519 and liboqs PQ signatures.
- SIMD-Nexus integration and Gimli SSE permutation.
- Gimli SSE regression test against reference.
- Gimli sponge helpers and XChaCha20+Gimli wrapper with tests.
- XChaCha20+AES+Gimli wrapper with configurable tag length.
- AES-CTR helper using nimcrypto core with optional SSE/AVX XOR.
- XChaCha20 SIMD keystream implementation with SSE/AVX lanes.
- Gimli reference vector test (c-ref).
- AES-CTR vs nimcrypto CTR + AES-GCM vs libsodium comparison tests.
- AES-CTR streaming state with in-place transforms.
- XChaCha20+AES+Gimli wrapper available without nimcrypto.
- ChunkyCrypto module with threaded chunk encrypt/decrypt + hash tree.
- Hybrid KEX modules renamed to duo/triple with ASCII headers.
- Bindings/builders moved into dedicated src folders.

Working on:
- Argon2 pure Nim implementation or dedicated binding wrapper.
- Optional Poly1305 AEAD path for the wrapper-level XChaCha20 flow.
- Hybrid public-key crypto plan: 3-layer scheme using McEliece + Curve25519 + Kyber.

Last big change or problem:
- Added ChunkyCrypto wrapper and moved bindings/builders into dedicated folders.

Fix attempt and result:
- Updated imports/tests for the new module layout and expanded ChunkyCrypto tests.

