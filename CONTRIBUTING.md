# Contributing to Tyr-Crypto

## Purpose
Tyr-Crypto is the workspace crypto primitive repo. Keep changes inside this boundary:

```text
+-------------------------+----------------------------------------------+
| In scope                | Out of scope                                 |
+-------------------------+----------------------------------------------+
| typed crypto wrappers   | application protocols                       |
| pure-Nim primitives     | certificate policy                          |
| optional backend binds  | account/database state                      |
| wasm/JS bridge code     | transport/session orchestration             |
| vector/regression tests | production key-management infrastructure    |
| native build helpers    | app-specific authorization policy           |
+-------------------------+----------------------------------------------+
```

## Read First
Before changing behavior, read:

- [README.md](README.md)
- [src/tyr_crypto.nim](src/tyr_crypto.nim)
- [basic_api.nim](src/protocols/wrapper/basic_api.nim)
- [CODE_LAYOUT.md](docs/CODE_LAYOUT.md)
- [TESTS.md](docs/TESTS.md)
- [.iron/conventions/PROJECTS.md](.iron/conventions/PROJECTS.md)
- [.iron/meta/registry.nim](.iron/meta/registry.nim)

If the change touches wasm/JS, also read:

- [json_api.nim](src/protocols/wrapper/wasm/level2/json_api.nim)
- [exports.nim](src/protocols/wrapper/wasm/exports.nim)
- [tyr_crypto.mjs](bindings/js/tyr_crypto.mjs)
- [tyr_crypto.d.ts](bindings/js/tyr_crypto.d.ts)

## Architecture Rules
```text
raw input
   |
   v
sanitize/validate
   |
   v
typed crypto material
   |
   v
small primitive or wrapper operation
   |
   v
explicit output bytes/tag/signature/envelope
```

- [basic_api.nim](src/protocols/wrapper/basic_api.nim) is the canonical public wrapper surface.
- `Tyr`-suffixed material names identify local pure-Nim implementations.
- Unsuffixed backend-backed materials may coexist where a pure-Nim alternative also exists.
- Keep optional backend paths optional. Missing libraries should fail with a descriptive error.
- Do not silently replace a backend path with a custom path unless the public API name makes that explicit.

## Crypto Rules
- Preserve explicit endianness. Do not rely on host-endian memory casts for protocol-critical state.
- Treat side-channel exposure as a first-class constraint. Use branchless comparisons or mask-based selection where secrets are involved.
- Validate material sizes, output lengths, and raw user/dev-facing inputs before acting on them.
- Prefer small shared modules over copy-pasted per-tier variants.
- If you add a custom algorithm, add scalar code first, then vectors, then SIMD parity if a SIMD backend is added.

## High-Risk Areas
```text
+-----------------------------------------------------------+----------------------+
| Path                                                      | Risk                 |
+-----------------------------------------------------------+----------------------+
| src/protocols/wrapper/basic_api.nim                       | public API behavior  |
| src/protocols/custom_crypto/asymmetric/pq/mceliece/       | large KEM internals  |
| src/protocols/custom_crypto/asymmetric/pq/falcon/         | slow signature path  |
| src/protocols/custom_crypto/symmetric/sha3/               | hash/XOF core        |
| src/protocols/custom_crypto/symmetric/poly1305/           | authenticator core   |
| src/protocols/bindings/                                  | native ABI loading   |
| src/protocols/wrapper/wasm/                               | public wasm ABI      |
+-----------------------------------------------------------+----------------------+
```

## Testing Expectations
Run the smallest relevant checks first, then widen based on risk:

```text
small code change
   |
   +--> nimble check_core
   +--> focused test file
   +--> nimble test for larger behavior changes
   +--> full/native/mobile matrix when bindings, SIMD, or Android changed
```

Common commands:

```bash
nimble check_core
nimble check
nimble test
nimble test_wasm
nimble test_neon_checks
nimble test_simd_matrix
```

Use [test_primitives_api.nim](tests/test_primitives_api.nim) when dispatch behavior changes and [test_quick_api.nim](tests/test_quick_api.nim) when typed material layout changes.

## Documentation Rules
- Update [README.md](README.md) when the public surface, commands, dependency story, or issue playbook changes.
- Update [docs/CODE_LAYOUT.md](docs/CODE_LAYOUT.md), [docs/TESTS.md](docs/TESTS.md), or [docs/BENCHMARKS.md](docs/BENCHMARKS.md) when their tables stop matching reality.
- Keep examples aligned with the exported API.
- Remove stale references instead of leaving temporary legacy notes.

## Native Builders
Builder tasks live in [tyr_crypto.nimble](tyr_crypto.nimble) and [tools/](tools).

```bash
nimble build_libsodium
nimble build_liboqs
nimble build_openssl
```

## Review Checklist
```text
+------------------------------------------------------------+------+
| Question                                                   | Done |
+------------------------------------------------------------+------+
| Does the change stay inside Tyr-Crypto's repo boundary?    | [ ]  |
| Are custom-vs-backend names still obvious?                 | [ ]  |
| Are raw inputs sanitized before public/user-facing use?     | [ ]  |
| Are secret-dependent branches avoided where practical?      | [ ]  |
| Are output lengths and material sizes validated?            | [ ]  |
| Are vectors or parity tests added for new primitives?       | [ ]  |
| Were README/docs/progress notes updated for larger changes? | [ ]  |
+------------------------------------------------------------+------+
```

## License
Contributions are expected to follow the repo's existing `Unlicense` model unless stated otherwise. Third-party source, submodules, research documents, and generated native artifacts keep their upstream license and notice requirements.
