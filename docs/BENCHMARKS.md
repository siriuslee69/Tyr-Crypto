# Benchmarks

## Entry Points

| Command | Purpose |
|---------|---------|
| `nimble bench_custom_crypto` | Tyr-only custom primitive report |
| `nimble bench_custom_kdf` | Custom KDF tail/full-memory round table |
| `nimble bench_pq_profiles` | Matched scalar/AVX2 liboqs profile builds |
| `nimble perf_sigma_pq` | Sigma comparison against current liboqs |
| `nimble perf_sigma_kyber` | Focused Kyber comparison |
| `nimble perf_sigma_falcon` | Falcon split phase comparison |
| `nimble perf_otter_pq` | Otter timing spans for PQ wrapper hot paths |
| `nimble perf_otter_kyber` | Focused Otter timing for Kyber |

The unified report accepts section arguments. A focused post-fix Falcon run can
be built and executed without the unrelated byte/KEM tables:

```bash
TYR_FALCON_BENCH_VARIANT=512 nim c --threads:on -d:release -r tools/bench_custom_crypto_table.nim signature falcon
TYR_FALCON_BENCH_VARIANT=1024 tools/bench_custom_crypto_table signature falcon
```

The first command compiles with Tyr's automatic safe host capabilities. The
second reuses that executable and selects Falcon-1024. Current local results are
about `51 ms` and `322 ms` per keygen respectively; older curated Falcon phone
snapshots predate the NTRU reducer fix and must not be used as current keygen
guidance.

## Artifact Layout

```
build/benchmarks/               local generated JSON and logs (ignored)
docs/benchmarks/*.json          curated benchmark snapshots
docs/benchmarks/*.html          rendered benchmark reports
docs/research/*/benchmarks/     research-specific trial data
```

## Measurement Flow

```
select profile
   |
   v
build native dependency profile, if needed
   |
   v
run Sigma or Otter benchmark
   |
   v
write JSON/logs to build/
   |
   v
copy curated snapshots to docs/benchmarks/
   |
   v
render asymmetric benchmark HTML reports
```

## Interpretation Rules

| Signal | How to read it |
|--------|---------------|
| desktop JSON | workstation baseline for scalar/SIMD changes |
| phone JSON | ARM64/NEON behavior on physical devices |
| rejected JSON | measured experiment kept for comparison only |
| Otter spans | hotspot direction, not a full security proof |
| Sigma comparisons | relative backend/runtime comparison |

Benchmark runs are promoted to `docs/benchmarks/` only when they explain an implementation change, a rejected experiment, or a current production caveat.

## Available Benchmark Snapshots

```
docs/benchmarks/
  asymmetric_desktop.json          All PQ algorithms (desktop)
  kyber_{phone,infinix,moto_g56}.json    Kyber on 3 devices
  dilithium_{phone,infinix,moto_g56}.json
  falcon_{phone,infinix,moto_g56}.json   + falcon512/1024 desktop split
  frodo_{phone,infinix,moto_g56}.json    + deep final profiles
  bike_{phone,infinix,moto_g56}.json
  mceliece_{phone,infinix,moto_g56}.json
  sphincs_{phone,infinix,moto_g56}.json
  x25519_{phone,infinix,moto_g56}.json   + full/summary variants
  ntru_saber_{desktop,edge50,infinix,moto_g56}.json
```

Performance optimization history for NTRU/SABER (multiplication variants, isochronous sampling, stack buffers): [docs/research/ntru_saber/README.md](research/ntru_saber/README.md)
