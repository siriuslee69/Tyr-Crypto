# Tyr-Crypto Benchmarks

## Benchmark Entry Points

```text
+--------------------------+-----------------------------------------------+
| Command                  | Purpose                                       |
+--------------------------+-----------------------------------------------+
| nimble bench_custom_crypto | Tyr-only custom primitive report            |
| nimble bench_custom_kdf    | custom KDF tail/full-memory round table     |
| nimble bench_pq_profiles | matched scalar/AVX2 liboqs profile builds    |
| nimble perf_sigma_pq     | Sigma comparison against current liboqs      |
| nimble perf_sigma_kyber  | focused Kyber comparison                     |
| nimble perf_sigma_falcon | focused Falcon split phase comparison        |
| nimble perf_otter_pq     | Otter timing spans for PQ wrapper hot paths  |
| nimble perf_otter_kyber  | focused Otter timing for Kyber               |
+--------------------------+-----------------------------------------------+
```

## Artifact Layout

```text
build/benchmarks/             <- local generated JSON and logs, ignored
docs/benchmarks/*.json        <- curated benchmark snapshots
docs/benchmarks/*.html        <- rendered benchmark reports
docs/research/*/benchmarks/   <- research-specific trial data
```

## Measurement Flow

```text
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

## Current Interpretation Rules

```text
+----------------------+-----------------------------------------------+
| Signal               | How to read it                                |
+----------------------+-----------------------------------------------+
| desktop JSON         | workstation baseline for scalar/SIMD changes  |
| phone JSON           | ARM64/NEON behavior on physical devices       |
| rejected JSON        | measured experiment kept for comparison only  |
| Otter spans          | hotspot direction, not a full security proof  |
| Sigma comparisons    | relative backend/runtime comparison           |
+----------------------+-----------------------------------------------+
```

Benchmark runs are only promoted to `docs/benchmarks/` when they explain a kept implementation change, a rejected experiment, or a current production caveat.
