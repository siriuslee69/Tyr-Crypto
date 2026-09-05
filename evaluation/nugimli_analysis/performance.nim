## -----------------------------------------------------------------
## NuGimli Performance <- stable release-mode operation benchmarks
## -----------------------------------------------------------------

import metaPragmas
import otter_repo_evaluation
import ../../src/tyr/ciphers/gimli
import ./primitives

const
  benchmarkSamples* = 7
  benchmarkTargetBoxes = 300_000

proc estimatedBoxes[N: static[int]](): int {.inline, role: {math}.} =
  ## N: Cascade width whose full-round Gimli box count is estimated.
  const
    chunks = N div 4
  result = (chunks - 2) * fullRounds[N]()

proc benchmarkProfile*[N: static[int]](seedValue: uint64): seq[StableBenchResult]
    {.role: {orchestrator}.} =
  ## seedValue: deterministic Cascade state and key seed.
  var
    A: array[6, BenchAlgo]
    S, X, K, C, T: array[N, uint32]
    seed: uint64 = seedValue
    sink: uint32 = 0'u32
    loops: int = 0
  fillState(S, seed)
  fillState(X, seed)
  fillState(K, seed)
  C = encryptFull(X, K)
  loops = max(100, benchmarkTargetBoxes div max(1, estimatedBoxes[N]()))
  A[0] = BenchAlgo(name: "permute_simd", bytesPerOp: N * 4,
    run: proc() {.closure.} =
      permuteFull(S, true)
      sink = sink xor S[0])
  A[1] = BenchAlgo(name: "permute_scalar", bytesPerOp: N * 4,
    run: proc() {.closure.} =
      permuteFull(S, false)
      sink = sink xor S[N - 1])
  A[2] = BenchAlgo(name: "inverse_simd", bytesPerOp: N * 4,
    run: proc() {.closure.} =
      invertFull(S, true)
      sink = sink xor S[0])
  A[3] = BenchAlgo(name: "inverse_scalar", bytesPerOp: N * 4,
    run: proc() {.closure.} =
      invertFull(S, false)
      sink = sink xor S[N - 1])
  A[4] = BenchAlgo(name: "encrypt", bytesPerOp: N * 4,
    run: proc() {.closure.} =
      T = encryptFull(X, K)
      X[0] = X[0] xor T[0]
      sink = sink xor T[N - 1])
  A[5] = BenchAlgo(name: "decrypt", bytesPerOp: N * 4,
    run: proc() {.closure.} =
      T = decryptFull(C, K)
      C[0] = C[0] xor T[0]
      sink = sink xor T[N - 1])
  result = compareAlgorithmsStable(A, loops = loops, warmup = 32,
    samples = benchmarkSamples)
  if sink == 0x6f747465'u32:
    raise newException(ValueError, "unreachable benchmark sink")

proc benchmarkGimli*(seedValue: uint64): StableBenchResult
    {.role: {orchestrator}.} =
  ## seedValue: deterministic baseline state seed.
  var
    A: array[1, BenchAlgo]
    S: Gimli_Block
    seed: uint64 = seedValue
    sink: uint32 = 0'u32
    R: seq[StableBenchResult] = @[]
  fillState(S, seed)
  A[0] = BenchAlgo(name: "Gimli-384 permute", bytesPerOp: 48,
    run: proc() {.closure.} =
      gimliPermute(S)
      sink = sink xor S[0])
  R = compareAlgorithmsStable(A, loops = 20_000, warmup = 64,
    samples = benchmarkSamples)
  result = R[0]
  if sink == 0x6f747465'u32:
    raise newException(ValueError, "unreachable baseline sink")
