## ----------------------------------------------------------------------
## NuGimli Leakage Evaluation <- fixed/random Welch timing measurements
## ----------------------------------------------------------------------

import std/[monotimes, os, strutils]
import tyrPragmas
import otter_repo_evaluation
import ../../src/tyr/ciphers/nugimli/types
import ../../src/tyr/ciphers/nugimli/domain
import ../../src/tyr/ciphers/nugimli/cascade
import ../../src/tyr/ciphers/nugimli/reference

const
  leakageSamplesPerClass = 50_000
  leakageBatch = 4
  derivationSamplesPerClass = 10_000
  leakageThreshold = 4.5

type
  LeakageOperation = enum
    loEncrypt
    loDecrypt
    loDerive

proc nextSplitMix(S: var uint64): uint64 {.inline, role: {math}.} =
  ## S: deterministic measurement-order and input generator state.
  var
    z: uint64 = 0'u64
  S = S + 0x9e3779b97f4a7c15'u64
  z = S
  z = (z xor (z shr 30)) * 0xbf58476d1ce4e5b9'u64
  z = (z xor (z shr 27)) * 0x94d049bb133111eb'u64
  result = z xor (z shr 31)

proc fillWords[N: static[int]](S: var array[N, uint32], seed: var uint64)
    {.inline, role: {helper}.} =
  ## S: test state. seed: deterministic non-secret generator.
  var
    i: int = 0
  i = 0
  while i < N:
    S[i] = uint32(nextSplitMix(seed))
    i = i + 1

proc encryptCascade[N: static[int]](X, K: array[N, uint32]): array[N, uint32]
    {.inline, role: {encryptor}.} =
  ## X/K: exact-width plaintext and key.
  when N == 16:
    result = cascadeEncrypt512(X, K)
  elif N == 32:
    result = cascadeEncrypt1024(X, K)
  else:
    result = cascadeEncrypt2048(X, K)

proc decryptCascade[N: static[int]](C, K: array[N, uint32]): array[N, uint32]
    {.inline, role: {decryptor}.} =
  ## C/K: exact-width ciphertext and key.
  when N == 16:
    result = cascadeDecrypt512(C, K)
  elif N == 32:
    result = cascadeDecrypt1024(C, K)
  else:
    result = cascadeDecrypt2048(C, K)

proc measureCipher[N: static[int]](op: LeakageOperation,
    randomClass: bool, seed: var uint64, sink: var uint32): float64
    {.role: {orchestrator}.} =
  ## op/randomClass/seed: timing class. sink: optimizer-resistant output use.
  var
    X, K, C, T, R: array[N, uint32]
    started, stopped: MonoTime
    i: int = 0
  fillWords(X, seed)
  if randomClass:
    fillWords(K, seed)
  C = encryptCascade(X, K)
  started = getMonoTime()
  i = 0
  while i < leakageBatch:
    T = X
    T[0] = T[0] xor uint32(i)
    if op == loEncrypt:
      R = encryptCascade(T, K)
    else:
      R = decryptCascade(C, K)
    i = i + 1
  stopped = getMonoTime()
  sink = sink xor R[0]
  result = float64(stopped.ticks - started.ticks) / float64(leakageBatch)

proc deriveCascade[N: static[int]](S: array[N, uint32],
    tag: CascadeDomainTag): uint32 {.role: {truthBuilder}.} =
  ## S/tag: exact-width source and fixed public domain tag.
  when N == 16:
    result = deriveCascade1024(S, tag).key[0]
  elif N == 32:
    result = deriveCascade2048(S, tag).key[0]
  else:
    result = deriveCascade512(S, tag).key[0]

proc measureDerivation[N: static[int]](randomClass: bool, seed: var uint64,
    tag: CascadeDomainTag, sink: var uint32): float64
    {.role: {orchestrator}.} =
  ## randomClass/seed/tag: timing class. sink: optimizer-resistant output use.
  var
    S: array[N, uint32]
    started, stopped: MonoTime
    value: uint32 = 0'u32
  if randomClass:
    fillWords(S, seed)
  started = getMonoTime()
  value = deriveCascade(S, tag)
  stopped = getMonoTime()
  sink = sink xor value
  result = float64(stopped.ticks - started.ticks)

proc collectCipherSamples[N: static[int]](op: LeakageOperation,
    samples: int, seedValue: uint64): TimingLeakageResult
    {.role: {orchestrator}.} =
  ## op/samples/seedValue: fixed-versus-random cipher timing campaign.
  var
    Fixed, Random: seq[float64] = @[]
    seed: uint64 = seedValue
    sink: uint32 = 0'u32
    randomClass: bool = false
  Fixed = newSeqOfCap[float64](samples)
  Random = newSeqOfCap[float64](samples)
  while Fixed.len < samples or Random.len < samples:
    randomClass = (nextSplitMix(seed) and 1'u64) != 0'u64
    if randomClass and Random.len < samples:
      Random.add(measureCipher[N](op, true, seed, sink))
    elif not randomClass and Fixed.len < samples:
      Fixed.add(measureCipher[N](op, false, seed, sink))
  result = welchTimingLeakage($op & "-" & $(N * 32), Fixed, Random,
    leakageThreshold)
  if sink == 0x43544c4b'u32:
    raise newException(ValueError, "unreachable leakage sink")

proc collectDerivationSamples[N: static[int]](samples: int,
    seedValue: uint64): TimingLeakageResult {.role: {orchestrator}.} =
  ## samples/seedValue: fixed-versus-random tagged derivation campaign.
  var
    Fixed, Random: seq[float64] = @[]
    seed: uint64 = seedValue
    sink: uint32 = 0'u32
    randomClass: bool = false
    tag: CascadeDomainTag = cascadeDomainTag("timing/leakage/v1")
  Fixed = newSeqOfCap[float64](samples)
  Random = newSeqOfCap[float64](samples)
  while Fixed.len < samples or Random.len < samples:
    randomClass = (nextSplitMix(seed) and 1'u64) != 0'u64
    if randomClass and Random.len < samples:
      Random.add(measureDerivation[N](true, seed, tag, sink))
    elif not randomClass and Fixed.len < samples:
      Fixed.add(measureDerivation[N](false, seed, tag, sink))
  result = welchTimingLeakage("derive-" & $(N * 32), Fixed, Random,
    leakageThreshold)
  if sink == 0x43544c4b'u32:
    raise newException(ValueError, "unreachable derivation sink")

proc resultRow(R: TimingLeakageResult): string {.role: {dataWriter}.} =
  ## R: one leakage result rendered as Markdown.
  result = "| " & R.name & " | " & $R.fixedSamples & " | " &
    formatFloat(R.fixedMean, ffDecimal, 2) & " | " &
    formatFloat(R.randomMean, ffDecimal, 2) & " | " &
    formatFloat(R.firstOrderT, ffDecimal, 4) & " | " &
    formatFloat(R.secondOrderT, ffDecimal, 4) & " | " &
    formatFloat(R.maxAbsT, ffDecimal, 4) & " | " & $R.passed & " |\n"

proc runLeakageEvaluation*() {.role: {metaOrchestrator}.} =
  var
    R: seq[TimingLeakageResult] = @[]
    text: string = ""
    i: int = 0
  R.add(collectCipherSamples[16](loEncrypt, leakageSamplesPerClass, 0x1001'u64))
  R.add(collectCipherSamples[32](loEncrypt, leakageSamplesPerClass, 0x1002'u64))
  R.add(collectCipherSamples[64](loEncrypt, leakageSamplesPerClass, 0x1003'u64))
  R.add(collectCipherSamples[16](loDecrypt, leakageSamplesPerClass, 0x2001'u64))
  R.add(collectCipherSamples[32](loDecrypt, leakageSamplesPerClass, 0x2002'u64))
  R.add(collectCipherSamples[64](loDecrypt, leakageSamplesPerClass, 0x2003'u64))
  R.add(collectDerivationSamples[16](derivationSamplesPerClass, 0x3001'u64))
  R.add(collectDerivationSamples[32](derivationSamplesPerClass, 0x3002'u64))
  R.add(collectDerivationSamples[64](derivationSamplesPerClass, 0x3003'u64))
  text.add("# NuGimli Cascade timing leakage evaluation\n\n")
  text.add("Threshold: `|t| < " & $leakageThreshold & "` for both first- and second-order Welch tests.\n\n")
  text.add("| Operation | Samples/class | Fixed ns | Random ns | First t | Second t | Max | Pass |\n")
  text.add("|---|---:|---:|---:|---:|---:|---:|---:|\n")
  i = 0
  while i < R.len:
    text.add(resultRow(R[i]))
    i = i + 1
  text.add("\nTiming tests are empirical and complement, rather than replace, source/code-generation review.\n")
  text.add("\n## Source and generated-code review\n\n")
  text.add("- Scalar and SIMD Gimli boxes contain fixed-count loops and bitwise/rotation operations only.\n")
  text.add("- Cascade data accesses use public loop/chunk/lane indices; no address depends on plaintext, key, or derived state contents.\n")
  text.add("- Cascade branches select public family, round, width, bounds, and loop termination conditions. No branch consumes secret contents.\n")
  text.add("- The keyed transform is two fixed-width XOR passes around a fixed-round permutation.\n")
  text.add("- Tagged SHAKE derivation branches only on public source/target lengths, tag length, context length, and output length.\n")
  text.add("- Temporary derivation buffers and explicit derived-material cleanup use compiler-resistant volatile zero stores.\n")
  text.add("- Release disassembly contains loop, bounds-check, overflow-check, and public-schedule branches; no secret-indexed lookup or secret-content branch was identified.\n")
  text.add("\nThis covers software timing/cache behavior. It does not provide masking against physical power, electromagnetic, fault-injection, or shared-hardware transient-execution attacks.\n")
  createDir("build")
  writeFile("build/nugimli_leakage.md", text)
  stdout.write(text)

when isMainModule:
  runLeakageEvaluation()
