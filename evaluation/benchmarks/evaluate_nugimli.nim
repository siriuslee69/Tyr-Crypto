## -----------------------------------------------------------------
## NuGimli Evaluation <- run all empirical checks and write report
## -----------------------------------------------------------------

import std/os
import tyrPragmas
import otter_repo_evaluation
import ../nugimli_analysis/types
import ../nugimli_analysis/primitives
import ../nugimli_analysis/security
import ../nugimli_analysis/performance
import ../nugimli_analysis/report

const
  evaluationSeed = 0x6e7567696d6c6931'u64

proc capabilities(): string {.role: {parser}.} =
  result = hostCPU & "/" & hostOS & ", release"
  when defined(sse2):
    result.add(", SSE2")
  when defined(avx2):
    result.add(", AVX2 host")
  when defined(neon) or defined(arm64) or defined(aarch64):
    result.add(", NEON")

proc evaluateProfile[N: static[int]](seed: uint64): ProfileResult
    {.role: {orchestrator}.} =
  ## seed: deterministic Cascade profile seed.
  result.name = "Cascade-" & $(N * 32)
  result.bits = N * 32
  result.plaintext = evaluateAvalanche[N](false, seed xor 0x01'u64)
  result.key = evaluateAvalanche[N](true, seed xor 0x02'u64)
  result.differential = evaluateDifferential[N](seed xor 0x03'u64)
  result.plaintextWeak = evaluateWeakPath[N](false,
    result.plaintext.minInputBit, seed xor 0x07'u64)
  result.keyWeak = evaluateWeakPath[N](true,
    result.key.minInputBit, seed xor 0x08'u64)
  result.components = evaluateComponents[N](seed xor 0x09'u64)
  result.statistical = evaluateStatistics[N](seed xor 0x04'u64)
  result.diffusion = evaluateDiffusion[N](seed xor 0x05'u64)
  result.performance = benchmarkProfile[N](seed xor 0x06'u64)

proc appendProfiles(R: var seq[ProfileResult], seed: uint64)
    {.role: {orchestrator}.} =
  ## R/seed: result destination and Cascade evaluation domain.
  R.add(evaluateProfile[16](seed xor 512'u64))
  R.add(evaluateProfile[32](seed xor 1024'u64))
  R.add(evaluateProfile[64](seed xor 2048'u64))

proc runEvaluation*() {.role: {metaOrchestrator}.} =
  var
    R: seq[ProfileResult] = @[]
    baseline: StableBenchResult
    text: string = ""
    path: string = joinPath("build", "nugimli_evaluation.md")
  appendProfiles(R, evaluationSeed xor 0x22'u64)
  baseline = benchmarkGimli(evaluationSeed xor 0x44'u64)
  text = formatAnalysisReport(R, baseline, capabilities())
  createDir("build")
  writeFile(path, text)
  stdout.write(text)
  stdout.write("\nReport: " & absolutePath(path) & "\n")

when isMainModule:
  runEvaluation()
