## ------------------------------------------------------------------
## NuGimli Advanced Evaluation <- structural and algebraic searches
## ------------------------------------------------------------------

import std/[os, strutils]
import runePragmas
import ../nugimli_analysis/advanced_security

proc row(R: AdvancedSecurityResult): string {.role: {dataWriter}.} =
  ## R: one width's advanced security evidence row.
  result = "| Cascade-" & $R.bits & " | " & $R.linearRank & "/" & $R.bits &
    " | " & $R.affineRank & "/" & $R.bits & " | " &
    $R.deterministicDifferentials & " | " & $R.deterministicRelatedKeys &
    " | " & $R.equivalentKeyBits & " | " & $R.symmetryMatches & "/" &
    $R.symmetryTests & " | " & $R.slideMatches & "/" & $R.slideTests & " | " &
    $R.structuredInvariantMatches & "/" & $R.structuredInvariantTests & " | " &
    formatFloat(R.maxLinearCorrelation, ffDecimal, 6) & " | " &
    $R.minimumDifferenceFingerprints & "/" & $differentialTrailSamples & " | " &
    formatFloat(R.maxProjectedDifferentialProbability, ffDecimal, 6) & " | >=" &
    $R.algebraicDegreeLowerBound & " |\n"

proc analyze512(R: ptr AdvancedSecurityResult) {.thread, role: {orchestrator}.} =
  ## R: isolated result slot for Cascade-512.
  R[] = analyzeAdvanced[16](0x414456353132'u64)

proc analyze1024(R: ptr AdvancedSecurityResult) {.thread, role: {orchestrator}.} =
  ## R: isolated result slot for Cascade-1024.
  R[] = analyzeAdvanced[32](0x41445631303234'u64)

proc analyze2048(R: ptr AdvancedSecurityResult) {.thread, role: {orchestrator}.} =
  ## R: isolated result slot for Cascade-2048.
  R[] = analyzeAdvanced[64](0x41445632303438'u64)

proc runAdvancedEvaluation*() {.role: {metaOrchestrator}.} =
  var
    Results: array[3, AdvancedSecurityResult]
    text: string = ""
    i: int = 0
  when compileOption("threads"):
    var
      T0: Thread[ptr AdvancedSecurityResult]
      T1: Thread[ptr AdvancedSecurityResult]
      T2: Thread[ptr AdvancedSecurityResult]
    createThread(T0, analyze512, addr Results[0])
    createThread(T1, analyze1024, addr Results[1])
    createThread(T2, analyze2048, addr Results[2])
    joinThread(T0)
    joinThread(T1)
    joinThread(T2)
  else:
    analyze512(addr Results[0])
    analyze1024(addr Results[1])
    analyze2048(addr Results[2])
  text.add("# NuGimli Cascade advanced security evidence\n\n")
  text.add("Full GF(2) rank is an exact certificate against nonzero linear/affine parity invariants. Other searches are bounded computational evidence.\n\n")
  text.add("| Profile | Linear rank | Affine rank | Constant differentials | Constant related-key | Equivalent bits | Rotation matches | Slide matches | Structured invariant matches | Max linear correlation | Min differential identities | Max projected differential p | Degree lower bound |\n")
  text.add("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n")
  i = 0
  while i < Results.len:
    text.add(row(Results[i]))
    i = i + 1
  text.add("\nBounds: " & $deterministicTrials & " bases per plaintext bit, " &
    $relatedKeyTrials & " bases per key bit, " & $symmetryTrials &
    " samples per symmetry, " & $linearMasks & " masks x " &
    $linearSamples & " samples, derivatives through order " &
    $algebraicDegreeTarget & ", and " & $differentialTrailInputs &
    " projected differences x " & $differentialTrailSamples & " bases.\n")
  text.add("\n## Exact construction arguments\n\n")
  text.add("- The Gimli column box is triangular from low to high bit because every nonlinear dependency is left-shifted. The inverse recurrence reconstructs `x`, then `y`, then `z` for each bit position; 32 fixed iterations recover the complete words.\n")
  text.add("- Rotations, lane exchanges, XOR constants, the one-bit Cascade twist, and chunk exchanges are individually bijective. Their round composition is therefore bijective, and reverse order with inverse rotations gives the implemented inverse.\n")
  text.add("- `E_K(X) = K xor P(X xor K)` is inverted exactly by `K xor P^-1(C xor K)`.\n")
  text.add("- Full GF(2) ranks above rule out every nonzero linear or affine parity invariant, since an invariant mask would need to be orthogonal to a full basis.\n")
  text.add("- The tagged derivation prefix is injectively length-encoded across version, purpose, source width, target width, output length, tag, and context. Distinct domains therefore become distinct SHAKE256 inputs; output separation then relies on SHAKE256's standard XOF security assumption.\n")
  text.add("\nThese arguments do not prove resistance to arbitrary nonlinear differential, integral, interpolation, or future cryptanalytic attacks.\n")
  createDir("build")
  writeFile("build/nugimli_advanced.md", text)
  stdout.write(text)

when isMainModule:
  runAdvancedEvaluation()
