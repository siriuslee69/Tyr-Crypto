## -------------------------------------------------------------
## NuGimli Analysis Report <- deterministic Markdown rendering
## -------------------------------------------------------------

import std/strutils
import tyrPragmas
import otter_repo_evaluation
import ./types
import ./security

proc decimal(x: float64, places: int = 4): string {.inline, role: {helper}.} =
  ## x: value to format. places: decimal digits.
  result = formatFloat(x, ffDecimal, places)

proc percent(x: float64): string {.inline, role: {helper}.} =
  ## x: ratio formatted as a percentage.
  result = decimal(x * 100.0, 2) & "%"

proc profileVerdict(R: ProfileResult): string {.role: {truthBuilder}.} =
  ## R: measured profile result classified by structural checks first.
  var
    words: int = R.bits div 32
  if R.components.count > 1 or R.plaintext.minChangedWords < words or
      R.key.minChangedWords < words:
    return "STRUCTURAL FAILURE"
  if R.plaintext.meanRatio < 0.45 or R.plaintext.meanRatio > 0.55 or
      R.key.meanRatio < 0.45 or R.key.meanRatio > 0.55:
    return "DIFFUSION CONCERN"
  if R.plaintext.maxOutputBias > 0.10 or R.key.maxOutputBias > 0.10:
    return "BIT-BIAS CONCERN"
  result = "no sampled structural failure"

proc failureList(R: StatisticalResult): string {.role: {helper}.} =
  ## R: statistical result whose failed names are joined.
  if R.failedNames.len == 0:
    result = "none"
  else:
    result = R.failedNames.join(", ")

proc weakDifferenceText(R: WeakPathResult): string {.role: {helper}.} =
  ## R: weak path rendered only when its output difference is deterministic.
  if R.distinctDifferences == 1:
    result = R.firstDifference
  else:
    result = "variable"

proc diffusionText(P: openArray[DiffusionPoint]): string {.role: {helper}.} =
  ## P: reduced-round diffusion points.
  var
    L: seq[string] = @[]
    i: int = 0
  i = 0
  while i < P.len:
    L.add($P[i].rounds & "r=" & percent(P[i].meanRatio) & "/" &
      $P[i].minChangedWords & "w")
    i = i + 1
  result = L.join("; ")

proc appendSecurityTable(s: var string, R: openArray[ProfileResult])
    {.role: {dataWriter}.} =
  ## s: report destination. R: profile results.
  var
    i: int = 0
  s.add("## Full-round findings\n\n")
  s.add("| Profile | Verdict | Components | Plain mean | Plain bias | Plain min words | Key mean | Key bias | Key min words | Differential mean/p | NIST-style |\n")
  s.add("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n")
  i = 0
  while i < R.len:
    s.add("| " & R[i].name & " | " & profileVerdict(R[i]) & " | " &
      $R[i].components.count & " | " &
      percent(R[i].plaintext.meanRatio) & " | " &
      percent(R[i].plaintext.maxOutputBias) & " | " &
      $R[i].plaintext.minChangedWords & "/" & $(R[i].bits div 32) & " | " &
      percent(R[i].key.meanRatio) & " | " &
      percent(R[i].key.maxOutputBias) & " | " &
      $R[i].key.minChangedWords & "/" & $(R[i].bits div 32) & " | " &
      percent(R[i].differential.meanRatio) & "/" &
      decimal(R[i].differential.pValue, 6) & " | " &
      $R[i].statistical.passed & "/" & $R[i].statistical.total & " |\n")
    i = i + 1
  s.add("\n")

proc appendStatisticalDetails(s: var string, R: openArray[ProfileResult])
    {.role: {dataWriter}.} =
  ## s: report destination. R: profile statistical details.
  var
    i: int = 0
  s.add("## Statistical details\n\n")
  s.add("The stream is fixed-key encryption of consecutive counter blocks. ")
  s.add("These are one-sequence diagnostics, not an official SP 800-22 campaign.\n\n")
  s.add("| Profile | Minimum p-value | Failed diagnostics |\n")
  s.add("|---|---:|---|\n")
  i = 0
  while i < R.len:
    s.add("| " & R[i].name & " | " & decimal(R[i].statistical.minPValue, 8) &
      " | " & failureList(R[i].statistical) & " |\n")
    i = i + 1
  s.add("\n")

proc appendWeakPathTable(s: var string, R: openArray[ProfileResult])
    {.role: {dataWriter}.} =
  ## s: report destination. R: exact weakest input-bit observations.
  var
    i: int = 0
  s.add("## Weak one-bit paths\n\n")
  s.add("A partial count of `4/4` means the same input bit missed at least one output word in every base state. ")
  s.add("A zero count of `4/4` means an exact ciphertext collision for that key-bit flip in every base state.\n\n")
  s.add("| Profile | Plain bit | Plain distinct/min bits/min words | Plain difference | Key bit | Key distinct/zero/min words | Key difference | Components |\n")
  s.add("|---|---:|---:|---|---:|---:|---|---:|\n")
  i = 0
  while i < R.len:
    s.add("| " & R[i].name & " | " & $R[i].plaintextWeak.inputBit & " | " &
      $R[i].plaintextWeak.distinctDifferences & "/" &
      $R[i].plaintextWeak.minDistance & "/" &
      $R[i].plaintextWeak.minChangedWords & " | " &
      weakDifferenceText(R[i].plaintextWeak) & " | " &
      $R[i].keyWeak.inputBit & " | " &
      $R[i].keyWeak.distinctDifferences & "/" &
      $R[i].keyWeak.zeroDifferences & "/" &
      $R[i].keyWeak.minChangedWords & " | " &
      weakDifferenceText(R[i].keyWeak) & " | " &
      R[i].components.sizes.join("+") & " |\n")
    i = i + 1
  s.add("\n")

proc appendDiffusionTable(s: var string, R: openArray[ProfileResult])
    {.role: {dataWriter}.} =
  ## s: report destination. R: reduced-round diffusion curves.
  var
    i: int = 0
  s.add("## Reduced-round diffusion\n\n")
  s.add("Each point is `mean changed bits / minimum active 32-bit words` over three input-bit positions.\n\n")
  s.add("| Profile | Curve |\n|---|---|\n")
  i = 0
  while i < R.len:
    s.add("| " & R[i].name & " | " & diffusionText(R[i].diffusion) & " |\n")
    i = i + 1
  s.add("\n")

proc appendPerformanceRows(s: var string, R: ProfileResult)
    {.role: {dataWriter}.} =
  ## s: report destination. R: one profile's timing rows.
  var
    i: int = 0
  i = 0
  while i < R.performance.len:
    s.add("| " & R.name & " | " & R.performance[i].name & " | " &
      $R.performance[i].medianNs & " | " &
      $R.performance[i].minNs & " | " &
      $R.performance[i].maxNs & " | " &
      decimal(R.performance[i].mibPerSecond, 2) & " |\n")
    i = i + 1

proc appendPerformanceTable(s: var string, R: openArray[ProfileResult],
    baseline: StableBenchResult) {.role: {dataWriter}.} =
  ## s: report destination. R: profile timings. baseline: Gimli reference.
  var
    i: int = 0
  s.add("## Performance\n\n")
  s.add("Release build, median of " & $baseline.samples & " samples. ")
  s.add("Throughput counts one complete state per operation.\n\n")
  s.add("Baseline: **" & baseline.name & "** = " & $baseline.medianNs &
    " ns, " & decimal(baseline.mibPerSecond, 2) & " MiB/s.\n\n")
  s.add("| Profile | Operation | Median ns | Min ns | Max ns | MiB/s |\n")
  s.add("|---|---|---:|---:|---:|---:|\n")
  i = 0
  while i < R.len:
    appendPerformanceRows(s, R[i])
    i = i + 1
  s.add("\n")

proc appendRootCause(s: var string) {.role: {dataWriter}.} =
  ## s: report destination receiving the algebraic structural explanation.
  s.add("## Structural root cause\n\n")
  s.add("For one exact Gimli box, set only bit 31 of input row `z`: `Delta z = 0x80000000`. ")
  s.add("Every use of `z` in the `b` and `c` outputs is shifted left, so that bit is discarded modulo 32 bits. ")
  s.add("The `a` output contains unshifted `z`. Therefore `Delta z31 -> Delta a31` with probability 1, independent of `x` and `y`. ")
  s.add("Cascade's mandatory one-bit twist moves this trail away from the shift-discard boundary before the next round; the bounded full-round searches report whether a deterministic trail reappears.\n\n")
  s.add("For the keyed construction, if `P(S xor D) = P(S) xor D`, then keys `K` and `K xor D` are equivalent:\n\n")
  s.add("```text\nE_(K xor D)(X)\n= K xor D xor P(X xor K xor D)\n= K xor D xor P(X xor K) xor D\n= K xor P(X xor K)\n= E_K(X)\n```\n\n")

proc appendPerformanceInterpretation(s: var string,
    R: openArray[ProfileResult]) {.role: {dataWriter}.} =
  ## s: report destination. R: timings summarized by backend behavior.
  var
    forwardPortableWins, inverseSimdWins: int = 0
    i: int = 0
  i = 0
  while i < R.len:
    if R[i].performance.len >= 4:
      if R[i].performance[1].medianNs < R[i].performance[0].medianNs:
        forwardPortableWins = forwardPortableWins + 1
      if R[i].performance[2].medianNs < R[i].performance[3].medianNs:
        inverseSimdWins = inverseSimdWins + 1
    i = i + 1
  s.add("On this host, the portable forward box beat the explicit 128-bit SIMD box in " &
    $forwardPortableWins & "/" & $R.len & " profiles. ")
  s.add("The explicit SIMD inverse beat the portable inverse in " &
    $inverseSimdWins & "/" & $R.len & " profiles. ")
  s.add("Repeated vector load/store traffic dominates the forward schedules, especially Cascade.\n\n")

proc formatAnalysisReport*(R: openArray[ProfileResult], baseline: StableBenchResult,
    capabilities: string): string {.role: {dataWriter}.} =
  ## R: all profile outcomes. baseline/capabilities: benchmark context.
  result.add("# NuGimli empirical security evaluation\n\n")
  result.add("Generated: " & isoTimestamp() & "  \n")
  result.add("Build: " & capabilities & "\n\n")
  result.add("This report is empirical cryptanalysis, not a security proof. ")
  result.add("Passing statistical tests does not establish cipher security.\n\n")
  result.add("Parameters: " & $avalancheTrials & " avalanche base states, " &
    $differentialSamples & " fixed-difference samples, " &
    $weakPathSamples & " weak-path validation states, " &
    $(statisticalBytes * 8) & " statistical bits per profile.\n\n")
  appendSecurityTable(result, R)
  appendWeakPathTable(result, R)
  appendRootCause(result)
  appendStatisticalDetails(result, R)
  appendDiffusionTable(result, R)
  appendPerformanceTable(result, R, baseline)
  appendPerformanceInterpretation(result, R)
  result.add("## Interpretation rules\n\n")
  result.add("- `STRUCTURAL FAILURE` means at least one full-round one-bit change could not reach every output word.\n")
  result.add("- Component sizes come from an empirical word-influence graph over every input bit.\n")
  result.add("- Output-bit bias is measured over all input-bit flips and deterministic base states.\n")
  result.add("- Differential p-values use one projected 8-bit output difference and are descriptive under multiple comparisons.\n")
  result.add("- NIST-style results cover the lower-cost core diagnostics and one stream, not the official multi-sequence process.\n")
