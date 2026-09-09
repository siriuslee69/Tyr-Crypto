## ---------------------------------------------------------------------
## NuGimli Stream Report <- campaign CSV and summarized Markdown output
## ---------------------------------------------------------------------

import std/[algorithm, strutils, tables]
import std/math as stdmath
import runePragmas
import otter_repo_evaluation
import ./stream_types
import ./stream_campaign

type
  RouteAggregate = object
    count: int
    minShannon: float64
    minEntropy: float64
    maxBitBias: float64
    maxCorrelation: float64
    minimumNistPassed: int
    repeats: uint64
    collisions: uint64
    worstJob: string

  RegressionRow = object
    jobName: string
    stage: int
    widthBits: int
    firstEntropy: float64
    lastEntropy: float64
    delta: float64

proc decimal(x: float64, places: int = 6): string {.inline, role: {helper}.} =
  ## x: value to format. places: decimal digits.
  result = formatFloat(x, ffDecimal, places)

proc routeText(R: array[3, int]): string {.role: {helper}.} =
  ## R: word widths rendered as bit-width route.
  result = $(R[0] * 32) & "->" & $(R[1] * 32) & "->" & $(R[2] * 32)

proc checkpointName(C: StreamCheckpoint): string {.role: {helper}.} =
  ## C: checkpoint dimensions rendered as a stable job name.
  if C.mode == smCrossWidth:
    result = entropyName(C.source) & "/" & routeText(C.route) & "/" &
      adapterName(C.adapter) & "/" & feedName(C.feedMode)
  else:
    result = entropyName(C.source) & "/" & streamModeName(C.mode) & "/" &
      $C.widthBits

proc checkpointCsv(C: StreamCheckpoint): string {.role: {dataWriter}.} =
  ## C: one checkpoint encoded as a CSV row.
  result = checkpointName(C) & "," & entropyName(C.source) & "," &
    streamModeName(C.mode) & "," & adapterName(C.adapter) & "," &
    feedName(C.feedMode) & "," & routeText(C.route) & "," & $C.stage & "," &
    $C.widthBits & "," & $C.intervalStart & "," & $C.intervalEnd & "," &
    $C.sampledBytes & "," & decimal(C.shannonEntropy) & "," &
    decimal(C.minEntropy) & "," & decimal(C.onesRatio) & "," &
    decimal(C.serialCorrelation) & "," & decimal(C.zeroByteRatio) & "," &
    $C.consecutiveRepeats & "," & $C.fingerprintCollisions & "," &
    $C.nistPassed & "," & $C.nistTotal & "," & decimal(C.minPValue, 8) &
    "," & $C.failedTestMask

proc formatStreamCsv*(R: StreamCampaignResult): string {.role: {dataWriter}.} =
  ## R: campaign whose complete checkpoint matrix is encoded as CSV.
  var
    i: int = 0
  result.add("job,source,mode,adapter,feed,route,stage,width_bits,interval_start,interval_end,sampled_bytes,shannon,min_entropy,ones_ratio,serial_correlation,zero_byte_ratio,consecutive_repeats,fingerprint_collisions,nist_passed,nist_total,min_p,failed_tests\n")
  i = 0
  while i < R.checkpoints.len:
    result.add(checkpointCsv(R.checkpoints[i]) & "\n")
    i = i + 1

proc isFinalCheckpoint(C: StreamCheckpoint, R: StreamCampaignResult): bool
    {.inline, role: {parser}.} =
  ## C/R: checkpoint and campaign dimensions used to identify final windows.
  if C.mode == smCrossWidth:
    result = C.stage == 2 and C.intervalEnd == R.routeBlocks
  else:
    result = C.intervalEnd == R.baseBlocks

proc directRow(s: var string, C: StreamCheckpoint) {.role: {dataWriter}.} =
  ## s: report destination. C: final direct stream checkpoint.
  var
    bias: float64 = abs(C.onesRatio - 0.5)
  s.add("| " & entropyName(C.source) & " | " & streamModeName(C.mode) & " | " &
    $C.widthBits & " | " & decimal(C.shannonEntropy, 4) & " | " &
    decimal(C.minEntropy, 4) & " | " & decimal(bias, 6) & " | " &
    decimal(C.serialCorrelation, 6) & " | " & $C.consecutiveRepeats & " | " &
    $C.fingerprintCollisions & " | " & $C.nistPassed & "/" & $C.nistTotal & " |\n")

proc appendDirectTable(s: var string, R: StreamCampaignResult)
    {.role: {dataWriter}.} =
  ## s: report destination. R: campaign containing direct stream rows.
  var
    i: int = 0
  s.add("## Direct stream final windows\n\n")
  s.add("| Entropy source | Mode | Width | Shannon | Min entropy | Bit bias | Lag-1 corr | Repeats | Hash collisions | Core tests |\n")
  s.add("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|\n")
  i = 0
  while i < R.checkpoints.len:
    if R.checkpoints[i].mode != smCrossWidth and
        isFinalCheckpoint(R.checkpoints[i], R):
      directRow(s, R.checkpoints[i])
    i = i + 1
  s.add("\n")

proc routeGroupKey(C: StreamCheckpoint): string {.role: {helper}.} =
  ## C: route checkpoint grouped by source, adapter, and feed behavior.
  result = entropyName(C.source) & "/" & adapterName(C.adapter) & "/" &
    feedName(C.feedMode)

proc updateAggregate(A: var RouteAggregate, C: StreamCheckpoint)
    {.role: {truthBuilder}.} =
  ## A: route aggregate. C: final route checkpoint.
  var
    bias, correlation: float64 = 0.0
  bias = abs(C.onesRatio - 0.5)
  correlation = abs(C.serialCorrelation)
  if A.count == 0 or C.shannonEntropy < A.minShannon:
    A.minShannon = C.shannonEntropy
    A.worstJob = checkpointName(C)
  if A.count == 0 or C.minEntropy < A.minEntropy:
    A.minEntropy = C.minEntropy
  if C.nistTotal > 0 and (A.count == 0 or C.nistPassed < A.minimumNistPassed):
    A.minimumNistPassed = C.nistPassed
  A.maxBitBias = max(A.maxBitBias, bias)
  A.maxCorrelation = max(A.maxCorrelation, correlation)
  A.repeats = A.repeats + C.consecutiveRepeats
  A.collisions = A.collisions + C.fingerprintCollisions
  A.count = A.count + 1

proc routeAggregates(R: StreamCampaignResult): Table[string, RouteAggregate]
    {.role: {truthBuilder}.} =
  ## R: campaign reduced to final route group summaries.
  var
    i: int = 0
    key: string = ""
    A: RouteAggregate
  i = 0
  while i < R.checkpoints.len:
    if R.checkpoints[i].mode == smCrossWidth and
        isFinalCheckpoint(R.checkpoints[i], R):
      key = routeGroupKey(R.checkpoints[i])
      A = result.getOrDefault(key)
      updateAggregate(A, R.checkpoints[i])
      result[key] = A
    i = i + 1

proc appendRouteTable(s: var string, R: StreamCampaignResult)
    {.role: {dataWriter}.} =
  ## s: report destination. R: campaign summarized by route dimensions.
  var
    T: Table[string, RouteAggregate] = routeAggregates(R)
    K: seq[string] = @[]
    i: int = 0
    A: RouteAggregate
  for key in T.keys:
    K.add(key)
  K.sort()
  s.add("## Cross-width final-window aggregates\n\n")
  s.add("Each row summarizes all 27 three-width routes for one source/adapter/key-feed combination.\n\n")
  s.add("| Source / adapter / feed | Routes | Worst Shannon | Worst min entropy | Max bit bias | Max correlation | Repeats | Hash collisions | Minimum core pass | Worst route |\n")
  s.add("|---|---:|---:|---:|---:|---:|---:|---:|---:|---|\n")
  i = 0
  while i < K.len:
    A = T[K[i]]
    s.add("| " & K[i] & " | " & $A.count & " | " & decimal(A.minShannon, 4) &
      " | " & decimal(A.minEntropy, 4) & " | " & decimal(A.maxBitBias, 6) &
      " | " & decimal(A.maxCorrelation, 6) & " | " & $A.repeats & " | " &
      $A.collisions & " | " & $A.minimumNistPassed & "/11 | " & A.worstJob & " |\n")
    i = i + 1
  s.add("\n")

proc addFailureMask(F: var array[11, int], mask: uint32)
    {.inline, role: {truthBuilder}.} =
  ## F: per-test failure counts. mask: one final window's failed tests.
  var
    bit: int = 0
  bit = 0
  while bit < F.len:
    if (mask and (1'u32 shl bit)) != 0'u32:
      F[bit] = F[bit] + 1
    bit = bit + 1

proc appendNistCampaignTable(s: var string, R: StreamCampaignResult)
    {.role: {dataWriter}.} =
  ## s: report destination. R: final-window failures aggregated per test.
  const
    names: array[11, string] = [
      "monobit", "block frequency", "runs", "longest run", "matrix rank",
      "spectral", "approximate entropy", "serial 1", "serial 2",
      "cumulative sums forward", "cumulative sums reverse"
    ]
  var
    Failures: array[11, int]
    i, bit, jobs: int = 0
    rate: float64 = 0.0
    status: string = ""
    P: ProportionResult
  i = 0
  while i < R.checkpoints.len:
    if R.checkpoints[i].nistTotal == 11:
      jobs = jobs + 1
      addFailureMask(Failures, R.checkpoints[i].failedTestMask)
    i = i + 1
  s.add("## Campaign-wide core statistical proportions\n\n")
  s.add("Individual p-values use alpha 0.01. The status compares each test's failure proportion with the three-sigma interval expected across " & $jobs & " final windows.\n\n")
  s.add("| Test | Failures | Failure rate | Expected interval | Status |\n")
  s.add("|---|---:|---:|---:|---|\n")
  bit = 0
  while bit < Failures.len:
    rate = float64(Failures[bit]) / float64(jobs)
    P = evaluateFailureProportion(names[bit], Failures[bit], jobs)
    status = if P.passed: "within expectation" else: "outside expectation"
    s.add("| " & names[bit] & " | " & $Failures[bit] & "/" & $jobs & " | " &
      decimal(rate, 6) & " | " & decimal(P.lower, 6) & ".." &
      decimal(P.upper, 6) & " | " & status & " |\n")
    bit = bit + 1
  s.add("\n")

proc regressionKey(C: StreamCheckpoint): string {.role: {helper}.} =
  ## C: checkpoint keyed by job and stage.
  result = checkpointName(C) & "#" & $C.stage

proc correctedEntropy(C: StreamCheckpoint): float64 {.role: {math}.} =
  ## C: checkpoint Shannon estimate with first-order finite-sample correction.
  result = C.shannonEntropy
  if C.sampledBytes > 0'u64:
    result = result + 255.0 /
      (2.0 * float64(C.sampledBytes) * stdmath.ln(2.0))

proc appendMatureWindowSummary(s: var string, R: StreamCampaignResult)
    {.role: {dataWriter}.} =
  ## s: report destination. R: all sufficiently large intermediate windows.
  var
    i, rows: int = 0
    minShannon, minEntropy: float64 = 9.0
    maxBias, maxCorrelation: float64 = 0.0
    repeats, collisions: uint64 = 0'u64
  i = 0
  while i < R.checkpoints.len:
    if R.checkpoints[i].sampledBytes >= 100_000'u64:
      rows = rows + 1
      minShannon = min(minShannon, correctedEntropy(R.checkpoints[i]))
      minEntropy = min(minEntropy, R.checkpoints[i].minEntropy)
      maxBias = max(maxBias, abs(R.checkpoints[i].onesRatio - 0.5))
      maxCorrelation = max(maxCorrelation,
        abs(R.checkpoints[i].serialCorrelation))
      repeats = repeats + R.checkpoints[i].consecutiveRepeats
      collisions = collisions + R.checkpoints[i].fingerprintCollisions
    i = i + 1
  s.add("## All mature intermediate windows\n\n")
  s.add("Across " & $rows & " stage/checkpoint windows with at least 100000 sampled bytes:\n\n")
  s.add("- Minimum corrected Shannon entropy: `" & decimal(minShannon, 6) & "` bits per byte.\n")
  s.add("- Minimum empirical min-entropy: `" & decimal(minEntropy, 6) & "` bits per byte.\n")
  s.add("- Maximum bit bias: `" & decimal(maxBias, 6) & "`.\n")
  s.add("- Maximum absolute lag-one correlation: `" & decimal(maxCorrelation, 6) & "`.\n")
  s.add("- Consecutive repeats: `" & $repeats & "`; sampled fingerprint collisions: `" & $collisions & "`.\n\n")

proc buildRegressions(R: StreamCampaignResult): seq[RegressionRow]
    {.role: {truthBuilder}.} =
  ## R: campaign reduced to first-versus-last entropy deltas.
  var
    First, Last: Table[string, StreamCheckpoint]
    i: int = 0
    key: string = ""
    C0, C1: StreamCheckpoint
    row: RegressionRow
  i = 0
  while i < R.checkpoints.len:
    if R.checkpoints[i].sampledBytes >= 100_000'u64:
      key = regressionKey(R.checkpoints[i])
      if key notin First:
        First[key] = R.checkpoints[i]
      Last[key] = R.checkpoints[i]
    i = i + 1
  for itemKey, firstValue in First.pairs:
    C0 = firstValue
    C1 = Last[itemKey]
    row.jobName = checkpointName(C0)
    row.stage = C0.stage
    row.widthBits = C0.widthBits
    row.firstEntropy = correctedEntropy(C0)
    row.lastEntropy = correctedEntropy(C1)
    row.delta = row.lastEntropy - row.firstEntropy
    result.add(row)
  result.sort(proc(a, b: RegressionRow): int = cmp(a.delta, b.delta))

proc appendRegressionTable(s: var string, R: StreamCampaignResult)
    {.role: {dataWriter}.} =
  ## s: report destination. R: campaign whose worst entropy deltas are shown.
  var
    Rows: seq[RegressionRow] = buildRegressions(R)
    i, limit: int = 0
  limit = min(30, Rows.len)
  s.add("## Worst observed entropy changes over time\n\n")
  s.add("Only intervals with at least 100000 sampled bytes are compared. Shannon values use a first-order finite-sample correction; negative values indicate regression.\n\n")
  s.add("| Job | Stage | Width | First Shannon | Last Shannon | Delta |\n")
  s.add("|---|---:|---:|---:|---:|---:|\n")
  i = 0
  while i < limit:
    s.add("| " & Rows[i].jobName & " | " & $Rows[i].stage & " | " &
      $Rows[i].widthBits & " | " & decimal(Rows[i].firstEntropy, 5) & " | " &
      decimal(Rows[i].lastEntropy, 5) & " | " & decimal(Rows[i].delta, 6) & " |\n")
    i = i + 1
  s.add("\n")

proc problematic(C: StreamCheckpoint, R: StreamCampaignResult): bool
    {.inline, role: {parser}.} =
  ## C/R: final checkpoint classified by conservative engineering thresholds.
  if not isFinalCheckpoint(C, R):
    return false
  result = C.shannonEntropy < 7.90 or C.minEntropy < 7.0 or
    abs(C.onesRatio - 0.5) > 0.01 or abs(C.serialCorrelation) > 0.02 or
    C.consecutiveRepeats > 0'u64 or C.fingerprintCollisions > 0'u64

proc appendProblems(s: var string, R: StreamCampaignResult)
    {.role: {dataWriter}.} =
  ## s: report destination. R: campaign whose threshold failures are listed.
  var
    i, count: int = 0
  s.add("## Threshold findings\n\n")
  i = 0
  while i < R.checkpoints.len:
    if problematic(R.checkpoints[i], R):
      count = count + 1
      if count <= 100:
        s.add("- `" & checkpointName(R.checkpoints[i]) & "`: H=" &
          decimal(R.checkpoints[i].shannonEntropy, 4) & ", Hmin=" &
          decimal(R.checkpoints[i].minEntropy, 4) & ", bias=" &
          decimal(abs(R.checkpoints[i].onesRatio - 0.5), 6) & ", corr=" &
          decimal(R.checkpoints[i].serialCorrelation, 6) & ", tests=" &
          $R.checkpoints[i].nistPassed & "/" & $R.checkpoints[i].nistTotal & "\n")
    i = i + 1
  if count == 0:
    s.add("No final checkpoint crossed the configured engineering thresholds.\n")
  if count > 100:
    s.add("\nOnly the first 100 of " & $count & " findings are shown; use the CSV for all rows.\n")
  s.add("\n")

proc formatStreamReport*(R: StreamCampaignResult): string {.role: {dataWriter}.} =
  ## R: completed stream campaign rendered as a concise Markdown report.
  result.add("# NuGimli Cascade stream and cross-width campaign\n\n")
  result.add("Threads: " & $R.threads & "  \n")
  result.add("Direct blocks per job: " & $R.baseBlocks & "  \n")
  result.add("Blocks per cross-width stage: " & $R.routeBlocks & "  \n")
  result.add("Elapsed: " & decimal(R.elapsedSeconds, 2) & " seconds  \n")
  result.add("Checkpoint rows: " & $R.checkpoints.len & "\n\n")
  result.add("The campaign covers zero, PIN/password, weak PRNG, deterministic SplitMix, and Tyr OS-cryptorandom initialization. ")
  result.add("All 27 width triples are tested with zero-pad/truncate, repetition, and XOR-fold/domain adapters, using independent and output-coupled target keys.\n\n")
  appendDirectTable(result, R)
  appendRouteTable(result, R)
  appendNistCampaignTable(result, R)
  appendMatureWindowSummary(result, R)
  appendRegressionTable(result, R)
  appendProblems(result, R)
  result.add("## Interpretation\n\n")
  result.add("- Shannon and min entropy are empirical byte-distribution estimates, not entropy proofs.\n")
  result.add("- Adapter rows are intentionally separate because repetition and zero-extension can inject structure before the next Cascade stage.\n")
  result.add("- Core statistical results use the final 8192 sampled bytes with a capped spectral transform.\n")
  result.add("- Fingerprint collisions cover the first 100000 blocks of each reported interval.\n")
  result.add("\n## Security caveats\n\n")
  result.add("- Uniform ciphertext does not add guessing resistance to a zero, PIN, password, or predictable key. Password material still requires a memory-hard KDF.\n")
  result.add("- Expanding a 512-bit source into a 1024- or 2048-bit state cannot create additional source entropy, regardless of output statistics.\n")
  result.add("- Truncation discards source entropy; repetition and zero-extension add deterministic structure. A domain-separated KDF or XOF is required for real width conversion.\n")
  result.add("- Coupled-key routes deliberately set the target key equal to its initial state. Then `E_K(K) = K xor P(0)`, so this mode is algebraically unsafe even when later stream windows look random.\n")
