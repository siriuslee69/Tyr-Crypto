## ------------------------------------------------------------------------
## NuGimli Reduced-Round Evaluation <- security margin per width and variant
## ------------------------------------------------------------------------
##
##   nimble evaluate_nugimli_rounds              all widths, all lane-mix variants
##   nimble evaluate_nugimli_rounds -- --shipped  only the shipped design (faster)
##
##   ┌────────────┐   ┌──────────────────┐   ┌───────────────┐
##   │ round_model│──>│ reduced_rounds   │──>│ this file:    │──> build/nugimli_rounds.md
##   │ (== src/)  │   │ trails           │   │ table + notes │
##   └────────────┘   └──────────────────┘   └───────────────┘
##
## One thread per (width, variant). Each fills one row. The model is
## pinned to src/ by evaluation/tests/test_nugimli_model.nim; run that
## first after any change to the round function.

import std/[os, strutils, strformat, math]
import runePragmas
import ../nugimli_analysis/primitives
import ../nugimli_analysis/round_model
import ../nugimli_analysis/reduced_rounds
import ../nugimli_analysis/trails

const
  trailShown = [4, 6, 8]
  checkSamples = 1 shl 18

type
  RoundsEvidence = object
    bits, rounds: int
    mix: LaneMix
    fwd, bwd: ReachSummary
    zeroSumFwd, zeroSumBwd: array[2, int]   ## cube sizes 8 and 12
    symmetry: array[3, int]
    trail: array[9, float]                  ## greedy weight for 1..8 rounds
    trailPast: int                          ## first round count with weight >= block bits
    checks: array[2, TrailCheck]            ## 2- and 3-round trails on real pairs

  Job = object
    mix: LaneMix
    row: RoundsEvidence

proc trailPast(T: seq[float], bits: int): int {.role: {parser}.} =
  ## T/bits: greedy weights and block size. First round count past the block.
  var
    k: int = 1
  result = T.len
  while k < T.len and result == T.len:
    if T[k] >= float(bits): result = k
    k = k + 1

proc analyzeWidth[N: static[int]](J: ptr Job) {.role: {orchestrator}.} =
  ## J: job slot. Runs every measurement for one width and variant.
  var
    T: seq[float] = greedyTrails[N](J.mix)
    k: int = 1
  J.row.bits = N * 32
  J.row.rounds = fullRounds[N]()
  J.row.mix = J.mix
  J.row.fwd = reachSummary[N](false, J.mix)
  J.row.bwd = reachSummary[N](true, J.mix)
  J.row.zeroSumFwd = [zeroSumWorst[N](8, false, J.mix), zeroSumWorst[N](12, false, J.mix)]
  J.row.zeroSumBwd = [zeroSumWorst[N](8, true, J.mix), zeroSumWorst[N](12, true, J.mix)]
  J.row.symmetry = [symmetryRounds[N](0, J.mix), symmetryRounds[N](1, J.mix),
    symmetryRounds[N](2, J.mix)]
  while k <= 8:
    J.row.trail[k] = T[k]
    k = k + 1
  J.row.trailPast = trailPast(T, N * 32)
  J.row.checks = [trailCheck[N](2, checkSamples, J.mix),
    trailCheck[N](3, checkSamples, J.mix)]

proc analyze512(J: ptr Job) {.thread, role: {orchestrator}.} = analyzeWidth[16](J)
proc analyze1024(J: ptr Job) {.thread, role: {orchestrator}.} = analyzeWidth[32](J)
proc analyze2048(J: ptr Job) {.thread, role: {orchestrator}.} = analyzeWidth[64](J)

proc capped(k, cap: int): string {.role: {parser}.} =
  ## k/cap: measured rounds and the window length; past the window prints ">cap".
  if k > cap: result = ">" & $cap
  else: result = $k

proc reachCell(R: ReachSummary): string {.role: {parser}.} =
  ## R: own-start and worst full diffusion.
  result = capped(R.own.full, diffusionMaxRounds) & " / " &
    capped(R.worst.full, diffusionMaxRounds)

proc marginCell(E: RoundsEvidence): string {.role: {parser}.} =
  ## E: one row. Worst forward + worst backward diffusion against the rounds.
  var
    used: int = E.fwd.worst.full + E.bwd.worst.full
  if max(E.fwd.worst.full, E.bwd.worst.full) > diffusionMaxRounds:
    result = "not reached"
  else:
    result = &"{used}/{E.rounds} ({round(100.0 * float(used) / float(E.rounds)).int} %)"

proc weightText(w: float, bits: int): string {.role: {parser}.} =
  ## w/bits: trail weight and block size. The search stops once a trail
  ## costs more than the block, so an unset weight means "above the block".
  if w == Inf: result = ">" & $bits
  else: result = $int(round(w))

proc trailCell(E: RoundsEvidence): string {.role: {parser}.} =
  ## E: one row. Greedy weights at the shown round counts.
  var
    i: int = 0
  while i < trailShown.len:
    if i > 0: result.add(" / ")
    result.add(weightText(E.trail[trailShown[i]], E.bits))
    i = i + 1

proc row(E: RoundsEvidence): string {.role: {dataWriter}.} =
  ## E: one width and variant as a markdown table row.
  result = &"| {E.bits} | {E.mix} | {E.rounds} | {reachCell(E.fwd)} | {reachCell(E.bwd)} | " &
    &"{marginCell(E)} | {E.fwd.worst.lanes} / {E.bwd.worst.lanes} | " &
    &"{capped(E.zeroSumFwd[0], zeroSumMaxRounds)}, {capped(E.zeroSumFwd[1], zeroSumMaxRounds)} / " &
    &"{capped(E.zeroSumBwd[0], zeroSumMaxRounds)}, {capped(E.zeroSumBwd[1], zeroSumMaxRounds)} | " &
    &"{E.symmetry[0]} / {E.symmetry[1]} / {E.symmetry[2]} | {trailCell(E)} | {E.trailPast} |\n"

proc checkLine(E: RoundsEvidence): string {.role: {dataWriter}.} =
  ## E: one row. Trail model against real pairs.
  result = &"- {E.bits} {E.mix}: 2 rounds predicted {E.checks[0].predicted:.2f}, " &
    &"measured {E.checks[0].measured:.2f}; 3 rounds predicted " &
    &"{E.checks[1].predicted:.2f}, measured {E.checks[1].measured:.2f}\n"

proc gimliLine(): string {.role: {dataWriter}.} =
  ## The greedy search on original Gimli, for calibration.
  var
    G: seq[float] = gimliGreedyTrails()
    k: int = 1
  result = "- Gimli-384, same greedy search, rounds 1..8:"
  while k <= 8:
    result.add(" " & weightText(G[k], 384))
    k = k + 1
  result.add(". Published best 8-round trail: about 52. Greedy overestimates about 3x.\n")

proc startJobs(J: var seq[Job], T: var seq[Thread[ptr Job]], mixes: seq[LaneMix])
    {.role: {orchestrator}.} =
  ## J/T: job slots and threads, 3 per variant (512, 1024, 2048).
  var
    i: int = 0
  J.setLen(mixes.len * 3)
  T.setLen(mixes.len * 3)
  while i < J.len:
    J[i].mix = mixes[i div 3]
    case i mod 3
    of 0: createThread(T[i], analyze512, addr J[i])
    of 1: createThread(T[i], analyze1024, addr J[i])
    else: createThread(T[i], analyze2048, addr J[i])
    i = i + 1

proc runRoundsEvaluation*(shippedOnly: bool) {.role: {metaOrchestrator}.} =
  ## shippedOnly: measure lmEvenChunks (the shipped design) only.
  var
    J: seq[Job] = @[]
    T: seq[Thread[ptr Job]] = @[]
    text: string = ""
    i: int = 0
    mixes: seq[LaneMix] = @[lmEvenChunks]
  if not shippedOnly: mixes = @[lmEvenChunks, lmOneChunk, lmAllChunks]
  startJobs(J, T, mixes)
  joinThreads(T)
  text.add("# NuGimli Cascade reduced-round evidence\n\n")
  text.add("Rounds each property survives. Fewer is better; the gap to the full round count is the margin.\n\n")
  text.add("| Bits | Lane mix | Rounds | Full diffusion fwd (own / worst) | bwd (own / worst) | fwd+bwd worst | Lane reach fwd / bwd | Zero-sum fwd d=8, 12 / bwd d=8, 12 | Symmetry gone (3 kinds) | Greedy trail weight 4 / 6 / 8 rounds | Trail weight > block after |\n")
  text.add("|---:|---|---:|---|---|---|---|---|---|---|---:|\n")
  while i < J.len:
    text.add(row(J[i].row))
    i = i + 1
  text.add("\nLane mix (which chunks get the lane swap on even rounds):\n\n")
  text.add("- every even chunk (shipped since 2026-10-11): chunks 0, 2, 4 ... Half the state changes lanes; odd chunks keep theirs, so lanes really meet.\n")
  text.add("- one chunk (first design): chunk (5r) mod C. Only 1/C of the state can change lanes per swap round; wide states mixed slowly.\n")
  text.add("- every chunk: control. A swap applied the same way to every chunk only renames the columns: boxes, twist and butterfly all work column by column, so no bit ever meets another lane. Never use this.\n")
  text.add("\n## Trail model on real pairs\n\n")
  i = 0
  while i < J.len:
    text.add(checkLine(J[i].row))
    i = i + 1
  text.add(gimliLine())
  text.add(&"\nSampling: {diffusionInputs} input bits x {diffusionSamples} pairs per window, windows of {diffusionMaxRounds} rounds at every start; " &
    &"zero-sums over 6 bit sets x {zeroSumBases} random bases at the own start; symmetry over {symmetrySamples} starts; " &
    &"trail checks over {checkSamples} pairs. \">n\" = not reached within the measured window.\n")
  createDir("build")
  writeFile("build/nugimli_rounds.md", text)
  stdout.write(text)

when isMainModule:
  runRoundsEvaluation("--shipped" in commandLineParams())
