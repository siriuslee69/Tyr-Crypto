## ----------------------------------------------------------------------
## NuGimli Stream Campaign <- cross-width generation on fixed worker set
## ----------------------------------------------------------------------

import std/[bitops, monotimes, random]
import metaPragmas
import ../../src/tyr/helpers/random as tyrRandom
import ./primitives
import ./stream_types
import ./stream_metrics

const
  streamWidths: array[3, int] = [16, 32, 64]
  defaultBaseBlocks* = 10_000_000'u64
  defaultRouteBlocks* = 1_000_000'u64

proc entropyName*(s: EntropySource): string {.role: {parser}.} =
  ## s: entropy source identifier.
  case s
  of esZero:
    result = "zero"
  of esPin0000:
    result = "pin-0000"
  of esPassword:
    result = "password"
  of esWeakRandom:
    result = "weak-std-random"
  of esSplitMix:
    result = "splitmix"
  of esCryptoRandom:
    result = "os-cryptorandom"

proc streamModeName*(m: StreamMode): string {.role: {parser}.} =
  ## m: stream mode identifier.
  case m
  of smCounter:
    result = "counter"
  of smFeedback:
    result = "feedback"
  of smCrossWidth:
    result = "cross-width"

proc adapterName*(a: AdapterMode): string {.role: {parser}.} =
  ## a: cross-width adapter identifier.
  case a
  of amZeroPadTruncate:
    result = "zero-pad-truncate"
  of amRepeat:
    result = "repeat"
  of amXorFoldDomain:
    result = "xor-fold-domain"

proc feedName*(f: FeedMode): string {.role: {parser}.} =
  ## f: target-key feed identifier.
  case f
  of fmIndependentKey:
    result = "independent-key"
  of fmCoupledKey:
    result = "coupled-key"

proc fillRepeated(M: var array[256, uint8], text: string)
    {.role: {helper}.} =
  ## M: entropy material. text: repeated byte source.
  var
    i: int = 0
  i = 0
  while i < M.len:
    M[i] = uint8(ord(text[i mod text.len]))
    i = i + 1

proc fillWeakRandom(M: var array[256, uint8], id: int) {.role: {helper}.} =
  ## M: entropy material. id: deterministic insecure PRNG seed domain.
  var
    R: Rand = initRand(0x13900 + id * 7919)
    i: int = 0
  i = 0
  while i < M.len:
    M[i] = uint8(rand(R, 255))
    i = i + 1

proc fillSplitMix(M: var array[256, uint8], id: int) {.role: {helper}.} =
  ## M: entropy material. id: deterministic SplitMix seed domain.
  var
    seed: uint64 = 0x73747265616d0001'u64 xor uint64(id)
    i: int = 0
    z: uint64 = 0'u64
  i = 0
  while i < M.len:
    z = nextSplitMix(seed)
    M[i] = uint8(z)
    i = i + 1

proc fillCryptoRandom(M: var array[256, uint8]) {.role: {dataFetcher}.} =
  ## M: entropy material populated by Tyr's mixed OS CSPRNG.
  var
    B: seq[uint8] = tyrRandom.cryptoRandomBytes(M.len)
    i: int = 0
  i = 0
  while i < M.len:
    M[i] = B[i]
    i = i + 1

proc fillMaterial(M: var array[256, uint8], s: EntropySource,
    id: int) {.role: {dataFetcher}.} =
  ## M: job entropy material. s/id: source and unique job domain.
  case s
  of esZero:
    discard
  of esPin0000:
    fillRepeated(M, "0000")
  of esPassword:
    fillRepeated(M, "correct horse battery staple")
  of esWeakRandom:
    fillWeakRandom(M, id)
  of esSplitMix:
    fillSplitMix(M, id)
  of esCryptoRandom:
    fillCryptoRandom(M)

proc materialWord(M: array[256, uint8], offset, wordIndex: int): uint32
    {.inline, role: {parser}.} =
  ## M: source material. offset/wordIndex: cyclic little-endian word location.
  var
    i, index: int = 0
  i = 0
  while i < 4:
    index = (offset + wordIndex * 4 + i) mod M.len
    result = result or (uint32(M[index]) shl (i * 8))
    i = i + 1

proc wideFromMaterial(M: array[256, uint8], wordCount,
    offset: int): WideState {.role: {truthBuilder}.} =
  ## M: source bytes. wordCount/offset: target width and source offset.
  var
    i: int = 0
  result.wordCount = wordCount
  i = 0
  while i < wordCount:
    result.words[i] = materialWord(M, offset, i)
    i = i + 1

proc adaptZeroPad(S: WideState, targetWords: int): WideState
    {.role: {truthBuilder}.} =
  ## S: source state. targetWords: truncation or zero-extension width.
  var
    i: int = 0
  result.wordCount = targetWords
  i = 0
  while i < min(S.wordCount, targetWords):
    result.words[i] = S.words[i]
    i = i + 1

proc adaptRepeat(S: WideState, targetWords: int): WideState
    {.role: {truthBuilder}.} =
  ## S: source state. targetWords: repeated/truncated target width.
  var
    i: int = 0
  result.wordCount = targetWords
  i = 0
  while i < targetWords:
    result.words[i] = S.words[i mod S.wordCount]
    i = i + 1

proc foldSourceWord(S: WideState, T: var WideState, i: int)
    {.inline, role: {math}.} =
  ## S/T: source and folded target. i: source word index.
  var
    target, rotation: int = 0
  target = i mod T.wordCount
  rotation = (i div T.wordCount + i * 7) mod 31 + 1
  T.words[target] = T.words[target] xor rotateLeftBits(S.words[i], rotation)

proc expandFoldedWord(S: WideState, T: var WideState, i: int,
    domain: uint32) {.inline, role: {math}.} =
  ## S/T: source and target. i/domain: expansion word and route separator.
  var
    rotation: int = 0
  rotation = (i * 11) mod 31 + 1
  T.words[i] = T.words[i] xor rotateLeftBits(S.words[i mod S.wordCount], rotation) xor
    (domain + uint32(i) * 0x9e3779b9'u32)

proc adaptXorFold(S: WideState, targetWords: int,
    domain: uint32): WideState {.role: {truthBuilder}.} =
  ## S: source state. targetWords/domain: mixed target width and separator.
  var
    i: int = 0
  result.wordCount = targetWords
  i = 0
  while i < S.wordCount:
    foldSourceWord(S, result, i)
    i = i + 1
  i = S.wordCount
  while i < targetWords:
    expandFoldedWord(S, result, i, domain)
    i = i + 1

proc adaptState*(S: WideState, targetWords: int, a: AdapterMode,
    domain: uint32): WideState {.role: {truthBuilder}.} =
  ## S: source output. targetWords/a/domain: explicit width adapter settings.
  case a
  of amZeroPadTruncate:
    result = adaptZeroPad(S, targetWords)
  of amRepeat:
    result = adaptRepeat(S, targetWords)
  of amXorFoldDomain:
    result = adaptXorFold(S, targetWords, domain)

proc checkpointsFor(maxBlocks: uint64, route: bool): seq[uint64]
    {.role: {truthBuilder}.} =
  ## maxBlocks: stage length. route: compact or long checkpoint profile.
  const
    basePoints: array[6, uint64] = [1'u64, 16'u64, 256'u64, 4_096'u64,
      65_536'u64, 1_000_000'u64]
    routePoints: array[3, uint64] = [1'u64, 4_096'u64, 65_536'u64]
  var
    i: int = 0
  if route:
    i = 0
    while i < routePoints.len:
      if routePoints[i] < maxBlocks:
        result.add(routePoints[i])
      i = i + 1
  else:
    i = 0
    while i < basePoints.len:
      if basePoints[i] < maxBlocks:
        result.add(basePoints[i])
      i = i + 1
  result.add(maxBlocks)

proc arrayFromWide[N: static[int]](S: WideState): array[N, uint32]
    {.inline, role: {helper}.} =
  ## S: wide state copied into an exact-width Cascade state.
  var
    i: int = 0
  i = 0
  while i < N:
    result[i] = S.words[i]
    i = i + 1

proc wideFromArray[N: static[int]](S: array[N, uint32]): WideState
    {.inline, role: {helper}.} =
  ## S: exact-width Cascade state copied into a route state.
  var
    i: int = 0
  result.wordCount = N
  i = 0
  while i < N:
    result.words[i] = S[i]
    i = i + 1

proc checkpointTemplate(J: StreamJob, stage, widthBits: int,
    startBlock, endBlock: uint64): StreamCheckpoint {.role: {truthBuilder}.} =
  ## J: parent job. stage/width/range: checkpoint identity.
  result.source = J.source
  result.mode = J.mode
  result.adapter = J.adapter
  result.feedMode = J.feedMode
  result.route = J.route
  result.stage = stage
  result.widthBits = widthBits
  result.intervalStart = startBlock
  result.intervalEnd = endBlock

proc runStage[N: static[int]](J: var StreamJob, initial, keyWide: WideState,
    blocks: uint64, stage: int, finalStage: bool): WideState
    {.role: {orchestrator}.} =
  ## J: job receiving checkpoints. initial/keyWide/blocks/stage: stage settings.
  var
    X, base, K, C: array[N, uint32]
    M: StreamMetricMemory
    Points: seq[uint64] = checkpointsFor(blocks, J.mode == smCrossWidth)
    pointIndex: int = 0
    blockIndex, intervalStart: uint64 = 0'u64
    R: StreamCheckpoint
  X = arrayFromWide[N](initial)
  base = X
  K = arrayFromWide[N](keyWide)
  resetMetrics(M)
  blockIndex = 1'u64
  intervalStart = 1'u64
  while blockIndex <= blocks:
    if J.mode == smCounter:
      X = base
      X[0] = X[0] xor uint32(blockIndex - 1'u64)
      X[1] = X[1] xor uint32((blockIndex - 1'u64) shr 32)
    C = encryptFull(X, K)
    observeState(M, C, blockIndex)
    if J.mode != smCounter:
      X = C
    if pointIndex < Points.len and blockIndex == Points[pointIndex]:
      R = checkpointTemplate(J, stage, N * 32, intervalStart, blockIndex)
      snapshotMetrics(M, R, finalStage and blockIndex == blocks)
      J.results[J.resultCount] = R
      J.resultCount = J.resultCount + 1
      resetMetrics(M)
      intervalStart = blockIndex + 1'u64
      pointIndex = pointIndex + 1
    blockIndex = blockIndex + 1'u64
  result = wideFromArray(C)

proc dispatchStage(J: var StreamJob, initial, key: WideState, blocks: uint64,
    stage: int, finalStage: bool): WideState {.role: {orchestrator}.} =
  ## J: job. initial/key/blocks/stage/finalStage: width-dispatched stage settings.
  case initial.wordCount
  of 16:
    result = runStage[16](J, initial, key, blocks, stage, finalStage)
  of 32:
    result = runStage[32](J, initial, key, blocks, stage, finalStage)
  of 64:
    result = runStage[64](J, initial, key, blocks, stage, finalStage)
  else:
    raise newException(ValueError, "unsupported Cascade stream width")

proc processBaseJob(J: var StreamJob) {.role: {orchestrator}.} =
  ## J: direct counter or feedback stream job.
  var
    state, key: WideState
  state = wideFromMaterial(J.material, J.route[0], 0)
  key = wideFromMaterial(J.material, J.route[0], 73)
  discard dispatchStage(J, state, key, J.baseBlocks, 0, true)

proc stageKey(J: StreamJob, state: WideState, stage: int): WideState
    {.role: {truthBuilder}.} =
  ## J: route job. state/stage: target state and key coupling selection.
  if stage > 0 and J.feedMode == fmCoupledKey:
    return state
  result = wideFromMaterial(J.material, state.wordCount, 73 + stage * 29)

proc processRouteJob(J: var StreamJob) {.role: {orchestrator}.} =
  ## J: three-stage cross-width feedback route.
  var
    state, key, output: WideState
    stage, targetWords: int = 0
    domain: uint32 = 0'u32
  state = wideFromMaterial(J.material, J.route[0], 0)
  stage = 0
  while stage < 3:
    key = stageKey(J, state, stage)
    output = dispatchStage(J, state, key, J.routeBlocks, stage, stage == 2)
    if stage < 2:
      targetWords = J.route[stage + 1]
      domain = uint32(stage + 1) xor uint32(J.route[0] * 512 +
        J.route[1] * 32 + J.route[2])
      state = adaptState(output, targetWords, J.adapter, domain)
    stage = stage + 1

proc processJob(J: var StreamJob) {.role: {orchestrator}.} =
  ## J: campaign job dispatched by stream mode.
  if J.mode == smCrossWidth:
    processRouteJob(J)
  else:
    processBaseJob(J)

proc workerMain(W: ptr StreamWorker) {.thread, role: {orchestrator}.} =
  ## W: worker owning an isolated sequence of campaign jobs.
  var
    i: int = 0
  i = 0
  while i < W.jobs.len:
    processJob(W.jobs[i])
    i = i + 1

proc routeFromIndex(index: int): array[3, int] {.role: {parser}.} =
  ## index: base-three route number covering all 27 width triples.
  result[0] = streamWidths[index div 9]
  result[1] = streamWidths[(index div 3) mod 3]
  result[2] = streamWidths[index mod 3]

proc prepareJobResults(J: var StreamJob) {.role: {helper}.} =
  ## J: fully configured job whose plain result storage is preallocated.
  var
    count: int = 0
  if J.mode == smCrossWidth:
    count = checkpointsFor(J.routeBlocks, true).len * 3
  else:
    count = checkpointsFor(J.baseBlocks, false).len
  J.results.setLen(count)

proc addBaseWidthJobs(J: var seq[StreamJob], source: EntropySource,
    width: int, baseBlocks, routeBlocks: uint64,
    id: var int) {.role: {truthBuilder}.}

proc addRouteAdapterJobs(J: var seq[StreamJob], source: EntropySource,
    route: array[3, int], adapter: AdapterMode, baseBlocks,
    routeBlocks: uint64, id: var int) {.role: {truthBuilder}.}

proc addBaseJobs(J: var seq[StreamJob], source: EntropySource,
    baseBlocks, routeBlocks: uint64, id: var int) {.role: {truthBuilder}.} =
  ## J: destination. source/block counts/id: all direct width dimensions.
  var
    widthIndex: int = 0
  widthIndex = 0
  while widthIndex < streamWidths.len:
    addBaseWidthJobs(J, source, streamWidths[widthIndex], baseBlocks,
      routeBlocks, id)
    widthIndex = widthIndex + 1

proc addBaseWidthJobs(J: var seq[StreamJob], source: EntropySource,
    width: int, baseBlocks, routeBlocks: uint64,
    id: var int) {.role: {truthBuilder}.} =
  ## J: destination. source/width/block counts/id: two direct stream modes.
  var
    modeIndex: int = 0
    job: StreamJob
  modeIndex = 0
  while modeIndex < 2:
    job = default(StreamJob)
    job.source = source
    job.mode = StreamMode(modeIndex)
    job.route[0] = width
    job.baseBlocks = baseBlocks
    job.routeBlocks = routeBlocks
    fillMaterial(job.material, source, id)
    prepareJobResults(job)
    J.add(job)
    id = id + 1
    modeIndex = modeIndex + 1

proc addRouteVariants(J: var seq[StreamJob], source: EntropySource,
    route: array[3, int], baseBlocks, routeBlocks: uint64,
    id: var int) {.role: {truthBuilder}.} =
  ## J: destination. source/route/block counts/id: route dimensions.
  var
    adapterIndex: int = 0
  adapterIndex = 0
  while adapterIndex <= ord(AdapterMode.high):
    addRouteAdapterJobs(J, source, route, AdapterMode(adapterIndex),
      baseBlocks, routeBlocks, id)
    adapterIndex = adapterIndex + 1

proc addRouteAdapterJobs(J: var seq[StreamJob], source: EntropySource,
    route: array[3, int], adapter: AdapterMode, baseBlocks,
    routeBlocks: uint64, id: var int) {.role: {truthBuilder}.} =
  ## J: destination. source/route/adapter/block counts/id: both key feeds.
  var
    feedIndex: int = 0
    job: StreamJob
  feedIndex = 0
  while feedIndex <= ord(FeedMode.high):
    job = default(StreamJob)
    job.source = source
    job.mode = smCrossWidth
    job.adapter = adapter
    job.feedMode = FeedMode(feedIndex)
    job.route = route
    job.baseBlocks = baseBlocks
    job.routeBlocks = routeBlocks
    fillMaterial(job.material, source, id)
    prepareJobResults(job)
    J.add(job)
    id = id + 1
    feedIndex = feedIndex + 1

proc addRouteJobs(J: var seq[StreamJob], source: EntropySource,
    baseBlocks, routeBlocks: uint64, id: var int) {.role: {truthBuilder}.} =
  ## J: destination. source/block counts/id: all route job dimensions.
  var
    routeIndex: int = 0
    route: array[3, int]
  routeIndex = 0
  while routeIndex < 27:
    route = routeFromIndex(routeIndex)
    addRouteVariants(J, source, route, baseBlocks, routeBlocks, id)
    routeIndex = routeIndex + 1

proc buildStreamJobs*(baseBlocks, routeBlocks: uint64): seq[StreamJob]
    {.role: {truthBuilder}.} =
  ## baseBlocks/routeBlocks: direct and per-route-stage block counts.
  var
    sourceIndex, id: int = 0
    source: EntropySource
  sourceIndex = 0
  while sourceIndex <= ord(EntropySource.high):
    source = EntropySource(sourceIndex)
    addBaseJobs(result, source, baseBlocks, routeBlocks, id)
    addRouteJobs(result, source, baseBlocks, routeBlocks, id)
    sourceIndex = sourceIndex + 1

proc distributeJobs(J: seq[StreamJob], threadCount: int): seq[StreamWorker]
    {.role: {truthBuilder}.} =
  ## J: campaign jobs distributed round-robin over threadCount workers.
  var
    i: int = 0
  result.setLen(threadCount)
  i = 0
  while i < J.len:
    result[i mod threadCount].jobs.add(J[i])
    i = i + 1

proc collectJobResults(R: var seq[StreamCheckpoint], J: StreamJob)
    {.role: {truthBuilder}.}

proc collectWorkerResults(R: var seq[StreamCheckpoint], W: StreamWorker)
    {.role: {truthBuilder}.}

proc collectResults(W: seq[StreamWorker]): seq[StreamCheckpoint]
    {.role: {truthBuilder}.} =
  ## W: completed workers whose job checkpoints are flattened.
  var
    workerIndex: int = 0
  workerIndex = 0
  while workerIndex < W.len:
    collectWorkerResults(result, W[workerIndex])
    workerIndex = workerIndex + 1

proc collectJobResults(R: var seq[StreamCheckpoint], J: StreamJob)
    {.role: {truthBuilder}.} =
  ## R: flattened destination. J: one completed job.
  var
    i: int = 0
  i = 0
  while i < J.resultCount:
    R.add(J.results[i])
    i = i + 1

proc collectWorkerResults(R: var seq[StreamCheckpoint], W: StreamWorker)
    {.role: {truthBuilder}.} =
  ## R: flattened destination. W: one completed worker.
  var
    i: int = 0
  i = 0
  while i < W.jobs.len:
    collectJobResults(R, W.jobs[i])
    i = i + 1

proc runWorkers(W: var seq[StreamWorker]) {.role: {orchestrator}.} =
  ## W: workers launched together when thread support is enabled.
  when compileOption("threads"):
    var
      T: seq[Thread[ptr StreamWorker]] = @[]
      i: int = 0
    T.setLen(W.len)
    i = 0
    while i < W.len:
      createThread(T[i], workerMain, addr W[i])
      i = i + 1
    i = 0
    while i < T.len:
      joinThread(T[i])
      i = i + 1
  else:
    var
      i: int = 0
    i = 0
    while i < W.len:
      workerMain(addr W[i])
      i = i + 1

proc runStreamCampaign*(threadCount: int, baseBlocks: uint64 = defaultBaseBlocks,
    routeBlocks: uint64 = defaultRouteBlocks): StreamCampaignResult
    {.role: {metaOrchestrator}.} =
  ## threadCount/baseBlocks/routeBlocks: campaign parallelism and scale.
  var
    J: seq[StreamJob] = @[]
    W: seq[StreamWorker] = @[]
    started, stopped: MonoTime
    threads: int = max(1, threadCount)
  J = buildStreamJobs(baseBlocks, routeBlocks)
  threads = min(threads, J.len)
  W = distributeJobs(J, threads)
  started = getMonoTime()
  runWorkers(W)
  stopped = getMonoTime()
  result.threads = threads
  result.baseBlocks = baseBlocks
  result.routeBlocks = routeBlocks
  result.elapsedSeconds = float64(stopped.ticks - started.ticks) / 1_000_000_000.0
  result.checkpoints = collectResults(W)
