## =====================================================================
## | Tyr CPU stress <- three load rounds, every answer checked, 2 modes |
## =====================================================================
##
## What this program does, in plain words
## --------------------------------------
## It makes every processor thread of the computer calculate Tyr crypto.
## One source file, two programs (the mode is fixed when it is built):
##
##   scalar  one plain number at a time ("scalar" := no vector
##           instructions, no AVX2, no AES-NI)     -> tyr-scalar-stress
##   simd    8 numbers per instruction (AVX2 and AES-NI code paths)
##                                                 -> tyr-simd-stress
##
## Either program works in three rounds, each for the same time:
##
##   round 1  LOW     a quarter of the threads work, the rest idle
##   round 2  MEDIUM  half of the threads work
##   round 3  FULL    every thread works
##
## On the 13th-gen i9-13900K (8 fast cores x 2 threads + 16 small cores
## = 32 threads) that is 8, 16 and 32 busy threads.
##
## Which threads are picked first? One thread of every physical core
## comes before any second thread of a core, so low load really means
## "8 different cores", not "4 cores with both their threads":
##
##   thread order   0  2  4 ... 14 | 16 17 ... 31 | 1  3  5 ... 15
##                  \____fast cores____/  \_small cores_/  \_2nd thread_/
##   LOW    = first  8 of them
##   MEDIUM = first 16 of them
##   FULL   = all    32 of them
##
## How a broken CPU shows itself
## -----------------------------
## Every thread repeats ONE fixed piece of work. The answer of that work
## is folded into one 64-bit number (the "digest"). The main thread
## computes the digest twice before the rounds start. After that, every
## repeat of every thread must produce the same digest. A different digest
## means a core calculated something wrong (too hot, too little voltage,
## a bad overclock). That is counted as an error and the exit code is 1.
##
##   fixed work -> digest ---equal?--- golden digest (made before round 1)
##                              |
##                              no -> errors += 1 (thread and CPU number kept)
##
## One repeat of the fixed work:
##
##   XChaCha20 4 KiB | AES-256-CTR 4 KiB | BLAKE3 8 blocks + 4 KiB hash
##   Gimli (2x in scalar mode, 8 lanes in simd mode)
##   SHA-256 + SHA-512 4 KiB | SHA3-256 1 KiB
##   X25519 multiply | Ed25519 sign + verify
##
## XChaCha20, AES, the 8 BLAKE3 blocks and Gimli use the vector code in
## simd mode and the plain code in scalar mode. The rest is plain code in
## both modes.
##
## Logs
## ----
## Every line is printed AND appended to a log file in the folder of the
## program itself (so a stick keeps its own logs). A line is written the
## moment it exists, so a crash or a power loss keeps everything before it.
## Log name: tyr-<mode>-stress.log  (scalar or simd)
##
## How to run
## ----------
##   tyr-scalar-stress                     3 rounds x 120 s
##   tyr-simd-stress --seconds:20          3 rounds x 20 s (quick check)
##   tyr-scalar-stress --round:full        only the full-load round
##   tyr-scalar-stress --log:path.log      another log file
##
## Build: `nimble build_tyr_stress` (this machine) or
## `nimble build_tyr_stress_static` (files that run on any x86-64 Linux,
## for example a portable NixOS stick).

when defined(avx2):
  when not defined(aesni):
    {.error: "simd mode needs AES-NI too: -d:tyrSimd=avx2,aesni".}
  const modeName = "simd"
else:
  when defined(sse2) or defined(aesni):
    {.error: "scalar mode must be built scalar: -d:tyrSimd=scalar".}
  const modeName = "scalar"

import std/[os, strutils, monotimes, cpuinfo, atomics, algorithm, tables, times]

import runePragmas

when defined(avx2):
  import ../../src/tyr/ciphers/chacha/xchacha20_simd
else:
  import ../../src/tyr/ciphers/chacha/xchacha20
import ../../src/tyr/ciphers/aes_ctr
import ../../src/tyr/ciphers/gimli
import ../../src/tyr/hashes/blake3
import ../../src/tyr/hashes/sha256
import ../../src/tyr/hashes/sha512
import ../../src/tyr/hashes/sha3
import ../../src/tyr/kems/x25519
import ../../src/tyr/signatures/ed25519

const
  defaultSeconds = 120
  workBytes = 4096
  sha3Bytes = 1024
  blakeLanes = 8
  maxCpus = 1024
  nsPerSecond = 1_000_000_000'i64
  reportEverySeconds = 10
  bytesPerRepeat = uint64(workBytes * 4 + blakeLanes * 64 + sha3Bytes + 96)
  fnvPrime = 0x100000001b3'u64
  fnvStart = 0xcbf29ce484222325'u64

type
  Round = object
    name: string
    threads: int

  Work {.role: memory, expectedCount: [1, 1024], lifeCycle: lcForever.} = object
    ## Fixed input of one thread. Every thread owns a private copy.
    key: array[32, byte]
    nonce: array[24, byte]
    aesNonce: array[16, byte]
    data: array[workBytes, byte]
    sha3Data: array[sha3Bytes, byte]
    blakeCvs: array[blakeLanes, Blake3Cv]
    blakeBlocks: array[blakeLanes, Blake3Block]
    gimliBase: Gimli_Block
    xSecret: X25519Bytes32
    xPublic: X25519Bytes32
    edSecret: seq[byte]
    edPublic: seq[byte]
    message: array[96, byte]

  WorkerState {.role: truthState, expectedCount: [1, 1024],
      lifeCycle: lcForever.} = object
    ## One thread: what it works on, what it has done, what went wrong.
    id: int
    cpu: int
    golden: uint64
    work: Work
    repeats: Atomic[int64]
    errors: Atomic[int64]
    firstErrorAt: Atomic[int64]

var
  gActive: Atomic[int] = default(Atomic[int])
  gQuit: Atomic[bool] = default(Atomic[bool])
  gLog: File = nil

## ╭⟢ Small helpers

proc say(s: string) {.role: {dataWriter}.} =
  ## s: one line, printed and appended (with the time) to the log file.
  ## Both are flushed at once, so nothing waits in a buffer.
  echo s
  stdout.flushFile()
  if gLog != nil:
    gLog.writeLine(now().format("yyyy-MM-dd HH:mm:ss") & "  " & s)
    gLog.flushFile()

proc fillBytes(A: var openArray[byte], seed: int) {.role: {helper}.} =
  ## A: bytes to fill; seed: shifts the pattern. Same seed, same bytes.
  var
    i: int = 0
  while i < A.len:
    A[i] = byte((seed + i * 31 + (i shr 8)) and 0xff)
    i = i + 1

proc foldBytes(A: openArray[byte], h: var uint64) {.role: {math}, inline.} =
  ## A: bytes to mix; h: the running digest. Mixes 8 bytes per step.
  var
    i: int = 0
    w: uint64 = 0
    k: int = 0
  while i < A.len:
    w = 0
    k = 0
    while k < 8 and i + k < A.len:
      w = w or (uint64(A[i + k]) shl (8 * k))
      k = k + 1
    h = (h xor w) * fnvPrime
    h = (h shl 13) or (h shr 51)
    i = i + 8

proc foldWords(A: openArray[uint32], h: var uint64) {.role: {math}, inline.} =
  ## A: 32-bit words to mix; h: the running digest.
  var
    i: int = 0
  while i < A.len:
    h = (h xor uint64(A[i])) * fnvPrime
    h = (h shl 13) or (h shr 51)
    i = i + 1

## ╭⟢ The fixed piece of work

proc initWork(W: var Work, seed: int) {.role: {helper}.} =
  ## W: the input to fill; seed: shifts the pattern.
  var
    i: int = 0
    j: int = 0
    pair: Ed25519Keypair = default(Ed25519Keypair)
    edSeed: array[32, byte] = default(array[32, byte])
  fillBytes(W.key, 0x11 + seed)
  fillBytes(W.nonce, 0x31 + seed)
  fillBytes(W.aesNonce, 0x51 + seed)
  fillBytes(W.data, 0x71 + seed)
  fillBytes(W.sha3Data, 0x13 + seed)
  fillBytes(W.xSecret, 0x29 + seed)
  fillBytes(W.xPublic, 0x47 + seed)
  fillBytes(W.message, 0x65 + seed)
  fillBytes(edSeed, 0x83 + seed)
  W.xPublic[31] = W.xPublic[31] and 0x7f
  pair = ed25519TyrKeypairFromSeed(edSeed)
  W.edSecret = pair.secretKey
  W.edPublic = pair.publicKey
  i = 0
  while i < blakeLanes:
    j = 0
    while j < 8:
      W.blakeCvs[i][j] = 0x6a09e667'u32 + uint32(seed + i + j)
      j = j + 1
    j = 0
    while j < 16:
      W.blakeBlocks[i][j] = 0x01020304'u32 + uint32(seed + i * 3 + j)
      j = j + 1
    i = i + 1
  i = 0
  while i < 12:
    W.gimliBase[i] = 0x10203040'u32 + uint32(seed + i)
    i = i + 1

proc runCiphers(W: Work, h: var uint64) {.role: {math}.} =
  ## W: the input; h: the digest the answers are mixed into.
  var
    chachaOut: seq[byte] = @[]
    aesOut: seq[byte] = @[]
  when defined(avx2):
    chachaOut = xchacha20StreamSimd(W.key, W.nonce, workBytes, 0'u32, xcbAvx2)
    aesOut = aesCtrXor(W.key, W.aesNonce, W.data, acbAvx2)
  else:
    chachaOut = xchacha20Xor(W.key, W.nonce, 0'u32, W.data)
    aesOut = aesCtrXor(W.key, W.aesNonce, W.data, acbScalar)
  foldBytes(chachaOut, h)
  foldBytes(aesOut, h)

proc runBlake(W: Work, h: var uint64) {.role: {math}.} =
  ## W: the input; h: the digest the answers are mixed into.
  var
    blakeOut: seq[Blake3Out] = @[]
    blakeTree: seq[byte] = @[]
    i: int = 0
  when defined(avx2):
    blakeOut = @(blake3CompressAvx8(W.blakeCvs, W.blakeBlocks, 7'u64, 64'u32,
      0'u32))
  else:
    blakeOut = blake3CompressBatch(W.blakeCvs, W.blakeBlocks, 7'u64, 64'u32,
      0'u32, bcbScalar)
  i = 0
  while i < blakeOut.len:
    foldWords(blakeOut[i], h)
    i = i + 1
  blakeTree = blake3Hash(W.data, 32)
  foldBytes(blakeTree, h)

proc runGimli(W: Work, h: var uint64) {.role: {math}.} =
  ## W: the input; h: the digest the answers are mixed into.
  when defined(avx2):
    var
      lanes: array[8, Gimli_Block] = default(array[8, Gimli_Block])
      i: int = 0
    while i < 8:
      lanes[i] = W.gimliBase
      i = i + 1
    gimliPermuteAvx8x(lanes)
    i = 0
    while i < 8:
      foldWords(lanes[i], h)
      i = i + 1
  else:
    var
      state: Gimli_Block = W.gimliBase
    gimliCoreRef(state)
    gimliCoreRef(state)
    foldWords(state, h)

proc runDigests(W: Work, h: var uint64) {.role: {math}.} =
  ## W: the input; h: the digest the answers are mixed into.
  var
    d256: Sha256Digest = default(Sha256Digest)
    d512: Sha512Digest = default(Sha512Digest)
    d3: seq[byte] = @[]
  d256 = sha256Hash(W.data)
  foldBytes(d256, h)
  d512 = sha512Hash(W.data)
  foldBytes(d512, h)
  d3 = sha3_256(W.sha3Data)
  foldBytes(d3, h)

proc runCurves(W: Work, h: var uint64) {.role: {math}.} =
  ## W: the input; h: the digest the answers are mixed into.
  var
    shared: X25519Bytes32 = default(X25519Bytes32)
    ok: bool = false
    sig: seq[byte] = @[]
    verified: bool = false
  ok = x25519ScalarmultRaw(shared, W.xSecret, W.xPublic)
  foldBytes(shared, h)
  h = (h xor uint64(ok)) * fnvPrime
  sig = ed25519TyrSign(W.message, W.edSecret)
  foldBytes(sig, h)
  verified = ed25519TyrVerify(W.message, sig, W.edPublic)
  h = (h xor uint64(verified)) * fnvPrime

proc workDigest(W: Work): uint64 {.role: {orchestrator}.} =
  ## W: the input -> the digest of one full repeat.
  var
    h: uint64 = fnvStart
  runCiphers(W, h)
  runBlake(W, h)
  runGimli(W, h)
  runDigests(W, h)
  runCurves(W, h)
  result = h

## ╭⟢ Pinning a thread to one CPU

when defined(linux):
  proc sched_setaffinity(pid: cint, size: csize_t,
      mask: pointer): cint {.importc, header: "<sched.h>".}

  proc pinToCpu(cpu: int): bool {.role: {helper}.} =
    ## cpu: number of the logical CPU -> true when the system accepted it.
    var
      mask: array[maxCpus div 64, uint64] = default(array[maxCpus div 64, uint64])
    if cpu < 0 or cpu >= maxCpus:
      return false
    mask[cpu div 64] = 1'u64 shl uint64(cpu mod 64)
    result = sched_setaffinity(0, csize_t(sizeof(mask)), addr mask) == 0
elif defined(windows):
  proc GetCurrentThread(): pointer {.importc, stdcall, dynlib: "kernel32".}
  proc SetThreadAffinityMask(h: pointer, mask: uint): uint {.importc,
    stdcall, dynlib: "kernel32".}

  proc pinToCpu(cpu: int): bool {.role: {helper}.} =
    ## cpu: number of the logical CPU (0..63) -> true when accepted.
    if cpu < 0 or cpu >= 64:
      return false
    result = SetThreadAffinityMask(GetCurrentThread(), uint(1) shl uint(cpu)) != 0
else:
  proc pinToCpu(cpu: int): bool {.role: {helper}.} =
    ## cpu: ignored on this system -> always false.
    result = false

proc readSysText(path: string): string {.role: {dataFetcher}.} =
  ## path: a tiny text file -> its content, or "" when it cannot be read.
  try:
    result = readFile(path).strip()
  except IOError:
    result = ""

proc cpuOrder(n: int): seq[int] {.role: {truthBuilder}.} =
  ## n: number of logical CPUs -> CPU numbers, first thread of each core
  ## first, second threads last. Without /sys information: 0, 1, 2 ...
  var
    firstOfCore: seq[int] = @[]
    second: seq[int] = @[]
    seen: Table[string, bool] = initTable[string, bool]()
    core: string = ""
    i: int = 0
  while i < n:
    core = readSysText("/sys/devices/system/cpu/cpu" & $i &
      "/topology/core_id") & "@" & readSysText(
      "/sys/devices/system/cpu/cpu" & $i & "/topology/physical_package_id")
    if seen.hasKey(core) and core != "@":
      second.add(i)
    else:
      seen[core] = true
      firstOfCore.add(i)
    i = i + 1
  result = firstOfCore & second

## ╭⟢ The worker thread

proc worker(S: ptr WorkerState) {.thread, role: {actor}.} =
  ## S: this thread's state. Works while its id is below the active count.
  var
    digest: uint64 = 0
    pinned: bool = false
  pinned = pinToCpu(S.cpu)
  if not pinned:
    S.cpu = -1
  while not gQuit.load(moRelaxed):
    if S.id >= gActive.load(moRelaxed):
      sleep(20)
      continue
    digest = workDigest(S.work)
    if digest != S.golden:
      S.errors.atomicInc(1)
      if S.firstErrorAt.load(moRelaxed) == 0:
        S.firstErrorAt.store(S.repeats.load(moRelaxed) + 1)
    S.repeats.atomicInc(1)

## ╭⟢ Reading the machine (main thread)

proc packageTempC(): int {.role: {dataFetcher}.} =
  ## -> package temperature in whole degrees C, or -1 when not readable.
  var
    dirs: seq[string] = @[]
    t: string = ""
  try:
    for kind, path in walkDir("/sys/class/hwmon"):
      dirs.add(path)
  except OSError:
    return -1
  dirs.sort()
  for d in dirs:
    if readSysText(d & "/name") == "coretemp":
      t = readSysText(d & "/temp1_input")
      if t.len > 0:
        return parseInt(t) div 1000
  result = -1

proc tempText(c: int): string {.role: {helper}.} =
  ## c: degrees C or -1 -> text for the log.
  if c >= 0:
    result = $c & " C"
  else:
    result = "n/a"

proc sumRepeats(W: ptr UncheckedArray[WorkerState], n: int): int64 {.
    role: {parser}.} =
  ## W: all workers; n: how many -> repeats done so far.
  var
    i: int = 0
  while i < n:
    result = result + W[i].repeats.load(moRelaxed)
    i = i + 1

proc sumErrors(W: ptr UncheckedArray[WorkerState], n: int): int64 {.
    role: {parser}.} =
  ## W: all workers; n: how many -> wrong digests so far.
  var
    i: int = 0
  while i < n:
    result = result + W[i].errors.load(moRelaxed)
    i = i + 1

proc rate(repeats: int64, ns: int64): string {.role: {helper}.} =
  ## repeats: done; ns: time they took -> repeats per second as text.
  var
    r: float64 = 0.0
  if ns > 0:
    r = float64(repeats) * float64(nsPerSecond) / float64(ns)
  result = formatFloat(r, ffDecimal, 1)

proc mibPerSecond(repeats: int64, ns: int64): string {.role: {helper}.} =
  ## repeats: done; ns: time they took -> bytes pushed through, MiB/s.
  var
    r: float64 = 0.0
  if ns > 0:
    r = float64(repeats) * float64(bytesPerRepeat) /
      1048576.0 * float64(nsPerSecond) / float64(ns)
  result = formatFloat(r, ffDecimal, 1)

## ╭⟢ One round

proc runRound(R: Round, seconds: int, W: ptr UncheckedArray[WorkerState],
    n: int): tuple[repeats, errors: int64, peakC: int] {.role: {orchestrator}.} =
  ## R: the round; seconds: its length; W: all workers; n: how many exist.
  ## -> repeats done, errors seen and highest package temperature.
  var
    startRepeats: int64 = sumRepeats(W, n)
    startErrors: int64 = sumErrors(W, n)
    start: int64 = getMonoTime().ticks
    stop: int64 = start + int64(seconds) * nsPerSecond
    lastReport: int64 = start
    lastRepeats: int64 = startRepeats
    tick: int64 = start
    repeatsNow: int64 = 0
    tempC: int = 0
  result.peakC = -1
  gActive.store(R.threads)
  say("round " & R.name & ": " & $R.threads & " threads busy for " &
    $seconds & " s")
  while tick < stop:
    sleep(250)
    tick = getMonoTime().ticks
    tempC = packageTempC()
    if tempC > result.peakC:
      result.peakC = tempC
    if tick - lastReport >= int64(reportEverySeconds) * nsPerSecond:
      repeatsNow = sumRepeats(W, n)
      say("  " & align($((tick - start) div nsPerSecond), 4) & " s  " &
        align(rate(repeatsNow - lastRepeats, tick - lastReport), 10) &
        " repeats/s  temp " & tempText(tempC) &
        "  errors " & $(sumErrors(W, n) - startErrors))
      lastReport = tick
      lastRepeats = repeatsNow
  gActive.store(0)
  result.repeats = sumRepeats(W, n) - startRepeats
  result.errors = sumErrors(W, n) - startErrors
  say("  done " & R.name & ": " & $result.repeats & " repeats, " &
    mibPerSecond(result.repeats, tick - start) & " MiB/s, peak " &
    tempText(result.peakC) & ", errors " & $result.errors)

## ╭⟢ Log file

proc openLog(path: string): File {.role: {helper}.} =
  ## path: log file or "" -> the file opened for appending. "" means
  ## tyr-<mode>-stress.log in the folder of this program; when that folder
  ## cannot be written, the current folder is used instead.
  var
    p: string = path
  result = nil
  if p.len == 0:
    p = joinPath(getAppDir(), "tyr-" & modeName & "-stress.log")
  if open(result, p, fmAppend):
    return
  p = "tyr-" & modeName & "-stress.log"
  if not open(result, p, fmAppend):
    result = nil
    echo "warning: no log file could be opened, printing only"
    return
  echo "warning: program folder not writable, log is ", absolutePath(p)

## ╭⟢ Command line

proc optionValue(name, fallback: string): string {.role: {parser}.} =
  ## name: option name without dashes -> the text after `--name:`, or fallback.
  var
    i: int = 1
    a: string = ""
  result = fallback
  while i <= paramCount():
    a = paramStr(i)
    if a.startsWith("--" & name & ":"):
      result = a[name.len + 3 .. ^1]
    i = i + 1

proc roundsFor(logical: int, which: string): seq[Round] {.
    role: {truthBuilder}.} =
  ## logical: number of logical CPUs; which: low, medium, full or all.
  var
    all: seq[Round] = @[]
    i: int = 0
  all.add(Round(name: "low", threads: max(1, logical div 4)))
  all.add(Round(name: "medium", threads: max(1, logical div 2)))
  all.add(Round(name: "full", threads: logical))
  while i < all.len:
    if which == "all" or which == all[i].name:
      result.add(all[i])
    i = i + 1
  if result.len == 0:
    quit("--round must be low, medium, full or all", 1)

proc parseSeconds(): int {.role: {parser}.} =
  ## -> the length of each round from --seconds:N.
  var
    text: string = optionValue("seconds", $defaultSeconds)
  try:
    result = parseInt(text)
  except ValueError:
    quit("invalid --seconds value: " & text, 1)
  if result <= 0:
    quit("--seconds must be greater than zero", 1)

## ╭⟢ Main

proc startWorkers(W: ptr UncheckedArray[WorkerState],
    T: var seq[Thread[ptr WorkerState]], order: seq[int], golden: uint64) {.
    role: {orchestrator}.} =
  ## W: all workers; T: their threads; order: CPU of each worker;
  ## golden: the digest every repeat must give.
  var
    i: int = 0
  while i < T.len:
    W[i].id = i
    W[i].cpu = order[i]
    W[i].golden = golden
    createThread(T[i], worker, addr W[i])
    i = i + 1

proc reportErrors(W: ptr UncheckedArray[WorkerState], n: int) {.
    role: {dataWriter}.} =
  ## W: all workers; n: how many -> one log line per thread with errors.
  var
    i: int = 0
  while i < n:
    if W[i].errors.load() > 0:
      say("ERROR thread " & $i & " on CPU " & $W[i].cpu & ": " &
        $W[i].errors.load() & " wrong digest(s), first at repeat " &
        $W[i].firstErrorAt.load())
    i = i + 1

proc main() {.role: {metaOrchestrator}.} =
  var
    seconds: int = parseSeconds()
    logical: int = max(1, countProcessors())
    rounds: seq[Round] = roundsFor(logical, optionValue("round", "all"))
    order: seq[int] = cpuOrder(logical)
    golden: uint64 = 0
    again: uint64 = 0
    W: ptr UncheckedArray[WorkerState] = nil
    threads: seq[Thread[ptr WorkerState]] = @[]
    totalErrors: int64 = 0
    outcome: tuple[repeats, errors: int64, peakC: int] = (0'i64, 0'i64, 0)
    i: int = 0
    pinnedCount: int = 0
  when not compileOption("threads"):
    quit("this program needs --threads:on", 1)
  gLog = openLog(optionValue("log", ""))
  say("== Tyr " & modeName & " stress: " & $logical & " logical CPUs, " &
    $rounds.len & " round(s) x " & $seconds & " s ==")
  W = cast[ptr UncheckedArray[WorkerState]](
    allocShared0(logical * sizeof(WorkerState)))
  threads.setLen(logical)
  i = 0
  while i < logical:
    initWork(W[i].work, 0)
    i = i + 1
  golden = workDigest(W[0].work)
  again = workDigest(W[0].work)
  if golden != again:
    say("FAIL: the same work gave two answers before the rounds began.")
    quit(1)
  say("golden digest 0x" & toHex(golden, 16))
  startWorkers(W, threads, order, golden)
  sleep(300)
  i = 0
  while i < logical:
    if W[i].cpu >= 0:
      pinnedCount = pinnedCount + 1
    i = i + 1
  say("threads pinned to their own CPU: " & $pinnedCount & " of " & $logical)
  i = 0
  while i < rounds.len:
    outcome = runRound(rounds[i], seconds, W, logical)
    totalErrors = totalErrors + outcome.errors
    i = i + 1
  gQuit.store(true)
  i = 0
  while i < logical:
    joinThread(threads[i])
    i = i + 1
  reportErrors(W, logical)
  if totalErrors == 0:
    say("RESULT: PASS - every repeat on every thread matched the golden digest.")
  else:
    say("RESULT: FAIL - " & $totalErrors & " wrong digest(s). The CPU is unstable.")
  deallocShared(W)
  gLog.close()
  if totalErrors > 0:
    quit(1)

when isMainModule:
  main()
