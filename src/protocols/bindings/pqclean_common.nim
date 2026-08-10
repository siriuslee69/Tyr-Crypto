## -----------------------------------------------------------------
## PQClean Common <- shared SHAKE/SHA3 and deterministic RNG plumbing
## -----------------------------------------------------------------

import ../custom_crypto/aes_core
import ../custom_crypto/random

{.passC: "-Isubmodules/pqclean/common".}
{.compile: "../../../submodules/pqclean/common/aes.c".}
{.compile: "../../../submodules/pqclean/common/fips202.c".}

const
  pqKatEntropyBytes* = 48
  pqKatSeedBytes* = 48
  pqRandomFeedBytes* = 131072

type
  ## NIST AES-256-CTR DRBG state used by PQ KAT generators.
  PqNistDrbgState* = object
    key*: array[32, byte]
    v*: array[16, byte]
    reseedCounter*: int

var
  pqFeedPtr {.threadvar.}: ptr UncheckedArray[uint8]
  pqFeedLen {.threadvar.}: int
  pqFeedPos {.threadvar.}: int
  pqDrbg {.threadvar.}: PqNistDrbgState
  pqDrbgReady {.threadvar.}: bool

proc tyrPqRandombytesSet(feed: ptr uint8, feedLen: csize_t) {.cdecl.}
proc tyrPqRandombytesSeedKat(seed48: ptr uint8) {.cdecl.}
proc tyrPqRandombytesClear() {.cdecl.}
proc tyrPqRandombytesRemaining*(): csize_t {.cdecl.}

proc secureClearBytes*(A: var openArray[byte]) {.raises: [].} =
  ## Best-effort short-lived byte buffer wipe.
  var
    i: int = 0
  i = 0
  while i < A.len:
    A[i] = 0'u8
    i = i + 1

proc secureClearBytes*(S: var seq[byte]) {.raises: [].} =
  ## Best-effort short-lived byte sequence wipe.
  if S.len > 0:
    secureClearBytes(S.toOpenArray(0, S.len - 1))

template withPqRandomFeed*(F: var seq[byte], body: untyped) =
  if F.len == 0:
    tyrPqRandombytesSet(nil, 0)
  else:
    tyrPqRandombytesSet(cast[ptr uint8](addr F[0]), csize_t(F.len))
  try:
    body
  finally:
    tyrPqRandombytesClear()

template withPqKatRandomSeed*(S: openArray[byte], body: untyped) =
  if S.len != pqKatSeedBytes:
    raise newException(ValueError, "PQ KEM KAT seed must be 48 bytes")
  tyrPqRandombytesSeedKat(cast[ptr uint8](unsafeAddr S[0]))
  try:
    body
  finally:
    tyrPqRandombytesClear()

template withPqSystemRandom*(body: untyped) =
  tyrPqRandombytesClear()
  try:
    body
  finally:
    tyrPqRandombytesClear()

proc incrementV(S: var PqNistDrbgState) =
  var
    i: int = 15
  i = 15
  while i >= 0:
    if S.v[i] == 0xff'u8:
      S.v[i] = 0'u8
      i = i - 1
    else:
      S.v[i] = S.v[i] + 1'u8
      break

proc aes256EcbBlock(k: openArray[byte], input: array[16, byte]): array[16, byte] =
  var
    ctx: Aes256Ctx
  ctx.init(k)
  result = encryptBlock(ctx, input)

proc nistDrbgUpdate*(S: var PqNistDrbgState,
    provided: ptr array[pqKatEntropyBytes, byte] = nil) =
  ## Apply the NIST KAT AES-256-CTR DRBG update function.
  var
    temp: array[pqKatEntropyBytes, byte]
    blk: array[16, byte]
    i: int = 0
  i = 0
  while i < 3:
    incrementV(S)
    blk = aes256EcbBlock(S.key, S.v)
    copyMem(addr temp[i * 16], addr blk[0], 16)
    i = i + 1
  if provided != nil:
    i = 0
    while i < pqKatEntropyBytes:
      temp[i] = temp[i] xor provided[][i]
      i = i + 1
  i = 0
  while i < 32:
    S.key[i] = temp[i]
    i = i + 1
  i = 0
  while i < 16:
    S.v[i] = temp[32 + i]
    i = i + 1
  secureClearBytes(temp)
  secureClearBytes(blk)

proc initNistDrbg*(entropy: openArray[byte],
    personalization: openArray[byte] = @[]): PqNistDrbgState =
  ## Initialize the same AES-256-CTR DRBG used by NIST KAT files.
  var
    seedMaterial: array[pqKatEntropyBytes, byte]
    i: int = 0
  if entropy.len != pqKatEntropyBytes:
    raise newException(ValueError, "NIST DRBG entropy must be 48 bytes")
  if personalization.len != 0 and personalization.len != pqKatEntropyBytes:
    raise newException(ValueError, "NIST DRBG personalization must be 48 bytes")
  i = 0
  while i < pqKatEntropyBytes:
    seedMaterial[i] = entropy[i]
    if personalization.len == pqKatEntropyBytes:
      seedMaterial[i] = seedMaterial[i] xor personalization[i]
    i = i + 1
  nistDrbgUpdate(result, addr seedMaterial)
  result.reseedCounter = 1
  secureClearBytes(seedMaterial)

proc nistDrbgRandomBytes*(S: var PqNistDrbgState, n: int): seq[byte] =
  ## Generate bytes from the NIST KAT DRBG and update state.
  var
    blk: array[16, byte]
    offset: int = 0
    take: int = 0
    i: int = 0
  result = newSeq[byte](n)
  offset = 0
  while offset < n:
    incrementV(S)
    blk = aes256EcbBlock(S.key, S.v)
    take = min(16, n - offset)
    i = 0
    while i < take:
      result[offset + i] = blk[i]
      i = i + 1
    offset = offset + take
  nistDrbgUpdate(S)
  S.reseedCounter = S.reseedCounter + 1
  secureClearBytes(blk)

proc pqFeedFromKatSeed*(seed: openArray[byte], n: int = pqRandomFeedBytes): seq[byte] =
  ## Expand a 48-byte KAT seed into the stream consumed by PQClean randombytes.
  var
    drbg: PqNistDrbgState
  drbg = initNistDrbg(seed)
  result = nistDrbgRandomBytes(drbg, n)
  secureClearBytes(drbg.key)
  secureClearBytes(drbg.v)

proc pqFeedFromOptionalSeed*(seed: openArray[byte],
    n: int = pqRandomFeedBytes): seq[byte] =
  ## Build a deterministic PQClean randombytes feed from a caller or system seed.
  var
    entropy: seq[byte] = @[]
  if seed.len != 0 and seed.len != pqKatSeedBytes:
    raise newException(ValueError, "PQ KEM seeded operation requires a 48-byte KAT seed")
  if seed.len == pqKatSeedBytes:
    result = pqFeedFromKatSeed(seed, n)
  else:
    entropy = cryptoRandomBytes(pqKatSeedBytes)
    result = pqFeedFromKatSeed(entropy, n)
    secureClearBytes(entropy)

proc clearThreadDrbg() =
  secureClearBytes(pqDrbg.key)
  secureClearBytes(pqDrbg.v)
  pqDrbg.reseedCounter = 0
  pqDrbgReady = false

proc copyToOutput(outBytes: ptr UncheckedArray[uint8], offset: int,
    A: openArray[byte]) =
  var
    i: int = 0
  while i < A.len:
    outBytes[offset + i] = uint8(A[i])
    i = i + 1

proc fillFromFeed(outBytes: ptr UncheckedArray[uint8], offset: var int,
    remaining: var int) =
  var
    take: int = 0
    i: int = 0
  if pqFeedPtr.isNil or pqFeedPos >= pqFeedLen or remaining <= 0:
    return
  take = pqFeedLen - pqFeedPos
  if take > remaining:
    take = remaining
  i = 0
  while i < take:
    outBytes[offset + i] = pqFeedPtr[pqFeedPos + i]
    i = i + 1
  pqFeedPos = pqFeedPos + take
  offset = offset + take
  remaining = remaining - take

proc fillFromDrbg(outBytes: ptr UncheckedArray[uint8], offset: int,
    remaining: int): bool =
  var
    bytes: seq[byte] = @[]
  if remaining <= 0 or not pqDrbgReady:
    return false
  bytes = nistDrbgRandomBytes(pqDrbg, remaining)
  copyToOutput(outBytes, offset, bytes)
  secureClearBytes(bytes)
  result = true

proc fillFromSystem(outBytes: ptr UncheckedArray[uint8], offset, remaining: int) =
  var
    bytes: seq[byte] = @[]
    i: int = 0
  if remaining <= 0:
    return
  try:
    bytes = cryptoRandomBytes(remaining)
    copyToOutput(outBytes, offset, bytes)
    secureClearBytes(bytes)
  except CatchableError:
    i = 0
    while i < remaining:
      outBytes[offset + i] = 0'u8
      i = i + 1

proc tyrPqRandombytesFill(outPtr: ptr uint8, outLen: csize_t) =
  var
    outBytes: ptr UncheckedArray[uint8]
    offset: int = 0
    remaining: int = int(outLen)
  if outPtr.isNil or remaining <= 0:
    return
  outBytes = cast[ptr UncheckedArray[uint8]](outPtr)
  fillFromFeed(outBytes, offset, remaining)
  if fillFromDrbg(outBytes, offset, remaining):
    return
  fillFromSystem(outBytes, offset, remaining)

proc tyrPqRandombytesSet(feed: ptr uint8, feedLen: csize_t) {.cdecl,
    exportc: "tyr_pq_randombytes_set".} =
  clearThreadDrbg()
  pqFeedPtr = cast[ptr UncheckedArray[uint8]](feed)
  pqFeedLen = int(feedLen)
  pqFeedPos = 0

proc tyrPqRandombytesSeedKat(seed48: ptr uint8) {.cdecl,
    exportc: "tyr_pq_randombytes_seed_kat".} =
  var
    seed: array[pqKatSeedBytes, byte]
    seedBytes: ptr UncheckedArray[uint8]
    i: int = 0
  pqFeedPtr = nil
  pqFeedLen = 0
  pqFeedPos = 0
  clearThreadDrbg()
  if seed48.isNil:
    return
  seedBytes = cast[ptr UncheckedArray[uint8]](seed48)
  i = 0
  while i < pqKatSeedBytes:
    seed[i] = byte(seedBytes[i])
    i = i + 1
  pqDrbg = initNistDrbg(seed)
  pqDrbgReady = true
  secureClearBytes(seed)

proc tyrPqRandombytesClear() {.cdecl,
    exportc: "tyr_pq_randombytes_clear".} =
  pqFeedPtr = nil
  pqFeedLen = 0
  pqFeedPos = 0
  clearThreadDrbg()

proc tyrPqRandombytesRemaining*(): csize_t {.cdecl,
    exportc: "tyr_pq_randombytes_remaining".} =
  if pqFeedPos >= pqFeedLen:
    return csize_t(0)
  result = csize_t(pqFeedLen - pqFeedPos)

proc PQCLEAN_randombytes*(outPtr: ptr uint8, outLen: csize_t): cint {.cdecl,
    exportc: "PQCLEAN_randombytes".} =
  tyrPqRandombytesFill(outPtr, outLen)
  result = 0

proc randombytes*(outPtr: ptr uint8, outLen: csize_t) {.cdecl,
    exportc: "randombytes".} =
  tyrPqRandombytesFill(outPtr, outLen)
