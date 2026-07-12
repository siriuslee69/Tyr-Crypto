## ----------------------------------------------------------------
## PQ RNG <- pure-Nim NIST KAT DRBG and short-lived byte wiping
## ----------------------------------------------------------------

import std/volatile

import ../../../aes_core
import ../../../random

const
  pqKatEntropyBytes* = 48
  pqKatSeedBytes* = 48

type
  ## NIST AES-256-CTR DRBG state used by PQ KAT generators.
  PqNistDrbgState* = object
    key*: array[32, byte]
    v*: array[16, byte]
    reseedCounter*: int

  ## Random source used by pure-Nim PQ implementations.
  PqRandomContext* = object
    deterministic*: bool
    drbg*: PqNistDrbgState

## Reference: [PQ-SUPPORT] FIPS 202 XOF use and SP 800-90A deterministic KAT support; random-source and deterministic KAT generation rules for `secureClearBytes`; pitfall: use deterministic generation only for KAT replay and system entropy in production.
proc secureClearBytes*(A: var openArray[byte]) {.raises: [].} =
  ## Volatile short-lived byte buffer wipe for secret material.
  var
    i: int = 0
    B: ptr UncheckedArray[byte]
  if A.len == 0:
    return
  B = cast[ptr UncheckedArray[byte]](addr A[0])
  i = 0
  while i < A.len:
    volatileStore(addr B[i], 0'u8)
    i = i + 1

## Reference: [PQ-SUPPORT] FIPS 202 XOF use and SP 800-90A deterministic KAT support; random-source and deterministic KAT generation rules for `secureClearBytes`; pitfall: use deterministic generation only for KAT replay and system entropy in production.
proc secureClearBytes*(S: var seq[byte]) {.raises: [].} =
  ## Volatile short-lived byte sequence wipe for secret material.
  if S.len > 0:
    secureClearBytes(S.toOpenArray(0, S.len - 1))

## Reference: [PQ-SUPPORT] FIPS 202 XOF use and SP 800-90A deterministic KAT support; random-source and deterministic KAT generation rules for `incrementV`; pitfall: use deterministic generation only for KAT replay and system entropy in production.
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

## Reference: [PQ-SUPPORT] FIPS 202 XOF use and SP 800-90A deterministic KAT support; random-source and deterministic KAT generation rules for `aes256EcbBlock`; pitfall: use deterministic generation only for KAT replay and system entropy in production.
proc aes256EcbBlock(k: openArray[byte], input: array[16, byte]): array[16, byte] =
  var
    ctx: Aes256Ctx
  ctx.init(k)
  result = encryptBlock(ctx, input)

## Reference: [PQ-SUPPORT] FIPS 202 XOF use and SP 800-90A deterministic KAT support; random-source and deterministic KAT generation rules for `nistDrbgUpdate`; pitfall: use deterministic generation only for KAT replay and system entropy in production.
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

## Reference: [PQ-SUPPORT] FIPS 202 XOF use and SP 800-90A deterministic KAT support; random-source and deterministic KAT generation rules for `initNistDrbg`; pitfall: use deterministic generation only for KAT replay and system entropy in production.
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

## Reference: [PQ-SUPPORT] FIPS 202 XOF use and SP 800-90A deterministic KAT support; random-source and deterministic KAT generation rules for `nistDrbgRandomBytes`; pitfall: use deterministic generation only for KAT replay and system entropy in production.
proc nistDrbgRandomBytes*(S: var PqNistDrbgState, n: int): seq[byte] =
  ## Generate bytes from the NIST KAT DRBG and update state once per call.
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

## Reference: [PQ-SUPPORT] FIPS 202 XOF use and SP 800-90A deterministic KAT support; random-source and deterministic KAT generation rules for `initPqKatRandomContext`; pitfall: use deterministic generation only for KAT replay and system entropy in production.
proc initPqKatRandomContext*(seed: openArray[byte]): PqRandomContext =
  ## Build a deterministic random context from a 48-byte KAT seed.
  if seed.len != pqKatSeedBytes:
    raise newException(ValueError, "PQ KEM KAT seed must be 48 bytes")
  result.deterministic = true
  result.drbg = initNistDrbg(seed)

## Reference: [PQ-SUPPORT] FIPS 202 XOF use and SP 800-90A deterministic KAT support; random-source and deterministic KAT generation rules for `initPqSystemRandomContext`; pitfall: use deterministic generation only for KAT replay and system entropy in production.
proc initPqSystemRandomContext*(): PqRandomContext =
  ## Build a system-random context.
  result.deterministic = false

## Reference: [PQ-SUPPORT] FIPS 202 XOF use and SP 800-90A deterministic KAT support; random-source and deterministic KAT generation rules for `pqRandomBytes`; pitfall: use deterministic generation only for KAT replay and system entropy in production.
proc pqRandomBytes*(S: var PqRandomContext, n: int): seq[byte] =
  ## Return `n` random bytes with KAT-compatible per-call DRBG updates.
  if n < 0:
    raise newException(ValueError, "random byte count must be non-negative")
  if S.deterministic:
    result = nistDrbgRandomBytes(S.drbg, n)
  else:
    result = cryptoRandomBytes(n)

## Reference: [PQ-SUPPORT] FIPS 202 XOF use and SP 800-90A deterministic KAT support; random-source and deterministic KAT generation rules for `clearPqRandomContext`; pitfall: use deterministic generation only for KAT replay and system entropy in production.
proc clearPqRandomContext*(S: var PqRandomContext) =
  ## Wipe deterministic DRBG state when present.
  if S.deterministic:
    secureClearBytes(S.drbg.key)
    secureClearBytes(S.drbg.v)
  S.deterministic = false
  S.drbg.reseedCounter = 0
