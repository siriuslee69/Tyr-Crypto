## ---------------------------------------------------------
## SHA3 <- scalar Keccak-f[1600] hashing with fixed variants
## ---------------------------------------------------------

import std/[bitops, dynlib, os, strutils]
import ../../helpers/otter_support

type
  ## Supported fixed-output SHA3 variants.
  Sha3Variant* = enum
    svSha3_224,
    svSha3_256,
    svSha3_384,
    svSha3_512

  ## Raw Keccak-f[1600] state as 25 little-endian 64-bit lanes.
  Sha3State* = array[25, uint64]

const
  sha3DomainSuffix = 0x06'u8
  shakeDomainSuffix = 0x1f'u8
  shake128RateBytes* = 168
  shake256RateBytes* = 136
  keccakLaneBytes = 8
  opensslShakeLibNames = when defined(windows):
                           @["libcrypto-3-x64.dll"]
                         elif defined(macosx):
                           @["libcrypto.3.dylib", "libcrypto.dylib"]
                         else:
                           @["libcrypto.so.3", "libcrypto.so"]
  keccakRoundConstants: array[24, uint64] = [
    0x0000000000000001'u64, 0x0000000000008082'u64,
    0x800000000000808a'u64, 0x8000000080008000'u64,
    0x000000000000808b'u64, 0x0000000080000001'u64,
    0x8000000080008081'u64, 0x8000000000008009'u64,
    0x000000000000008a'u64, 0x0000000000000088'u64,
    0x0000000080008009'u64, 0x000000008000000a'u64,
    0x000000008000808b'u64, 0x800000000000008b'u64,
    0x8000000000008089'u64, 0x8000000000008003'u64,
    0x8000000000008002'u64, 0x8000000000000080'u64,
    0x000000000000800a'u64, 0x800000008000000a'u64,
    0x8000000080008081'u64, 0x8000000000008080'u64,
    0x0000000080000001'u64, 0x8000000080008008'u64
  ]
  keccakRhoOffsets: array[25, int32] = [
    0'i32, 1'i32, 62'i32, 28'i32, 27'i32,
    36'i32, 44'i32, 6'i32, 55'i32, 20'i32,
    3'i32, 10'i32, 43'i32, 25'i32, 39'i32,
    41'i32, 45'i32, 15'i32, 21'i32, 8'i32,
    18'i32, 2'i32, 61'i32, 56'i32, 14'i32
  ]

type
  EVP_MD = object
  EVP_MD_CTX = object

  EvpShake256Proc = proc (): ptr EVP_MD {.cdecl.}
  EvpMdCtxNewProc = proc (): ptr EVP_MD_CTX {.cdecl.}
  EvpMdCtxFreeProc = proc (ctx: ptr EVP_MD_CTX) {.cdecl.}
  EvpDigestInitExProc = proc (ctx: ptr EVP_MD_CTX, typ: ptr EVP_MD,
    engine: pointer): cint {.cdecl.}
  EvpDigestUpdateProc = proc (ctx: ptr EVP_MD_CTX, data: pointer,
    len: csize_t): cint {.cdecl.}
  EvpDigestFinalXofProc = proc (ctx: ptr EVP_MD_CTX, md: ptr uint8,
    len: csize_t): cint {.cdecl.}

var
  opensslShakeHandle: LibHandle
  opensslShakeChecked: bool = false
  opensslShakeReady: bool = false
  osslShake256: EvpShake256Proc
  osslMdCtxNew: EvpMdCtxNewProc
  osslMdCtxFree: EvpMdCtxFreeProc
  osslDigestInitEx: EvpDigestInitExProc
  osslDigestUpdate: EvpDigestUpdateProc
  osslDigestFinalXof: EvpDigestFinalXofProc

proc appendOpenSslCandidates(candidates: var seq[string], dirPath: string) =
  var
    trimmed = dirPath.strip()
    name: string = ""
  if trimmed.len == 0:
    return
  for name in opensslShakeLibNames:
    candidates.add(joinPath(trimmed, name))

proc collectOpenSslCandidates(): seq[string] =
  var
    envDirs = getEnv("OPENSSL_LIB_DIRS").strip()
    pathDirs = getEnv("PATH").split(PathSep)
    dirPath: string = ""
    moduleDir = splitFile(currentSourcePath()).dir
    repoRoot = absolutePath(joinPath(moduleDir, "..", "..", "..", ".."))
    commonWindowsDirs = [
      r"C:\Program Files\Git\mingw64\bin",
      r"C:\msys64\mingw64\bin",
      r"C:\msys64\clang64\bin"
    ]
    name: string = ""
  for name in opensslShakeLibNames:
    result.add(name)
  if envDirs.len > 0:
    for dirPath in envDirs.split({';', ':'}):
      appendOpenSslCandidates(result, dirPath)
  appendOpenSslCandidates(result, joinPath(repoRoot, "build", "openssl", "lib"))
  appendOpenSslCandidates(result, joinPath(repoRoot, "build", "openssl", "install", "lib"))
  for dirPath in pathDirs:
    appendOpenSslCandidates(result, dirPath)
  when defined(windows):
    for dirPath in commonWindowsDirs:
      appendOpenSslCandidates(result, dirPath)

proc unloadOpenSslShake() =
  if opensslShakeHandle != nil:
    unloadLib(opensslShakeHandle)
    opensslShakeHandle = nil
  opensslShakeReady = false

proc loadOpenSslSymbol[T](symName: string, target: var T): bool =
  let addrSym = symAddr(opensslShakeHandle, symName)
  if addrSym.isNil:
    unloadOpenSslShake()
    return false
  target = cast[T](addrSym)
  true

proc ensureOpenSslShakeLoaded(): bool =
  var
    candidate: string = ""
  if opensslShakeChecked:
    return opensslShakeReady
  opensslShakeChecked = true
  for candidate in collectOpenSslCandidates():
    opensslShakeHandle = loadLib(candidate)
    if opensslShakeHandle != nil:
      break
  if opensslShakeHandle == nil:
    return false
  if not loadOpenSslSymbol("EVP_shake256", osslShake256):
    return false
  if not loadOpenSslSymbol("EVP_MD_CTX_new", osslMdCtxNew):
    return false
  if not loadOpenSslSymbol("EVP_MD_CTX_free", osslMdCtxFree):
    return false
  if not loadOpenSslSymbol("EVP_DigestInit_ex", osslDigestInitEx):
    return false
  if not loadOpenSslSymbol("EVP_DigestUpdate", osslDigestUpdate):
    return false
  if not loadOpenSslSymbol("EVP_DigestFinalXOF", osslDigestFinalXof):
    return false
  opensslShakeReady = true
  true

proc shake256OpenSslInto(dst: var openArray[byte], A: openArray[byte]): bool =
  var
    ctx: ptr EVP_MD_CTX
  if not ensureOpenSslShakeLoaded():
    return false
  ctx = osslMdCtxNew()
  if ctx == nil:
    return false
  defer:
    osslMdCtxFree(ctx)
  if osslDigestInitEx(ctx, osslShake256(), nil) != 1:
    return false
  if A.len > 0 and osslDigestUpdate(ctx, unsafeAddr A[0], csize_t(A.len)) != 1:
    return false
  if dst.len > 0 and osslDigestFinalXof(ctx, unsafeAddr dst[0], csize_t(dst.len)) != 1:
    return false
  result = true

proc shake256OpenSslInto(dst: var openArray[byte], A0, A1: openArray[byte]): bool =
  var
    ctx: ptr EVP_MD_CTX
  if not ensureOpenSslShakeLoaded():
    return false
  ctx = osslMdCtxNew()
  if ctx == nil:
    return false
  defer:
    osslMdCtxFree(ctx)
  if osslDigestInitEx(ctx, osslShake256(), nil) != 1:
    return false
  if A0.len > 0 and osslDigestUpdate(ctx, unsafeAddr A0[0], csize_t(A0.len)) != 1:
    return false
  if A1.len > 0 and osslDigestUpdate(ctx, unsafeAddr A1[0], csize_t(A1.len)) != 1:
    return false
  if dst.len > 0 and osslDigestFinalXof(ctx, unsafeAddr dst[0], csize_t(dst.len)) != 1:
    return false
  result = true

proc shake256OpenSslInto(dst: var openArray[byte], A0, A1, A2: openArray[byte]): bool =
  var
    ctx: ptr EVP_MD_CTX
  if not ensureOpenSslShakeLoaded():
    return false
  ctx = osslMdCtxNew()
  if ctx == nil:
    return false
  defer:
    osslMdCtxFree(ctx)
  if osslDigestInitEx(ctx, osslShake256(), nil) != 1:
    return false
  if A0.len > 0 and osslDigestUpdate(ctx, unsafeAddr A0[0], csize_t(A0.len)) != 1:
    return false
  if A1.len > 0 and osslDigestUpdate(ctx, unsafeAddr A1[0], csize_t(A1.len)) != 1:
    return false
  if A2.len > 0 and osslDigestUpdate(ctx, unsafeAddr A2[0], csize_t(A2.len)) != 1:
    return false
  if dst.len > 0 and osslDigestFinalXof(ctx, unsafeAddr dst[0], csize_t(dst.len)) != 1:
    return false
  result = true

proc shake256OpenSslChunksInto(dst: var openArray[byte], A0, A1, A2: openArray[byte]): bool =
  var
    ctx: ptr EVP_MD_CTX
  if not ensureOpenSslShakeLoaded():
    return false
  ctx = osslMdCtxNew()
  if ctx == nil:
    return false
  defer:
    osslMdCtxFree(ctx)
  if osslDigestInitEx(ctx, osslShake256(), nil) != 1:
    return false
  if A0.len > 0 and osslDigestUpdate(ctx, unsafeAddr A0[0], csize_t(A0.len)) != 1:
    return false
  if A1.len > 0 and osslDigestUpdate(ctx, unsafeAddr A1[0], csize_t(A1.len)) != 1:
    return false
  if A2.len > 0 and osslDigestUpdate(ctx, unsafeAddr A2[0], csize_t(A2.len)) != 1:
    return false
  if dst.len > 0 and osslDigestFinalXof(ctx, unsafeAddr dst[0], csize_t(dst.len)) != 1:
    return false
  result = true

proc shake256OpenSslWordsLeInto(dst: var openArray[uint16], A: openArray[byte]): bool =
  var
    ctx: ptr EVP_MD_CTX
    tmp: seq[byte] = @[]
    i: int = 0
  if not ensureOpenSslShakeLoaded():
    return false
  ctx = osslMdCtxNew()
  if ctx == nil:
    return false
  defer:
    osslMdCtxFree(ctx)
  if osslDigestInitEx(ctx, osslShake256(), nil) != 1:
    return false
  if A.len > 0 and osslDigestUpdate(ctx, unsafeAddr A[0], csize_t(A.len)) != 1:
    return false
  when cpuEndian == littleEndian:
    if dst.len > 0 and osslDigestFinalXof(ctx, cast[ptr uint8](unsafeAddr dst[0]),
        csize_t(dst.len * sizeof(uint16))) != 1:
      return false
  else:
    if dst.len > 0:
      tmp = newSeq[byte](dst.len * 2)
      if osslDigestFinalXof(ctx, unsafeAddr tmp[0], csize_t(tmp.len)) != 1:
        return false
      i = 0
      while i < dst.len:
        dst[i] = uint16(tmp[i * 2]) or (uint16(tmp[i * 2 + 1]) shl 8)
        i = i + 1
  result = true

proc sha3DigestBytes*(v: Sha3Variant): int =
  ## Return the digest length in bytes for a fixed SHA3 variant.
  case v
  of svSha3_224:
    result = 28
  of svSha3_256:
    result = 32
  of svSha3_384:
    result = 48
  of svSha3_512:
    result = 64

proc sha3RateBytes*(v: Sha3Variant): int =
  ## Return the sponge rate in bytes for a fixed SHA3 variant.
  case v
  of svSha3_224:
    result = 144
  of svSha3_256:
    result = 136
  of svSha3_384:
    result = 104
  of svSha3_512:
    result = 72

proc sha3VariantFromOutLen*(outLen: int): Sha3Variant =
  ## Map the legacy output-length selector to a fixed SHA3 variant.
  case outLen
  of 28:
    result = svSha3_224
  of 32:
    result = svSha3_256
  of 48:
    result = svSha3_384
  of 64:
    result = svSha3_512
  else:
    raise newException(ValueError,
      "sha3 output length must be one of 28, 32, 48, or 64")

## Fixed-rate Keccak helpers only index caller-validated buffers and fixed-size
## stack scratch, so we disable bounds checks in this hot region to reduce the
## scalar SHA3/SHAKE overhead seen by Kyber and the other PQ backends.
{.push boundChecks: off.}

proc laneIdx(x, y: int): int {.inline.} =
  result = x + y * 5

proc load64Le(A: openArray[byte], o: int): uint64 {.inline.} =
  result =
    uint64(A[o]) or
    (uint64(A[o + 1]) shl 8) or
    (uint64(A[o + 2]) shl 16) or
    (uint64(A[o + 3]) shl 24) or
    (uint64(A[o + 4]) shl 32) or
    (uint64(A[o + 5]) shl 40) or
    (uint64(A[o + 6]) shl 48) or
    (uint64(A[o + 7]) shl 56)

proc store64Le(A: var openArray[byte], o: int, v: uint64) {.inline.} =
  A[o] = byte(v and 0xff'u64)
  A[o + 1] = byte((v shr 8) and 0xff'u64)
  A[o + 2] = byte((v shr 16) and 0xff'u64)
  A[o + 3] = byte((v shr 24) and 0xff'u64)
  A[o + 4] = byte((v shr 32) and 0xff'u64)
  A[o + 5] = byte((v shr 40) and 0xff'u64)
  A[o + 6] = byte((v shr 48) and 0xff'u64)
  A[o + 7] = byte((v shr 56) and 0xff'u64)

proc absorbBlock(S: var Sha3State, A: openArray[byte], o, rateBytes: int) =
  var
    lane: int = 0
    laneCount: int = 0
  laneCount = rateBytes div keccakLaneBytes
  lane = 0
  while lane < laneCount:
    S[lane] = S[lane] xor load64Le(A, o + lane * keccakLaneBytes)
    lane = lane + 1

proc absorbFinalBlockWithDomain(S: var Sha3State, A: openArray[byte], o, rateBytes: int,
    domain: byte) =
  var
    blk: array[168, byte]
    take: int = 0
    i: int = 0
  take = A.len - o
  if take < 0:
    take = 0
  i = 0
  while i < take:
    blk[i] = A[o + i]
    i = i + 1
  blk[take] = blk[take] xor domain
  blk[rateBytes - 1] = blk[rateBytes - 1] xor 0x80'u8
  absorbBlock(S, blk, 0, rateBytes)

proc keccakF1600Ref*(S: var Sha3State)
proc shake256Into*(dst: var openArray[byte], A: openArray[byte])
proc shake256Into*(dst: var openArray[byte], A0, A1: openArray[byte])
proc shake256Into*(dst: var openArray[byte], A0, A1, A2: openArray[byte])
proc shake256WordsLeInto*(dst: var openArray[uint16], A: openArray[byte])
proc shake128Into*(dst: var openArray[byte], A: openArray[byte])

proc squeezeBytesState(S: var Sha3State, dst: var openArray[byte], rateBytes: int) =
  var
    i: int = 0
    laneBytes {.noinit.}: array[8, byte]
    produced: int = 0
    take: int = 0
    blockBytes: int = 0
  while produced < dst.len:
    blockBytes = rateBytes
    if blockBytes > dst.len - produced:
      blockBytes = dst.len - produced
    i = 0
    while i * keccakLaneBytes < blockBytes:
      store64Le(laneBytes, 0, S[i])
      take = blockBytes - i * keccakLaneBytes
      if take > keccakLaneBytes:
        take = keccakLaneBytes
      for j in 0 ..< take:
        dst[produced + i * keccakLaneBytes + j] = laneBytes[j]
      i = i + 1
    produced = produced + blockBytes
    if produced < dst.len:
      keccakF1600Ref(S)

proc squeezeBytesInto(S0: Sha3State, dst: var openArray[byte], rateBytes: int) =
  var
    S {.noinit.} = S0
  squeezeBytesState(S, dst, rateBytes)

proc squeezeWordsLeInto(S0: Sha3State, dst: var openArray[uint16], rateBytes: int) =
  var
    S {.noinit.} = S0
    produced: int = 0
    blockWords: int = 0
    lane: int = 0
    laneValue: uint64 = 0
    wordIdx: int = 0
  while produced < dst.len:
    blockWords = rateBytes div 2
    if blockWords > dst.len - produced:
      blockWords = dst.len - produced
    lane = 0
    while lane * 4 < blockWords:
      laneValue = S[lane]
      wordIdx = blockWords - lane * 4
      if wordIdx > 4:
        wordIdx = 4
      if wordIdx > 0:
        dst[produced + lane * 4 + 0] = uint16(laneValue and 0xffff'u64)
      if wordIdx > 1:
        dst[produced + lane * 4 + 1] = uint16((laneValue shr 16) and 0xffff'u64)
      if wordIdx > 2:
        dst[produced + lane * 4 + 2] = uint16((laneValue shr 32) and 0xffff'u64)
      if wordIdx > 3:
        dst[produced + lane * 4 + 3] = uint16((laneValue shr 48) and 0xffff'u64)
      lane = lane + 1
    produced = produced + blockWords
    if produced < dst.len:
      keccakF1600Ref(S)

proc squeezeBytes(S0: Sha3State, outLen, rateBytes: int): seq[byte] =
  result = newSeq[byte](outLen)
  squeezeBytesInto(S0, result, rateBytes)

proc absorbFinalBlock(S: var Sha3State, A: openArray[byte], o, rateBytes: int) =
  absorbFinalBlockWithDomain(S, A, o, rateBytes, sha3DomainSuffix)

proc absorbPartState(S: var Sha3State, tail: var array[168, byte], tailLen: var int,
    A: openArray[byte], rateBytes: int) =
  var
    offset: int = 0
    take: int = 0
    i: int = 0
  if tailLen > 0:
    take = rateBytes - tailLen
    if take > A.len:
      take = A.len
    i = 0
    while i < take:
      tail[tailLen + i] = A[i]
      i = i + 1
    tailLen = tailLen + take
    offset = take
    if tailLen == rateBytes:
      absorbBlock(S, tail, 0, rateBytes)
      keccakF1600Ref(S)
      tailLen = 0
  while offset + rateBytes <= A.len:
    absorbBlock(S, A, offset, rateBytes)
    keccakF1600Ref(S)
    offset = offset + rateBytes
  while offset < A.len:
    tail[tailLen] = A[offset]
    tailLen = tailLen + 1
    offset = offset + 1

proc absorbFinalPartsWithDomain(S: var Sha3State, rateBytes: int, domain: byte,
    A: openArray[byte]) =
  var
    tail: array[168, byte]
    tailLen: int = 0
    i: int = 0
  absorbPartState(S, tail, tailLen, A, rateBytes)
  i = tailLen
  while i < rateBytes:
    tail[i] = 0'u8
    i = i + 1
  tail[tailLen] = tail[tailLen] xor domain
  tail[rateBytes - 1] = tail[rateBytes - 1] xor 0x80'u8
  absorbBlock(S, tail, 0, rateBytes)

proc absorbFinalPartsWithDomain(S: var Sha3State, rateBytes: int, domain: byte,
    A0, A1: openArray[byte]) =
  var
    tail: array[168, byte]
    tailLen: int = 0
    i: int = 0
  absorbPartState(S, tail, tailLen, A0, rateBytes)
  absorbPartState(S, tail, tailLen, A1, rateBytes)
  i = tailLen
  while i < rateBytes:
    tail[i] = 0'u8
    i = i + 1
  tail[tailLen] = tail[tailLen] xor domain
  tail[rateBytes - 1] = tail[rateBytes - 1] xor 0x80'u8
  absorbBlock(S, tail, 0, rateBytes)

proc absorbFinalPartsWithDomain(S: var Sha3State, rateBytes: int, domain: byte,
    A0, A1, A2: openArray[byte]) =
  var
    tail: array[168, byte]
    tailLen: int = 0
    i: int = 0
  absorbPartState(S, tail, tailLen, A0, rateBytes)
  absorbPartState(S, tail, tailLen, A1, rateBytes)
  absorbPartState(S, tail, tailLen, A2, rateBytes)
  i = tailLen
  while i < rateBytes:
    tail[i] = 0'u8
    i = i + 1
  tail[tailLen] = tail[tailLen] xor domain
  tail[rateBytes - 1] = tail[rateBytes - 1] xor 0x80'u8
  absorbBlock(S, tail, 0, rateBytes)

proc keccakF1600Ref*(S: var Sha3State) =
  ## Apply the scalar Keccak-f[1600] permutation to a 25-lane state.
  var
    c0: uint64 = 0
    c1: uint64 = 0
    c2: uint64 = 0
    c3: uint64 = 0
    c4: uint64 = 0
    d0: uint64 = 0
    d1: uint64 = 0
    d2: uint64 = 0
    d3: uint64 = 0
    d4: uint64 = 0
    b0: uint64 = 0
    b1: uint64 = 0
    b2: uint64 = 0
    b3: uint64 = 0
    b4: uint64 = 0
    b5: uint64 = 0
    b6: uint64 = 0
    b7: uint64 = 0
    b8: uint64 = 0
    b9: uint64 = 0
    b10: uint64 = 0
    b11: uint64 = 0
    b12: uint64 = 0
    b13: uint64 = 0
    b14: uint64 = 0
    b15: uint64 = 0
    b16: uint64 = 0
    b17: uint64 = 0
    b18: uint64 = 0
    b19: uint64 = 0
    b20: uint64 = 0
    b21: uint64 = 0
    b22: uint64 = 0
    b23: uint64 = 0
    b24: uint64 = 0
    round: int = 0
  round = 0
  while round < keccakRoundConstants.len:
    c0 = S[0] xor S[5] xor S[10] xor S[15] xor S[20]
    c1 = S[1] xor S[6] xor S[11] xor S[16] xor S[21]
    c2 = S[2] xor S[7] xor S[12] xor S[17] xor S[22]
    c3 = S[3] xor S[8] xor S[13] xor S[18] xor S[23]
    c4 = S[4] xor S[9] xor S[14] xor S[19] xor S[24]

    d0 = c4 xor rotateLeftBits(c1, 1)
    d1 = c0 xor rotateLeftBits(c2, 1)
    d2 = c1 xor rotateLeftBits(c3, 1)
    d3 = c2 xor rotateLeftBits(c4, 1)
    d4 = c3 xor rotateLeftBits(c0, 1)

    S[0] = S[0] xor d0
    S[5] = S[5] xor d0
    S[10] = S[10] xor d0
    S[15] = S[15] xor d0
    S[20] = S[20] xor d0
    S[1] = S[1] xor d1
    S[6] = S[6] xor d1
    S[11] = S[11] xor d1
    S[16] = S[16] xor d1
    S[21] = S[21] xor d1
    S[2] = S[2] xor d2
    S[7] = S[7] xor d2
    S[12] = S[12] xor d2
    S[17] = S[17] xor d2
    S[22] = S[22] xor d2
    S[3] = S[3] xor d3
    S[8] = S[8] xor d3
    S[13] = S[13] xor d3
    S[18] = S[18] xor d3
    S[23] = S[23] xor d3
    S[4] = S[4] xor d4
    S[9] = S[9] xor d4
    S[14] = S[14] xor d4
    S[19] = S[19] xor d4
    S[24] = S[24] xor d4

    b0 = S[0]
    b10 = rotateLeftBits(S[1], 1)
    b20 = rotateLeftBits(S[2], 62)
    b5 = rotateLeftBits(S[3], 28)
    b15 = rotateLeftBits(S[4], 27)
    b16 = rotateLeftBits(S[5], 36)
    b1 = rotateLeftBits(S[6], 44)
    b11 = rotateLeftBits(S[7], 6)
    b21 = rotateLeftBits(S[8], 55)
    b6 = rotateLeftBits(S[9], 20)
    b7 = rotateLeftBits(S[10], 3)
    b17 = rotateLeftBits(S[11], 10)
    b2 = rotateLeftBits(S[12], 43)
    b12 = rotateLeftBits(S[13], 25)
    b22 = rotateLeftBits(S[14], 39)
    b23 = rotateLeftBits(S[15], 41)
    b8 = rotateLeftBits(S[16], 45)
    b18 = rotateLeftBits(S[17], 15)
    b3 = rotateLeftBits(S[18], 21)
    b13 = rotateLeftBits(S[19], 8)
    b14 = rotateLeftBits(S[20], 18)
    b24 = rotateLeftBits(S[21], 2)
    b9 = rotateLeftBits(S[22], 61)
    b19 = rotateLeftBits(S[23], 56)
    b4 = rotateLeftBits(S[24], 14)

    S[0] = b0 xor ((not b1) and b2)
    S[1] = b1 xor ((not b2) and b3)
    S[2] = b2 xor ((not b3) and b4)
    S[3] = b3 xor ((not b4) and b0)
    S[4] = b4 xor ((not b0) and b1)
    S[5] = b5 xor ((not b6) and b7)
    S[6] = b6 xor ((not b7) and b8)
    S[7] = b7 xor ((not b8) and b9)
    S[8] = b8 xor ((not b9) and b5)
    S[9] = b9 xor ((not b5) and b6)
    S[10] = b10 xor ((not b11) and b12)
    S[11] = b11 xor ((not b12) and b13)
    S[12] = b12 xor ((not b13) and b14)
    S[13] = b13 xor ((not b14) and b10)
    S[14] = b14 xor ((not b10) and b11)
    S[15] = b15 xor ((not b16) and b17)
    S[16] = b16 xor ((not b17) and b18)
    S[17] = b17 xor ((not b18) and b19)
    S[18] = b18 xor ((not b19) and b15)
    S[19] = b19 xor ((not b15) and b16)
    S[20] = b20 xor ((not b21) and b22)
    S[21] = b21 xor ((not b22) and b23)
    S[22] = b22 xor ((not b23) and b24)
    S[23] = b23 xor ((not b24) and b20)
    S[24] = b24 xor ((not b20) and b21)

    S[0] = S[0] xor keccakRoundConstants[round]
    round = round + 1

proc sha3DigestInto*(dst: var openArray[byte], A: openArray[byte], v: Sha3Variant) =
  ## Shared fixed-length SHA3 helper for callers that already own the output buffer.
  var
    S: Sha3State
    rateBytes: int = 0
    offset: int = 0
  if dst.len != sha3DigestBytes(v):
    raise newException(ValueError, "sha3 output buffer length does not match variant")
  rateBytes = sha3RateBytes(v)
  offset = 0
  while offset + rateBytes <= A.len:
    absorbBlock(S, A, offset, rateBytes)
    keccakF1600Ref(S)
    offset = offset + rateBytes
  absorbFinalBlock(S, A, offset, rateBytes)
  keccakF1600Ref(S)
  squeezeBytesInto(S, dst, rateBytes)

proc sha3Digest*(A: openArray[byte], v: Sha3Variant): seq[byte] =
  ## Hash `A` with the selected fixed SHA3 variant.
  result = newSeq[byte](sha3DigestBytes(v))
  sha3DigestInto(result, A, v)

proc shake128AbsorbOnce*(S: var Sha3State, A: openArray[byte]) =
  ## Shared SHAKE128 absorb helper so Kyber can stream squeezes without rebuilding input buffers.
  absorbFinalPartsWithDomain(S, shake128RateBytes, shakeDomainSuffix, A)
  keccakF1600Ref(S)

proc shake256AbsorbOnce*(S: var Sha3State, A: openArray[byte]) =
  ## Shared SHAKE256 absorb helper so Dilithium can stream squeezes without rebuilding input buffers.
  absorbFinalPartsWithDomain(S, shake256RateBytes, shakeDomainSuffix, A)
  keccakF1600Ref(S)

proc shake128SqueezeBlocksInto*(S: var Sha3State, dst: var openArray[byte]) =
  ## Continue squeezing full SHAKE128 blocks from an already absorbed state.
  var
    produced: int = 0
  if dst.len mod shake128RateBytes != 0:
    raise newException(ValueError, "shake128 block squeeze requires a whole number of blocks")
  while produced < dst.len:
    store64Le(dst, produced + 0, S[0])
    store64Le(dst, produced + 8, S[1])
    store64Le(dst, produced + 16, S[2])
    store64Le(dst, produced + 24, S[3])
    store64Le(dst, produced + 32, S[4])
    store64Le(dst, produced + 40, S[5])
    store64Le(dst, produced + 48, S[6])
    store64Le(dst, produced + 56, S[7])
    store64Le(dst, produced + 64, S[8])
    store64Le(dst, produced + 72, S[9])
    store64Le(dst, produced + 80, S[10])
    store64Le(dst, produced + 88, S[11])
    store64Le(dst, produced + 96, S[12])
    store64Le(dst, produced + 104, S[13])
    store64Le(dst, produced + 112, S[14])
    store64Le(dst, produced + 120, S[15])
    store64Le(dst, produced + 128, S[16])
    store64Le(dst, produced + 136, S[17])
    store64Le(dst, produced + 144, S[18])
    store64Le(dst, produced + 152, S[19])
    store64Le(dst, produced + 160, S[20])
    produced = produced + shake128RateBytes
    keccakF1600Ref(S)

proc shake256SqueezeBlocksInto*(S: var Sha3State, dst: var openArray[byte]) =
  ## Continue squeezing full SHAKE256 blocks from an already absorbed state.
  var
    produced: int = 0
  if dst.len mod shake256RateBytes != 0:
    raise newException(ValueError, "shake256 block squeeze requires a whole number of blocks")
  while produced < dst.len:
    store64Le(dst, produced + 0, S[0])
    store64Le(dst, produced + 8, S[1])
    store64Le(dst, produced + 16, S[2])
    store64Le(dst, produced + 24, S[3])
    store64Le(dst, produced + 32, S[4])
    store64Le(dst, produced + 40, S[5])
    store64Le(dst, produced + 48, S[6])
    store64Le(dst, produced + 56, S[7])
    store64Le(dst, produced + 64, S[8])
    store64Le(dst, produced + 72, S[9])
    store64Le(dst, produced + 80, S[10])
    store64Le(dst, produced + 88, S[11])
    store64Le(dst, produced + 96, S[12])
    store64Le(dst, produced + 104, S[13])
    store64Le(dst, produced + 112, S[14])
    store64Le(dst, produced + 120, S[15])
    store64Le(dst, produced + 128, S[16])
    produced = produced + shake256RateBytes
    keccakF1600Ref(S)

proc shake256*(A: openArray[byte], outLen: int): seq[byte] =
  ## SHAKE256 XOF over `A` with arbitrary `outLen`.
  if outLen < 0:
    raise newException(ValueError, "shake256 output length must be >= 0")
  result = newSeq[byte](outLen)
  shake256Into(result, A)

proc shake256ChunksInto*(dst: var openArray[byte], A0, A1, A2: openArray[byte]) =
  ## Chunked SHAKE256 absorb path used by SPHINCS-style `R || PK || M` hashing
  ## so callers can avoid assembling temporary concatenation buffers.
  otterSpan("sha3.shake256ChunksInto"):
    var
      S: Sha3State
      blk: array[shake256RateBytes, byte]
      used: int = 0

    proc absorbPartialChunk(A: openArray[byte]) =
      var
        offset: int = 0
        take: int = 0
      if used == 0:
        while offset + shake256RateBytes <= A.len:
          absorbBlock(S, A, offset, shake256RateBytes)
          keccakF1600Ref(S)
          offset = offset + shake256RateBytes
      while offset < A.len:
        take = min(shake256RateBytes - used, A.len - offset)
        copyMem(addr blk[used], unsafeAddr A[offset], take)
        used = used + take
        offset = offset + take
        if used == shake256RateBytes:
          absorbBlock(S, blk, 0, shake256RateBytes)
          keccakF1600Ref(S)
          used = 0

    proc finalizePartial() =
      var
        finalBlock: array[shake256RateBytes, byte]
      if used > 0:
        copyMem(addr finalBlock[0], addr blk[0], used)
      finalBlock[used] = finalBlock[used] xor shakeDomainSuffix
      finalBlock[shake256RateBytes - 1] = finalBlock[shake256RateBytes - 1] xor 0x80'u8
      absorbBlock(S, finalBlock, 0, shake256RateBytes)
      keccakF1600Ref(S)

    if shake256OpenSslChunksInto(dst, A0, A1, A2):
      return
    absorbPartialChunk(A0)
    absorbPartialChunk(A1)
    absorbPartialChunk(A2)
    finalizePartial()
    squeezeBytesInto(S, dst, shake256RateBytes)

proc shake256Into*(dst: var openArray[byte], A: openArray[byte]) =
  ## SHAKE256 XOF over `A` into a preallocated output buffer.
  otterSpan("sha3.shake256Into"):
    var
      S: Sha3State
    if shake256OpenSslInto(dst, A):
      return
    shake256AbsorbOnce(S, A)
    squeezeBytesInto(S, dst, shake256RateBytes)

proc shake256Into*(dst: var openArray[byte], A0, A1: openArray[byte]) =
  ## SHAKE256 XOF over `A0 || A1` without a temporary concatenation buffer.
  var
    empty: array[0, byte]
  shake256ChunksInto(dst, A0, A1, empty)

proc shake256Into*(dst: var openArray[byte], A0, A1, A2: openArray[byte]) =
  ## SHAKE256 XOF over `A0 || A1 || A2` without a temporary concatenation buffer.
  shake256ChunksInto(dst, A0, A1, A2)

proc shake256WordsLeInto*(dst: var openArray[uint16], A: openArray[byte]) =
  ## SHAKE256 XOF over `A` into a preallocated little-endian word buffer.
  otterSpan("sha3.shake256WordsLeInto"):
    var
      S: Sha3State
      rateBytes = shake256RateBytes
      offset: int = 0
    if shake256OpenSslWordsLeInto(dst, A):
      return
    while offset + rateBytes <= A.len:
      absorbBlock(S, A, offset, rateBytes)
      keccakF1600Ref(S)
      offset = offset + rateBytes
    absorbFinalBlockWithDomain(S, A, offset, rateBytes, shakeDomainSuffix)
    keccakF1600Ref(S)
    squeezeWordsLeInto(S, dst, rateBytes)

proc shake128Into*(dst: var openArray[byte], A: openArray[byte]) =
  ## SHAKE128 XOF over `A` into a preallocated output buffer.
  var
    S: Sha3State
  shake128AbsorbOnce(S, A)
  squeezeBytesState(S, dst, shake128RateBytes)

proc shake128*(A: openArray[byte], outLen: int): seq[byte] =
  ## SHAKE128 XOF over `A` with arbitrary `outLen`.
  if outLen < 0:
    raise newException(ValueError, "shake128 output length must be >= 0")
  result = newSeq[byte](outLen)
  shake128Into(result, A)

proc sha3_224Into*(dst: var openArray[byte], A: openArray[byte]) =
  ## Hash `A` with SHA3-224 into a caller-owned buffer.
  sha3DigestInto(dst, A, svSha3_224)

proc sha3_256Into*(dst: var openArray[byte], A: openArray[byte]) =
  ## Hash `A` with SHA3-256 into a caller-owned buffer.
  sha3DigestInto(dst, A, svSha3_256)

proc sha3_384Into*(dst: var openArray[byte], A: openArray[byte]) =
  ## Hash `A` with SHA3-384 into a caller-owned buffer.
  sha3DigestInto(dst, A, svSha3_384)

proc sha3_512Into*(dst: var openArray[byte], A: openArray[byte]) =
  ## Hash `A` with SHA3-512 into a caller-owned buffer.
  sha3DigestInto(dst, A, svSha3_512)

proc sha3_224*(A: openArray[byte]): seq[byte] =
  ## Hash `A` with SHA3-224.
  result = sha3Digest(A, svSha3_224)

proc sha3_256*(A: openArray[byte]): seq[byte] =
  ## Hash `A` with SHA3-256.
  result = sha3Digest(A, svSha3_256)

proc sha3_384*(A: openArray[byte]): seq[byte] =
  ## Hash `A` with SHA3-384.
  result = sha3Digest(A, svSha3_384)

proc sha3_512*(A: openArray[byte]): seq[byte] =
  ## Hash `A` with SHA3-512.
  result = sha3Digest(A, svSha3_512)

proc sha3Hash*(A: openArray[byte], outLen: int = 32): seq[byte] =
  ## Compatibility wrapper that selects a fixed SHA3 variant from `outLen`.
  result = sha3Digest(A, sha3VariantFromOutLen(outLen))

{.pop.}

when defined(amd64) or defined(i386):
  import ./sha3_simd
  export sha3_simd
