## ---------------------------------------------------------
## SHA3 <- scalar Keccak-f[1600] hashing with fixed variants
## ---------------------------------------------------------

import std/bitops
when defined(tyrSha3OpenSslTestOnly):
  import std/[dynlib, os, strutils]
import ../../../helpers/otter_support

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

when defined(tyrSha3OpenSslTestOnly):
  ## TEST-ONLY: this optional SHAKE256 fast path exists purely for benchmarking
  ## and A/B checks against external providers. Do not enable it in production.
  static:
    echo "[Tyr-Crypto] -d:tyrSha3OpenSslTestOnly enables libcrypto-backed SHAKE256 for testing only. Never use this in production."

  const
    opensslShakeLibNames = when defined(windows):
                             @["libcrypto-3-x64.dll"]
                           elif defined(macosx):
                             @["libcrypto.3.dylib", "libcrypto.dylib"]
                           else:
                             @["libcrypto.so.3", "libcrypto.so"]

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
## stack scratch, so we disable bounds/overflow checks in this hot region to
## reduce the scalar SHA3/SHAKE overhead seen by the PQ backends.
{.push boundChecks: off, overflowChecks: off.}

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

proc store64Le(A: var openArray[byte], o: int, v: uint64) {.inline, raises: [].} =
  A[o] = byte(v and 0xff'u64)
  A[o + 1] = byte((v shr 8) and 0xff'u64)
  A[o + 2] = byte((v shr 16) and 0xff'u64)
  A[o + 3] = byte((v shr 24) and 0xff'u64)
  A[o + 4] = byte((v shr 32) and 0xff'u64)
  A[o + 5] = byte((v shr 40) and 0xff'u64)
  A[o + 6] = byte((v shr 48) and 0xff'u64)
  A[o + 7] = byte((v shr 56) and 0xff'u64)

proc absorbBlock(S: var Sha3State, A: openArray[byte], o, rateBytes: int) {.inline, raises: [].} =
  var
    lane: int = 0
    laneCount: int = 0
  laneCount = rateBytes div keccakLaneBytes
  lane = 0
  while lane < laneCount:
    S[lane] = S[lane] xor load64Le(A, o + lane * keccakLaneBytes)
    lane = lane + 1

proc absorbFinalBlockWithDomain(S: var Sha3State, A: openArray[byte], o, rateBytes: int,
    domain: byte) {.inline, raises: [].} =
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

proc keccakF1600Ref*(S: var Sha3State) {.raises: [].}
proc shake256Into*(dst: var openArray[byte], A: openArray[byte])
proc shake256Into*(dst: var openArray[byte], A0, A1: openArray[byte])
proc shake256Into*(dst: var openArray[byte], A0, A1, A2: openArray[byte])
proc shake256WordsLeInto*(dst: var openArray[uint16], A: openArray[byte])
proc shake128Into*(dst: var openArray[byte], A: openArray[byte])

proc squeezeBytesState(S: var Sha3State, dst: var openArray[byte], rateBytes: int) {.inline, raises: [].} =
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

proc squeezeBytesInto(S0: Sha3State, dst: var openArray[byte], rateBytes: int) {.inline, raises: [].} =
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
    A: openArray[byte], rateBytes: int) {.inline, raises: [].} =
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
    A: openArray[byte]) {.inline, raises: [].} =
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
    A0, A1: openArray[byte]) {.inline, raises: [].} =
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
    A0, A1, A2: openArray[byte]) {.inline, raises: [].} =
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

proc keccakF1600Ref*(S: var Sha3State) {.raises: [].} =
  ## Apply the scalar Keccak-f[1600] permutation to a 25-lane state.
  template chiRow(x0, x1, x2, x3, x4, y0, y1, y2, y3, y4: untyped) =
    x0 = y0 xor ((not y1) and y2)
    x1 = y1 xor ((not y2) and y3)
    x2 = y2 xor ((not y3) and y4)
    x3 = y3 xor ((not y4) and y0)
    x4 = y4 xor ((not y0) and y1)

  var
    a0: uint64 = S[0]
    a1: uint64 = S[1]
    a2: uint64 = S[2]
    a3: uint64 = S[3]
    a4: uint64 = S[4]
    a5: uint64 = S[5]
    a6: uint64 = S[6]
    a7: uint64 = S[7]
    a8: uint64 = S[8]
    a9: uint64 = S[9]
    a10: uint64 = S[10]
    a11: uint64 = S[11]
    a12: uint64 = S[12]
    a13: uint64 = S[13]
    a14: uint64 = S[14]
    a15: uint64 = S[15]
    a16: uint64 = S[16]
    a17: uint64 = S[17]
    a18: uint64 = S[18]
    a19: uint64 = S[19]
    a20: uint64 = S[20]
    a21: uint64 = S[21]
    a22: uint64 = S[22]
    a23: uint64 = S[23]
    a24: uint64 = S[24]
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
    c0 = a0 xor a5 xor a10 xor a15 xor a20
    c1 = a1 xor a6 xor a11 xor a16 xor a21
    c2 = a2 xor a7 xor a12 xor a17 xor a22
    c3 = a3 xor a8 xor a13 xor a18 xor a23
    c4 = a4 xor a9 xor a14 xor a19 xor a24

    d0 = c4 xor rotateLeftBits(c1, 1)
    d1 = c0 xor rotateLeftBits(c2, 1)
    d2 = c1 xor rotateLeftBits(c3, 1)
    d3 = c2 xor rotateLeftBits(c4, 1)
    d4 = c3 xor rotateLeftBits(c0, 1)

    a0 = a0 xor d0
    a5 = a5 xor d0
    a10 = a10 xor d0
    a15 = a15 xor d0
    a20 = a20 xor d0
    a1 = a1 xor d1
    a6 = a6 xor d1
    a11 = a11 xor d1
    a16 = a16 xor d1
    a21 = a21 xor d1
    a2 = a2 xor d2
    a7 = a7 xor d2
    a12 = a12 xor d2
    a17 = a17 xor d2
    a22 = a22 xor d2
    a3 = a3 xor d3
    a8 = a8 xor d3
    a13 = a13 xor d3
    a18 = a18 xor d3
    a23 = a23 xor d3
    a4 = a4 xor d4
    a9 = a9 xor d4
    a14 = a14 xor d4
    a19 = a19 xor d4
    a24 = a24 xor d4

    b0 = a0
    b10 = rotateLeftBits(a1, 1)
    b20 = rotateLeftBits(a2, 62)
    b5 = rotateLeftBits(a3, 28)
    b15 = rotateLeftBits(a4, 27)
    b16 = rotateLeftBits(a5, 36)
    b1 = rotateLeftBits(a6, 44)
    b11 = rotateLeftBits(a7, 6)
    b21 = rotateLeftBits(a8, 55)
    b6 = rotateLeftBits(a9, 20)
    b7 = rotateLeftBits(a10, 3)
    b17 = rotateLeftBits(a11, 10)
    b2 = rotateLeftBits(a12, 43)
    b12 = rotateLeftBits(a13, 25)
    b22 = rotateLeftBits(a14, 39)
    b23 = rotateLeftBits(a15, 41)
    b8 = rotateLeftBits(a16, 45)
    b18 = rotateLeftBits(a17, 15)
    b3 = rotateLeftBits(a18, 21)
    b13 = rotateLeftBits(a19, 8)
    b14 = rotateLeftBits(a20, 18)
    b24 = rotateLeftBits(a21, 2)
    b9 = rotateLeftBits(a22, 61)
    b19 = rotateLeftBits(a23, 56)
    b4 = rotateLeftBits(a24, 14)

    chiRow(a0, a1, a2, a3, a4, b0, b1, b2, b3, b4)
    chiRow(a5, a6, a7, a8, a9, b5, b6, b7, b8, b9)
    chiRow(a10, a11, a12, a13, a14, b10, b11, b12, b13, b14)
    chiRow(a15, a16, a17, a18, a19, b15, b16, b17, b18, b19)
    chiRow(a20, a21, a22, a23, a24, b20, b21, b22, b23, b24)

    a0 = a0 xor keccakRoundConstants[round]
    round = round + 1

  S[0] = a0
  S[1] = a1
  S[2] = a2
  S[3] = a3
  S[4] = a4
  S[5] = a5
  S[6] = a6
  S[7] = a7
  S[8] = a8
  S[9] = a9
  S[10] = a10
  S[11] = a11
  S[12] = a12
  S[13] = a13
  S[14] = a14
  S[15] = a15
  S[16] = a16
  S[17] = a17
  S[18] = a18
  S[19] = a19
  S[20] = a20
  S[21] = a21
  S[22] = a22
  S[23] = a23
  S[24] = a24

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

proc shake128AbsorbOnce*(S: var Sha3State, A: openArray[byte]) {.inline, raises: [].} =
  ## Shared SHAKE128 absorb helper so Kyber can stream squeezes without rebuilding input buffers.
  absorbFinalPartsWithDomain(S, shake128RateBytes, shakeDomainSuffix, A)
  keccakF1600Ref(S)

proc shake256AbsorbOnce*(S: var Sha3State, A: openArray[byte]) {.inline, raises: [].} =
  ## Shared SHAKE256 absorb helper so Dilithium can stream squeezes without rebuilding input buffers.
  absorbFinalPartsWithDomain(S, shake256RateBytes, shakeDomainSuffix, A)
  keccakF1600Ref(S)

template shake256OneBlockAlignedInto*(dst, msg: untyped) =
  ## Specialized SHAKE256 path for one-block, 8-byte-aligned inputs.
  ## SPHINCS hits this shape constantly for `pub_seed || addr || input`.
  block:
    static:
      doAssert msg.len > 0
      doAssert msg.len < shake256RateBytes
      doAssert (msg.len mod 8) == 0
    var
      S: Sha3State
    when msg.len == 64:
      S[0] = load64Le(msg, 0)
      S[1] = load64Le(msg, 8)
      S[2] = load64Le(msg, 16)
      S[3] = load64Le(msg, 24)
      S[4] = load64Le(msg, 32)
      S[5] = load64Le(msg, 40)
      S[6] = load64Le(msg, 48)
      S[7] = load64Le(msg, 56)
      S[8] = uint64(shakeDomainSuffix)
    elif msg.len == 80:
      S[0] = load64Le(msg, 0)
      S[1] = load64Le(msg, 8)
      S[2] = load64Le(msg, 16)
      S[3] = load64Le(msg, 24)
      S[4] = load64Le(msg, 32)
      S[5] = load64Le(msg, 40)
      S[6] = load64Le(msg, 48)
      S[7] = load64Le(msg, 56)
      S[8] = load64Le(msg, 64)
      S[9] = load64Le(msg, 72)
      S[10] = uint64(shakeDomainSuffix)
    else:
      var lane: int = 0
      while lane * keccakLaneBytes < msg.len:
        S[lane] = load64Le(msg, lane * keccakLaneBytes)
        lane = lane + 1
      S[msg.len div keccakLaneBytes] = S[msg.len div keccakLaneBytes] xor uint64(shakeDomainSuffix)
    S[(shake256RateBytes - 1) div keccakLaneBytes] =
      S[(shake256RateBytes - 1) div keccakLaneBytes] xor
      (0x80'u64 shl (8 * ((shake256RateBytes - 1) mod keccakLaneBytes)))
    keccakF1600Ref(S)
    if dst.len == 16:
      store64Le(dst, 0, S[0])
      store64Le(dst, 8, S[1])
    else:
      squeezeBytesInto(S, dst, shake256RateBytes)

proc shake128SqueezeBlocksIntoUnchecked*(S: var Sha3State, dst: var openArray[byte]) {.inline, raises: [].} =
  var
    produced: int = 0
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

proc shake128SqueezeBlocksInto*(S: var Sha3State, dst: var openArray[byte]) =
  ## Continue squeezing full SHAKE128 blocks from an already absorbed state.
  if dst.len mod shake128RateBytes != 0:
    raise newException(ValueError, "shake128 block squeeze requires a whole number of blocks")
  shake128SqueezeBlocksIntoUnchecked(S, dst)

proc shake256SqueezeBlocksIntoUnchecked*(S: var Sha3State, dst: var openArray[byte]) {.inline, raises: [].} =
  var
    produced: int = 0
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

proc shake256SqueezeBlocksInto*(S: var Sha3State, dst: var openArray[byte]) =
  ## Continue squeezing full SHAKE256 blocks from an already absorbed state.
  if dst.len mod shake256RateBytes != 0:
    raise newException(ValueError, "shake256 block squeeze requires a whole number of blocks")
  shake256SqueezeBlocksIntoUnchecked(S, dst)

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

    when defined(tyrSha3OpenSslTestOnly):
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
    when defined(tyrSha3OpenSslTestOnly):
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
    when defined(tyrSha3OpenSslTestOnly):
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
