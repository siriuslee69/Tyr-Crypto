## -----------------------------------------------------------------------
## Argon2 <- scalar Argon2i/Argon2id password hashing in Nim
## -> Ported from libsodium's reference Argon2 path without SIMD branches
## -> Keeps the memory-hard primitive local to custom_crypto
## -----------------------------------------------------------------------

import ../blake3/blake3
import ../gimli/gimli_sponge
import ../secure_memory

when defined(sse2) or defined(avx2) or defined(neon) or defined(arm64) or defined(aarch64):
  import ./argon2_simd
  export argon2_simd

const
  argon2Version* = 19
  argon2SaltBytes* = 16
  argon2OutLenDefault* = 32
  argon2MinOutLen* = 16
  argon2MinSaltBytes* = 8
  argon2BlockSize = 1024
  argon2QwordsInBlock = argon2BlockSize div 8
  argon2SyncPoints = 4
  argon2AddressesInBlock = 128
  argon2PrehashDigestLength = 64
  blake2bBlockSize = 128
  blake2bDigestBytes = 64
  blake2bHalfDigestBytes = 32
  blake2bIv = [
    0x6A09E667F3BCC908'u64, 0xBB67AE8584CAA73B'u64,
    0x3C6EF372FE94F82B'u64, 0xA54FF53A5F1D36F1'u64,
    0x510E527FADE682D1'u64, 0x9B05688C2B3E6C1F'u64,
    0x1F83D9ABFB41BD6B'u64, 0x5BE0CD19137E2179'u64
  ]
  blake2bSigma = [
    [0'u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14'u8, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11'u8, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7'u8, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9'u8, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2'u8, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12'u8, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13'u8, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6'u8, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10'u8, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]
  ]

type
  Argon2Algorithm* = enum
    a2Argon2i,
    a2Argon2id

  Argon2HashAlgorithm* = enum
    ## Standard Argon2 input/final hash path backed by BLAKE2b/BLAKE2b-long.
    a2hBlake2b,
    ## Custom Argon-style variant backed by BLAKE3 XOF output.
    a2hBlake3,
    ## Custom Argon-style variant backed by the Gimli sponge XOF.
    a2hGimli

  Argon2Backend* = enum
    a2bAuto,
    a2bScalar,
    a2bSse2,
    a2bNeon,
    a2bAvx2

  Argon2Params* = object
    passCount*: int
    memoryKiB*: int
    laneCount*: int
    outLen*: int

  Blake2bState = object
    chain: array[8, uint64]
    counter0: uint64
    counter1: uint64
    buffer: array[blake2bBlockSize, byte]
    bufferLen: int
    outLen: int

  ArgonBlock = array[argon2QwordsInBlock, uint64]

  ArgonInstance = object
    memory: seq[ArgonBlock]
    pseudoRands: seq[uint64]
    passCount: int
    memoryBlocks: int
    segmentLength: int
    laneLength: int
    laneCount: int
    algorithm: Argon2Algorithm

  ArgonPosition = object
    passIndex: int
    laneIndex: int
    sliceIndex: int
    blockIndex: int


proc appendBytes(B: var seq[byte], A: openArray[byte]) =
  ## B: destination byte buffer.
  ## A: bytes to append.
  var
    i: int = 0
  i = 0
  while i < A.len:
    B.add(A[i])
    i = i + 1


proc appendUint32Le(B: var seq[byte], v: uint32) =
  ## B: destination byte buffer.
  ## v: value to encode in little-endian form.
  var
    i: int = 0
  i = 0
  while i < 4:
    B.add(byte((v shr (i * 8)) and 0xff'u32))
    i = i + 1


proc loadUint64Le(A: openArray[byte], offset: int): uint64 =
  ## A: byte source.
  ## offset: starting byte offset.
  var
    i: int = 0
  i = 0
  while i < 8:
    result = result or (uint64(A[offset + i]) shl (i * 8))
    i = i + 1


proc storeUint64Le(A: var openArray[byte], offset: int, v: uint64) =
  ## A: destination byte buffer.
  ## offset: starting byte offset.
  ## v: value to encode in little-endian form.
  var
    i: int = 0
  i = 0
  while i < 8:
    A[offset + i] = byte((v shr (i * 8)) and 0xff'u64)
    i = i + 1


proc rotateRight64(v: uint64, shiftCount: int): uint64 =
  ## v: word to rotate.
  ## shiftCount: number of right-rotation bits.
  result = (v shr shiftCount) or (v shl (64 - shiftCount))


template blake2bG(V, a, b, c, d, x, y: untyped) =
  V[a] = V[a] + V[b] + x
  V[d] = rotateRight64(V[d] xor V[a], 32)
  V[c] = V[c] + V[d]
  V[b] = rotateRight64(V[b] xor V[c], 24)
  V[a] = V[a] + V[b] + y
  V[d] = rotateRight64(V[d] xor V[a], 16)
  V[c] = V[c] + V[d]
  V[b] = rotateRight64(V[b] xor V[c], 63)


template blake2bRound(V, M, roundIndex: untyped) =
  blake2bG(V, 0, 4, 8, 12, M[blake2bSigma[roundIndex][0]], M[blake2bSigma[roundIndex][1]])
  blake2bG(V, 1, 5, 9, 13, M[blake2bSigma[roundIndex][2]], M[blake2bSigma[roundIndex][3]])
  blake2bG(V, 2, 6, 10, 14, M[blake2bSigma[roundIndex][4]], M[blake2bSigma[roundIndex][5]])
  blake2bG(V, 3, 7, 11, 15, M[blake2bSigma[roundIndex][6]], M[blake2bSigma[roundIndex][7]])
  blake2bG(V, 0, 5, 10, 15, M[blake2bSigma[roundIndex][8]], M[blake2bSigma[roundIndex][9]])
  blake2bG(V, 1, 6, 11, 12, M[blake2bSigma[roundIndex][10]], M[blake2bSigma[roundIndex][11]])
  blake2bG(V, 2, 7, 8, 13, M[blake2bSigma[roundIndex][12]], M[blake2bSigma[roundIndex][13]])
  blake2bG(V, 3, 4, 9, 14, M[blake2bSigma[roundIndex][14]], M[blake2bSigma[roundIndex][15]])


proc compressBlake2b(S: var Blake2bState, isLast: bool) =
  ## S: BLAKE2b state to compress.
  ## isLast: marks the final block.
  var
    V: array[16, uint64]
    M: array[16, uint64]
    i: int = 0
  defer:
    secureClearPod(V)
    secureClearPod(M)
  i = 0
  while i < 8:
    V[i] = S.chain[i]
    V[i + 8] = blake2bIv[i]
    i = i + 1
  V[12] = V[12] xor S.counter0
  V[13] = V[13] xor S.counter1
  if isLast:
    V[14] = not V[14]
  i = 0
  while i < 16:
    M[i] = loadUint64Le(S.buffer, i * 8)
    i = i + 1
  blake2bRound(V, M, 0)
  blake2bRound(V, M, 1)
  blake2bRound(V, M, 2)
  blake2bRound(V, M, 3)
  blake2bRound(V, M, 4)
  blake2bRound(V, M, 5)
  blake2bRound(V, M, 6)
  blake2bRound(V, M, 7)
  blake2bRound(V, M, 8)
  blake2bRound(V, M, 9)
  blake2bRound(V, M, 0)
  blake2bRound(V, M, 1)
  i = 0
  while i < 8:
    S.chain[i] = S.chain[i] xor V[i] xor V[i + 8]
    i = i + 1


proc addBlake2bCounter(S: var Blake2bState, amount: int) =
  ## S: BLAKE2b state to update.
  ## amount: processed byte count to add.
  var
    previous: uint64 = S.counter0
  S.counter0 = S.counter0 + uint64(amount)
  if S.counter0 < previous:
    S.counter1 = S.counter1 + 1'u64


proc initBlake2b(S: var Blake2bState, outLen: int) =
  ## S: BLAKE2b state to initialize.
  ## outLen: requested digest length in bytes.
  var
    i: int = 0
  if outLen <= 0 or outLen > blake2bDigestBytes:
    raise newException(ValueError, "BLAKE2b output length must be in 1..64")
  i = 0
  while i < blake2bBlockSize:
    S.buffer[i] = 0
    i = i + 1
  i = 0
  while i < 8:
    S.chain[i] = blake2bIv[i]
    i = i + 1
  S.chain[0] = S.chain[0] xor (0x01010000'u64 xor uint64(outLen))
  S.counter0 = 0'u64
  S.counter1 = 0'u64
  S.bufferLen = 0
  S.outLen = outLen


proc updateBlake2b(S: var Blake2bState, A: openArray[byte]) =
  ## S: BLAKE2b state to update.
  ## A: input bytes to absorb.
  var
    i: int = 0
  i = 0
  while i < A.len:
    if S.bufferLen == blake2bBlockSize:
      addBlake2bCounter(S, blake2bBlockSize)
      compressBlake2b(S, false)
      S.bufferLen = 0
    S.buffer[S.bufferLen] = A[i]
    S.bufferLen = S.bufferLen + 1
    i = i + 1


proc finishBlake2b(S: var Blake2bState): seq[byte] =
  ## S: BLAKE2b state to finalize.
  var
    i: int = 0
  addBlake2bCounter(S, S.bufferLen)
  i = S.bufferLen
  while i < blake2bBlockSize:
    S.buffer[i] = 0
    i = i + 1
  compressBlake2b(S, true)
  result = newSeq[byte](S.outLen)
  i = 0
  while i < S.outLen:
    result[i] = byte((S.chain[i shr 3] shr (8 * (i and 7))) and 0xff'u64)
    i = i + 1


proc blake2bHash(A: openArray[byte], outLen: int): seq[byte] =
  ## A: input bytes.
  ## outLen: requested digest length in bytes.
  var
    S: Blake2bState
  defer:
    secureClearPod(S)
  initBlake2b(S, outLen)
  updateBlake2b(S, A)
  result = finishBlake2b(S)


proc copyInto(D: var seq[byte], offset: int, A: openArray[byte], take: int) =
  ## D: destination byte buffer.
  ## offset: write start inside D.
  ## A: source bytes.
  ## take: number of bytes to copy.
  var
    i: int = 0
  i = 0
  while i < take:
    D[offset + i] = A[i]
    i = i + 1


proc blake2bLong(A: openArray[byte], outLen: int): seq[byte] =
  ## A: input bytes.
  ## outLen: requested output length in bytes.
  var
    input: seq[byte] = @[]
    outBuffer: seq[byte] = @[]
    inBuffer: seq[byte] = @[]
    produced: int = 0
    remaining: int = 0
  if outLen <= 0:
    raise newException(ValueError, "Argon2 hash output length must be positive")
  if uint64(outLen) > uint64(high(uint32)):
    raise newException(ValueError, "Argon2 hash output length is too large")
  input = newSeqOfCap[byte](A.len + 4)
  appendUint32Le(input, uint32(outLen))
  appendBytes(input, A)
  if outLen <= blake2bDigestBytes:
    result = blake2bHash(input, outLen)
    return
  outBuffer = blake2bHash(input, blake2bDigestBytes)
  result = newSeq[byte](outLen)
  copyInto(result, 0, outBuffer, blake2bHalfDigestBytes)
  produced = blake2bHalfDigestBytes
  remaining = outLen - blake2bHalfDigestBytes
  while remaining > blake2bDigestBytes:
    inBuffer = outBuffer
    outBuffer = blake2bHash(inBuffer, blake2bDigestBytes)
    copyInto(result, produced, outBuffer, blake2bHalfDigestBytes)
    produced = produced + blake2bHalfDigestBytes
    remaining = remaining - blake2bHalfDigestBytes
  inBuffer = outBuffer
  outBuffer = blake2bHash(inBuffer, remaining)
  copyInto(result, produced, outBuffer, remaining)


proc fixedHash(A: openArray[byte], outLen: int,
    h: Argon2HashAlgorithm): seq[byte] =
  ## A: input bytes.
  ## outLen: requested digest length in bytes.
  ## h: selected hash primitive for the Argon front/back hash steps.
  case h
  of a2hBlake2b:
    result = blake2bHash(A, outLen)
  of a2hBlake3:
    result = blake3Hash(A, outLen)
  of a2hGimli:
    result = gimliXof(@[], @[], A, outLen)


proc xofHash(A: openArray[byte], outLen: int,
    h: Argon2HashAlgorithm): seq[byte] =
  ## A: input bytes.
  ## outLen: requested digest length in bytes.
  ## h: selected extendable-output primitive for block seeding/finalization.
  case h
  of a2hBlake2b:
    result = blake2bLong(A, outLen)
  of a2hBlake3:
    result = blake3Hash(A, outLen)
  of a2hGimli:
    result = gimliXof(@[], @[], A, outLen)


proc algorithmCode(a: Argon2Algorithm): uint32 =
  ## a: Argon2 variant selector.
  case a
  of a2Argon2i:
    result = 1'u32
  of a2Argon2id:
    result = 2'u32


proc initArgon2Params*(passCount, memoryKiB, laneCount, outLen: int): Argon2Params =
  ## passCount: number of Argon2 passes.
  ## memoryKiB: requested memory in kibibytes.
  ## laneCount: number of lanes for the memory matrix.
  ## outLen: requested hash length in bytes.
  result.passCount = passCount
  result.memoryKiB = memoryKiB
  result.laneCount = laneCount
  result.outLen = outLen


proc resolveArgon2Backend*(b: Argon2Backend): Argon2Backend =
  ## b: requested execution backend.
  when defined(avx2):
    if b == a2bAuto:
      return a2bAvx2
  else:
    if b == a2bAvx2:
      return a2bScalar
  when defined(sse2):
    if b == a2bSse2:
      return a2bSse2
  else:
    if b == a2bSse2:
      return a2bScalar
  when defined(neon) or defined(arm64) or defined(aarch64):
    if b == a2bNeon:
      return a2bNeon
  else:
    if b == a2bNeon:
      return a2bScalar
  if b == a2bAuto:
    when defined(avx2):
      return a2bAvx2
    elif defined(neon) or defined(arm64) or defined(aarch64):
      return a2bNeon
    elif defined(sse2):
      return a2bSse2
    else:
      return a2bScalar
  result = b


proc validateArgon2Params(p: Argon2Params, passwordLen, saltLen: int) =
  ## p: Argon2 parameter set.
  ## passwordLen: password byte length.
  ## saltLen: salt byte length.
  if p.passCount < 1:
    raise newException(ValueError, "Argon2 pass count must be at least 1")
  if p.memoryKiB < 2 * argon2SyncPoints:
    raise newException(ValueError, "Argon2 memory cost must be at least 8 KiB")
  if p.laneCount < 1:
    raise newException(ValueError, "Argon2 lane count must be at least 1")
  if p.outLen < argon2MinOutLen:
    raise newException(ValueError, "Argon2 output length must be at least 16 bytes")
  if saltLen < argon2MinSaltBytes:
    raise newException(ValueError, "Argon2 salt length must be at least 8 bytes")
  if uint64(p.passCount) > uint64(high(uint32)):
    raise newException(ValueError, "Argon2 pass count is too large")
  if uint64(p.memoryKiB) > uint64(high(uint32)):
    raise newException(ValueError, "Argon2 memory cost is too large")
  if uint64(p.laneCount) > uint64(high(uint32)):
    raise newException(ValueError, "Argon2 lane count is too large")
  if uint64(p.outLen) > uint64(high(uint32)):
    raise newException(ValueError, "Argon2 output length is too large")
  if uint64(passwordLen) > uint64(high(uint32)):
    raise newException(ValueError, "Argon2 password length is too large")
  if uint64(saltLen) > uint64(high(uint32)):
    raise newException(ValueError, "Argon2 salt length is too large")
  if p.memoryKiB < 2 * argon2SyncPoints * p.laneCount:
    raise newException(ValueError, "Argon2 memory cost must fit at least 8 blocks per lane")


proc alignedMemoryBlocks(memoryKiB, laneCount: int): int =
  ## memoryKiB: requested memory in kibibytes.
  ## laneCount: requested number of lanes.
  var
    memoryBlocks: int = memoryKiB
    minBlocks: int = 2 * argon2SyncPoints * laneCount
    stride: int = laneCount * argon2SyncPoints
  if memoryBlocks < minBlocks:
    memoryBlocks = minBlocks
  result = (memoryBlocks div stride) * stride


proc buildInitialHashInput(a: Argon2Algorithm, password,
    salt: openArray[byte], p: Argon2Params): seq[byte] =
  ## a: Argon2 variant selector.
  ## password: password bytes.
  ## salt: salt bytes.
  ## p: Argon2 parameter set.
  var
    B: seq[byte] = @[]
  B = newSeqOfCap[byte](48 + password.len + salt.len)
  appendUint32Le(B, uint32(p.laneCount))
  appendUint32Le(B, uint32(p.outLen))
  appendUint32Le(B, uint32(p.memoryKiB))
  appendUint32Le(B, uint32(p.passCount))
  appendUint32Le(B, uint32(argon2Version))
  appendUint32Le(B, algorithmCode(a))
  appendUint32Le(B, uint32(password.len))
  appendBytes(B, password)
  appendUint32Le(B, uint32(salt.len))
  appendBytes(B, salt)
  appendUint32Le(B, 0'u32)
  appendUint32Le(B, 0'u32)
  result = B


proc buildInitialHash(a: Argon2Algorithm, password, salt: openArray[byte],
    p: Argon2Params, h: Argon2HashAlgorithm): seq[byte] =
  ## a: Argon2 variant selector.
  ## password: password bytes.
  ## salt: salt bytes.
  ## p: Argon2 parameter set.
  ## h: selected hash primitive.
  var
    input: seq[byte] = buildInitialHashInput(a, password, salt, p)
  defer:
    secureClearBytes(input)
  result = fixedHash(input, argon2PrehashDigestLength, h)


proc buildFirstBlockSeed(initialHash: openArray[byte], blockIndex,
    laneIndex: int): seq[byte] =
  ## initialHash: 64-byte Argon2 prehash digest.
  ## blockIndex: first-block selector inside the lane.
  ## laneIndex: lane selector.
  var
    B: seq[byte] = @[]
  B = newSeqOfCap[byte](argon2PrehashDigestLength + 8)
  appendBytes(B, initialHash)
  appendUint32Le(B, uint32(blockIndex))
  appendUint32Le(B, uint32(laneIndex))
  result = B


proc loadBlock(A: openArray[byte]): ArgonBlock =
  ## A: 1024-byte block input in little-endian order.
  var
    i: int = 0
  if A.len != argon2BlockSize:
    raise newException(ValueError, "Argon2 block loader requires 1024 bytes")
  i = 0
  while i < argon2QwordsInBlock:
    result[i] = loadUint64Le(A, i * 8)
    i = i + 1


proc blockToBytes(B: ArgonBlock): seq[byte] =
  ## B: 1024-byte Argon2 block split into 64-bit words.
  var
    i: int = 0
  result = newSeq[byte](argon2BlockSize)
  i = 0
  while i < argon2QwordsInBlock:
    storeUint64Le(result, i * 8, B[i])
    i = i + 1


proc fBlaMka(x, y: uint64): uint64 =
  ## x: left 64-bit input word.
  ## y: right 64-bit input word.
  var
    lowMask: uint64 = 0xffffffff'u64
    product: uint64 = (x and lowMask) * (y and lowMask)
  result = x + y + (product shl 1)


template argon2G(V, a, b, c, d: untyped) =
  V[a] = fBlaMka(V[a], V[b])
  V[d] = rotateRight64(V[d] xor V[a], 32)
  V[c] = fBlaMka(V[c], V[d])
  V[b] = rotateRight64(V[b] xor V[c], 24)
  V[a] = fBlaMka(V[a], V[b])
  V[d] = rotateRight64(V[d] xor V[a], 16)
  V[c] = fBlaMka(V[c], V[d])
  V[b] = rotateRight64(V[b] xor V[c], 63)


proc applyArgon2Rounds(B: var ArgonBlock) =
  ## B: Argon2 block to permute in place.
  var
    i: int = 0
    base: int = 0
  i = 0
  while i < 8:
    base = 16 * i
    argon2G(B, base + 0, base + 4, base + 8, base + 12)
    argon2G(B, base + 1, base + 5, base + 9, base + 13)
    argon2G(B, base + 2, base + 6, base + 10, base + 14)
    argon2G(B, base + 3, base + 7, base + 11, base + 15)
    argon2G(B, base + 0, base + 5, base + 10, base + 15)
    argon2G(B, base + 1, base + 6, base + 11, base + 12)
    argon2G(B, base + 2, base + 7, base + 8, base + 13)
    argon2G(B, base + 3, base + 4, base + 9, base + 14)
    i = i + 1
  i = 0
  while i < 8:
    argon2G(B, 2 * i, 2 * i + 32, 2 * i + 64, 2 * i + 96)
    argon2G(B, 2 * i + 1, 2 * i + 33, 2 * i + 65, 2 * i + 97)
    argon2G(B, 2 * i + 16, 2 * i + 48, 2 * i + 80, 2 * i + 112)
    argon2G(B, 2 * i + 17, 2 * i + 49, 2 * i + 81, 2 * i + 113)
    argon2G(B, 2 * i, 2 * i + 33, 2 * i + 80, 2 * i + 113)
    argon2G(B, 2 * i + 1, 2 * i + 48, 2 * i + 81, 2 * i + 96)
    argon2G(B, 2 * i + 16, 2 * i + 49, 2 * i + 64, 2 * i + 97)
    argon2G(B, 2 * i + 17, 2 * i + 32, 2 * i + 65, 2 * i + 112)
    i = i + 1


proc copyBlockWords(D: var ArgonBlock, A: openArray[uint64]) =
  ## D: destination block words.
  ## A: source block words.
  var
    i: int = 0
  i = 0
  while i < argon2QwordsInBlock:
    D[i] = A[i]
    i = i + 1


proc applyArgon2RoundsScalar*(B: var openArray[uint64]) =
  ## B: Argon2 block words to permute with the scalar core.
  var
    tmpBlock: ArgonBlock
  if B.len != argon2QwordsInBlock:
    raise newException(ValueError, "Argon2 scalar round helper requires 128 words")
  copyBlockWords(tmpBlock, B)
  applyArgon2Rounds(tmpBlock)
  var
    i: int = 0
  i = 0
  while i < argon2QwordsInBlock:
    B[i] = tmpBlock[i]
    i = i + 1


proc xorBlock(D: var ArgonBlock, S: ArgonBlock) =
  ## D: destination block to xor into.
  ## S: source block.
  var
    i: int = 0
  i = 0
  while i < argon2QwordsInBlock:
    D[i] = D[i] xor S[i]
    i = i + 1


proc fillBlock(prevBlock, refBlock: ArgonBlock): ArgonBlock


proc fillBlockWithXor(prevBlock, refBlock, nextBlock: ArgonBlock): ArgonBlock


proc fillBlockScalar*(prevBlock, refBlock: openArray[uint64],
    outBlock: var openArray[uint64]) =
  ## prevBlock: previous block inside the lane.
  ## refBlock: referenced block selected by the index function.
  ## outBlock: destination block.
  var
    prevArr: ArgonBlock
    refArr: ArgonBlock
    outArr: ArgonBlock
    i: int = 0
  if prevBlock.len != argon2QwordsInBlock or refBlock.len != argon2QwordsInBlock or
      outBlock.len != argon2QwordsInBlock:
    raise newException(ValueError, "Argon2 scalar block helper requires 128 words")
  copyBlockWords(prevArr, prevBlock)
  copyBlockWords(refArr, refBlock)
  outArr = fillBlock(prevArr, refArr)
  i = 0
  while i < argon2QwordsInBlock:
    outBlock[i] = outArr[i]
    i = i + 1


proc fillBlockWithXorScalar*(prevBlock, refBlock, nextBlock: openArray[uint64],
    outBlock: var openArray[uint64]) =
  ## prevBlock: previous block inside the lane.
  ## refBlock: referenced block selected by the index function.
  ## nextBlock: existing destination block for pass>0 xor mode.
  ## outBlock: destination block.
  var
    prevArr: ArgonBlock
    refArr: ArgonBlock
    nextArr: ArgonBlock
    outArr: ArgonBlock
    i: int = 0
  if prevBlock.len != argon2QwordsInBlock or refBlock.len != argon2QwordsInBlock or
      nextBlock.len != argon2QwordsInBlock or outBlock.len != argon2QwordsInBlock:
    raise newException(ValueError, "Argon2 scalar xor-block helper requires 128 words")
  copyBlockWords(prevArr, prevBlock)
  copyBlockWords(refArr, refBlock)
  copyBlockWords(nextArr, nextBlock)
  outArr = fillBlockWithXor(prevArr, refArr, nextArr)
  i = 0
  while i < argon2QwordsInBlock:
    outBlock[i] = outArr[i]
    i = i + 1


proc fillBlock(prevBlock, refBlock: ArgonBlock, backend: Argon2Backend): ArgonBlock =
  ## prevBlock: previous block inside the lane.
  ## refBlock: referenced block selected by the index function.
  ## backend: resolved execution backend.
  case backend
  of a2bAvx2:
    when defined(avx2):
      fillArgon2BlockAvx4x(prevBlock, refBlock, result)
    else:
      result = fillBlock(prevBlock, refBlock)
  of a2bNeon:
    when defined(neon) or defined(arm64) or defined(aarch64):
      fillArgon2BlockNeon2x(prevBlock, refBlock, result)
    else:
      result = fillBlock(prevBlock, refBlock)
  of a2bSse2:
    when defined(sse2):
      fillArgon2BlockSse2x(prevBlock, refBlock, result)
    else:
      result = fillBlock(prevBlock, refBlock)
  else:
    result = fillBlock(prevBlock, refBlock)


proc fillBlockWithXor(prevBlock, refBlock, nextBlock: ArgonBlock,
    backend: Argon2Backend): ArgonBlock =
  ## prevBlock: previous block inside the lane.
  ## refBlock: referenced block selected by the index function.
  ## nextBlock: existing destination block for pass>0 xor mode.
  ## backend: resolved execution backend.
  case backend
  of a2bAvx2:
    when defined(avx2):
      fillArgon2BlockWithXorAvx4x(prevBlock, refBlock, nextBlock, result)
    else:
      result = fillBlockWithXor(prevBlock, refBlock, nextBlock)
  of a2bNeon:
    when defined(neon) or defined(arm64) or defined(aarch64):
      fillArgon2BlockWithXorNeon2x(prevBlock, refBlock, nextBlock, result)
    else:
      result = fillBlockWithXor(prevBlock, refBlock, nextBlock)
  of a2bSse2:
    when defined(sse2):
      fillArgon2BlockWithXorSse2x(prevBlock, refBlock, nextBlock, result)
    else:
      result = fillBlockWithXor(prevBlock, refBlock, nextBlock)
  else:
    result = fillBlockWithXor(prevBlock, refBlock, nextBlock)


proc fillBlock(prevBlock, refBlock: ArgonBlock): ArgonBlock =
  ## prevBlock: previous block inside the lane.
  ## refBlock: referenced block selected by the index function.
  var
    blockR: ArgonBlock = refBlock
  xorBlock(blockR, prevBlock)
  result = blockR
  applyArgon2Rounds(blockR)
  xorBlock(result, blockR)


proc fillBlockWithXor(prevBlock, refBlock, nextBlock: ArgonBlock): ArgonBlock =
  ## prevBlock: previous block inside the lane.
  ## refBlock: referenced block selected by the index function.
  ## nextBlock: existing destination block for pass>0 xor mode.
  var
    blockR: ArgonBlock = refBlock
  xorBlock(blockR, prevBlock)
  result = blockR
  xorBlock(result, nextBlock)
  applyArgon2Rounds(blockR)
  xorBlock(result, blockR)


proc usesDataIndependentAddressing(a: Argon2Algorithm, passIndex,
    sliceIndex: int): bool =
  ## a: Argon2 variant selector.
  ## passIndex: current pass index.
  ## sliceIndex: current slice index.
  result = true
  if a == a2Argon2id and (passIndex != 0 or sliceIndex >= argon2SyncPoints div 2):
    result = false


proc generateAddresses(I: ArgonInstance, P: ArgonPosition,
    R: var seq[uint64], backend: Argon2Backend) =
  ## I: current Argon2 instance state.
  ## P: current fill position.
  ## R: reusable pseudo-random address buffer.
  var
    zeroBlock: ArgonBlock
    inputBlock: ArgonBlock
    addressBlock: ArgonBlock
    tmpBlock: ArgonBlock
    i: int = 0
  defer:
    secureClearPod(zeroBlock)
    secureClearPod(inputBlock)
    secureClearPod(addressBlock)
    secureClearPod(tmpBlock)
  if R.len != I.segmentLength:
    R.setLen(I.segmentLength)
  inputBlock[0] = uint64(P.passIndex)
  inputBlock[1] = uint64(P.laneIndex)
  inputBlock[2] = uint64(P.sliceIndex)
  inputBlock[3] = uint64(I.memoryBlocks)
  inputBlock[4] = uint64(I.passCount)
  inputBlock[5] = uint64(algorithmCode(I.algorithm))
  i = 0
  while i < I.segmentLength:
    if (i mod argon2AddressesInBlock) == 0:
      inputBlock[6] = inputBlock[6] + 1'u64
      tmpBlock = fillBlock(zeroBlock, inputBlock, backend)
      addressBlock = fillBlock(zeroBlock, tmpBlock, backend)
    R[i] = addressBlock[i mod argon2AddressesInBlock]
    i = i + 1


proc calcReferenceAreaSize(I: ArgonInstance, P: ArgonPosition,
    sameLane: bool): int =
  ## I: current Argon2 instance state.
  ## P: current fill position.
  ## sameLane: true when the referenced block stays in the active lane.
  if P.passIndex == 0:
    if P.sliceIndex == 0:
      result = P.blockIndex - 1
      return
    if sameLane:
      result = P.sliceIndex * I.segmentLength + P.blockIndex - 1
      return
    result = P.sliceIndex * I.segmentLength
    if P.blockIndex == 0:
      result = result - 1
    return
  if sameLane:
    result = I.laneLength - I.segmentLength + P.blockIndex - 1
    return
  result = I.laneLength - I.segmentLength
  if P.blockIndex == 0:
    result = result - 1


proc indexAlpha(I: ArgonInstance, P: ArgonPosition,
    pseudoRandLow: uint32, sameLane: bool): int =
  ## I: current Argon2 instance state.
  ## P: current fill position.
  ## pseudoRandLow: low 32 bits used for the skewed position map.
  ## sameLane: true when the referenced block stays in the active lane.
  var
    referenceAreaSize: int = calcReferenceAreaSize(I, P, sameLane)
    relativePosition: uint64 = uint64(pseudoRandLow)
    startPosition: int = 0
  relativePosition = (relativePosition * relativePosition) shr 32
  relativePosition = uint64(referenceAreaSize - 1) -
    ((uint64(referenceAreaSize) * relativePosition) shr 32)
  if P.passIndex != 0:
    if P.sliceIndex == argon2SyncPoints - 1:
      startPosition = 0
    else:
      startPosition = (P.sliceIndex + 1) * I.segmentLength
  result = startPosition + int(relativePosition) - I.laneLength
  if result < 0:
    result = result + I.laneLength


proc fillFirstBlocks(I: var ArgonInstance, initialHash: openArray[byte],
    h: Argon2HashAlgorithm) =
  ## I: current Argon2 instance state.
  ## initialHash: 64-byte Argon2 prehash digest.
  ## h: selected extendable-output primitive.
  var
    laneIndex: int = 0
    seedBytes: seq[byte] = @[]
  defer:
    secureClearBytes(seedBytes)
  laneIndex = 0
  while laneIndex < I.laneCount:
    seedBytes = buildFirstBlockSeed(initialHash, 0, laneIndex)
    I.memory[laneIndex * I.laneLength] = loadBlock(xofHash(seedBytes,
      argon2BlockSize, h))
    seedBytes = buildFirstBlockSeed(initialHash, 1, laneIndex)
    I.memory[laneIndex * I.laneLength + 1] = loadBlock(xofHash(seedBytes,
      argon2BlockSize, h))
    secureClearBytes(seedBytes)
    laneIndex = laneIndex + 1


proc fillSegment(I: var ArgonInstance, P0: ArgonPosition,
    backend: Argon2Backend) =
  ## I: current Argon2 instance state.
  ## P0: current pass/lane/slice position to fill.
  var
    P: ArgonPosition = P0
    startingIndex: int = 0
    currentOffset: int = 0
    previousOffset: int = 0
    i: int = 0
    pseudoRand: uint64 = 0
    refLane: int = 0
    refIndex: int = 0
    refOffset: int = 0
    dataIndependent: bool = usesDataIndependentAddressing(I.algorithm,
      P.passIndex, P.sliceIndex)
  if dataIndependent:
    generateAddresses(I, P, I.pseudoRands, backend)
  if P.passIndex == 0 and P.sliceIndex == 0:
    startingIndex = 2
  currentOffset = P.laneIndex * I.laneLength + P.sliceIndex * I.segmentLength + startingIndex
  if (currentOffset mod I.laneLength) == 0:
    previousOffset = currentOffset + I.laneLength - 1
  else:
    previousOffset = currentOffset - 1
  i = startingIndex
  while i < I.segmentLength:
    if (currentOffset mod I.laneLength) == 1:
      previousOffset = currentOffset - 1
    if dataIndependent:
      pseudoRand = I.pseudoRands[i]
    else:
      pseudoRand = I.memory[previousOffset][0]
    refLane = int((pseudoRand shr 32) mod uint64(I.laneCount))
    if P.passIndex == 0 and P.sliceIndex == 0:
      refLane = P.laneIndex
    P.blockIndex = i
    refIndex = indexAlpha(I, P, uint32(pseudoRand and 0xffffffff'u64),
      refLane == P.laneIndex)
    refOffset = refLane * I.laneLength + refIndex
    if P.passIndex != 0:
      I.memory[currentOffset] = fillBlockWithXor(I.memory[previousOffset],
        I.memory[refOffset], I.memory[currentOffset], backend)
    else:
      I.memory[currentOffset] = fillBlock(I.memory[previousOffset],
        I.memory[refOffset], backend)
    i = i + 1
    currentOffset = currentOffset + 1
    previousOffset = previousOffset + 1


proc initInstance(a: Argon2Algorithm, p: Argon2Params): ArgonInstance =
  ## a: Argon2 variant selector.
  ## p: Argon2 parameter set.
  result.memoryBlocks = alignedMemoryBlocks(p.memoryKiB, p.laneCount)
  result.segmentLength = result.memoryBlocks div (p.laneCount * argon2SyncPoints)
  result.laneLength = result.segmentLength * argon2SyncPoints
  result.passCount = p.passCount
  result.laneCount = p.laneCount
  result.algorithm = a
  result.memory = newSeq[ArgonBlock](result.memoryBlocks)
  result.pseudoRands = newSeq[uint64](result.segmentLength)

proc clearInstance(I: var ArgonInstance) {.raises: [].} =
  ## Overwrite the full memory-hard work area before releasing it.
  var
    i: int = 0
  while i < I.memory.len:
    secureClearPod(I.memory[i])
    i = i + 1
  i = 0
  while i < I.pseudoRands.len:
    secureClearPod(I.pseudoRands[i])
    i = i + 1
  I.memory.setLen(0)
  I.pseudoRands.setLen(0)


proc finalizeInstance(I: var ArgonInstance, outLen: int,
    h: Argon2HashAlgorithm): seq[byte] =
  ## I: current Argon2 instance state.
  ## outLen: requested hash length in bytes.
  ## h: selected extendable-output primitive.
  var
    finalBlock: ArgonBlock = I.memory[I.laneLength - 1]
    laneIndex: int = 1
    finalBytes: seq[byte] = @[]
  defer:
    secureClearPod(finalBlock)
    secureClearBytes(finalBytes)
  laneIndex = 1
  while laneIndex < I.laneCount:
    xorBlock(finalBlock, I.memory[laneIndex * I.laneLength + (I.laneLength - 1)])
    laneIndex = laneIndex + 1
  finalBytes = blockToBytes(finalBlock)
  result = xofHash(finalBytes, outLen, h)


proc argon2Hash*(a: Argon2Algorithm, password, salt: openArray[byte],
    p: Argon2Params, b: Argon2Backend = a2bAuto): seq[byte] =
  ## a: Argon2 variant selector.
  ## password: password bytes.
  ## salt: salt bytes.
  ## p: Argon2 parameter set.
  var
    I: ArgonInstance
    P: ArgonPosition
    initialHash: seq[byte] = @[]
    passIndex: int = 0
    sliceIndex: int = 0
    laneIndex: int = 0
    backend: Argon2Backend
  defer:
    clearInstance(I)
    secureClearBytes(initialHash)
  validateArgon2Params(p, password.len, salt.len)
  backend = resolveArgon2Backend(b)
  I = initInstance(a, p)
  initialHash = buildInitialHash(a, password, salt, p, a2hBlake2b)
  fillFirstBlocks(I, initialHash, a2hBlake2b)
  passIndex = 0
  while passIndex < I.passCount:
    sliceIndex = 0
    while sliceIndex < argon2SyncPoints:
      laneIndex = 0
      while laneIndex < I.laneCount:
        P.passIndex = passIndex
        P.laneIndex = laneIndex
        P.sliceIndex = sliceIndex
        P.blockIndex = 0
        fillSegment(I, P, backend)
        laneIndex = laneIndex + 1
      sliceIndex = sliceIndex + 1
    passIndex = passIndex + 1
  result = finalizeInstance(I, p.outLen, a2hBlake2b)


proc argon2Hash*(a: Argon2Algorithm, password, salt: openArray[byte],
    p: Argon2Params, h: Argon2HashAlgorithm,
    b: Argon2Backend = a2bAuto): seq[byte] =
  ## a: Argon2 variant selector.
  ## password: password bytes.
  ## salt: salt bytes.
  ## p: Argon2 parameter set.
  ## h: selected hash primitive for the custom Argon front/back hash path.
  ## b: requested execution backend for block filling.
  var
    I: ArgonInstance
    P: ArgonPosition
    initialHash: seq[byte] = @[]
    passIndex: int = 0
    sliceIndex: int = 0
    laneIndex: int = 0
    backend: Argon2Backend
  defer:
    clearInstance(I)
    secureClearBytes(initialHash)
  validateArgon2Params(p, password.len, salt.len)
  backend = resolveArgon2Backend(b)
  I = initInstance(a, p)
  initialHash = buildInitialHash(a, password, salt, p, h)
  fillFirstBlocks(I, initialHash, h)
  passIndex = 0
  while passIndex < I.passCount:
    sliceIndex = 0
    while sliceIndex < argon2SyncPoints:
      laneIndex = 0
      while laneIndex < I.laneCount:
        P.passIndex = passIndex
        P.laneIndex = laneIndex
        P.sliceIndex = sliceIndex
        P.blockIndex = 0
        fillSegment(I, P, backend)
        laneIndex = laneIndex + 1
      sliceIndex = sliceIndex + 1
    passIndex = passIndex + 1
  result = finalizeInstance(I, p.outLen, h)


proc argon2Hash*(a: Argon2Algorithm, password, salt: openArray[byte],
    passCount, memoryKiB, laneCount, outLen: int,
    b: Argon2Backend = a2bAuto): seq[byte] =
  ## a: Argon2 variant selector.
  ## password: password bytes.
  ## salt: salt bytes.
  ## passCount: number of Argon2 passes.
  ## memoryKiB: requested memory in kibibytes.
  ## laneCount: number of lanes.
  ## outLen: requested hash length in bytes.
  result = argon2Hash(a, password, salt,
    initArgon2Params(passCount, memoryKiB, laneCount, outLen), b)


proc argon2Hash*(a: Argon2Algorithm, password, salt: openArray[byte],
    passCount, memoryKiB, laneCount, outLen: int,
    h: Argon2HashAlgorithm, b: Argon2Backend = a2bAuto): seq[byte] =
  ## a: Argon2 variant selector.
  ## password: password bytes.
  ## salt: salt bytes.
  ## passCount: number of Argon2 passes.
  ## memoryKiB: requested memory in kibibytes.
  ## laneCount: number of lanes.
  ## outLen: requested hash length in bytes.
  ## h: selected hash primitive for the custom Argon front/back hash path.
  ## b: requested execution backend.
  result = argon2Hash(a, password, salt,
    initArgon2Params(passCount, memoryKiB, laneCount, outLen), h, b)


proc argon2iHash*(password, salt: openArray[byte], p: Argon2Params,
    b: Argon2Backend = a2bAuto): seq[byte] =
  ## password: password bytes.
  ## salt: salt bytes.
  ## p: Argon2 parameter set.
  result = argon2Hash(a2Argon2i, password, salt, p, b)


proc argon2iHash*(password, salt: openArray[byte], p: Argon2Params,
    h: Argon2HashAlgorithm, b: Argon2Backend = a2bAuto): seq[byte] =
  ## password: password bytes.
  ## salt: salt bytes.
  ## p: Argon2 parameter set.
  ## h: selected hash primitive for the custom Argon front/back hash path.
  ## b: requested execution backend.
  result = argon2Hash(a2Argon2i, password, salt, p, h, b)


proc argon2idHash*(password, salt: openArray[byte], p: Argon2Params,
    b: Argon2Backend = a2bAuto): seq[byte] =
  ## password: password bytes.
  ## salt: salt bytes.
  ## p: Argon2 parameter set.
  result = argon2Hash(a2Argon2id, password, salt, p, b)


proc argon2idHash*(password, salt: openArray[byte], p: Argon2Params,
    h: Argon2HashAlgorithm, b: Argon2Backend = a2bAuto): seq[byte] =
  ## password: password bytes.
  ## salt: salt bytes.
  ## p: Argon2 parameter set.
  ## h: selected hash primitive for the custom Argon front/back hash path.
  ## b: requested execution backend.
  result = argon2Hash(a2Argon2id, password, salt, p, h, b)


proc argon2iHash*(password, salt: openArray[byte], passCount,
    memoryKiB, laneCount, outLen: int,
    b: Argon2Backend = a2bAuto): seq[byte] =
  ## password: password bytes.
  ## salt: salt bytes.
  ## passCount: number of Argon2 passes.
  ## memoryKiB: requested memory in kibibytes.
  ## laneCount: number of lanes.
  ## outLen: requested hash length in bytes.
  result = argon2Hash(a2Argon2i, password, salt, passCount, memoryKiB,
    laneCount, outLen, b)


proc argon2iHash*(password, salt: openArray[byte], passCount,
    memoryKiB, laneCount, outLen: int,
    h: Argon2HashAlgorithm, b: Argon2Backend = a2bAuto): seq[byte] =
  ## password: password bytes.
  ## salt: salt bytes.
  ## passCount: number of Argon2 passes.
  ## memoryKiB: requested memory in kibibytes.
  ## laneCount: number of lanes.
  ## outLen: requested hash length in bytes.
  ## h: selected hash primitive for the custom Argon front/back hash path.
  ## b: requested execution backend.
  result = argon2Hash(a2Argon2i, password, salt, passCount, memoryKiB,
    laneCount, outLen, h, b)


proc argon2idHash*(password, salt: openArray[byte], passCount,
    memoryKiB, laneCount, outLen: int,
    b: Argon2Backend = a2bAuto): seq[byte] =
  ## password: password bytes.
  ## salt: salt bytes.
  ## passCount: number of Argon2 passes.
  ## memoryKiB: requested memory in kibibytes.
  ## laneCount: number of lanes.
  ## outLen: requested hash length in bytes.
  result = argon2Hash(a2Argon2id, password, salt, passCount, memoryKiB,
    laneCount, outLen, b)


proc argon2idHash*(password, salt: openArray[byte], passCount,
    memoryKiB, laneCount, outLen: int,
    h: Argon2HashAlgorithm, b: Argon2Backend = a2bAuto): seq[byte] =
  ## password: password bytes.
  ## salt: salt bytes.
  ## passCount: number of Argon2 passes.
  ## memoryKiB: requested memory in kibibytes.
  ## laneCount: number of lanes.
  ## outLen: requested hash length in bytes.
  ## h: selected hash primitive for the custom Argon front/back hash path.
  ## b: requested execution backend.
  result = argon2Hash(a2Argon2id, password, salt, passCount, memoryKiB,
    laneCount, outLen, h, b)
