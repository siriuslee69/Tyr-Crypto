import std/bitops

when defined(amd64) or defined(i386):
  import ./blake3_simd
  export blake3_simd

const
  blockLen = 64
  chunkLen = 1024
  outLenDefault* = 32
  iv: array[8, uint32] = [
    0x6a09e667'u32, 0xbb67ae85'u32, 0x3c6ef372'u32, 0xa54ff53a'u32,
    0x510e527f'u32, 0x9b05688c'u32, 0x1f83d9ab'u32, 0x5be0cd19'u32
  ]
  msgPerm: array[16, int] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]
  flagChunkStart = 1'u32
  flagChunkEnd   = 2'u32
  flagParent     = 4'u32
  flagRoot       = 8'u32
  flagKeyedHash  = 16'u32
  flagDeriveKeyContext = 32'u32
  flagDeriveKeyMaterial = 64'u32

type
  Blake3Mode* = enum
    b3mHash = 0'u32
    b3mKeyedHash = flagKeyedHash
    b3mDeriveKeyContext = flagDeriveKeyContext
    b3mDeriveKeyMaterial = flagDeriveKeyMaterial

  Output = object
    inputCv: array[8, uint32]
    blockWords: array[16, uint32]
    blockLen: uint32
    flags: uint32
    counter: uint64

  Blake3Hasher* = object
    key: array[8, uint32]
    baseFlags: uint32
    chunkIndex: uint64
    chunkBuf: seq[byte]
    chunkBufLen: int
    stackCvs: seq[array[8, uint32]]
    stackLevels: seq[int]
    hasOutput: bool
    lastOutput: Output

  Blake3CompressBackend* = enum
    bcbAuto
    bcbScalar
    bcbSse2
    bcbAvx2

when not declared(Blake3Cv):
  type
    Blake3Cv* = array[8, uint32]
    Blake3Block* = array[16, uint32]
    Blake3Out* = array[16, uint32]

proc store32(outBuf: var openArray[byte], offset: int, w: uint32) {.inline.} =
  outBuf[offset] = byte(w and 0xff)
  outBuf[offset + 1] = byte((w shr 8) and 0xff)
  outBuf[offset + 2] = byte((w shr 16) and 0xff)
  outBuf[offset + 3] = byte((w shr 24) and 0xff)

proc load32(input: openArray[byte], offset: int): uint32 {.inline.} =
  result =
    uint32(input[offset]) or
    (uint32(input[offset + 1]) shl 8) or
    (uint32(input[offset + 2]) shl 16) or
    (uint32(input[offset + 3]) shl 24)

proc g(v: var array[16, uint32], a, b, c, d: int, x, y: uint32) {.inline.} =
  v[a] = v[a] + v[b] + x
  v[d] = rotateRightBits(v[d] xor v[a], 16)
  v[c] = v[c] + v[d]
  v[b] = rotateRightBits(v[b] xor v[c], 12)
  v[a] = v[a] + v[b] + y
  v[d] = rotateRightBits(v[d] xor v[a], 8)
  v[c] = v[c] + v[d]
  v[b] = rotateRightBits(v[b] xor v[c], 7)

proc permute(schedule: var array[16, int]) {.inline.} =
  var next: array[16, int]
  for i in 0 ..< 16:
    next[i] = schedule[msgPerm[i]]
  schedule = next

proc compress(cv: array[8, uint32], words: array[16, uint32], counter: uint64, blkLen, flags: uint32): array[16, uint32] =
  var state: array[16, uint32]
  for i in 0 .. 7:
    state[i] = cv[i]
  state[8] = iv[0]
  state[9] = iv[1]
  state[10] = iv[2]
  state[11] = iv[3]
  state[12] = uint32(counter and 0xffffffff'u64)
  state[13] = uint32((counter shr 32) and 0xffffffff'u64)
  state[14] = blkLen
  state[15] = flags

  var schedule: array[16, int]
  for i in 0 ..< 16:
    schedule[i] = i

  for _ in 0 ..< 7:
    g(state, 0, 4, 8, 12, words[schedule[0]], words[schedule[1]])
    g(state, 1, 5, 9, 13, words[schedule[2]], words[schedule[3]])
    g(state, 2, 6, 10, 14, words[schedule[4]], words[schedule[5]])
    g(state, 3, 7, 11, 15, words[schedule[6]], words[schedule[7]])

    g(state, 0, 5, 10, 15, words[schedule[8]], words[schedule[9]])
    g(state, 1, 6, 11, 12, words[schedule[10]], words[schedule[11]])
    g(state, 2, 7, 8, 13, words[schedule[12]], words[schedule[13]])
    g(state, 3, 4, 9, 14, words[schedule[14]], words[schedule[15]])

    permute(schedule)

  for i in 0 ..< 8:
    result[i] = state[i] xor state[i + 8]
    result[i + 8] = result[i] xor cv[i]

proc blake3Compress*(cv: array[8, uint32], words: array[16, uint32], counter: uint64, blkLen, flags: uint32): array[16, uint32] =
  ## cv: chaining value words.
  ## words: input message block words.
  ## counter: chunk counter.
  ## blkLen: block length.
  ## flags: BLAKE3 flags.
  result = compress(cv, words, counter, blkLen, flags)

proc resolveBackend(b: Blake3CompressBackend): Blake3CompressBackend =
  when defined(avx2):
    if b == bcbAuto:
      return bcbAvx2
  else:
    if b == bcbAvx2:
      return bcbScalar
  when defined(sse2):
    if b == bcbAuto:
      return bcbSse2
  else:
    if b == bcbSse2:
      return bcbScalar
  if b == bcbAuto:
    return bcbScalar
  result = b

proc blake3CompressBatch*(
    cvs: openArray[Blake3Cv],
    blocks: openArray[Blake3Block],
    counter: uint64,
    blkLen, flags: uint32,
    b: Blake3CompressBackend = bcbAuto
  ): seq[Blake3Out] =
  ## Batch compression where counter/blkLen/flags are shared across all lanes.
  doAssert cvs.len == blocks.len
  result = newSeq[Blake3Out](cvs.len)
  var
    backend: Blake3CompressBackend
    i: int = 0
  backend = resolveBackend(b)
  when defined(avx2):
    if backend == bcbAvx2:
      while i + 8 <= cvs.len:
        var
          cv8: array[8, Blake3Cv]
          bl8: array[8, Blake3Block]
          out8: array[8, Blake3Out]
          j: int = 0
        j = 0
        while j < 8:
          cv8[j] = cvs[i + j]
          bl8[j] = blocks[i + j]
          j = j + 1
        out8 = blake3CompressAvx8(cv8, bl8, counter, blkLen, flags)
        j = 0
        while j < 8:
          result[i + j] = out8[j]
          j = j + 1
        i = i + 8
  when defined(sse2):
    if backend == bcbSse2 or backend == bcbAvx2:
      while i + 4 <= cvs.len:
        var
          cv4: array[4, Blake3Cv]
          bl4: array[4, Blake3Block]
          out4: array[4, Blake3Out]
          j: int = 0
        j = 0
        while j < 4:
          cv4[j] = cvs[i + j]
          bl4[j] = blocks[i + j]
          j = j + 1
        out4 = blake3CompressSse4(cv4, bl4, counter, blkLen, flags)
        j = 0
        while j < 4:
          result[i + j] = out4[j]
          j = j + 1
        i = i + 4
  while i < cvs.len:
    result[i] = blake3Compress(cvs[i], blocks[i], counter, blkLen, flags)
    i = i + 1

proc chainingValue(outWords: array[16, uint32]): array[8, uint32] {.inline.} =
  for i in 0 ..< 8:
    result[i] = outWords[i]

proc outputBytes(outputNode: Output, rootFlag: bool, dst: var openArray[byte]) =
  var
    produced = 0
    blockCounter = 0'u64
    blockBuf: array[blockLen, byte]
  let flags = outputNode.flags or (if rootFlag: flagRoot else: 0'u32)
  while produced < dst.len:
    let comp = compress(outputNode.inputCv, outputNode.blockWords, blockCounter,
      outputNode.blockLen, flags)
    var idx = 0
    for w in comp:
      store32(blockBuf, idx, w)
      inc idx, 4
    let take = min(blockLen, dst.len - produced)
    for j in 0 ..< take:
      dst[produced + j] = blockBuf[j]
    produced += take
    inc blockCounter

proc parentOutput(left, right: array[8, uint32], key: array[8, uint32], baseFlags: uint32): Output =
  var words: array[16, uint32]
  for i in 0 ..< 8:
    words[i] = left[i]
    words[8 + i] = right[i]
  Output(inputCv: key, blockWords: words, blockLen: blockLen.uint32, flags: baseFlags or flagParent, counter: 0'u64)

proc chunkOutput(chunk: openArray[byte], chunkIndex: uint64, key: array[8, uint32], baseFlags: uint32): Output =
  var 
    cv = key
    offset = 0
    blockWords = default(array[16, uint32])
    thisBlockLen: uint32
    thisFlags: uint32
    blockCv = cv  # Remember the input cv for the final block so we can rebuild the Output later.

  if chunk.len == 0:
    thisBlockLen = 0
    thisFlags = baseFlags or flagChunkStart or flagChunkEnd
    return Output(inputCv: cv, blockWords: blockWords, blockLen: thisBlockLen, flags: thisFlags, counter: chunkIndex)

  var blockIndex = 0
  while offset < chunk.len:
    thisBlockLen = uint32(min(blockLen, chunk.len - offset))
    for i in 0 ..< 16:
      var w = 0'u32
      let off = offset + i * 4
      for b in 0 ..< 4:
        let idxByte = off + b
        if idxByte < chunk.len:
          w = w or (uint32(chunk[idxByte]) shl (8 * b))
      blockWords[i] = w
    thisFlags = baseFlags
    if blockIndex == 0:
      thisFlags = thisFlags or flagChunkStart
    if offset + blockLen >= chunk.len:
      thisFlags = thisFlags or flagChunkEnd
    blockCv = cv
    let outWords = compress(blockCv, blockWords, chunkIndex, thisBlockLen, thisFlags)
    cv = chainingValue(outWords)
    offset += blockLen
    inc blockIndex
  Output(inputCv: blockCv, blockWords: blockWords, blockLen: thisBlockLen, flags: thisFlags, counter: chunkIndex)

proc initBlake3Hasher*(): Blake3Hasher =
  var
    s: Blake3Hasher
  s.key = iv
  s.baseFlags = 0'u32
  s.chunkIndex = 0'u64
  s.chunkBuf = @[]
  s.chunkBuf.setLen(chunkLen)
  s.chunkBufLen = 0
  s.stackCvs = @[]
  s.stackLevels = @[]
  s.hasOutput = false
  result = s

proc pushCv(s: var Blake3Hasher, cv: array[8, uint32], level: int) =
  var
    lvl: int = 0
    leftCv: array[8, uint32]
    rightCv: array[8, uint32]
    outNode: Output
    parentCv: array[8, uint32]
  s.stackCvs.add(cv)
  s.stackLevels.add(level)
  while s.stackLevels.len >= 2 and s.stackLevels[^1] == s.stackLevels[^2]:
    lvl = s.stackLevels[^1] + 1
    rightCv = s.stackCvs[^1]
    leftCv = s.stackCvs[^2]
    s.stackCvs.setLen(s.stackCvs.len - 2)
    s.stackLevels.setLen(s.stackLevels.len - 2)
    outNode = parentOutput(leftCv, rightCv, s.key, s.baseFlags)
    parentCv = chainingValue(compress(outNode.inputCv, outNode.blockWords, outNode.counter, outNode.blockLen, outNode.flags))
    s.lastOutput = outNode
    s.hasOutput = true
    s.stackCvs.add(parentCv)
    s.stackLevels.add(lvl)

proc processChunk(s: var Blake3Hasher, l: int) =
  var
    outNode: Output
    cv: array[8, uint32]
  if l == 0:
    outNode = chunkOutput(@[], s.chunkIndex, s.key, s.baseFlags)
  else:
    outNode = chunkOutput(s.chunkBuf.toOpenArray(0, l - 1), s.chunkIndex, s.key, s.baseFlags)
  cv = chainingValue(compress(outNode.inputCv, outNode.blockWords, outNode.counter, outNode.blockLen, outNode.flags))
  if not s.hasOutput:
    s.lastOutput = outNode
    s.hasOutput = true
  pushCv(s, cv, 0)
  s.chunkIndex = s.chunkIndex + 1'u64

proc updateBlake3*(s: var Blake3Hasher, bs: openArray[byte]) =
  var
    i: int = 0
    take: int = 0
    j: int = 0
  i = 0
  while i < bs.len:
    take = min(chunkLen - s.chunkBufLen, bs.len - i)
    j = 0
    while j < take:
      s.chunkBuf[s.chunkBufLen + j] = bs[i + j]
      j = j + 1
    s.chunkBufLen = s.chunkBufLen + take
    i = i + take
    if s.chunkBufLen == chunkLen:
      processChunk(s, chunkLen)
      s.chunkBufLen = 0

proc finalBlake3*(s: var Blake3Hasher, outLen: int = outLenDefault): seq[byte] =
  var
    accCv: array[8, uint32]
    outNode: Output
    i: int = 0
  if outLen <= 0:
    raise newException(ValueError, "output length must be positive")
  if s.chunkBufLen > 0 or s.chunkIndex == 0'u64:
    processChunk(s, s.chunkBufLen)
    s.chunkBufLen = 0
  if s.stackCvs.len == 0:
    return @[]
  accCv = s.stackCvs[^1]
  i = s.stackCvs.len - 2
  while i >= 0:
    outNode = parentOutput(s.stackCvs[i], accCv, s.key, s.baseFlags)
    accCv = chainingValue(compress(outNode.inputCv, outNode.blockWords, outNode.counter, outNode.blockLen, outNode.flags))
    s.lastOutput = outNode
    s.hasOutput = true
    i = i - 1
  result = newSeq[byte](outLen)
  outputBytes(s.lastOutput, true, result)

proc blake3HashFile*(p: string, outLen: int = outLenDefault): seq[byte] =
  ## Computes a BLAKE3 hash for a file path using streaming updates.
  var
    s: Blake3Hasher
    f: File
    buf: seq[byte] = @[]
    readLen: int = 0
  s = initBlake3Hasher()
  buf.setLen(64 * 1024)
  f = open(p, fmRead)
  defer: f.close()
  while true:
    readLen = f.readBytes(buf, 0, buf.len)
    if readLen <= 0:
      break
    updateBlake3(s, buf.toOpenArray(0, readLen - 1))
  result = finalBlake3(s, outLen)

proc hashInternal(input: openArray[byte], key: array[8, uint32], baseFlags: uint32,
    outLen: int): seq[byte] =
  if outLen <= 0:
    raise newException(ValueError, "output length must be positive")

  var chunkOutputs: seq[Output]
  if input.len == 0:
    chunkOutputs.add(chunkOutput(input, 0, key, baseFlags))
  else:
    var idx = 0
    var chunkIndex = 0'u64
    while idx < input.len:
      let take = min(chunkLen, input.len - idx)
      chunkOutputs.add(chunkOutput(input[idx ..< idx + take], chunkIndex, key, baseFlags))
      inc chunkIndex
      idx += take

  var currentCvs: seq[array[8, uint32]]
  currentCvs.setLen(chunkOutputs.len)
  for i, node in chunkOutputs:
    currentCvs[i] = chainingValue(compress(node.inputCv, node.blockWords, node.counter, node.blockLen, node.flags))

  var lastOutput: Output
  if chunkOutputs.len == 1:
    lastOutput = chunkOutputs[0]
  else:
    var levelCvs = currentCvs
    while levelCvs.len > 1:
      var nextCvs: seq[array[8, uint32]]
      var idx = 0
      while idx + 1 < levelCvs.len:
        let parent = parentOutput(levelCvs[idx], levelCvs[idx + 1], key, baseFlags)
        lastOutput = parent
        nextCvs.add(chainingValue(compress(parent.inputCv, parent.blockWords, parent.counter, parent.blockLen, parent.flags)))
        idx += 2
      if idx < levelCvs.len:
        nextCvs.add(levelCvs[idx])
      levelCvs = nextCvs

  result = newSeq[byte](outLen)
  outputBytes(lastOutput, true, result)

proc keyWords(key: openArray[byte]): array[8, uint32] =
  if key.len != 32:
    raise newException(ValueError, "BLAKE3 keyed mode requires a 32-byte key")
  for i in 0 ..< result.len:
    result[i] = load32(key, i * 4)

proc modeFlags(mode: Blake3Mode): uint32 =
  case mode
  of b3mHash:
    result = 0'u32
  of b3mKeyedHash:
    result = flagKeyedHash
  of b3mDeriveKeyContext:
    result = flagDeriveKeyContext
  of b3mDeriveKeyMaterial:
    result = flagDeriveKeyMaterial

proc blake3Digest*(input: openArray[byte], mode: Blake3Mode = b3mHash,
    key: openArray[byte] = [], outLen: int = outLenDefault): seq[byte] =
  ## input: bytes to hash.
  ## mode: BLAKE3 mode selector.
  ## key: 32-byte key required in keyed-hash mode.
  ## outLen: output length.
  case mode
  of b3mHash:
    if key.len != 0:
      raise newException(ValueError, "plain blake3 hash does not accept a key")
    result = hashInternal(input, iv, modeFlags(mode), outLen)
  of b3mKeyedHash:
    result = hashInternal(input, keyWords(key), modeFlags(mode), outLen)
  of b3mDeriveKeyContext, b3mDeriveKeyMaterial:
    raise newException(ValueError, "derive-key mode is not implemented")

proc blake3Hash*(input: openArray[byte], outLen: int = outLenDefault): seq[byte] =
  ## Computes an unkeyed BLAKE3 hash with configurable output length (default 32 bytes).
  result = blake3Digest(input, b3mHash, [], outLen)

proc blake3KeyedHash*(key, input: openArray[byte],
    outLen: int = outLenDefault): seq[byte] =
  ## Computes a keyed BLAKE3 hash for MAC/KDF-style use.
  result = blake3Digest(input, b3mKeyedHash, key, outLen)

when isMainModule:
  let emptyHash = blake3Hash(@[])
  let emptyExpected = [
    byte 0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6,
    0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc, 0xc9, 0x49,
    0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7,
    0xcc, 0x9a, 0x93, 0xca, 0xe4, 0x1f, 0x32, 0x62
  ]
  doAssert emptyHash == emptyExpected

  let abcHash = blake3Hash(@['a'.byte, 'b'.byte, 'c'.byte])
  let abcExpected = [
    byte 0x64, 0x37, 0xb3, 0xac, 0x38, 0x46, 0x51, 0x33,
    0xff, 0xb6, 0x3b, 0x75, 0x27, 0x3a, 0x8d, 0xb5,
    0x48, 0xc5, 0x58, 0x46, 0x5d, 0x79, 0xdb, 0x03,
    0xfd, 0x35, 0x9c, 0x6c, 0xd5, 0xbd, 0x9d, 0x85
  ]
  doAssert abcHash == abcExpected
