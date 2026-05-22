## --------------------------------------------------------------------
## Custom KDF <- flat-memory, algorithm-agnostic block-generator KDF
## --------------------------------------------------------------------

import ./aes/aes_ctr
import ./blake3/blake3
import ./chacha/chacha20
import ./chacha/xchacha20
import ./gimli/gimli_sponge
import ./sha3/sha3

const
  kdfDomain = "tyr-custom-kdf-v2"
  customKdfTailBlockCount* = 16
  customKdfMinBlockCount* = 64

type
  CustomKdfAlgorithm* = enum
    ## Built-in deterministic block generator backed by the Gimli sponge.
    ckaGimli,
    ## Built-in deterministic block generator backed by BLAKE3 XOF output.
    ckaBlake3,
    ## Built-in deterministic block generator backed by SHA3-512 chunks.
    ckaSha3,
    ## Built-in deterministic block generator backed by SHAKE128 XOF output.
    ckaShake128,
    ## Built-in deterministic block generator backed by SHAKE256 XOF output.
    ckaShake256,
    ## Built-in deterministic block generator backed by ChaCha20 stream output.
    ckaChaCha20,
    ## Built-in deterministic block generator backed by XChaCha20 stream output.
    ckaXChaCha20,
    ## Built-in deterministic block generator backed by AES-256-CTR output.
    ckaAesCtr

  CustomKdfParams* = object
    ## roundCount: number of tail-xor/full-memory refill rounds.
    roundCount*: int
    ## memorySize: requested flat byte-array size; partial final blocks are unused.
    memorySize*: int
    ## hashCount: number of full-memory hash/refill passes per round.
    hashCount*: int
    ## blockSize: logical block size inside the flat byte array.
    blockSize*: int

  CustomKdfBlockGenerator* = proc (
    input: openArray[uint8],
    blockIndex: uint64,
    outLen: int
  ): seq[uint8]


proc appendStringBytes(B: var seq[uint8], s: string) =
  ## B: destination bytes.
  ## s: string to append as byte values.
  var
    i: int = 0
  i = 0
  while i < s.len:
    B.add(uint8(ord(s[i])))
    i = i + 1


proc appendBytes(B: var seq[uint8], A: openArray[uint8]) =
  ## B: destination bytes.
  ## A: bytes to append.
  var
    i: int = 0
  i = 0
  while i < A.len:
    B.add(A[i])
    i = i + 1


proc appendUint64Le(B: var seq[uint8], v: uint64) =
  ## B: destination bytes.
  ## v: value to encode little-endian.
  var
    i: int = 0
  i = 0
  while i < 8:
    B.add(uint8((v shr (i * 8)) and 0xff'u64))
    i = i + 1


proc algorithmId(a: CustomKdfAlgorithm): uint8 =
  ## a: built-in block generator selector.
  result = uint8(ord(a))


proc buildGeneratorInput(a: CustomKdfAlgorithm, input: openArray[uint8],
    blockIndex: uint64): seq[uint8] =
  ## a: built-in block generator selector.
  ## input: generator input material.
  ## blockIndex: domain-separated stream/block index.
  var
    B: seq[uint8] = @[]
  B = newSeqOfCap[uint8](kdfDomain.len + input.len + 24)
  appendStringBytes(B, kdfDomain)
  B.add(algorithmId(a))
  appendUint64Le(B, blockIndex)
  appendUint64Le(B, uint64(input.len))
  appendBytes(B, input)
  result = B


proc buildChunkInput(B: openArray[uint8], chunkIndex: uint64): seq[uint8] =
  ## B: base generator input.
  ## chunkIndex: chunk counter for fixed-output expansion.
  var
    T: seq[uint8] = @[]
  T = newSeqOfCap[uint8](B.len + 8)
  appendBytes(T, B)
  appendUint64Le(T, chunkIndex)
  result = T


proc copyInto(D: var seq[uint8], offset: int, B: openArray[uint8], take: int) =
  ## D: destination bytes.
  ## offset: destination byte offset.
  ## B: source bytes.
  ## take: number of bytes to copy.
  var
    i: int = 0
  i = 0
  while i < take:
    D[offset + i] = B[i]
    i = i + 1


proc sha3Generator(B: openArray[uint8], outLen: int): seq[uint8] =
  ## B: already-domain-separated generator input.
  ## outLen: requested output length.
  var
    offset: int = 0
    take: int = 0
    chunkIndex: uint64 = 0
    chunkInput: seq[uint8] = @[]
    chunk: seq[uint8] = @[]
  result = newSeq[uint8](outLen)
  offset = 0
  chunkIndex = 0
  while offset < outLen:
    chunkInput = buildChunkInput(B, chunkIndex)
    chunk = sha3Hash(chunkInput, 64)
    take = chunk.len
    if outLen - offset < take:
      take = outLen - offset
    copyInto(result, offset, chunk, take)
    offset = offset + take
    chunkIndex = chunkIndex + 1'u64


proc streamMaterial(a: CustomKdfAlgorithm, input: openArray[uint8],
    blockIndex: uint64, label: string, outLen: int): seq[uint8] =
  ## a: built-in stream generator selector.
  ## input: generator input material.
  ## blockIndex: domain-separated stream/block index.
  ## label: key/nonce label.
  ## outLen: requested material length.
  var
    B: seq[uint8] = @[]
  B = buildGeneratorInput(a, input, blockIndex)
  appendStringBytes(B, label)
  result = blake3Hash(B, outLen)


proc customKdfBlock*(a: CustomKdfAlgorithm, input: openArray[uint8],
    blockIndex: uint64, outLen: int): seq[uint8] =
  ## a: built-in deterministic block generator selector.
  ## input: generator input material.
  ## blockIndex: domain-separated stream/block index.
  ## outLen: requested output length.
  var
    B: seq[uint8] = @[]
    key: seq[uint8] = @[]
    nonce: seq[uint8] = @[]
    zeros: seq[uint8] = @[]
  if outLen < 0:
    raise newException(ValueError, "KDF block output length must be >= 0")
  if outLen == 0:
    return @[]
  B = buildGeneratorInput(a, input, blockIndex)
  case a
  of ckaGimli:
    result = gimliXof(@[], @[], B, outLen)
  of ckaBlake3:
    result = blake3Hash(B, outLen)
  of ckaSha3:
    result = sha3Generator(B, outLen)
  of ckaShake128:
    result = shake128(B, outLen)
  of ckaShake256:
    result = shake256(B, outLen)
  of ckaChaCha20:
    key = streamMaterial(a, input, blockIndex, "key", 32)
    nonce = streamMaterial(a, input, blockIndex, "nonce", 12)
    result = chacha20Stream(key, nonce, outLen)
  of ckaXChaCha20:
    key = streamMaterial(a, input, blockIndex, "key", 32)
    nonce = streamMaterial(a, input, blockIndex, "nonce", 24)
    result = xchacha20Stream(key, nonce, outLen)
  of ckaAesCtr:
    key = streamMaterial(a, input, blockIndex, "key", 32)
    nonce = streamMaterial(a, input, blockIndex, "nonce", 16)
    zeros = newSeq[uint8](outLen)
    result = aesCtrXor(key, nonce, zeros)


proc initCustomKdfParams*(roundCount, memorySize, hashCount,
    blockSize: int): CustomKdfParams =
  ## roundCount: number of tail-xor/full-memory refill rounds.
  ## memorySize: requested flat byte-array size.
  ## hashCount: number of full-memory hash/refill passes per round.
  ## blockSize: logical block size inside the flat byte array.
  result.roundCount = roundCount
  result.memorySize = memorySize
  result.hashCount = hashCount
  result.blockSize = blockSize


proc checkedProduct(a, b: int, label: string): int =
  ## a: left factor.
  ## b: right factor.
  ## label: error label.
  if a > high(int) div b:
    raise newException(ValueError, label & " is too large")
  result = a * b


proc validateParams(p: CustomKdfParams) =
  ## p: KDF parameter set.
  var
    usable: int = 0
    blockCount: int = 0
  if p.roundCount < 0:
    raise newException(ValueError, "KDF round count must be >= 0")
  if p.memorySize <= 0:
    raise newException(ValueError, "KDF memory size must be positive")
  if p.hashCount <= 0:
    raise newException(ValueError, "KDF hash count must be positive")
  if p.blockSize < 8:
    raise newException(ValueError, "KDF block size must be at least 8 bytes")
  if (p.blockSize mod 8) != 0:
    raise newException(ValueError, "KDF block size must be a multiple of 8")
  if p.memorySize < p.blockSize:
    raise newException(ValueError, "KDF memory size must fit at least one block")
  usable = (p.memorySize div p.blockSize) * p.blockSize
  blockCount = usable div p.blockSize
  if blockCount < customKdfMinBlockCount:
    raise newException(ValueError, "KDF memory size must fit at least 64 blocks")
  discard checkedProduct(p.hashCount, p.blockSize, "KDF hash output")


proc usableMemorySize*(memorySize, blockSize: int): int =
  ## memorySize: requested flat byte-array size.
  ## blockSize: logical block size.
  if blockSize <= 0:
    raise newException(ValueError, "block size must be positive")
  result = (memorySize div blockSize) * blockSize


proc calcBlockIndexLeftBound*(blockIndex, blockSize: int): int =
  ## blockIndex: logical block index.
  ## blockSize: logical block size.
  result = blockIndex * blockSize


proc calcBlockIndexRightBound*(blockIndex, blockSize: int): int =
  ## blockIndex: logical block index.
  ## blockSize: logical block size.
  ## Returns the exclusive right bound.
  result = calcBlockIndexLeftBound(blockIndex, blockSize) + blockSize


proc foldBlockToUint64*(B: openArray[uint8]): uint64 =
  ## B: logical block bytes to fold into a little-endian uint64.
  var
    folded: array[8, uint8]
    i: int = 0
  i = 0
  while i < B.len:
    folded[i mod 8] = folded[i mod 8] xor B[i]
    i = i + 1
  result =
    uint64(folded[0]) or
    (uint64(folded[1]) shl 8) or
    (uint64(folded[2]) shl 16) or
    (uint64(folded[3]) shl 24) or
    (uint64(folded[4]) shl 32) or
    (uint64(folded[5]) shl 40) or
    (uint64(folded[6]) shl 48) or
    (uint64(folded[7]) shl 56)


proc calcKdfBlockIndex*(B: openArray[uint8], blockCount: int): int =
  ## B: logical block bytes to fold and modulo.
  ## blockCount: number of logical blocks in the flat memory array.
  var
    folded: uint64 = 0
  if blockCount <= 0:
    raise newException(ValueError, "KDF block count must be positive")
  folded = foldBlockToUint64(B)
  result = int(folded mod uint64(blockCount))


proc calcKdfTargetBlockIndex*(B: openArray[uint8], blockCount: int,
    tailBlockCount: int = customKdfTailBlockCount): int =
  ## B: logical source block bytes to fold and modulo.
  ## blockCount: number of logical blocks in the flat memory array.
  ## tailBlockCount: protected tail-source block count excluded from targets.
  var
    targetBlockCount: int = 0
  if tailBlockCount <= 0:
    raise newException(ValueError, "KDF tail block count must be positive")
  if blockCount <= tailBlockCount:
    raise newException(ValueError, "KDF block count must exceed tail block count")
  targetBlockCount = blockCount - tailBlockCount
  result = calcKdfBlockIndex(B, targetBlockCount)


proc ensureBlockLength(B: openArray[uint8], blockSize: int) =
  ## B: generated block bytes.
  ## blockSize: expected block size.
  if B.len != blockSize:
    raise newException(ValueError, "KDF block generator returned wrong length")


proc fillMemory(M: var seq[uint8], seed: openArray[uint8],
    p: CustomKdfParams, g: CustomKdfBlockGenerator) =
  ## M: flat KDF memory byte array.
  ## seed: input key material.
  ## p: KDF parameter set.
  ## g: deterministic block generator.
  var
    offset: int = 0
    blockIndex: uint64 = 0
    genBlock: seq[uint8] = @[]
  offset = 0
  blockIndex = 0'u64
  while offset < M.len:
    genBlock = g(seed, blockIndex, p.blockSize)
    ensureBlockLength(genBlock, p.blockSize)
    copyInto(M, offset, genBlock, p.blockSize)
    offset = offset + p.blockSize
    blockIndex = blockIndex + 1'u64


proc readMemoryBlock(M: openArray[uint8], blockIndex, blockSize: int): seq[uint8] =
  ## M: flat KDF memory byte array.
  ## blockIndex: logical block index.
  ## blockSize: logical block size.
  var
    i: int = 0
    left: int = 0
  result = newSeq[uint8](blockSize)
  left = calcBlockIndexLeftBound(blockIndex, blockSize)
  i = 0
  while i < blockSize:
    result[i] = M[left + i]
    i = i + 1


proc xorBlockIntoMemory(M: var seq[uint8], blockIndex: int,
    B: openArray[uint8], blockSize: int): seq[uint8] =
  ## M: flat KDF memory byte array.
  ## blockIndex: logical block index to read, xor, and overwrite.
  ## B: provided block bytes.
  ## blockSize: logical block size.
  var
    i: int = 0
    left: int = 0
  if B.len != blockSize:
    raise newException(ValueError, "provided KDF block length mismatch")
  result = newSeq[uint8](blockSize)
  left = calcBlockIndexLeftBound(blockIndex, blockSize)
  i = 0
  while i < blockSize:
    result[i] = M[left + i] xor B[i]
    M[left + i] = result[i]
    i = i + 1


proc xorTailBlocksIntoMemory(M: var seq[uint8], blockCount, blockSize: int) =
  ## M: flat KDF memory byte array.
  ## blockCount: logical block count.
  ## blockSize: logical block size.
  var
    tailOffset: int = 0
    sourceIndex: int = 0
    targetIndex: int = 0
    sourceBlock: seq[uint8] = @[]
  tailOffset = 0
  while tailOffset < customKdfTailBlockCount:
    sourceIndex = blockCount - 1 - tailOffset
    sourceBlock = readMemoryBlock(M, sourceIndex, blockSize)
    targetIndex = calcKdfTargetBlockIndex(sourceBlock, blockCount)
    discard xorBlockIntoMemory(M, targetIndex, sourceBlock, blockSize)
    tailOffset = tailOffset + 1


proc refillMemoryFromFullHash(M: var seq[uint8], roundIndex: int,
    p: CustomKdfParams, g: CustomKdfBlockGenerator) =
  ## M: flat KDF memory byte array.
  ## roundIndex: current KDF round index.
  ## p: KDF parameter set.
  ## g: deterministic block generator.
  var
    nextMemory: seq[uint8] = @[]
    hashRound: int = 0
    blockIndex: uint64 = 0
  hashRound = 0
  while hashRound < p.hashCount:
    blockIndex = uint64(roundIndex) * uint64(p.hashCount) + uint64(hashRound)
    nextMemory = g(M, blockIndex, M.len)
    if nextMemory.len != M.len:
      raise newException(ValueError,
        "KDF block generator returned wrong full-memory length")
    copyInto(M, 0, nextMemory, M.len)
    hashRound = hashRound + 1


proc deriveCustomKdf*(seed: openArray[uint8], p: CustomKdfParams,
    g: CustomKdfBlockGenerator): seq[uint8] =
  ## seed: caller-provided input key material.
  ## p: KDF parameters: round count, memory size, hash count, block size.
  ## g: deterministic block generator backing the KDF.
  var
    usable: int = 0
    blockCount: int = 0
    M: seq[uint8] = @[]
    round: int = 0
  validateParams(p)
  usable = usableMemorySize(p.memorySize, p.blockSize)
  blockCount = usable div p.blockSize
  M = newSeq[uint8](usable)
  fillMemory(M, seed, p, g)
  round = 0
  while round < p.roundCount:
    xorTailBlocksIntoMemory(M, blockCount, p.blockSize)
    refillMemoryFromFullHash(M, round, p, g)
    round = round + 1
  result = readMemoryBlock(M, blockCount - 1, p.blockSize)


proc deriveCustomKdf*(seed: openArray[uint8], a: CustomKdfAlgorithm,
    p: CustomKdfParams): seq[uint8] =
  ## seed: caller-provided input key material.
  ## a: built-in deterministic block generator selector.
  ## p: KDF parameters: round count, memory size, hash count, block size.
  result = deriveCustomKdf(seed, p, proc (input: openArray[uint8],
      blockIndex: uint64, outLen: int): seq[uint8] =
    result = customKdfBlock(a, input, blockIndex, outLen)
  )


proc deriveCustomKdf*(seed: openArray[uint8], a: CustomKdfAlgorithm,
    roundCount, memorySize, hashCount, blockSize: int): seq[uint8] =
  ## seed: caller-provided input key material.
  ## a: built-in deterministic block generator selector.
  ## roundCount: number of tail-xor/full-memory refill rounds.
  ## memorySize: requested flat byte-array size.
  ## hashCount: number of full-memory hash/refill passes per round.
  ## blockSize: logical block size inside the flat byte array.
  var
    p: CustomKdfParams
  p = initCustomKdfParams(roundCount, memorySize, hashCount, blockSize)
  result = deriveCustomKdf(seed, a, p)


proc customKdf*(seed: openArray[uint8], a: CustomKdfAlgorithm,
    roundCount, memorySize, hashCount, blockSize: int): seq[uint8] =
  ## Convenience alias for `deriveCustomKdf`.
  result = deriveCustomKdf(seed, a, roundCount, memorySize, hashCount, blockSize)
