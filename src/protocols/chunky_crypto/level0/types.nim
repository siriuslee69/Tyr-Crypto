## ============================================================
## | ChunkyCrypto Types <- chunked file crypto configuration  |
## ============================================================

const
  chunkyMagic* = [
    byte('C'), byte('H'), byte('U'), byte('N'),
    byte('K'), byte('Y'), byte('0'), byte('1')
  ]
  chunkyVersion* = 1'u8
  defaultChunkBytes* = 1_073_741_824'i64
  fallbackChunkBytes* = 524_288_000'i64
  lowRamThresholdBytes* = 4_294_967_296'i64
  defaultBufferBytes* = 8_388_608
  defaultTagLen* = 64'u16

type
  ChunkyAlgo* = enum
    caXChaCha20Gimli,
    caAesGimli,
    caXChaCha20AesGimli

  HashAlgo* = enum
    haBlake3Tree,
    haGimliTree

  ChunkyOptions* = object
    ## chunkBytes: desired chunk size in bytes.
    chunkBytes*: int64
    ## forceChunkBytes: skip auto-reduction when memory is low.
    forceChunkBytes*: bool
    ## maxThreads: cap on concurrent chunk threads.
    maxThreads*: int
    ## bufferBytes: streaming buffer size per thread.
    bufferBytes*: int
    ## outputDir: directory for chunk outputs.
    outputDir*: string
    ## algo: chunk encryption algorithm.
    algo*: ChunkyAlgo
    ## tagLen: Gimli tag length for AEAD.
    tagLen*: uint16

  ChunkyManifest* = object
    version*: uint8
    algo*: ChunkyAlgo
    chunkBytes*: int64
    tagLen*: uint16
    chunkCount*: int
    originalSize*: int64
    baseNonce*: array[24, uint8]
    fileName*: string
    chunkFiles*: seq[string]

  ChunkHeader* = object
    magic*: array[8, uint8]
    version*: uint8
    algo*: ChunkyAlgo
    tagLen*: uint16
    chunkIndex*: uint64
    plainLen*: uint64
    nonce*: array[24, uint8]

  ChunkEncryptTask* = object
    inputPath*: string
    outputPath*: string
    chunkIndex*: uint64
    chunkOffset*: int64
    chunkLen*: int64
    baseNonce*: array[24, uint8]
    keyXs*: array[32, uint8]
    keyAs*: array[32, uint8]
    keyGs*: array[32, uint8]
    tagLen*: uint16
    bufferBytes*: int
    algo*: ChunkyAlgo
    ok*: bool
    err*: string

  ChunkDecryptTask* = object
    inputPath*: string
    outputPath*: string
    chunkIndex*: uint64
    baseNonce*: array[24, uint8]
    keyXs*: array[32, uint8]
    keyAs*: array[32, uint8]
    keyGs*: array[32, uint8]
    bufferBytes*: int
    ok*: bool
    err*: string

  ChunkHashTask* = object
    inputPath*: string
    chunkOffset*: int64
    chunkLen*: int64
    bufferBytes*: int
    algo*: HashAlgo
    hashs*: seq[uint8]
    ok*: bool
    err*: string

proc initChunkyOptions*(): ChunkyOptions =
  var o: ChunkyOptions
  o.chunkBytes = defaultChunkBytes
  o.forceChunkBytes = false
  o.maxThreads = 0
  o.bufferBytes = defaultBufferBytes
  o.outputDir = ""
  o.algo = caXChaCha20AesGimli
  o.tagLen = defaultTagLen
  result = o
