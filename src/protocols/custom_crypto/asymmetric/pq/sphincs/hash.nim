## -----------------------------------------------------------
## SPHINCS Hash <- SHAKE-based thash, PRF, and message hashing
## -----------------------------------------------------------

import ./params
import ./address
import ./context
import ./util
import ../../../sha3

when defined(amd64) or defined(i386):
  import simd_nexus/simd/base_operations
  import protocols/simd/generic_u64

when defined(amd64) or defined(i386):
  proc load64LeSphincs(A: openArray[byte], o: int): uint64 {.inline.} =
    result =
      uint64(A[o]) or
      (uint64(A[o + 1]) shl 8) or
      (uint64(A[o + 2]) shl 16) or
      (uint64(A[o + 3]) shl 24) or
      (uint64(A[o + 4]) shl 32) or
      (uint64(A[o + 5]) shl 40) or
      (uint64(A[o + 6]) shl 48) or
      (uint64(A[o + 7]) shl 56)

  proc packAddrChunkU64x2(A: array[2, SphincsAddress], o: int): u64x2 {.inline.} =
    result = u64x2(mm_set_epi64x(
      cast[int64](load64LeSphincs(A[1], o)),
      cast[int64](load64LeSphincs(A[0], o))
    ))

  proc packNodeChunkU64x2(A: var array[2, array[spxN, byte]], o: int): u64x2 {.inline.} =
    result = u64x2(mm_set_epi64x(
      cast[int64](load64LeSphincs(A[1], o)),
      cast[int64](load64LeSphincs(A[0], o))
    ))

  proc broadcastSeedU64x2(seed: array[spxN, byte], o: int): u64x2 {.inline.} =
    result = set1U64[u64x2](load64LeSphincs(seed, o))

  when defined(avx2):
    proc packAddrChunkU64x4(A: array[4, SphincsAddress], o: int): u64x4 {.inline.} =
      result = u64x4(mm256_set_epi64x(
        cast[int64](load64LeSphincs(A[3], o)),
        cast[int64](load64LeSphincs(A[2], o)),
        cast[int64](load64LeSphincs(A[1], o)),
        cast[int64](load64LeSphincs(A[0], o))
      ))

    proc packNodeChunkU64x4(A: var array[4, array[spxN, byte]], o: int): u64x4 {.inline.} =
      result = u64x4(mm256_set_epi64x(
        cast[int64](load64LeSphincs(A[3], o)),
        cast[int64](load64LeSphincs(A[2], o)),
        cast[int64](load64LeSphincs(A[1], o)),
        cast[int64](load64LeSphincs(A[0], o))
      ))

    proc broadcastSeedU64x4(seed: array[spxN, byte], o: int): u64x4 {.inline.} =
      result = set1U64[u64x4](load64LeSphincs(seed, o))

proc thash*(outBytes: var openArray[byte], input: openArray[byte], inblocks: int,
    ctx: SphincsCtx, A: SphincsAddress) =
  ## Match liboqs clean's exact stack buffer sizes and keep the dominant
  ## one-block SPHINCS hashes on the fixed-shape SHAKE256 fast path.
  case inblocks
  of 1:
    var buf: array[spxN + spxAddrBytes + spxN, byte]
    copyMem(addr buf[0], unsafeAddr ctx.pubSeed[0], spxN)
    copyMem(addr buf[spxN], unsafeAddr A[0], spxAddrBytes)
    copyMem(addr buf[spxN + spxAddrBytes], unsafeAddr input[0], spxN)
    shake256OneBlockAlignedInto(outBytes, buf)
  of 2:
    var buf: array[spxN + spxAddrBytes + (2 * spxN), byte]
    copyMem(addr buf[0], unsafeAddr ctx.pubSeed[0], spxN)
    copyMem(addr buf[spxN], unsafeAddr A[0], spxAddrBytes)
    copyMem(addr buf[spxN + spxAddrBytes], unsafeAddr input[0], 2 * spxN)
    shake256OneBlockAlignedInto(outBytes, buf)
  of spxForsTrees:
    var buf: array[spxN + spxAddrBytes + (spxForsTrees * spxN), byte]
    copyMem(addr buf[0], unsafeAddr ctx.pubSeed[0], spxN)
    copyMem(addr buf[spxN], unsafeAddr A[0], spxAddrBytes)
    copyMem(addr buf[spxN + spxAddrBytes], unsafeAddr input[0], spxForsTrees * spxN)
    shake256Into(outBytes, buf)
  of spxWotsLen:
    var buf: array[spxN + spxAddrBytes + (spxWotsLen * spxN), byte]
    copyMem(addr buf[0], unsafeAddr ctx.pubSeed[0], spxN)
    copyMem(addr buf[spxN], unsafeAddr A[0], spxAddrBytes)
    copyMem(addr buf[spxN + spxAddrBytes], unsafeAddr input[0], spxWotsLen * spxN)
    shake256Into(outBytes, buf)
  else:
    var
      buf: array[spxMaxThashBytes, byte]
      totalBytes: int = spxN + spxAddrBytes + (inblocks * spxN)
    copyMem(addr buf[0], unsafeAddr ctx.pubSeed[0], spxN)
    copyMem(addr buf[spxN], unsafeAddr A[0], spxAddrBytes)
    copyMem(addr buf[spxN + spxAddrBytes], unsafeAddr input[0], inblocks * spxN)
    shake256Into(outBytes, buf.toOpenArray(0, totalBytes - 1))

proc prfAddr*(outBytes: var openArray[byte], ctx: SphincsCtx, A: SphincsAddress) =
  var
    buf: array[(2 * spxN) + spxAddrBytes, byte]
  copyMem(addr buf[0], unsafeAddr ctx.pubSeed[0], spxN)
  copyMem(addr buf[spxN], unsafeAddr A[0], spxAddrBytes)
  copyMem(addr buf[spxN + spxAddrBytes], unsafeAddr ctx.skSeed[0], spxN)
  shake256OneBlockAlignedInto(outBytes, buf)

when defined(amd64) or defined(i386):
  proc thash1Batch2*(outBytes: var array[2, array[spxN, byte]],
      input: var array[2, array[spxN, byte]], ctx: SphincsCtx,
      A: array[2, SphincsAddress]) =
    shake256OneBlock64Sse2xLanesInto(outBytes,
      broadcastSeedU64x2(ctx.pubSeed, 0),
      broadcastSeedU64x2(ctx.pubSeed, 8),
      packAddrChunkU64x2(A, 0),
      packAddrChunkU64x2(A, 8),
      packAddrChunkU64x2(A, 16),
      packAddrChunkU64x2(A, 24),
      packNodeChunkU64x2(input, 0),
      packNodeChunkU64x2(input, 8)
    )

  proc prfAddrBatch2*(outBytes: var array[2, array[spxN, byte]], ctx: SphincsCtx,
      A: array[2, SphincsAddress]) =
    shake256OneBlock64Sse2xLanesInto(outBytes,
      broadcastSeedU64x2(ctx.pubSeed, 0),
      broadcastSeedU64x2(ctx.pubSeed, 8),
      packAddrChunkU64x2(A, 0),
      packAddrChunkU64x2(A, 8),
      packAddrChunkU64x2(A, 16),
      packAddrChunkU64x2(A, 24),
      broadcastSeedU64x2(ctx.skSeed, 0),
      broadcastSeedU64x2(ctx.skSeed, 8)
    )

  when defined(avx2):
    proc thash1Batch4*(outBytes: var array[4, array[spxN, byte]],
        input: var array[4, array[spxN, byte]], ctx: SphincsCtx,
        A: array[4, SphincsAddress]) =
      shake256OneBlock64Avx4xLanesInto(outBytes,
        broadcastSeedU64x4(ctx.pubSeed, 0),
        broadcastSeedU64x4(ctx.pubSeed, 8),
        packAddrChunkU64x4(A, 0),
        packAddrChunkU64x4(A, 8),
        packAddrChunkU64x4(A, 16),
        packAddrChunkU64x4(A, 24),
        packNodeChunkU64x4(input, 0),
        packNodeChunkU64x4(input, 8)
      )

    proc prfAddrBatch4*(outBytes: var array[4, array[spxN, byte]], ctx: SphincsCtx,
        A: array[4, SphincsAddress]) =
      shake256OneBlock64Avx4xLanesInto(outBytes,
        broadcastSeedU64x4(ctx.pubSeed, 0),
        broadcastSeedU64x4(ctx.pubSeed, 8),
        packAddrChunkU64x4(A, 0),
        packAddrChunkU64x4(A, 8),
        packAddrChunkU64x4(A, 16),
        packAddrChunkU64x4(A, 24),
        broadcastSeedU64x4(ctx.skSeed, 0),
        broadcastSeedU64x4(ctx.skSeed, 8)
      )

proc genMessageRandom*(outR: var openArray[byte], skPrf, optrand, msg: openArray[byte],
    ctx: SphincsCtx) =
  discard ctx
  shake256ChunksInto(outR, skPrf, optrand, msg)

proc hashMessage*(digest: var openArray[byte], tree: var uint64, leafIdx: var uint32,
    r, pk, msg: openArray[byte], ctx: SphincsCtx) =
  const
    treeBits = spxTreeHeight * (spxD - 1)
    treeBytes = (treeBits + 7) div 8
    leafBits = spxTreeHeight
    leafBytes = (leafBits + 7) div 8
    dgstBytes = spxForsMsgBytes + treeBytes + leafBytes
  var
    buf: array[dgstBytes, byte]
    pos: int = 0
  discard ctx
  shake256ChunksInto(buf, r, pk, msg)
  copyMem(addr digest[0], addr buf[0], digest.len)
  pos = digest.len
  tree = bytesToUll(buf.toOpenArray(pos, pos + treeBytes - 1))
  tree = tree and ((not 0'u64) shr (64 - treeBits))
  pos = pos + treeBytes
  leafIdx = uint32(bytesToUll(buf.toOpenArray(pos, pos + leafBytes - 1)))
  leafIdx = leafIdx and ((not 0'u32) shr (32 - leafBits))
