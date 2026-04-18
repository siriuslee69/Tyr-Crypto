## ---------------------------------------------------------
## SPHINCS Address <- 32-byte address manipulation helpers
## ---------------------------------------------------------

import ./params

type
  SphincsAddress* = array[32, byte]

proc setLayerAddr*(A: var SphincsAddress, layer: uint32) =
  A[spxOffsetLayer] = byte(layer)

proc setTreeAddr*(A: var SphincsAddress, tree: uint64) =
  for i in 0 ..< 8:
    A[spxOffsetTree + 7 - i] = byte((tree shr (8 * i)) and 0xff'u64)

proc setType*(A: var SphincsAddress, kind: uint32) =
  A[spxOffsetType] = byte(kind)

proc copySubtreeAddr*(dst: var SphincsAddress, src: SphincsAddress) =
  copyMem(addr dst[0], unsafeAddr src[0], spxOffsetTree + 8)

proc setKeypairAddr*(A: var SphincsAddress, keypair: uint32) =
  A[spxOffsetKpAddr1] = byte(keypair)

proc copyKeypairAddr*(dst: var SphincsAddress, src: SphincsAddress) =
  copyMem(addr dst[0], unsafeAddr src[0], spxOffsetTree + 8)
  dst[spxOffsetKpAddr1] = src[spxOffsetKpAddr1]

proc setChainAddr*(A: var SphincsAddress, chain: uint32) =
  A[spxOffsetChainAddr] = byte(chain)

proc setHashAddr*(A: var SphincsAddress, h: uint32) =
  A[spxOffsetHashAddr] = byte(h)

proc setTreeHeight*(A: var SphincsAddress, treeHeight: uint32) =
  A[spxOffsetTreeHgt] = byte(treeHeight)

proc setTreeIndex*(A: var SphincsAddress, treeIndex: uint32) =
  A[spxOffsetTreeIndex + 0] = byte((treeIndex shr 24) and 0xff'u32)
  A[spxOffsetTreeIndex + 1] = byte((treeIndex shr 16) and 0xff'u32)
  A[spxOffsetTreeIndex + 2] = byte((treeIndex shr 8) and 0xff'u32)
  A[spxOffsetTreeIndex + 3] = byte(treeIndex and 0xff'u32)
