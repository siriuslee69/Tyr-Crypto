## ---------------------------------------------------------
## SPHINCS Address <- 32-byte address manipulation helpers
## ---------------------------------------------------------

import ./params

type
  SphincsAddress* = array[32, byte]

## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; address layout and hash-domain separation for `setLayerAddr`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc setLayerAddr*(A: var SphincsAddress, layer: uint32) =
  A[spxOffsetLayer] = byte(layer)

## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; address layout and hash-domain separation for `setTreeAddr`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc setTreeAddr*(A: var SphincsAddress, tree: uint64) =
  for i in 0 ..< 8:
    A[spxOffsetTree + 7 - i] = byte((tree shr (8 * i)) and 0xff'u64)

## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; address layout and hash-domain separation for `setType`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc setType*(A: var SphincsAddress, kind: uint32) =
  A[spxOffsetType] = byte(kind)

## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; address layout and hash-domain separation for `copySubtreeAddr`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc copySubtreeAddr*(dst: var SphincsAddress, src: SphincsAddress) =
  copyMem(addr dst[0], unsafeAddr src[0], spxOffsetTree + 8)

## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; address layout and hash-domain separation for `setKeypairAddr`; pitfall: keep transcript order, domain separation, sizes, and secret wiping exact.
proc setKeypairAddr*(A: var SphincsAddress, keypair: uint32) =
  A[spxOffsetKpAddr1] = byte(keypair)

## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; address layout and hash-domain separation for `copyKeypairAddr`; pitfall: keep transcript order, domain separation, sizes, and secret wiping exact.
proc copyKeypairAddr*(dst: var SphincsAddress, src: SphincsAddress) =
  copyMem(addr dst[0], unsafeAddr src[0], spxOffsetTree + 8)
  dst[spxOffsetKpAddr1] = src[spxOffsetKpAddr1]

## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; address layout and hash-domain separation for `setChainAddr`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc setChainAddr*(A: var SphincsAddress, chain: uint32) =
  A[spxOffsetChainAddr] = byte(chain)

## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; address layout and hash-domain separation for `setHashAddr`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc setHashAddr*(A: var SphincsAddress, h: uint32) =
  A[spxOffsetHashAddr] = byte(h)

## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; address layout and hash-domain separation for `setTreeHeight`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc setTreeHeight*(A: var SphincsAddress, treeHeight: uint32) =
  A[spxOffsetTreeHgt] = byte(treeHeight)

## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; address layout and hash-domain separation for `setTreeIndex`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc setTreeIndex*(A: var SphincsAddress, treeIndex: uint32) =
  A[spxOffsetTreeIndex + 0] = byte((treeIndex shr 24) and 0xff'u32)
  A[spxOffsetTreeIndex + 1] = byte((treeIndex shr 16) and 0xff'u32)
  A[spxOffsetTreeIndex + 2] = byte((treeIndex shr 8) and 0xff'u32)
  A[spxOffsetTreeIndex + 3] = byte(treeIndex and 0xff'u32)
