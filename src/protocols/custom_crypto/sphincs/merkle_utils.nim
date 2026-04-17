## --------------------------------------------------------------
## SPHINCS Merkle Utils <- root derivation and TreeHash routines
## --------------------------------------------------------------

import ./params
import ./address
import ./context
import ./hash
import ./util

proc computeRoot*(root: var openArray[byte], leaf: openArray[byte], leafIdx,
    idxOffset, treeHeight: uint32, authPath: openArray[byte], ctx: SphincsCtx,
    A: var SphincsAddress) =
  var
    buffer: array[2 * spxN, byte]
    currentLeafIdx = leafIdx
    currentOffset = idxOffset
    authOffset: int = 0
  if (leafIdx and 1'u32) != 0:
    copyMem(addr buffer[spxN], unsafeAddr leaf[0], spxN)
    copyMem(addr buffer[0], unsafeAddr authPath[0], spxN)
  else:
    copyMem(addr buffer[0], unsafeAddr leaf[0], spxN)
    copyMem(addr buffer[spxN], unsafeAddr authPath[0], spxN)
  authOffset = spxN
  for i in 0 ..< int(treeHeight - 1):
    currentLeafIdx = currentLeafIdx shr 1
    currentOffset = currentOffset shr 1
    setTreeHeight(A, uint32(i + 1))
    setTreeIndex(A, currentLeafIdx + currentOffset)
    if (currentLeafIdx and 1'u32) != 0:
      thash(buffer.toOpenArray(spxN, (2 * spxN) - 1), buffer, 2, ctx, A)
      copyMem(addr buffer[0], unsafeAddr authPath[authOffset], spxN)
    else:
      thash(buffer.toOpenArray(0, spxN - 1), buffer, 2, ctx, A)
      copyMem(addr buffer[spxN], unsafeAddr authPath[authOffset], spxN)
    authOffset = authOffset + spxN
  currentLeafIdx = currentLeafIdx shr 1
  currentOffset = currentOffset shr 1
  setTreeHeight(A, treeHeight)
  setTreeIndex(A, currentLeafIdx + currentOffset)
  thash(root, buffer, 2, ctx, A)

proc treehashx1*[T](root: var openArray[byte], authPath: var openArray[byte],
    ctx: SphincsCtx, leafIdx, idxOffset, treeHeight: uint32,
    genLeaf: proc (leaf: var openArray[byte], ctx: SphincsCtx, addrIdx: uint32,
      info: var T) {.nimcall.}, treeAddr: var SphincsAddress, info: var T) =
  var
    stack: array[spxMaxTreeHeight * spxN, byte]
    idx: uint32 = 0
    maxIdx = (1'u32 shl treeHeight) - 1'u32
  while true:
    var
      current: array[2 * spxN, byte]
      internalIdxOffset: uint32 = idxOffset
      internalIdx: uint32 = idx
      internalLeaf: uint32 = leafIdx
      h: uint32 = 0
    genLeaf(current.toOpenArray(spxN, (2 * spxN) - 1), ctx, idx + idxOffset, info)
    while true:
      if h == treeHeight:
        copyMem(addr root[0], addr current[spxN], spxN)
        return
      ## Keep auth-path selection branchless for the signing path: exactly one
      ## sibling per height matches, and the masked copy preserves all others.
      ctCopyBytesMasked(
        authPath.toOpenArray(int(h) * spxN, ((int(h) + 1) * spxN) - 1),
        current.toOpenArray(spxN, (2 * spxN) - 1),
        ctMaskEqU32(internalIdx xor internalLeaf, 1'u32)
      )
      if ((internalIdx and 1'u32) == 0'u32) and idx < maxIdx:
        break
      internalIdxOffset = internalIdxOffset shr 1
      setTreeHeight(treeAddr, h + 1)
      setTreeIndex(treeAddr, (internalIdx shr 1) + internalIdxOffset)
      copyMem(addr current[0], addr stack[int(h) * spxN], spxN)
      thash(current.toOpenArray(spxN, (2 * spxN) - 1), current, 2, ctx, treeAddr)
      h = h + 1
      internalIdx = internalIdx shr 1
      internalLeaf = internalLeaf shr 1
    copyMem(addr stack[int(h) * spxN], addr current[spxN], spxN)
    idx = idx + 1
