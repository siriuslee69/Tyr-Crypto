## ----------------------------------------------------------
## SPHINCS FORS <- FORS signing and public-key reconstruction
## ----------------------------------------------------------

import ./params
import ./address
import ./context
import ./hash
import ./merkle_utils
import ./util

type
  ForsGenLeafInfo = object
    leafAddr: SphincsAddress

proc forsGenLeafX1(leaf: var openArray[byte], ctx: SphincsCtx, addrIdx: uint32,
    info: var ForsGenLeafInfo) =
  setTreeIndex(info.leafAddr, addrIdx)
  setType(info.leafAddr, spxAddrTypeForsPrf)
  prfAddr(leaf, ctx, info.leafAddr)
  setType(info.leafAddr, spxAddrTypeForsTree)
  thash(leaf, leaf, 1, ctx, info.leafAddr)

proc messageToIndices*(indices: var openArray[uint32], msg: openArray[byte]) =
  var
    offset: int = 0
  for i in 0 ..< spxForsTrees:
    indices[i] = 0
    for j in 0 ..< spxForsHeight:
      indices[i] = indices[i] xor (uint32((msg[offset shr 3] shr (offset and 7)) and 1'u8) shl j)
      offset = offset + 1

proc forsSign*(sig: var seq[byte], sigOff: var int, pk: var array[spxN, byte], msg: openArray[byte],
    ctx: SphincsCtx, forsAddr: SphincsAddress) =
  var
    indices: array[spxForsTrees, uint32]
    roots: array[spxForsTrees * spxN, byte]
    treeAddr: SphincsAddress
    leafAddr: SphincsAddress
    pkAddr: SphincsAddress
    info: ForsGenLeafInfo
    idxOffset: uint32 = 0
    authPath: array[spxForsHeight * spxN, byte]
  defer:
    clearPlainData(indices)
    clearPlainData(roots)
  copyKeypairAddr(treeAddr, forsAddr)
  copyKeypairAddr(leafAddr, forsAddr)
  copyKeypairAddr(pkAddr, forsAddr)
  setType(pkAddr, spxAddrTypeForsPk)
  info.leafAddr = leafAddr
  messageToIndices(indices, msg)
  for i in 0 ..< spxForsTrees:
    idxOffset = uint32(i * (1 shl spxForsHeight))
    setTreeHeight(treeAddr, 0)
    setTreeIndex(treeAddr, indices[i] + idxOffset)
    setType(treeAddr, spxAddrTypeForsPrf)
    var skPart: array[spxN, byte]
    prfAddr(skPart, ctx, treeAddr)
    copyMem(addr sig[sigOff], addr skPart[0], spxN)
    sigOff = sigOff + spxN
    setType(treeAddr, spxAddrTypeForsTree)
    var rootNode: array[spxN, byte]
    var localTree = treeAddr
    treehashx1(rootNode, authPath, ctx, indices[i], idxOffset, uint32(spxForsHeight),
      forsGenLeafX1, localTree, info)
    copyMem(addr roots[i * spxN], addr rootNode[0], spxN)
    copyMem(addr sig[sigOff], addr authPath[0], authPath.len)
    sigOff = sigOff + authPath.len
    clearSensitivePlainData(skPart)
    clearPlainData(rootNode)
  thash(pk, roots, spxForsTrees, ctx, pkAddr)

proc forsPkFromSig*(pk: var array[spxN, byte], sig: openArray[byte], sigOff: var int, msg: openArray[byte],
    ctx: SphincsCtx, forsAddr: SphincsAddress) =
  var
    indices: array[spxForsTrees, uint32]
    roots: array[spxForsTrees * spxN, byte]
    treeAddr: SphincsAddress
    pkAddr: SphincsAddress
    idxOffset: uint32 = 0
  copyKeypairAddr(treeAddr, forsAddr)
  copyKeypairAddr(pkAddr, forsAddr)
  setType(treeAddr, spxAddrTypeForsTree)
  setType(pkAddr, spxAddrTypeForsPk)
  messageToIndices(indices, msg)
  for i in 0 ..< spxForsTrees:
    idxOffset = uint32(i * (1 shl spxForsHeight))
    setTreeHeight(treeAddr, 0)
    setTreeIndex(treeAddr, indices[i] + idxOffset)
    var
      leaf: array[spxN, byte]
      rootNode: array[spxN, byte]
    thash(leaf, sig.toOpenArray(sigOff, sigOff + spxN - 1), 1, ctx, treeAddr)
    sigOff = sigOff + spxN
    var localTree = treeAddr
    computeRoot(rootNode, leaf, indices[i], idxOffset, uint32(spxForsHeight),
      sig.toOpenArray(sigOff, sigOff + (spxForsHeight * spxN) - 1), ctx, localTree)
    copyMem(addr roots[i * spxN], addr rootNode[0], spxN)
    sigOff = sigOff + (spxForsHeight * spxN)
  thash(pk, roots, spxForsTrees, ctx, pkAddr)
