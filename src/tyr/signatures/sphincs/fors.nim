## ----------------------------------------------------------
## SPHINCS FORS <- FORS signing and public-key reconstruction
## ----------------------------------------------------------

import ./params
import ../../helpers/secure_memory
import ./address
import ./context
import ./hash
import ./merkle_utils
import ./util
import runePragmas

type
  ForsGenLeafInfo = object
    leafAddr: SphincsAddress

## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; FORS algorithms for `forsGenLeafX1`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc forsGenLeafX1(leaf: var openArray[byte], ctx: SphincsCtx, addrIdx: uint32,
    info: var ForsGenLeafInfo) {.role: {math}.} =
  ## leaf: receives FORS leaf addrIdx: the hash of its secret value.
  setTreeIndex(info.leafAddr, addrIdx)
  setType(info.leafAddr, spxAddrTypeForsPrf)
  prfAddr(leaf, ctx, info.leafAddr)
  setType(info.leafAddr, spxAddrTypeForsTree)
  thash(leaf, leaf, 1, ctx, info.leafAddr)

## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; FORS algorithms for `messageToIndices`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc messageToIndices*(indices: var openArray[uint32], msg: openArray[byte]) {.role: {parser}.} =
  ## msg: digest read as a bit string, least significant bit of each byte
  ## first. Every spxForsHeight bits become one tree index (low bit first).
  var
    bit: int = 0
    i: int = 0
    j: int = 0
  while bit < spxForsTrees * spxForsHeight:
    i = bit div spxForsHeight
    j = bit mod spxForsHeight
    if j == 0:
      indices[i] = 0
    indices[i] = indices[i] xor (uint32((msg[bit shr 3] shr (bit and 7)) and 1'u8) shl j)
    bit = bit + 1

## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; FORS algorithms for `forsSign`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc forsSign*(sig: var seq[byte], sigOff: var int, pk: var array[spxN, byte], msg: openArray[byte],
    ctx: SphincsCtx, forsAddr: SphincsAddress) {.role: {math}.} =
  ## Signs msg (a digest) with FORS: per tree, the secret leaf the digest
  ## picks plus its authentication path. pk: receives the FORS public key.
  var
    indices: array[spxForsTrees, uint32] = default(array[spxForsTrees, uint32])
    roots: array[spxForsTrees * spxN, byte] = default(array[spxForsTrees * spxN, byte])
    treeAddr: SphincsAddress = default(SphincsAddress)
    leafAddr: SphincsAddress = default(SphincsAddress)
    pkAddr: SphincsAddress = default(SphincsAddress)
    info: ForsGenLeafInfo = default(ForsGenLeafInfo)
    idxOffset: uint32 = 0
    authPath: array[spxForsHeight * spxN, byte] = default(array[spxForsHeight * spxN, byte])
    skPart: array[spxN, byte] = default(array[spxN, byte])
    rootNode: array[spxN, byte] = default(array[spxN, byte])
    localTree: SphincsAddress = default(SphincsAddress)
    i: int = 0
  defer:
    clearPlainData(indices)
    clearPlainData(roots)
    secureClearPod(skPart)
  copyKeypairAddr(treeAddr, forsAddr)
  copyKeypairAddr(leafAddr, forsAddr)
  copyKeypairAddr(pkAddr, forsAddr)
  setType(pkAddr, spxAddrTypeForsPk)
  info.leafAddr = leafAddr
  messageToIndices(indices, msg)
  while i < spxForsTrees:
    idxOffset = uint32(i * (1 shl spxForsHeight))
    setTreeHeight(treeAddr, 0)
    setTreeIndex(treeAddr, indices[i] + idxOffset)
    setType(treeAddr, spxAddrTypeForsPrf)
    prfAddr(skPart, ctx, treeAddr)
    copyMem(addr sig[sigOff], addr skPart[0], spxN)
    sigOff = sigOff + spxN
    setType(treeAddr, spxAddrTypeForsTree)
    localTree = treeAddr
    treehashx1(rootNode, authPath, ctx, indices[i], idxOffset, uint32(spxForsHeight),
      forsGenLeafX1, localTree, info)
    copyMem(addr roots[i * spxN], addr rootNode[0], spxN)
    copyMem(addr sig[sigOff], addr authPath[0], authPath.len)
    sigOff = sigOff + authPath.len
    secureClearPod(skPart)
    clearPlainData(rootNode)
    i = i + 1
  thash(pk, roots, spxForsTrees, ctx, pkAddr)

## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; FORS algorithms for `forsPkFromSig`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc forsPkFromSig*(pk: var array[spxN, byte], sig: openArray[byte], sigOff: var int, msg: openArray[byte],
    ctx: SphincsCtx, forsAddr: SphincsAddress) {.role: {math}.} =
  ## pk: receives the FORS public key rebuilt from a signature at sigOff
  ## (sigOff moves past it).
  var
    indices: array[spxForsTrees, uint32] = default(array[spxForsTrees, uint32])
    roots: array[spxForsTrees * spxN, byte] = default(array[spxForsTrees * spxN, byte])
    treeAddr: SphincsAddress = default(SphincsAddress)
    pkAddr: SphincsAddress = default(SphincsAddress)
    idxOffset: uint32 = 0
    leaf: array[spxN, byte] = default(array[spxN, byte])
    rootNode: array[spxN, byte] = default(array[spxN, byte])
    localTree: SphincsAddress = default(SphincsAddress)
    i: int = 0
  copyKeypairAddr(treeAddr, forsAddr)
  copyKeypairAddr(pkAddr, forsAddr)
  setType(treeAddr, spxAddrTypeForsTree)
  setType(pkAddr, spxAddrTypeForsPk)
  messageToIndices(indices, msg)
  while i < spxForsTrees:
    idxOffset = uint32(i * (1 shl spxForsHeight))
    setTreeHeight(treeAddr, 0)
    setTreeIndex(treeAddr, indices[i] + idxOffset)
    thash(leaf, sig.toOpenArray(sigOff, sigOff + spxN - 1), 1, ctx, treeAddr)
    sigOff = sigOff + spxN
    localTree = treeAddr
    computeRoot(rootNode, leaf, indices[i], idxOffset, uint32(spxForsHeight),
      sig.toOpenArray(sigOff, sigOff + (spxForsHeight * spxN) - 1), ctx, localTree)
    copyMem(addr roots[i * spxN], addr rootNode[0], spxN)
    sigOff = sigOff + (spxForsHeight * spxN)
    i = i + 1
  thash(pk, roots, spxForsTrees, ctx, pkAddr)
