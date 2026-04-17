## ----------------------------------------------------------
## SPHINCS Merkle <- WOTS-based hypertree signature helpers
## ----------------------------------------------------------

import ./params
import ./address
import ./context
import ./hash
import ./merkle_utils
import ./util
import ./wots

type
  WotsGenLeafInfo = object
    leafAddr: SphincsAddress
    pkAddr: SphincsAddress
    wotsSignLeaf: uint32
    wotsSig: ptr array[spxWotsBytes, byte]
    wotsSteps: ptr array[spxWotsLen, uint32]

proc wotsGenLeafX1(leaf: var openArray[byte], ctx: SphincsCtx, leafIdx: uint32,
    info: var WotsGenLeafInfo) =
  var
    pkBuffer: array[spxWotsBytes, byte]
    leafMask: uint32 = ctMaskEqU32(leafIdx, info.wotsSignLeaf)
    i: int = 0
    nodeOffset: int = 0
  defer:
    clearPlainData(leafMask)
  setKeypairAddr(info.leafAddr, leafIdx)
  setKeypairAddr(info.pkAddr, leafIdx)
  when defined(avx2):
    ## Keep the WOTS signing leaf path in 4-lane batches now that the shared
    ## AVX2 Keccak core is cheaper than four scalar one-block SHAKE calls.
    while i + 4 <= spxWotsLen:
      var
        nodes: array[4, array[spxN, byte]]
        addrs: array[4, SphincsAddress]
        chainTargets: array[4, uint32]
        lane: int = 0
        laneOffset: int = 0
        k: int = 0
      lane = 0
      while lane < 4:
        addrs[lane] = info.leafAddr
        setChainAddr(addrs[lane], uint32(i + lane))
        setHashAddr(addrs[lane], 0)
        setType(addrs[lane], spxAddrTypeWotsPrf)
        chainTargets[lane] =
          (info.wotsSteps[][i + lane] and leafMask) or
          (high(uint32) and not leafMask)
        lane = lane + 1
      prfAddrBatch4(nodes, ctx, addrs)
      lane = 0
      while lane < 4:
        setType(addrs[lane], spxAddrTypeWots)
        lane = lane + 1
      k = 0
      while true:
        lane = 0
        laneOffset = nodeOffset
        while lane < 4:
          ctCopyBytesMasked(
            info.wotsSig[].toOpenArray(laneOffset, laneOffset + spxN - 1),
            nodes[lane],
            ctMaskEqU32(uint32(k), chainTargets[lane])
          )
          laneOffset = laneOffset + spxN
          lane = lane + 1
        if k == (spxWotsW - 1):
          break
        lane = 0
        while lane < 4:
          setHashAddr(addrs[lane], uint32(k))
          lane = lane + 1
        thash1Batch4(nodes, nodes, ctx, addrs)
        k = k + 1
      lane = 0
      laneOffset = nodeOffset
      while lane < 4:
        copyMem(addr pkBuffer[laneOffset], addr nodes[lane][0], spxN)
        laneOffset = laneOffset + spxN
        lane = lane + 1
      clearSensitivePlainData(nodes)
      clearPlainData(chainTargets)
      i = i + 4
      nodeOffset = nodeOffset + (4 * spxN)
  while i < spxWotsLen:
    var
      node: array[spxN, byte]
      wotsK: uint32 =
        (info.wotsSteps[][i] and leafMask) or
        (high(uint32) and not leafMask)
      k: int = 0
    setChainAddr(info.leafAddr, uint32(i))
    setHashAddr(info.leafAddr, 0)
    setType(info.leafAddr, spxAddrTypeWotsPrf)
    prfAddr(node, ctx, info.leafAddr)
    setType(info.leafAddr, spxAddrTypeWots)
    while true:
      ctCopyBytesMasked(
        info.wotsSig[].toOpenArray(nodeOffset, nodeOffset + spxN - 1),
        node,
        ctMaskEqU32(uint32(k), wotsK)
      )
      if k == (spxWotsW - 1):
        break
      setHashAddr(info.leafAddr, uint32(k))
      thash(node, node, 1, ctx, info.leafAddr)
      k = k + 1
    copyMem(addr pkBuffer[nodeOffset], addr node[0], spxN)
    clearSensitivePlainData(node)
    clearPlainData(wotsK)
    i = i + 1
    nodeOffset = nodeOffset + spxN
  thash(leaf, pkBuffer, spxWotsLen, ctx, info.pkAddr)

proc merkleSign*(sig: var openArray[byte], sigOff: var int, root: var array[spxN, byte], ctx: SphincsCtx,
    wotsAddrBase, treeAddrBase: SphincsAddress, idxLeaf: uint32) =
  var
    authPath: array[spxTreeHeight * spxN, byte]
    wotsSig: array[spxWotsBytes, byte]
    steps: array[spxWotsLen, uint32]
    info: WotsGenLeafInfo
    localTree = treeAddrBase
  defer:
    clearPlainData(steps)
  setType(localTree, spxAddrTypeHashTree)
  setType(info.pkAddr, spxAddrTypeWotsPk)
  copySubtreeAddr(info.leafAddr, wotsAddrBase)
  copySubtreeAddr(info.pkAddr, wotsAddrBase)
  info.wotsSig = addr wotsSig
  info.wotsSteps = addr steps
  info.wotsSignLeaf = idxLeaf
  chainLengths(steps, root)
  treehashx1(root, authPath, ctx, idxLeaf, 0'u32, uint32(spxTreeHeight),
    wotsGenLeafX1, localTree, info)
  copyMem(addr sig[sigOff], addr wotsSig[0], wotsSig.len)
  sigOff = sigOff + spxWotsBytes
  copyMem(addr sig[sigOff], addr authPath[0], authPath.len)
  sigOff = sigOff + authPath.len

proc merkleGenRoot*(root: var array[spxN, byte], ctx: SphincsCtx) =
  var
    topTree: SphincsAddress
    wotsAddr: SphincsAddress
    scratch: array[spxWotsBytes + (spxTreeHeight * spxN), byte]
    scratchOff: int = 0
  setLayerAddr(topTree, uint32(spxD - 1))
  setLayerAddr(wotsAddr, uint32(spxD - 1))
  merkleSign(scratch, scratchOff, root, ctx, wotsAddr, topTree, high(uint32))
