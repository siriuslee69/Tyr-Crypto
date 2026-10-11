## ----------------------------------------------------------
## SPHINCS Merkle <- WOTS-based hypertree signature helpers
## ----------------------------------------------------------
##
## One Merkle tree of the hypertree has 2^treeHeight leaves. Each leaf is
## the hash of one WOTS public key, and a WOTS public key is the end of
## spxWotsLen hash chains:
##
##   chain c:  secret = PRF(address of c) -> hash -> hash -> ... -> end
##             (spxWotsW - 1 hashes)
##   leaf   =  hash(end of chain 0 | end of chain 1 | ...)
##
## While the leaf that signs is built, the WOTS signature is taken from
## the middle of each chain: the value after wotsSteps[c] hashes. Every
## leaf does the same work and the pick is masked, so nothing shows which
## leaf signs.
##
## Chains are hashed 4 at a time with AVX2, 2 at a time with SSE2/NEON,
## and one at a time for whatever is left.

import ./params
import ../../helpers/secure_memory
import ./address
import ./context
import ./hash
import ./merkle_utils
import ./util
import ./wots
import runePragmas

type
  WotsGenLeafInfo = object
    leafAddr: SphincsAddress
    pkAddr: SphincsAddress
    wotsSignLeaf: uint32
    wotsSig: ptr array[spxWotsBytes, byte]
    wotsSteps: ptr array[spxWotsLen, uint32]

## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; hypertree and authentication-path algorithms for `chainTarget`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc chainTarget(info: WotsGenLeafInfo, c: int, leafMask: uint32): uint32 {.inline, role: {math}.} =
  ## c: chain. Returns the step to capture: wotsSteps[c] on the signing
  ## leaf (leafMask all ones), otherwise a step no chain reaches.
  (info.wotsSteps[][c] and leafMask) or (high(uint32) and not leafMask)

when defined(sse2) or defined(neon) or defined(arm64) or defined(aarch64):
  ## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; hypertree and authentication-path algorithms for `captureLanes`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
  proc captureLanes[L: static[int]](info: var WotsGenLeafInfo,
      nodes: array[L, array[spxN, byte]], targets: array[L, uint32], c, k: int)
      {.inline, role: {math}.} =
    ## nodes: chains c ..< c + L after k hashes. Each lane is copied into
    ## the signature only when k is its target step (masked copy).
    var
      lane: int = 0
      o: int = c * spxN
    while lane < L:
      ctCopyBytesMasked(info.wotsSig[].toOpenArray(o, o + spxN - 1), nodes[lane],
        ctMaskEqU32(uint32(k), targets[lane]))
      o = o + spxN
      lane = lane + 1

  ## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; hypertree and authentication-path algorithms for `setLaneHashAddrs`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc setLaneHashAddrs[L: static[int]](addrs: var array[L, SphincsAddress], k: int)
      {.inline, role: {helper}.} =
    ## addrs: every lane address moves to hash step k.
    var
      lane: int = 0
    while lane < L:
      setHashAddr(addrs[lane], uint32(k))
      lane = lane + 1

  ## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; hypertree and authentication-path algorithms for `wotsChainLanes`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
  proc wotsChainLanes[L: static[int]](info: var WotsGenLeafInfo,
      pkBuffer: var array[spxWotsBytes, byte], ctx: SphincsCtx, c: int,
      leafMask: uint32) {.role: {math}.} =
    ## Chains c ..< c + L of one leaf, L lanes at once (L = 4 or 2).
    ## pkBuffer: receives their chain ends.
    ## Paper note: this is the applied SPHINCS+ hash-batching optimization from
    ## the SHA/SLH-DSA performance papers, with masked signature capture rather
    ## than the signer redesign from side-channel-resistant SPHINCS+ papers.
    var
      nodes: array[L, array[spxN, byte]] = default(array[L, array[spxN, byte]])
      addrs: array[L, SphincsAddress] = default(array[L, SphincsAddress])
      targets: array[L, uint32] = default(array[L, uint32])
      lane: int = 0
      k: int = 0
    defer:
      secureClearPod(nodes)
      clearPlainData(targets)
    while lane < L:
      addrs[lane] = info.leafAddr
      setChainAddr(addrs[lane], uint32(c + lane))
      setHashAddr(addrs[lane], 0)
      setType(addrs[lane], spxAddrTypeWotsPrf)
      targets[lane] = chainTarget(info, c + lane, leafMask)
      lane = lane + 1
    when L == 4:
      prfAddrBatch4(nodes, ctx, addrs)
    else:
      prfAddrBatch2(nodes, ctx, addrs)
    lane = 0
    while lane < L:
      setType(addrs[lane], spxAddrTypeWots)
      lane = lane + 1
    captureLanes(info, nodes, targets, c, 0)
    while k < spxWotsW - 1:
      setLaneHashAddrs(addrs, k)
      when L == 4:
        thash1Batch4(nodes, nodes, ctx, addrs)
      else:
        thash1Batch2(nodes, nodes, ctx, addrs)
      k = k + 1
      captureLanes(info, nodes, targets, c, k)
    lane = 0
    while lane < L:
      copyMem(addr pkBuffer[(c + lane) * spxN], addr nodes[lane][0], spxN)
      lane = lane + 1

## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; hypertree and authentication-path algorithms for `wotsChainOne`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc wotsChainOne(info: var WotsGenLeafInfo, pkBuffer: var array[spxWotsBytes, byte],
    ctx: SphincsCtx, c: int, leafMask: uint32) {.role: {math}.} =
  ## Chain c of one leaf, alone. pkBuffer: receives its chain end.
  var
    node: array[spxN, byte] = default(array[spxN, byte])
    target: uint32 = chainTarget(info, c, leafMask)
    o: int = c * spxN
    k: int = 0
  defer:
    secureClearPod(node)
    clearPlainData(target)
  setChainAddr(info.leafAddr, uint32(c))
  setHashAddr(info.leafAddr, 0)
  setType(info.leafAddr, spxAddrTypeWotsPrf)
  prfAddr(node, ctx, info.leafAddr)
  setType(info.leafAddr, spxAddrTypeWots)
  ctCopyBytesMasked(info.wotsSig[].toOpenArray(o, o + spxN - 1), node,
    ctMaskEqU32(0'u32, target))
  while k < spxWotsW - 1:
    setHashAddr(info.leafAddr, uint32(k))
    thash(node, node, 1, ctx, info.leafAddr)
    k = k + 1
    ctCopyBytesMasked(info.wotsSig[].toOpenArray(o, o + spxN - 1), node,
      ctMaskEqU32(uint32(k), target))
  copyMem(addr pkBuffer[o], addr node[0], spxN)

## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; hypertree and authentication-path algorithms for `wotsGenLeafX1`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc wotsGenLeafX1(leaf: var openArray[byte], ctx: SphincsCtx, leafIdx: uint32,
    info: var WotsGenLeafInfo) {.role: {math}.} =
  ## leaf: receives the hash of WOTS public key number leafIdx. On the
  ## signing leaf the WOTS signature is captured into info.wotsSig.
  var
    pkBuffer: array[spxWotsBytes, byte] = default(array[spxWotsBytes, byte])
    leafMask: uint32 = ctMaskEqU32(leafIdx, info.wotsSignLeaf)
    c: int = 0
  defer:
    clearPlainData(leafMask)
  setKeypairAddr(info.leafAddr, leafIdx)
  setKeypairAddr(info.pkAddr, leafIdx)
  when defined(avx2):
    while c + 4 <= spxWotsLen:
      wotsChainLanes[4](info, pkBuffer, ctx, c, leafMask)
      c = c + 4
  when defined(sse2) or defined(neon) or defined(arm64) or defined(aarch64):
    while c + 2 <= spxWotsLen:
      wotsChainLanes[2](info, pkBuffer, ctx, c, leafMask)
      c = c + 2
  while c < spxWotsLen:
    wotsChainOne(info, pkBuffer, ctx, c, leafMask)
    c = c + 1
  thash(leaf, pkBuffer, spxWotsLen, ctx, info.pkAddr)

## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; hypertree and authentication-path algorithms for `merkleSign`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc merkleSign*(sig: var openArray[byte], sigOff: var int, root: var array[spxN, byte], ctx: SphincsCtx,
    wotsAddrBase, treeAddrBase: SphincsAddress, idxLeaf: uint32) {.role: {math}.} =
  ## Signs root (the root of the tree below) with leaf idxLeaf of this
  ## tree. sig: receives [WOTS signature][authentication path] at sigOff,
  ## which moves past them. root: replaced by this tree's root.
  var
    authPath: array[spxTreeHeight * spxN, byte] = default(array[spxTreeHeight * spxN, byte])
    wotsSig: array[spxWotsBytes, byte] = default(array[spxWotsBytes, byte])
    steps: array[spxWotsLen, uint32] = default(array[spxWotsLen, uint32])
    info: WotsGenLeafInfo = default(WotsGenLeafInfo)
    localTree: SphincsAddress = treeAddrBase
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

## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; hypertree and authentication-path algorithms for `merkleGenRoot`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc merkleGenRoot*(root: var array[spxN, byte], ctx: SphincsCtx) {.role: {math}.} =
  ## root: receives the root of the top tree (the public key root).
  var
    topTree: SphincsAddress = default(SphincsAddress)
    wotsAddr: SphincsAddress = default(SphincsAddress)
    scratch: array[spxWotsBytes + (spxTreeHeight * spxN), byte] =
      default(array[spxWotsBytes + (spxTreeHeight * spxN), byte])
    scratchOff: int = 0
  setLayerAddr(topTree, uint32(spxD - 1))
  setLayerAddr(wotsAddr, uint32(spxD - 1))
  merkleSign(scratch, scratchOff, root, ctx, wotsAddr, topTree, high(uint32))
