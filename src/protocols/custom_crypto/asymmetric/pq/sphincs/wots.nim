## ----------------------------------------------------------
## SPHINCS WOTS <- WOTS+ helper functions for SPHINCS+ SHAKE
## ----------------------------------------------------------

import ./params
import ./address
import ./context
import ./hash
import ./util

when defined(sse2) or defined(neon) or defined(arm64) or defined(aarch64) or defined(avx2):
  ## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; WOTS+ algorithms for `applyWotsHashStep`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc applyWotsHashStep(node: var array[spxN, byte], ctx: SphincsCtx,
      A: var SphincsAddress, hashAddr: uint32) {.inline.} =
    ## Paper note: scalar WOTS steps remain available for lanes that cannot be
    ## safely batched at the same public chain address.
    setHashAddr(A, hashAddr)
    thash(node, node, 1, ctx, A)

  ## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; WOTS+ algorithms for `applyWotsHashStep2`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc applyWotsHashStep2(nodes: var array[2, array[spxN, byte]], ctx: SphincsCtx,
      addrs: var array[2, SphincsAddress], hashAddr: uint32) =
    ## Paper note: two WOTS chains at the same public hash address are batched
    ## through `thash1Batch2`, preserving the SPHINCS+ chain schedule.
    setHashAddr(addrs[0], hashAddr)
    setHashAddr(addrs[1], hashAddr)
    thash1Batch2(nodes, nodes, ctx, addrs)

when defined(avx2):
  ## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; WOTS+ algorithms for `applyWotsHashStep2`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc applyWotsHashStep2(nodes: var array[4, array[spxN, byte]], ctx: SphincsCtx,
      addrs: array[4, SphincsAddress], lane0, lane1: int, hashAddr: uint32) =
    ## Paper note: AVX2 verifier code batches only active lane pairs when four
    ## WOTS chains are not at the same public step.
    var
      pairNodes: array[2, array[spxN, byte]]
      pairAddrs: array[2, SphincsAddress]
    pairNodes[0] = nodes[lane0]
    pairNodes[1] = nodes[lane1]
    pairAddrs[0] = addrs[lane0]
    pairAddrs[1] = addrs[lane1]
    setHashAddr(pairAddrs[0], hashAddr)
    setHashAddr(pairAddrs[1], hashAddr)
    thash1Batch2(pairNodes, pairNodes, ctx, pairAddrs)
    nodes[lane0] = pairNodes[0]
    nodes[lane1] = pairNodes[1]

  ## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; WOTS+ algorithms for `applyWotsHashStep4`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc applyWotsHashStep4(nodes: var array[4, array[spxN, byte]], ctx: SphincsCtx,
      addrs: var array[4, SphincsAddress], hashAddr: uint32) =
    ## Paper note: full 4-lane WOTS batching applies only when all lanes share
    ## this exact public hash address.
    var
      lane: int = 0
    lane = 0
    while lane < 4:
      setHashAddr(addrs[lane], hashAddr)
      lane = lane + 1
    thash1Batch4(nodes, nodes, ctx, addrs)

## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; WOTS+ algorithms for `genChain`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc genChain(outNode: var array[16, byte], input: openArray[byte], start, steps: int,
    ctx: SphincsCtx, A: var SphincsAddress) =
  copyMem(addr outNode[0], unsafeAddr input[0], spxN)
  var
    i: int = start
  while i < start + steps and i < spxWotsW:
    setHashAddr(A, uint32(i))
    thash(outNode, outNode, 1, ctx, A)
    i = i + 1

## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; WOTS+ algorithms for `baseW`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc baseW*(output: var openArray[uint32], outLen: int, input: openArray[byte]) =
  var
    inIdx: int = 0
    outIdx: int = 0
    total: uint8 = 0
    bits: int = 0
    consumed: int = 0
  consumed = 0
  while consumed < outLen:
    if bits == 0:
      total = input[inIdx]
      inIdx = inIdx + 1
      bits = bits + 8
    bits = bits - 4
    output[outIdx] = uint32((total shr bits) and 15'u8)
    outIdx = outIdx + 1
    consumed = consumed + 1

## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; WOTS+ algorithms for `wotsChecksum`; pitfall: fail closed and preserve canonical, constant-time comparison where secrets are involved.
proc wotsChecksum*(output: var openArray[uint32], msgBaseW: openArray[uint32]) =
  var
    csum: uint32 = 0
    csumBytes: array[((spxWotsLen2 * spxWotsLogW) + 7) div 8, byte]
  for i in 0 ..< spxWotsLen1:
    csum = csum + uint32(15) - msgBaseW[i]
  csum = csum shl ((8 - ((spxWotsLen2 * spxWotsLogW) mod 8)) mod 8)
  ullToBytes(csumBytes, uint64(csum))
  baseW(output, spxWotsLen2, csumBytes)

## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; WOTS+ algorithms for `chainLengths`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc chainLengths*(output: var openArray[uint32], msg: openArray[byte]) =
  var
    csum: array[spxWotsLen2, uint32]
  baseW(output, spxWotsLen1, msg)
  wotsChecksum(csum, output)
  for i in 0 ..< spxWotsLen2:
    output[spxWotsLen1 + i] = csum[i]

## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; WOTS+ algorithms for `wotsPkFromSig`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc wotsPkFromSig*(pk: var openArray[byte], sig, msg: openArray[byte],
    ctx: SphincsCtx, A: var SphincsAddress) =
  ## Paper note: verifier-side batching groups public WOTS chain steps; it is a
  ## performance path and not the Multi-Armed SPHINCS+ signing variant.
  var
    lengths: array[spxWotsLen, uint32]
    i: int = 0
  chainLengths(lengths, msg)
  when defined(avx2):
    while i + 4 <= spxWotsLen:
      var
        nodes: array[4, array[spxN, byte]]
        addrs: array[4, SphincsAddress]
        starts: array[4, uint32]
        active: array[4, int]
        lane: int = 0
        activeLen: int = 0
        hashAddr: int = 0
      lane = 0
      while lane < 4:
        copyMem(addr nodes[lane][0], unsafeAddr sig[(i + lane) * spxN], spxN)
        addrs[lane] = A
        setChainAddr(addrs[lane], uint32(i + lane))
        starts[lane] = lengths[i + lane]
        lane = lane + 1
      hashAddr = 0
      while hashAddr < (spxWotsW - 1):
        activeLen = 0
        lane = 0
        while lane < 4:
          if uint32(hashAddr) >= starts[lane]:
            active[activeLen] = lane
            activeLen = activeLen + 1
          lane = lane + 1
        if activeLen == 4:
          ## Batch only lanes that really are at this exact chain step so the
          ## AVX2 verifier path stays identical to the scalar address schedule.
          applyWotsHashStep4(nodes, ctx, addrs, uint32(hashAddr))
        elif activeLen == 3:
          applyWotsHashStep2(nodes, ctx, addrs, active[0], active[1], uint32(hashAddr))
          applyWotsHashStep(nodes[active[2]], ctx, addrs[active[2]], uint32(hashAddr))
        elif activeLen == 2:
          applyWotsHashStep2(nodes, ctx, addrs, active[0], active[1], uint32(hashAddr))
        elif activeLen == 1:
          applyWotsHashStep(nodes[active[0]], ctx, addrs[active[0]], uint32(hashAddr))
        hashAddr = hashAddr + 1
      lane = 0
      while lane < 4:
        copyMem(addr pk[(i + lane) * spxN], addr nodes[lane][0], spxN)
        lane = lane + 1
      i = i + 4
  when defined(sse2) or defined(neon) or defined(arm64) or defined(aarch64):
    while i + 2 <= spxWotsLen:
      var
        nodes: array[2, array[spxN, byte]]
        addrs: array[2, SphincsAddress]
        starts: array[2, uint32]
        active: array[2, int]
        lane: int = 0
        activeLen: int = 0
        hashAddr: int = 0
      lane = 0
      while lane < 2:
        copyMem(addr nodes[lane][0], unsafeAddr sig[(i + lane) * spxN], spxN)
        addrs[lane] = A
        setChainAddr(addrs[lane], uint32(i + lane))
        starts[lane] = lengths[i + lane]
        lane = lane + 1
      hashAddr = 0
      while hashAddr < (spxWotsW - 1):
        activeLen = 0
        lane = 0
        while lane < 2:
          if uint32(hashAddr) >= starts[lane]:
            active[activeLen] = lane
            activeLen = activeLen + 1
          lane = lane + 1
        if activeLen == 2:
          applyWotsHashStep2(nodes, ctx, addrs, uint32(hashAddr))
        elif activeLen == 1:
          applyWotsHashStep(nodes[active[0]], ctx, addrs[active[0]], uint32(hashAddr))
        hashAddr = hashAddr + 1
      lane = 0
      while lane < 2:
        copyMem(addr pk[(i + lane) * spxN], addr nodes[lane][0], spxN)
        lane = lane + 1
      i = i + 2
  while i < spxWotsLen:
    setChainAddr(A, uint32(i))
    var node: array[16, byte]
    genChain(node, sig.toOpenArray(i * spxN, i * spxN + spxN - 1), int(lengths[i]),
      (spxWotsW - 1) - int(lengths[i]), ctx, A)
    copyMem(addr pk[i * spxN], addr node[0], spxN)
    i = i + 1
