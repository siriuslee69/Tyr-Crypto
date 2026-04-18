## ---------------------------------------------------------------------
## SPHINCS Operations <- pure-Nim SPHINCS+-SHAKE-128f-simple backend
## ---------------------------------------------------------------------

import ./params
import ./address
import ./context
import ./hash
import ./fors
import ./merkle
import ./merkle_utils
import ./wots
import ./util
import ../../../random

type
  SphincsTyrKeypair* = object
    variant*: SphincsVariant
    publicKey*: seq[byte]
    secretKey*: seq[byte]

proc initCtxFromSk(sk: openArray[byte]): SphincsCtx =
  if sk.len < (3 * spxN):
    raise newException(ValueError, "SPHINCS secret key must include skSeed and pubSeed")
  copyMem(addr result.skSeed[0], unsafeAddr sk[0], spxN)
  copyMem(addr result.pubSeed[0], unsafeAddr sk[2 * spxN], spxN)

proc copyRoot(dst: var array[spxN, byte], src: openArray[byte]) =
  copyMem(addr dst[0], unsafeAddr src[0], spxN)

proc sphincsTyrSeedKeypair*(v: SphincsVariant, seed: openArray[byte]): SphincsTyrKeypair =
  var
    p = params(v)
    ctx: SphincsCtx
    root: array[spxN, byte]
  defer:
    clearCtx(ctx)
  if seed.len != p.seedBytes:
    raise newException(ValueError, "SPHINCS seed keypair requires 48 bytes")
  result.variant = v
  result.secretKey = newSeq[byte](p.secretKeyBytes)
  copyMem(addr result.secretKey[0], unsafeAddr seed[0], p.seedBytes)
  result.publicKey = newSeq[byte](p.publicKeyBytes)
  copyMem(addr result.publicKey[0], unsafeAddr result.secretKey[2 * spxN], spxN)
  initCtx(ctx, result.secretKey.toOpenArray(2 * spxN, (3 * spxN) - 1),
    result.secretKey.toOpenArray(0, spxN - 1))
  merkleGenRoot(root, ctx)
  copyMem(addr result.secretKey[3 * spxN], addr root[0], spxN)
  copyMem(addr result.publicKey[spxN], addr root[0], spxN)

proc sphincsTyrKeypair*(v: SphincsVariant, seed: seq[byte] = @[]): SphincsTyrKeypair =
  var
    randomness: seq[byte] = @[]
  if seed.len > 0 and seed.len != 48:
    raise newException(ValueError, "SPHINCS seeded keypair requires 48 bytes")
  if seed.len == 0:
    randomness = cryptoRandomBytes(48)
  else:
    randomness = @seed
  defer:
    clearSensitiveBytes(randomness)
  result = sphincsTyrSeedKeypair(v, randomness)

proc sphincsTyrSignDerand*(v: SphincsVariant, msg: openArray[byte], sk: openArray[byte],
    optrand: openArray[byte]): seq[byte] =
  var
    p = params(v)
    ctx: SphincsCtx
    r: array[spxN, byte]
    mhash: array[spxForsMsgBytes, byte]
    rootNode: array[spxN, byte]
    tree: uint64 = 0
    idxLeaf: uint32 = 0
    wotsAddr, treeAddr: SphincsAddress
    sig = newSeq[byte](p.signatureBytes)
    sigOff: int = 0
  defer:
    clearCtx(ctx)
    clearPlainData(mhash)
    clearPlainData(rootNode)
    clearPlainData(tree)
    clearPlainData(idxLeaf)
  if sk.len != p.secretKeyBytes:
    raise newException(ValueError, "invalid SPHINCS secret key length")
  if optrand.len != p.n:
    raise newException(ValueError, "SPHINCS signing randomness must be 16 bytes")
  ctx = initCtxFromSk(sk)
  genMessageRandom(r, sk.toOpenArray(spxN, (2 * spxN) - 1), optrand, msg, ctx)
  copyMem(addr sig[0], addr r[0], spxN)
  sigOff = spxN
  hashMessage(mhash, tree, idxLeaf, r, sk.toOpenArray(2 * spxN, (4 * spxN) - 1), msg, ctx)
  setType(wotsAddr, spxAddrTypeWots)
  setType(treeAddr, spxAddrTypeHashTree)
  setTreeAddr(wotsAddr, tree)
  setKeypairAddr(wotsAddr, idxLeaf)
  forsSign(sig, sigOff, rootNode, mhash, ctx, wotsAddr)
  for i in 0 ..< p.d:
    setLayerAddr(treeAddr, uint32(i))
    setTreeAddr(treeAddr, tree)
    copySubtreeAddr(wotsAddr, treeAddr)
    setKeypairAddr(wotsAddr, idxLeaf)
    merkleSign(sig, sigOff, rootNode, ctx, wotsAddr, treeAddr, idxLeaf)
    idxLeaf = uint32(tree and ((1'u64 shl p.treeHeight) - 1'u64))
    tree = tree shr p.treeHeight
  result = sig

proc sphincsTyrSign*(v: SphincsVariant, msg: openArray[byte], sk: openArray[byte]): seq[byte] =
  result = sphincsTyrSignDerand(v, msg, sk, cryptoRandomBytes(16))

proc sphincsTyrVerify*(v: SphincsVariant, msg, sig, pk: openArray[byte]): bool =
  var
    p = params(v)
    ctx: SphincsCtx
    pubRoot: array[spxN, byte]
    mhash: array[spxForsMsgBytes, byte]
    wotsPk: array[spxWotsBytes, byte]
    rootNode: array[spxN, byte]
    leaf: array[spxN, byte]
    tree: uint64 = 0
    idxLeaf: uint32 = 0
    sigOff: int = 0
    wotsAddr, treeAddr, wotsPkAddr: SphincsAddress
  if sig.len != p.signatureBytes or pk.len != p.publicKeyBytes:
    return false
  initCtx(ctx, pk.toOpenArray(0, 15), pk.toOpenArray(0, 15))
  copyRoot(pubRoot, pk.toOpenArray(16, 31))
  setType(wotsAddr, spxAddrTypeWots)
  setType(treeAddr, spxAddrTypeHashTree)
  setType(wotsPkAddr, spxAddrTypeWotsPk)
  hashMessage(mhash, tree, idxLeaf, sig.toOpenArray(0, 15), pk, msg, ctx)
  sigOff = spxN
  setTreeAddr(wotsAddr, tree)
  setKeypairAddr(wotsAddr, idxLeaf)
  forsPkFromSig(rootNode, sig, sigOff, mhash, ctx, wotsAddr)
  for i in 0 ..< p.d:
    setLayerAddr(treeAddr, uint32(i))
    setTreeAddr(treeAddr, tree)
    copySubtreeAddr(wotsAddr, treeAddr)
    setKeypairAddr(wotsAddr, idxLeaf)
    copyKeypairAddr(wotsPkAddr, wotsAddr)
    wotsPkFromSig(wotsPk, sig.toOpenArray(sigOff, sigOff + p.wotsBytes - 1), rootNode, ctx, wotsAddr)
    sigOff = sigOff + p.wotsBytes
    thash(leaf, wotsPk, p.wotsLen, ctx, wotsPkAddr)
    var localTree = treeAddr
    computeRoot(rootNode, leaf, idxLeaf, 0'u32, uint32(p.treeHeight),
      sig.toOpenArray(sigOff, sigOff + p.treeHeight * 16 - 1), ctx, localTree)
    sigOff = sigOff + p.treeHeight * 16
    idxLeaf = uint32(tree and ((1'u64 shl p.treeHeight) - 1'u64))
    tree = tree shr p.treeHeight
  for i in 0 ..< 16:
    if rootNode[i] != pubRoot[i]:
      return false
  result = true
