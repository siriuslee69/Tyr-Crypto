## ----------------------------------------------------------------------
## SPHINCS Params <- parameter tables for the pure-Nim SPHINCS+ backend
## ----------------------------------------------------------------------

type
  ## Concrete SPHINCS+ parameter family implemented locally.
  SphincsVariant* = enum
    sphincsShake128fSimple

  ## Fixed parameter record for one SPHINCS+ family member.
  SphincsParams* = object
    name*: string
    n*: int
    fullHeight*: int
    d*: int
    forsHeight*: int
    forsTrees*: int
    wotsW*: int
    addrBytes*: int
    wotsLogW*: int
    wotsLen1*: int
    wotsLen2*: int
    wotsLen*: int
    wotsBytes*: int
    treeHeight*: int
    forsMsgBytes*: int
    forsBytes*: int
    forsPkBytes*: int
    signatureBytes*: int
    publicKeyBytes*: int
    secretKeyBytes*: int
    seedBytes*: int

const
  spxN* = 16
  spxFullHeight* = 66
  spxD* = 22
  spxForsHeight* = 6
  spxForsTrees* = 33
  spxWotsW* = 16
  spxAddrBytes* = 32
  spxWotsLogW* = 4
  spxWotsLen1* = (8 * spxN) div spxWotsLogW
  spxWotsLen2* = 3
  spxWotsLen* = spxWotsLen1 + spxWotsLen2
  spxWotsBytes* = spxWotsLen * spxN
  spxTreeHeight* = spxFullHeight div spxD
  spxMaxTreeHeight* = spxForsHeight
  spxForsMsgBytes* = ((spxForsHeight * spxForsTrees) + 7) div 8
  spxForsBytes* = (spxForsHeight + 1) * spxForsTrees * spxN
  spxForsPkBytes* = spxN
  spxSignatureBytes* = spxN + spxForsBytes + (spxD * spxWotsBytes) + (spxFullHeight * spxN)
  spxPublicKeyBytes* = 2 * spxN
  spxSecretKeyBytes* = 4 * spxN
  spxSeedBytes* = 3 * spxN
  spxMaxThashBytes* = spxN + spxAddrBytes + (spxWotsLen * spxN)

  spxAddrTypeWots* = 0'u32
  spxAddrTypeWotsPk* = 1'u32
  spxAddrTypeHashTree* = 2'u32
  spxAddrTypeForsTree* = 3'u32
  spxAddrTypeForsPk* = 4'u32
  spxAddrTypeWotsPrf* = 5'u32
  spxAddrTypeForsPrf* = 6'u32

  spxOffsetLayer* = 3
  spxOffsetTree* = 8
  spxOffsetType* = 19
  spxOffsetKpAddr2* = 22
  spxOffsetKpAddr1* = 23
  spxOffsetChainAddr* = 27
  spxOffsetHashAddr* = 31
  spxOffsetTreeHgt* = 27
  spxOffsetTreeIndex* = 28

proc buildSphincsShake128fSimple(): SphincsParams =
  result = SphincsParams(
    name: "SPHINCS+-SHAKE-128f-simple",
    n: spxN,
    fullHeight: spxFullHeight,
    d: spxD,
    forsHeight: spxForsHeight,
    forsTrees: spxForsTrees,
    wotsW: spxWotsW,
    addrBytes: spxAddrBytes,
    wotsLogW: spxWotsLogW,
    wotsLen1: spxWotsLen1,
    wotsLen2: spxWotsLen2,
    wotsLen: spxWotsLen,
    wotsBytes: spxWotsBytes,
    treeHeight: spxTreeHeight,
    forsMsgBytes: spxForsMsgBytes,
    forsBytes: spxForsBytes,
    forsPkBytes: spxForsPkBytes,
    signatureBytes: spxSignatureBytes,
    publicKeyBytes: spxPublicKeyBytes,
    secretKeyBytes: spxSecretKeyBytes,
    seedBytes: spxSeedBytes
  )

const sphincsParamsTable*: array[SphincsVariant, SphincsParams] = [
  sphincsShake128fSimple: buildSphincsShake128fSimple()
]

proc params*(v: SphincsVariant): SphincsParams {.inline.} =
  ## Return the fixed parameter set for one SPHINCS+ variant.
  result = sphincsParamsTable[v]
