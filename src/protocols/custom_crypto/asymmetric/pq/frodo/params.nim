## --------------------------------------------------------------------
## Frodo Params <- parameter table for the pure-Nim FrodoKEM backend
## --------------------------------------------------------------------

type
  ## Matrix generator used by one Frodo family member.
  FrodoMatrixGenerator* = enum
    fmgAes128
    fmgShake128

  ## SHAKE width used by the non-matrix Frodo XOF flows.
  FrodoXofKind* = enum
    fxShake128
    fxShake256

  ## Concrete FrodoKEM parameter family.
  FrodoVariant* = enum
    frodo640aes
    frodo640shake
    frodo976aes
    frodo976shake
    frodo1344aes
    frodo1344shake

  ## Fixed parameter record for one FrodoKEM family member.
  FrodoParams* = object
    name*: string
    n*: int
    nbar*: int
    logQ*: int
    q*: uint32
    extractedBits*: int
    stripeStep*: int
    parallelStep*: int
    bytesSeedA*: int
    bytesMu*: int
    bytesPkHash*: int
    xofKind*: FrodoXofKind
    matrixGenerator*: FrodoMatrixGenerator
    cdfTable*: array[13, uint16]
    cdfTableLen*: int
    publicKeyBytes*: int
    secretKeyBytes*: int
    ciphertextBytes*: int
    sharedSecretBytes*: int
    matrixKeyBytes*: int
    keypairRandomBytes*: int
    encapsRandomBytes*: int

proc buildFrodoParams(name: string, n, logQ, extractedBits, cdfTableLen,
    publicKeyBytes, secretKeyBytes, ciphertextBytes, sharedSecretBytes: int,
    xofKind: FrodoXofKind, matrixGenerator: FrodoMatrixGenerator,
    cdfTable: array[13, uint16]): FrodoParams =
  result = FrodoParams(
    name: name,
    n: n,
    nbar: 8,
    logQ: logQ,
    q: 1'u32 shl logQ,
    extractedBits: extractedBits,
    stripeStep: 8,
    parallelStep: 4,
    bytesSeedA: 16,
    bytesMu: (extractedBits * 8 * 8) div 8,
    bytesPkHash: sharedSecretBytes,
    xofKind: xofKind,
    matrixGenerator: matrixGenerator,
    cdfTable: cdfTable,
    cdfTableLen: cdfTableLen,
    publicKeyBytes: publicKeyBytes,
    secretKeyBytes: secretKeyBytes,
    ciphertextBytes: ciphertextBytes,
    sharedSecretBytes: sharedSecretBytes,
    matrixKeyBytes: 16,
    keypairRandomBytes: 2 * sharedSecretBytes + 16,
    encapsRandomBytes: (extractedBits * 8 * 8) div 8
  )

proc buildFrodo640Aes(): FrodoParams =
  result = buildFrodoParams(
    "frodo640aes",
    640,
    15,
    2,
    13,
    9616,
    19888,
    9720,
    16,
    fxShake128,
    fmgAes128,
    [4643'u16, 13363'u16, 20579'u16, 25843'u16, 29227'u16, 31145'u16, 32103'u16,
      32525'u16, 32689'u16, 32745'u16, 32762'u16, 32766'u16, 32767'u16]
  )

proc buildFrodo640Shake(): FrodoParams =
  result = buildFrodoParams(
    "frodo640shake",
    640,
    15,
    2,
    13,
    9616,
    19888,
    9720,
    16,
    fxShake128,
    fmgShake128,
    [4643'u16, 13363'u16, 20579'u16, 25843'u16, 29227'u16, 31145'u16, 32103'u16,
      32525'u16, 32689'u16, 32745'u16, 32762'u16, 32766'u16, 32767'u16]
  )

proc buildFrodo976Aes(): FrodoParams =
  result = buildFrodoParams(
    "frodo976aes",
    976,
    16,
    3,
    11,
    15632,
    31296,
    15744,
    24,
    fxShake256,
    fmgAes128,
    [5638'u16, 15915'u16, 23689'u16, 28571'u16, 31116'u16, 32217'u16, 32613'u16,
      32731'u16, 32760'u16, 32766'u16, 32767'u16, 0'u16, 0'u16]
  )

proc buildFrodo976Shake(): FrodoParams =
  result = buildFrodoParams(
    "frodo976shake",
    976,
    16,
    3,
    11,
    15632,
    31296,
    15744,
    24,
    fxShake256,
    fmgShake128,
    [5638'u16, 15915'u16, 23689'u16, 28571'u16, 31116'u16, 32217'u16, 32613'u16,
      32731'u16, 32760'u16, 32766'u16, 32767'u16, 0'u16, 0'u16]
  )

proc buildFrodo1344Aes(): FrodoParams =
  result = buildFrodoParams(
    "frodo1344aes",
    1344,
    16,
    4,
    7,
    21520,
    43088,
    21632,
    32,
    fxShake256,
    fmgAes128,
    [9142'u16, 23462'u16, 30338'u16, 32361'u16, 32725'u16, 32765'u16, 32767'u16,
      0'u16, 0'u16, 0'u16, 0'u16, 0'u16, 0'u16]
  )

proc buildFrodo1344Shake(): FrodoParams =
  result = buildFrodoParams(
    "frodo1344shake",
    1344,
    16,
    4,
    7,
    21520,
    43088,
    21632,
    32,
    fxShake256,
    fmgShake128,
    [9142'u16, 23462'u16, 30338'u16, 32361'u16, 32725'u16, 32765'u16, 32767'u16,
      0'u16, 0'u16, 0'u16, 0'u16, 0'u16, 0'u16]
  )

const frodoParamsTable*: array[FrodoVariant, FrodoParams] = [
  frodo640aes: buildFrodo640Aes(),
  frodo640shake: buildFrodo640Shake(),
  frodo976aes: buildFrodo976Aes(),
  frodo976shake: buildFrodo976Shake(),
  frodo1344aes: buildFrodo1344Aes(),
  frodo1344shake: buildFrodo1344Shake()
]

proc params*(v: FrodoVariant): FrodoParams {.inline.} =
  ## Return the fixed parameter set for one Frodo variant.
  result = frodoParamsTable[v]
