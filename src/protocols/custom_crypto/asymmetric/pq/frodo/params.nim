## --------------------------------------------------------------------
## Frodo Params <- parameter table for the pure-Nim FrodoKEM backend
## --------------------------------------------------------------------

type
  ## Concrete FrodoKEM parameter family.
  FrodoVariant* = enum
    frodo976aes

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
    cdfTable*: array[11, uint16]
    publicKeyBytes*: int
    secretKeyBytes*: int
    ciphertextBytes*: int
    sharedSecretBytes*: int
    matrixKeyBytes*: int
    keypairRandomBytes*: int
    encapsRandomBytes*: int

proc buildFrodo976Aes(): FrodoParams =
  result = FrodoParams(
    name: "frodo976aes",
    n: 976,
    nbar: 8,
    logQ: 16,
    q: 1'u32 shl 16,
    extractedBits: 3,
    stripeStep: 8,
    parallelStep: 4,
    bytesSeedA: 16,
    bytesMu: (3 * 8 * 8) div 8,
    bytesPkHash: 24,
    cdfTable: [5638'u16, 15915'u16, 23689'u16, 28571'u16, 31116'u16,
      32217'u16, 32613'u16, 32731'u16, 32760'u16, 32766'u16, 32767'u16],
    publicKeyBytes: 15632,
    secretKeyBytes: 31296,
    ciphertextBytes: 15744,
    sharedSecretBytes: 24,
    matrixKeyBytes: 16,
    keypairRandomBytes: 64,
    encapsRandomBytes: 24
  )

const frodoParamsTable*: array[FrodoVariant, FrodoParams] = [
  frodo976aes: buildFrodo976Aes()
]

proc params*(v: FrodoVariant): FrodoParams {.inline.} =
  ## Return the fixed parameter set for one Frodo variant.
  result = frodoParamsTable[v]
