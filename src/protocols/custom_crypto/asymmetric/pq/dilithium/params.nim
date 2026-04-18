## ----------------------------------------------------------------------
## Dilithium Params <- parameter tables for the pure-Nim ML-DSA backend
## ----------------------------------------------------------------------

type
  ## Concrete ML-DSA / Dilithium parameter family.
  DilithiumVariant* = enum
    dilithium44, ## original Dilithium2 / standardized ML-DSA-44
    dilithium65, ## original Dilithium3 / standardized ML-DSA-65
    dilithium87  ## original Dilithium5 / standardized ML-DSA-87

  ## Fixed parameter record for one ML-DSA family member.
  DilithiumParams* = object
    name*: string
    k*: int
    l*: int
    eta*: int
    tau*: int
    beta*: int32
    gamma1*: int32
    gamma2*: int32
    omega*: int
    ctildeBytes*: int
    polyEtaPackedBytes*: int
    polyT1PackedBytes*: int
    polyT0PackedBytes*: int
    polyZPackedBytes*: int
    polyW1PackedBytes*: int
    publicKeyBytes*: int
    secretKeyBytes*: int
    signatureBytes*: int

const
  dilithiumSeedBytes* = 32
  dilithiumCrhBytes* = 64
  dilithiumTrBytes* = 64
  dilithiumRndBytes* = 32
  dilithiumMaxL* = 7
  dilithiumMaxK* = 8
  dilithiumMaxCtildeBytes* = 64
  dilithiumN* = 256
  dilithiumQ* = 8380417'i32
  dilithiumD* = 13
  dilithiumRootOfUnity* = 1753'i32

proc buildDilithium44(): DilithiumParams =
  result = DilithiumParams(
    name: "ML-DSA-44",
    k: 4,
    l: 4,
    eta: 2,
    tau: 39,
    beta: 78,
    gamma1: 1 shl 17,
    gamma2: (dilithiumQ - 1) div 88,
    omega: 80,
    ctildeBytes: 32,
    polyEtaPackedBytes: 96,
    polyT1PackedBytes: 320,
    polyT0PackedBytes: 416,
    polyZPackedBytes: 576,
    polyW1PackedBytes: 192,
    publicKeyBytes: 1312,
    secretKeyBytes: 2560,
    signatureBytes: 2420
  )

proc buildDilithium65(): DilithiumParams =
  result = DilithiumParams(
    name: "ML-DSA-65",
    k: 6,
    l: 5,
    eta: 4,
    tau: 49,
    beta: 196,
    gamma1: 1 shl 19,
    gamma2: (dilithiumQ - 1) div 32,
    omega: 55,
    ctildeBytes: 48,
    polyEtaPackedBytes: 128,
    polyT1PackedBytes: 320,
    polyT0PackedBytes: 416,
    polyZPackedBytes: 640,
    polyW1PackedBytes: 128,
    publicKeyBytes: 1952,
    secretKeyBytes: 4032,
    signatureBytes: 3309
  )

proc buildDilithium87(): DilithiumParams =
  result = DilithiumParams(
    name: "ML-DSA-87",
    k: 8,
    l: 7,
    eta: 2,
    tau: 60,
    beta: 120,
    gamma1: 1 shl 19,
    gamma2: (dilithiumQ - 1) div 32,
    omega: 75,
    ctildeBytes: 64,
    polyEtaPackedBytes: 96,
    polyT1PackedBytes: 320,
    polyT0PackedBytes: 416,
    polyZPackedBytes: 640,
    polyW1PackedBytes: 128,
    publicKeyBytes: 2592,
    secretKeyBytes: 4896,
    signatureBytes: 4627
  )

const dilithiumParamsTable*: array[DilithiumVariant, DilithiumParams] = [
  dilithium44: buildDilithium44(),
  dilithium65: buildDilithium65(),
  dilithium87: buildDilithium87()
]

proc params*(v: DilithiumVariant): DilithiumParams {.inline.} =
  ## Return the fixed parameter set for one ML-DSA variant.
  result = dilithiumParamsTable[v]
