## --------------------------------------------------------------------
## ML-KEM Parameters <- parameter tables for the pure-Nim ML-KEM backend
## --------------------------------------------------------------------

const
  mlkemN* = 256
  mlkemQ* = 3329
  mlkemSymBytes* = 32
  mlkemSharedSecretBytes* = 32
  mlkemPolyBytes* = 384
  mlkemMaxK* = 4
  mlkemXofBlockBytes* = 168 ## SHAKE128 rate in bytes.

type
  ## FIPS 203 ML-KEM parameter sets.
  ## Sizes are the same as round-3 CRYSTALS-Kyber, the shared secrets are not:
  ## Tyr implemented round 3 until 2026-10-16 and now implements FIPS 203 only.
  MlKemVariant* = enum
    mlkem512, ## FIPS 203 ML-KEM-512  (security category 1)
    mlkem768, ## FIPS 203 ML-KEM-768  (category 3, the usual choice)
    mlkem1024 ## FIPS 203 ML-KEM-1024 (category 5)

  ## Fixed parameter record for one ML-KEM family member.
  MlKemParams* = object
    name*: string
    pqcleanName*: string
    k*: int
    eta1*: int
    eta2*: int
    polyCompressedBytes*: int
    polyVecCompressedBytes*: int
    indcpaMsgBytes*: int
    indcpaPublicKeyBytes*: int
    indcpaSecretKeyBytes*: int
    indcpaBytes*: int
    publicKeyBytes*: int
    secretKeyBytes*: int
    ciphertextBytes*: int
    sharedSecretBytes*: int
    xofBlockBytes*: int

const mlkemParamsTable*: array[MlKemVariant, MlKemParams] = [
  mlkem512: MlKemParams(
    name: "mlkem512",
    pqcleanName: "ml-kem-512",
    k: 2,
    eta1: 3,
    eta2: 2,
    polyCompressedBytes: 128,
    polyVecCompressedBytes: 640,
    indcpaMsgBytes: mlkemSymBytes,
    indcpaPublicKeyBytes: 800,
    indcpaSecretKeyBytes: 768,
    indcpaBytes: 768,
    publicKeyBytes: 800,
    secretKeyBytes: 1632,
    ciphertextBytes: 768,
    sharedSecretBytes: mlkemSharedSecretBytes,
    xofBlockBytes: mlkemXofBlockBytes
  ),
  mlkem768: MlKemParams(
    name: "mlkem768",
    pqcleanName: "ml-kem-768",
    k: 3,
    eta1: 2,
    eta2: 2,
    polyCompressedBytes: 128,
    polyVecCompressedBytes: 960,
    indcpaMsgBytes: mlkemSymBytes,
    indcpaPublicKeyBytes: 1184,
    indcpaSecretKeyBytes: 1152,
    indcpaBytes: 1088,
    publicKeyBytes: 1184,
    secretKeyBytes: 2400,
    ciphertextBytes: 1088,
    sharedSecretBytes: mlkemSharedSecretBytes,
    xofBlockBytes: mlkemXofBlockBytes
  ),
  mlkem1024: MlKemParams(
    name: "mlkem1024",
    pqcleanName: "ml-kem-1024",
    k: 4,
    eta1: 2,
    eta2: 2,
    polyCompressedBytes: 160,
    polyVecCompressedBytes: 1408,
    indcpaMsgBytes: mlkemSymBytes,
    indcpaPublicKeyBytes: 1568,
    indcpaSecretKeyBytes: 1536,
    indcpaBytes: 1568,
    publicKeyBytes: 1568,
    secretKeyBytes: 3168,
    ciphertextBytes: 1568,
    sharedSecretBytes: mlkemSharedSecretBytes,
    xofBlockBytes: mlkemXofBlockBytes
  )
]

## Reference: [FIPS-203] sections 4-7 and algorithms 1-21; parameter-set tables for `params`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc params*(v: MlKemVariant): MlKemParams {.inline.} =
  ## Return the fixed parameter set for one ML-KEM variant.
  result = mlkemParamsTable[v]
