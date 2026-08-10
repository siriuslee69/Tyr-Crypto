## --------------------------------------------------------------------
## Kyber Parameters <- parameter tables for the pure-Nim Kyber backend
## --------------------------------------------------------------------

const
  kyberN* = 256
  kyberQ* = 3329
  kyberSymBytes* = 32
  kyberSharedSecretBytes* = 32
  kyberPolyBytes* = 384
  kyberMaxK* = 4
  kyberXofBlockBytes* = 168 ## SHAKE128 rate in bytes.

type
  ## Legacy CRYSTALS-Kyber round-3 parameter family.
  ## These sizes match ML-KEM, but the KEM transcript does not: FIPS 203
  ## algorithms 19-21 removed Kyber round 3's pre-hash of encapsulation m.
  KyberVariant* = enum
    kyber512, ## CRYSTALS-Kyber512 round 3; not FIPS 203 ML-KEM-512
    kyber768, ## CRYSTALS-Kyber768 round 3; not FIPS 203 ML-KEM-768
    kyber1024 ## CRYSTALS-Kyber1024 round 3; not FIPS 203 ML-KEM-1024

  ## Fixed parameter record for one Kyber family member.
  KyberParams* = object
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

const kyberParamsTable*: array[KyberVariant, KyberParams] = [
  kyber512: KyberParams(
    name: "kyber512",
    pqcleanName: "pqcrystals_kyber512_ref",
    k: 2,
    eta1: 3,
    eta2: 2,
    polyCompressedBytes: 128,
    polyVecCompressedBytes: 640,
    indcpaMsgBytes: kyberSymBytes,
    indcpaPublicKeyBytes: 800,
    indcpaSecretKeyBytes: 768,
    indcpaBytes: 768,
    publicKeyBytes: 800,
    secretKeyBytes: 1632,
    ciphertextBytes: 768,
    sharedSecretBytes: kyberSharedSecretBytes,
    xofBlockBytes: kyberXofBlockBytes
  ),
  kyber768: KyberParams(
    name: "kyber768",
    pqcleanName: "pqcrystals_kyber768_ref",
    k: 3,
    eta1: 2,
    eta2: 2,
    polyCompressedBytes: 128,
    polyVecCompressedBytes: 960,
    indcpaMsgBytes: kyberSymBytes,
    indcpaPublicKeyBytes: 1184,
    indcpaSecretKeyBytes: 1152,
    indcpaBytes: 1088,
    publicKeyBytes: 1184,
    secretKeyBytes: 2400,
    ciphertextBytes: 1088,
    sharedSecretBytes: kyberSharedSecretBytes,
    xofBlockBytes: kyberXofBlockBytes
  ),
  kyber1024: KyberParams(
    name: "kyber1024",
    pqcleanName: "pqcrystals_kyber1024_ref",
    k: 4,
    eta1: 2,
    eta2: 2,
    polyCompressedBytes: 160,
    polyVecCompressedBytes: 1408,
    indcpaMsgBytes: kyberSymBytes,
    indcpaPublicKeyBytes: 1568,
    indcpaSecretKeyBytes: 1536,
    indcpaBytes: 1568,
    publicKeyBytes: 1568,
    secretKeyBytes: 3168,
    ciphertextBytes: 1568,
    sharedSecretBytes: kyberSharedSecretBytes,
    xofBlockBytes: kyberXofBlockBytes
  )
]

## Reference: [KYBER-R3-20210804] version 3.02 sections 1.3 and 4, algorithms 1-9; parameter-set tables for `params`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc params*(v: KyberVariant): KyberParams {.inline.} =
  ## Return the fixed parameter set for one Kyber variant.
  result = kyberParamsTable[v]
