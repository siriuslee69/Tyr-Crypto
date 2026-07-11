## -----------------------------------------------------------
## SABER Params <- fixed KEM layouts for pure-Nim SABER variants
## -----------------------------------------------------------

type
  ## Supported SABER module-LWR KEM parameter sets.
  SaberVariant* = enum
    lightSaber,
    saber,
    fireSaber

  ## Compatibility/reporting label; arithmetic is selected at compile time.
  SaberBackend* = enum
    saberAuto,
    saberClean,
    saberAvx2

  ## Fixed byte layout for one SABER parameter set.
  SaberParams* = object
    name*: string
    katName*: string
    l*: int
    mu*: int
    et*: int
    publicKeyBytes*: int
    secretKeyBytes*: int
    ciphertextBytes*: int
    sharedSecretBytes*: int
    polyCoinBytes*: int
    polyVecBytes*: int
    polyVecCompressedBytes*: int
    scaleBytesKem*: int
    indcpaPublicKeyBytes*: int
    indcpaSecretKeyBytes*: int

const
  saberSharedSecretBytes* = 32
  saberN* = 256
  saberEp* = 10
  saberP* = 1 shl saberEp
  saberEq* = 13
  saberQ* = 1 shl saberEq
  saberSeedBytes* = 32
  saberNoiseSeedBytes* = 32
  saberKeyBytes* = 32
  saberHashBytes* = 32
  saberPolyBytes* = saberEq * saberN div 8
  saberPolyCompressedBytes* = saberEp * saberN div 8

  saberParamsTable*: array[SaberVariant, SaberParams] = [
    lightSaber: SaberParams(
      name: "lightsaber",
      katName: "LightSaber",
      l: 2,
      mu: 10,
      et: 3,
      publicKeyBytes: 672,
      secretKeyBytes: 1568,
      ciphertextBytes: 736,
      sharedSecretBytes: saberSharedSecretBytes,
      polyCoinBytes: 10 * saberN div 8,
      polyVecBytes: 2 * saberPolyBytes,
      polyVecCompressedBytes: 2 * saberPolyCompressedBytes,
      scaleBytesKem: 3 * saberN div 8,
      indcpaPublicKeyBytes: 2 * saberPolyCompressedBytes + saberSeedBytes,
      indcpaSecretKeyBytes: 2 * saberPolyBytes
    ),
    saber: SaberParams(
      name: "saber",
      katName: "Saber",
      l: 3,
      mu: 8,
      et: 4,
      publicKeyBytes: 992,
      secretKeyBytes: 2304,
      ciphertextBytes: 1088,
      sharedSecretBytes: saberSharedSecretBytes,
      polyCoinBytes: 8 * saberN div 8,
      polyVecBytes: 3 * saberPolyBytes,
      polyVecCompressedBytes: 3 * saberPolyCompressedBytes,
      scaleBytesKem: 4 * saberN div 8,
      indcpaPublicKeyBytes: 3 * saberPolyCompressedBytes + saberSeedBytes,
      indcpaSecretKeyBytes: 3 * saberPolyBytes
    ),
    fireSaber: SaberParams(
      name: "firesaber",
      katName: "FireSaber",
      l: 4,
      mu: 6,
      et: 6,
      publicKeyBytes: 1312,
      secretKeyBytes: 3040,
      ciphertextBytes: 1472,
      sharedSecretBytes: saberSharedSecretBytes,
      polyCoinBytes: 6 * saberN div 8,
      polyVecBytes: 4 * saberPolyBytes,
      polyVecCompressedBytes: 4 * saberPolyCompressedBytes,
      scaleBytesKem: 6 * saberN div 8,
      indcpaPublicKeyBytes: 4 * saberPolyCompressedBytes + saberSeedBytes,
      indcpaSecretKeyBytes: 4 * saberPolyBytes
    )
  ]

proc params*(v: SaberVariant): SaberParams {.inline.} =
  ## Return the fixed layout for one SABER parameter set.
  result = saberParamsTable[v]

proc saberBackendAvailable*(backend: SaberBackend): bool {.inline.} =
  ## Report whether the requested backend exists in this build.
  case backend
  of saberAuto, saberClean:
    result = true
  of saberAvx2:
    when defined(avx2):
      result = true
    else:
      result = false

proc saberDefaultBackend*(): SaberBackend {.inline.} =
  ## Report the pure-Nim AVX2 mode when this build enables it.
  when defined(avx2):
    result = saberAvx2
  else:
    result = saberClean

proc saberResolveBackend*(backend: SaberBackend): SaberBackend =
  ## Resolve `auto` and reject modes unavailable in this build.
  result = backend
  if result == saberAuto:
    result = saberDefaultBackend()
  if not saberBackendAvailable(result):
    raise newException(ValueError, "SABER backend is not available in this build")
