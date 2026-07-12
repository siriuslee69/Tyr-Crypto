## ---------------------------------------------------------
## NTRU Params <- fixed KEM layouts for pure-Nim NTRU variants
## ---------------------------------------------------------

type
  ## Supported NTRU KEM parameter sets from the NIST Round-3 submission.
  NtruVariant* = enum
    ntruHps2048509,
    ntruHps2048677,
    ntruHps4096821,
    ntruHrss701

  ## Runtime-selectable implementation backend.
  NtruBackend* = enum
    ntruAuto,
    ntruClean,
    ntruAvx2

  ## Fixed byte layout for one NTRU parameter set.
  NtruParams* = object
    name*: string
    katName*: string
    n*: int
    logQ*: int
    hps*: bool
    weight*: int
    sampleIidBytes*: int
    sampleFtBytes*: int
    sampleFgBytes*: int
    sampleRmBytes*: int
    packDeg*: int
    packTrinaryBytes*: int
    owcpaMsgBytes*: int
    owcpaPublicKeyBytes*: int
    owcpaSecretKeyBytes*: int
    owcpaBytes*: int
    publicKeyBytes*: int
    secretKeyBytes*: int
    ciphertextBytes*: int
    sharedSecretBytes*: int

const
  ntruSharedSecretBytes* = 32
  ntruSeedBytes* = 32
  ntruPrfKeyBytes* = 32
  ntruMaxN* = 821
  ntruAvx2Build* =
    when defined(avx2):
      true
    else:
      false
  ntruPqcleanAvx2Build* =
    when defined(avx2) and (defined(linux) or defined(macosx)):
      true
    else:
      false

  ntruParamsTable*: array[NtruVariant, NtruParams] = [
    ntruHps2048509: NtruParams(
      name: "ntruhps2048509",
      katName: "NTRU-HPS-2048-509",
      n: 509,
      logQ: 11,
      hps: true,
      weight: 254,
      sampleIidBytes: 508,
      sampleFtBytes: 1905,
      sampleFgBytes: 2413,
      sampleRmBytes: 2413,
      packDeg: 508,
      packTrinaryBytes: 102,
      owcpaMsgBytes: 204,
      owcpaPublicKeyBytes: 699,
      owcpaSecretKeyBytes: 903,
      owcpaBytes: 699,
      publicKeyBytes: 699,
      secretKeyBytes: 935,
      ciphertextBytes: 699,
      sharedSecretBytes: ntruSharedSecretBytes
    ),
    ntruHps2048677: NtruParams(
      name: "ntruhps2048677",
      katName: "NTRU-HPS-2048-677",
      n: 677,
      logQ: 11,
      hps: true,
      weight: 254,
      sampleIidBytes: 676,
      sampleFtBytes: 2535,
      sampleFgBytes: 3211,
      sampleRmBytes: 3211,
      packDeg: 676,
      packTrinaryBytes: 136,
      owcpaMsgBytes: 272,
      owcpaPublicKeyBytes: 930,
      owcpaSecretKeyBytes: 1202,
      owcpaBytes: 930,
      publicKeyBytes: 930,
      secretKeyBytes: 1234,
      ciphertextBytes: 930,
      sharedSecretBytes: ntruSharedSecretBytes
    ),
    ntruHps4096821: NtruParams(
      name: "ntruhps4096821",
      katName: "NTRU-HPS-4096-821",
      n: 821,
      logQ: 12,
      hps: true,
      weight: 510,
      sampleIidBytes: 820,
      sampleFtBytes: 3075,
      sampleFgBytes: 3895,
      sampleRmBytes: 3895,
      packDeg: 820,
      packTrinaryBytes: 164,
      owcpaMsgBytes: 328,
      owcpaPublicKeyBytes: 1230,
      owcpaSecretKeyBytes: 1558,
      owcpaBytes: 1230,
      publicKeyBytes: 1230,
      secretKeyBytes: 1590,
      ciphertextBytes: 1230,
      sharedSecretBytes: ntruSharedSecretBytes
    ),
    ntruHrss701: NtruParams(
      name: "ntruhrss701",
      katName: "NTRU-HRSS-701",
      n: 701,
      logQ: 13,
      hps: false,
      weight: 0,
      sampleIidBytes: 700,
      sampleFtBytes: 0,
      sampleFgBytes: 1400,
      sampleRmBytes: 1400,
      packDeg: 700,
      packTrinaryBytes: 140,
      owcpaMsgBytes: 280,
      owcpaPublicKeyBytes: 1138,
      owcpaSecretKeyBytes: 1418,
      owcpaBytes: 1138,
      publicKeyBytes: 1138,
      secretKeyBytes: 1450,
      ciphertextBytes: 1138,
      sharedSecretBytes: ntruSharedSecretBytes
    )
  ]

## Reference: [NTRU-20190330] sections 1.8 and 2, DPKE and KEM algorithms; parameter-set tables for `params`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc params*(v: NtruVariant): NtruParams {.inline.} =
  ## Return the fixed layout for one NTRU parameter set.
  result = ntruParamsTable[v]

## Reference: [NTRU-20190330] sections 1.8 and 2, DPKE and KEM algorithms; parameter-set tables for `ntruBackendAvailable`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc ntruBackendAvailable*(backend: NtruBackend): bool {.inline.} =
  ## Report whether the requested backend exists in this build.
  case backend
  of ntruAuto, ntruClean:
    result = true
  of ntruAvx2:
    when ntruAvx2Build:
      result = true
    else:
      result = false

## Reference: [NTRU-20190330] sections 1.8 and 2, DPKE and KEM algorithms; parameter-set tables for `ntruDefaultBackend`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc ntruDefaultBackend*(): NtruBackend {.inline.} =
  ## Prefer the upstream AVX2 backend when this build enables it.
  when ntruAvx2Build:
    result = ntruAvx2
  else:
    result = ntruClean

## Reference: [NTRU-20190330] sections 1.8 and 2, DPKE and KEM algorithms; parameter-set tables for `ntruResolveBackend`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc ntruResolveBackend*(backend: NtruBackend): NtruBackend =
  ## Resolve `auto` and reject unavailable explicit backends.
  result = backend
  if result == ntruAuto:
    result = ntruDefaultBackend()
  if not ntruBackendAvailable(result):
    raise newException(ValueError, "NTRU backend is not available in this build")
