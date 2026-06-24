## ----------------------------------------------------------
## Falcon Params <- vendored Falcon size and backend metadata
## ----------------------------------------------------------

type
  ## Falcon variants supported by the local Tyr backend.
  FalconVariant* = enum
    falcon512
    falcon1024

  ## Backend selector for the vendored Falcon implementations.
  FalconBackend* = enum
    falconScalar
    falconSimd
    falconAuto

  ## Public size table for the local Falcon backend.
  FalconParams* = object
    publicKeyBytes*: int
    secretKeyBytes*: int
    signatureBytes*: int
    logn*: int

const
  falconParamsTable*: array[FalconVariant, FalconParams] = [
    FalconParams(publicKeyBytes: 897, secretKeyBytes: 1281, signatureBytes: 752, logn: 9),
    FalconParams(publicKeyBytes: 1793, secretKeyBytes: 2305, signatureBytes: 1462, logn: 10)
  ]

  falconCompileHasSimd* =
    defined(avx2) or defined(sse2) or defined(amd64) or defined(neon) or defined(arm64) or defined(aarch64)

var
  falconSimdEnabled {.threadvar.}: bool

proc params*(v: FalconVariant): FalconParams {.inline.} =
  ## Return the static parameter set for a Falcon variant.
  falconParamsTable[v]

proc expandedSecretBytes*(v: FalconVariant): int {.inline.} =
  ## Return the Falcon expanded-key size for sign-tree mode.
  var p = params(v)
  (8 * p.logn + 40) * (1 shl p.logn)

proc defaultBackend*(): FalconBackend {.inline.} =
  ## Return the default backend compiled into the current build.
  if falconCompileHasSimd:
    falconSimd
  else:
    falconScalar

proc backendAvailable*(backend: FalconBackend): bool {.inline.} =
  ## Tell whether the requested Falcon backend is available in this build.
  case backend
  of falconScalar, falconAuto:
    true
  of falconSimd:
    falconCompileHasSimd

proc backendName*(backend: FalconBackend): string {.inline.} =
  ## Stable printable backend label for benchmark output.
  case backend
  of falconScalar:
    "scalar"
  of falconSimd:
    "simd128"
  of falconAuto:
    "auto"

proc useFalconSimd*(): bool {.inline.} =
  ## Tell whether the current thread is executing the SIMD Falcon path.
  result = falconCompileHasSimd and falconSimdEnabled

template withFalconBackend*(backend: FalconBackend, body: untyped): untyped =
  ## Scope Falcon backend selection to the current thread.
  block:
    var previous = falconSimdEnabled
    falconSimdEnabled = falconCompileHasSimd and backend == falconSimd
    try:
      body
    finally:
      falconSimdEnabled = previous
