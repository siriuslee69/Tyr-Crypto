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

  ## Native floating-point SIMD is faster, but its division latency is not
  ## portable constant-time. Keep the integer-emulated scalar backend as the
  ## default even in SIMD builds. The unsafe backend requires an explicit opt-in.
  falconCompileHasSimd* = defined(falconUnsafeNativeFloatSimd) and (
    defined(avx2) or defined(sse2) or defined(amd64) or defined(neon) or
    defined(arm64) or defined(aarch64))

var
  falconSimdEnabled {.threadvar.}: bool

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; parameter-set tables for `params`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc params*(v: FalconVariant): FalconParams {.inline.} =
  ## Return the static parameter set for a Falcon variant.
  falconParamsTable[v]

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; parameter-set tables for `expandedSecretBytes`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc expandedSecretBytes*(v: FalconVariant): int {.inline.} =
  ## Return the Falcon expanded-key size for sign-tree mode.
  var p = params(v)
  (8 * p.logn + 40) * (1 shl p.logn)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; parameter-set tables for `defaultBackend`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc defaultBackend*(): FalconBackend {.inline.} =
  ## Return the default backend compiled into the current build.
  if falconCompileHasSimd:
    falconSimd
  else:
    falconScalar

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; parameter-set tables for `backendAvailable`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc backendAvailable*(backend: FalconBackend): bool {.inline.} =
  ## Tell whether the requested Falcon backend is available in this build.
  case backend
  of falconScalar, falconAuto:
    true
  of falconSimd:
    falconCompileHasSimd

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; parameter-set tables for `backendName`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc backendName*(backend: FalconBackend): string {.inline.} =
  ## Stable printable backend label for benchmark output.
  case backend
  of falconScalar:
    "scalar"
  of falconSimd:
    "simd128"
  of falconAuto:
    "auto"

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; parameter-set tables for `useFalconSimd`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
proc useFalconSimd*(): bool {.inline.} =
  ## Tell whether the current thread is executing the SIMD Falcon path.
  result = falconCompileHasSimd and falconSimdEnabled

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; parameter-set tables for `withFalconBackend`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
template withFalconBackend*(backend: FalconBackend, body: untyped): untyped =
  ## Scope Falcon backend selection to the current thread.
  block:
    var previous = falconSimdEnabled
    falconSimdEnabled = falconCompileHasSimd and backend == falconSimd
    try:
      body
    finally:
      falconSimdEnabled = previous
