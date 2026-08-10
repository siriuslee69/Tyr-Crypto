## ----------------------------------------------------------------
## Falcon Operations <- pure-Nim Falcon public API compatibility shim
## ----------------------------------------------------------------

import ./params
import ./keygen
import ./pure_verify
import ./sign
import ./util
import ../../../../helpers/otter_support

type
  ## Public/secret keypair emitted by the pure-Nim Falcon backend.
  FalconTyrKeypair* = object
    variant*: FalconVariant
    publicKey*: seq[byte]
    secretKey*: seq[byte]

  ## Expanded Falcon private material for repeated sign-tree usage.
  FalconPreparedSecret* = object
    variant*: FalconVariant
    backend*: FalconBackend
    expanded*: FalconExpandedSecret

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `requireBackend`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc requireBackend(backend: FalconBackend): FalconBackend {.inline.} =
  result = backend
  if result == falconAuto:
    result = defaultBackend()
  if not backendAvailable(result):
    raise newException(ValueError, "Falcon backend " & backendName(result) & " is not available in this build")

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `requireSizedBuffer`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc requireSizedBuffer(actual, expected: int, label: string) {.inline.} =
  if actual != expected:
    raise newException(ValueError, label & " has wrong size for variant")

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `requireMinBuffer`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc requireMinBuffer(actual, expected: int, label: string) {.inline.} =
  if actual < expected:
    raise newException(ValueError, label & " is smaller than the variant maximum")

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `requireKeypairBuffers`; pitfall: keep transcript order, domain separation, sizes, and secret wiping exact.
proc requireKeypairBuffers(p: FalconParams, publicKey, secretKey: openArray[byte]) {.inline.} =
  requireSizedBuffer(publicKey.len, p.publicKeyBytes, "Falcon public key buffer")
  requireSizedBuffer(secretKey.len, p.secretKeyBytes, "Falcon secret key buffer")

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `requireSecretKeyBuffer`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc requireSecretKeyBuffer(p: FalconParams, secretKey: openArray[byte]) {.inline.} =
  requireSizedBuffer(secretKey.len, p.secretKeyBytes, "Falcon secret key")

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `requireSignatureInputs`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc requireSignatureInputs(p: FalconParams, sig, sk: openArray[byte]) {.inline.} =
  requireMinBuffer(sig.len, p.signatureBytes, "Falcon signature buffer")
  requireSecretKeyBuffer(p, sk)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `copyInto`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc copyInto(dst: var openArray[byte], src: openArray[byte], label: string) {.inline.} =
  if dst.len < src.len:
    raise newException(ValueError, label & " is too small")
  if src.len > 0:
    copyBytes(dst, 0, src)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `falconTyrKeypairInto`; pitfall: keep transcript order, domain separation, sizes, and secret wiping exact.
proc falconTyrKeypairInto*(v: FalconVariant, publicKey, secretKey: var openArray[byte],
    backend: FalconBackend = falconAuto) {.otterBench.} =
  ## Generate a pure-Nim Falcon keypair into caller-owned buffers.
  let
    p = params(v)
    active = requireBackend(backend)
  var kp: tuple[publicKey, secretKey: seq[byte]]
  withFalconBackend(active):
    kp = falconKeygenPure(v)
  defer:
    secureClearBytes(kp.secretKey)
    kp.secretKey.setLen(0)
    kp.publicKey.setLen(0)
  requireKeypairBuffers(p, publicKey, secretKey)
  requireSizedBuffer(kp.publicKey.len, p.publicKeyBytes, "Falcon public key")
  requireSizedBuffer(kp.secretKey.len, p.secretKeyBytes, "Falcon secret key")
  copyInto(publicKey, kp.publicKey, "Falcon public key buffer")
  copyInto(secretKey, kp.secretKey, "Falcon secret key buffer")

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `falconTyrKeypair`; pitfall: keep transcript order, domain separation, sizes, and secret wiping exact.
proc falconTyrKeypair*(v: FalconVariant, backend: FalconBackend = falconAuto): FalconTyrKeypair {.otterTrace.} =
  ## Generate a pure-Nim Falcon keypair and return owned buffers.
  let active = requireBackend(backend)
  result.variant = v
  withFalconBackend(active):
    let kp = falconKeygenPure(v)
    result.publicKey = kp.publicKey
    result.secretKey = kp.secretKey

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `falconTyrKeypair`; pitfall: keep transcript order, domain separation, sizes, and secret wiping exact.
proc falconTyrKeypair*(v: FalconVariant, seed: openArray[byte],
    backend: FalconBackend = falconAuto): FalconTyrKeypair {.otterTrace.} =
  ## Generate a deterministic pure-Nim Falcon keypair from caller-provided
  ## seed material.
  let
    p = params(v)
    active = requireBackend(backend)
  var
    kp: tuple[publicKey, secretKey: seq[byte]]
  result.variant = v
  withFalconBackend(active):
    kp = falconKeygenFromSeed(v, seed)
  requireSizedBuffer(kp.publicKey.len, p.publicKeyBytes, "Falcon public key")
  requireSizedBuffer(kp.secretKey.len, p.secretKeyBytes, "Falcon secret key")
  result.publicKey = kp.publicKey
  result.secretKey = kp.secretKey

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `falconTyrSignInto`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc falconTyrSignInto*(v: FalconVariant, sig: var openArray[byte], sigLen: var int,
    msg, sk: openArray[byte], backend: FalconBackend = falconAuto) {.otterBench.} =
  ## Sign a message into a caller-owned max-sized Falcon signature buffer.
  let
    p = params(v)
    active = requireBackend(backend)
  var encoded: seq[byte]
  withFalconBackend(active):
    encoded = falconSignPure(v, msg, sk)
  requireSignatureInputs(p, sig, sk)
  requireMinBuffer(sig.len, encoded.len, "Falcon signature buffer")
  copyInto(sig, encoded, "Falcon signature buffer")
  sigLen = encoded.len

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `falconTyrSign`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc falconTyrSign*(v: FalconVariant, msg, sk: openArray[byte],
    backend: FalconBackend = falconAuto): seq[byte] {.otterTrace.} =
  ## Sign a message and return a trimmed Falcon signature.
  let active = requireBackend(backend)
  withFalconBackend(active):
    result = falconSignPure(v, msg, sk)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `falconTyrPrepareSecret`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc falconTyrPrepareSecret*(v: FalconVariant, sk: openArray[byte],
    backend: FalconBackend = falconAuto): FalconPreparedSecret {.otterBench, otterTrace.} =
  ## Expand Falcon private-key state for repeated sign-tree signing.
  let
    p = params(v)
    active = requireBackend(backend)
  requireSecretKeyBuffer(p, sk)
  result.variant = v
  result.backend = active
  withFalconBackend(active):
    result.expanded = prepareSecretKey(v, sk)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `falconTyrClearKeypair`; pitfall: keep transcript order, domain separation, sizes, and secret wiping exact.
proc falconTyrClearKeypair*(kp: var FalconTyrKeypair) =
  ## Best-effort zeroization for Falcon secret-key material.
  secureClearBytes(kp.secretKey)
  kp.secretKey.setLen(0)
  kp.publicKey.setLen(0)
  kp.variant = falcon512

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `falconTyrClearPreparedSecret`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc falconTyrClearPreparedSecret*(prepared: var FalconPreparedSecret) =
  ## Best-effort zeroization for prepared Falcon sign-tree state.
  clearExpandedSecret(prepared.expanded)
  prepared.variant = falcon512
  prepared.backend = falconScalar

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `falconTyrSignPreparedInto`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc falconTyrSignPreparedInto*(prepared: FalconPreparedSecret, sig: var openArray[byte],
    sigLen: var int, msg: openArray[byte]) {.otterBench.} =
  ## Sign with a pre-expanded Falcon key in sign-tree mode.
  let p = params(prepared.variant)
  var encoded: seq[byte]
  withFalconBackend(prepared.backend):
    encoded = falconSignPrepared(prepared.expanded, msg, prepared.variant)
  requireMinBuffer(sig.len, p.signatureBytes, "Falcon signature buffer")
  requireMinBuffer(sig.len, encoded.len, "Falcon signature buffer")
  copyInto(sig, encoded, "Falcon signature buffer")
  sigLen = encoded.len

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `falconTyrSignPrepared`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc falconTyrSignPrepared*(prepared: FalconPreparedSecret, msg: openArray[byte]): seq[byte] {.otterTrace.} =
  ## Sign with a pre-expanded Falcon key and return a trimmed signature.
  withFalconBackend(prepared.backend):
    result = falconSignPrepared(prepared.expanded, msg, prepared.variant)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key generation, encapsulation/signing, and decapsulation/verification algorithms for `falconTyrVerify`; pitfall: fail closed and preserve canonical, constant-time comparison where secrets are involved.
proc falconTyrVerify*(v: FalconVariant, msg, sig, pk: openArray[byte],
    backend: FalconBackend = falconAuto): bool {.otterBench, otterTrace.} =
  ## Verify a Falcon signature with the selected local backend.
  let
    p = params(v)
    active = requireBackend(backend)
  if pk.len != p.publicKeyBytes:
    return false
  if sig.len == 0 or sig.len > p.signatureBytes:
    return false
  withFalconBackend(active):
    result = falconVerifyPure(v, msg, sig, pk)
