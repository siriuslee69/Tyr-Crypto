## ----------------------------------------------------------
## SABER Operations <- KEM wrappers for the pure-Nim backend
## ----------------------------------------------------------

import ./params
import ./core
import ../common/pq_rng
import ../../../../helpers/otter_support

type
  ## Public/secret keypair emitted by the Tyr SABER backend.
  SaberTyrKeypair* = object
    variant*: SaberVariant
    backend*: SaberBackend
    publicKey*: seq[byte]
    secretKey*: seq[byte]

  ## Detached ciphertext plus shared secret emitted by SABER encapsulation.
  SaberTyrCipher* = object
    variant*: SaberVariant
    backend*: SaberBackend
    ciphertext*: seq[byte]
    sharedSecret*: seq[byte]

proc saberKeypairWithContext(v: SaberVariant, R: var PqRandomContext,
    backend: SaberBackend = saberAuto): SaberTyrKeypair {.otterBench, otterTrace.} =
  ## Generate a SABER keypair using a caller-owned random context.
  var
    p: SaberParams = params(v)
    active: SaberBackend = saberResolveBackend(backend)
  result.variant = v
  result.backend = active
  result.publicKey = newSeq[byte](p.publicKeyBytes)
  result.secretKey = newSeq[byte](p.secretKeyBytes)
  saberKemKeypairInto(result.publicKey, result.secretKey, p, R)

proc saberEncapsWithContext(v: SaberVariant, pk: openArray[byte],
    R: var PqRandomContext, backend: SaberBackend = saberAuto): SaberTyrCipher {.otterBench, otterTrace.} =
  ## Encapsulate with a caller-owned random context.
  var
    p: SaberParams = params(v)
    active: SaberBackend = saberResolveBackend(backend)
  if pk.len != p.publicKeyBytes:
    raise newException(ValueError, "invalid SABER public key length")
  result.variant = v
  result.backend = active
  result.ciphertext = newSeq[byte](p.ciphertextBytes)
  result.sharedSecret = newSeq[byte](p.sharedSecretBytes)
  saberKemEncInto(result.ciphertext, result.sharedSecret, pk, p, R)

proc saberKeypairWithActiveFeed*(v: SaberVariant,
    backend: SaberBackend = saberAuto): SaberTyrKeypair {.otterBench, otterTrace.} =
  ## Compatibility helper; pure Nim code uses a system-random context here.
  var
    R: PqRandomContext
  R = initPqSystemRandomContext()
  try:
    result = saberKeypairWithContext(v, R, backend)
  finally:
    clearPqRandomContext(R)

proc saberEncapsWithActiveFeed*(v: SaberVariant, pk: openArray[byte],
    backend: SaberBackend = saberAuto): SaberTyrCipher {.otterBench, otterTrace.} =
  ## Compatibility helper; pure Nim code uses a system-random context here.
  var
    R: PqRandomContext
  R = initPqSystemRandomContext()
  try:
    result = saberEncapsWithContext(v, pk, R, backend)
  finally:
    clearPqRandomContext(R)

proc saberTyrKeypairDerand*(v: SaberVariant, seed: openArray[byte],
    backend: SaberBackend = saberAuto): SaberTyrKeypair {.otterBench, otterTrace.} =
  ## Generate a SABER keypair from a 48-byte NIST KAT seed.
  var
    R: PqRandomContext
  R = initPqKatRandomContext(seed)
  try:
    result = saberKeypairWithContext(v, R, backend)
  finally:
    clearPqRandomContext(R)

proc saberTyrKeypair*(v: SaberVariant, seed: seq[byte] = @[],
    backend: SaberBackend = saberAuto): SaberTyrKeypair {.otterBench, otterTrace.} =
  ## Generate a pure-Nim SABER keypair, optionally from a 48-byte KAT seed.
  var
    R: PqRandomContext
  if seed.len == 0:
    R = initPqSystemRandomContext()
  else:
    R = initPqKatRandomContext(seed)
  try:
    result = saberKeypairWithContext(v, R, backend)
  finally:
    clearPqRandomContext(R)

proc saberTyrEncapsDerand*(v: SaberVariant, pk: openArray[byte], seed: openArray[byte],
    backend: SaberBackend = saberAuto): SaberTyrCipher {.otterBench, otterTrace.} =
  ## Encapsulate from a 48-byte NIST KAT seed.
  var
    R: PqRandomContext
  R = initPqKatRandomContext(seed)
  try:
    result = saberEncapsWithContext(v, pk, R, backend)
  finally:
    clearPqRandomContext(R)

proc saberTyrEncaps*(v: SaberVariant, pk: openArray[byte], seed: seq[byte] = @[],
    backend: SaberBackend = saberAuto): SaberTyrCipher {.otterBench, otterTrace.} =
  ## Encapsulate against a SABER public key.
  var
    R: PqRandomContext
  if seed.len == 0:
    R = initPqSystemRandomContext()
  else:
    R = initPqKatRandomContext(seed)
  try:
    result = saberEncapsWithContext(v, pk, R, backend)
  finally:
    clearPqRandomContext(R)

proc saberTyrDecaps*(v: SaberVariant, sk, ct: openArray[byte],
    backend: SaberBackend = saberAuto): seq[byte] {.otterBench, otterTrace.} =
  ## Decapsulate a SABER ciphertext and return the shared secret.
  var
    p: SaberParams = params(v)
  discard saberResolveBackend(backend)
  if sk.len != p.secretKeyBytes:
    raise newException(ValueError, "invalid SABER secret key length")
  if ct.len != p.ciphertextBytes:
    raise newException(ValueError, "invalid SABER ciphertext length")
  result = newSeq[byte](p.sharedSecretBytes)
  saberKemDecInto(result, sk, ct, p)

proc saberTyrKatKemFromSeed*(v: SaberVariant, seed: openArray[byte],
    backend: SaberBackend = saberAuto): tuple[keypair: SaberTyrKeypair,
    cipher: SaberTyrCipher] {.otterBench, otterTrace.} =
  ## Replay the NIST KAT sequence: one seed feeds keypair, then encapsulation.
  var
    R: PqRandomContext
  R = initPqKatRandomContext(seed)
  try:
    result.keypair = saberKeypairWithContext(v, R, backend)
    result.cipher = saberEncapsWithContext(v, result.keypair.publicKey, R, backend)
  finally:
    clearPqRandomContext(R)
