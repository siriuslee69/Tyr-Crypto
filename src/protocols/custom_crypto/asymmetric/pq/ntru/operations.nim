## ---------------------------------------------------------
## NTRU Operations <- KEM wrappers for the pure-Nim backend
## ---------------------------------------------------------

import ./params
import ./core
import ../common/pq_rng
import ../../../../helpers/otter_support

type
  ## Public/secret keypair emitted by the Tyr NTRU backend.
  NtruTyrKeypair* = object
    variant*: NtruVariant
    backend*: NtruBackend
    publicKey*: seq[byte]
    secretKey*: seq[byte]

  ## Detached ciphertext plus shared secret emitted by NTRU encapsulation.
  NtruTyrCipher* = object
    variant*: NtruVariant
    backend*: NtruBackend
    ciphertext*: seq[byte]
    sharedSecret*: seq[byte]

proc ntruKeypairWithContext(v: NtruVariant, R: var PqRandomContext,
    backend: NtruBackend = ntruAuto): NtruTyrKeypair {.otterBench, otterTrace.} =
  ## Generate an NTRU keypair using a caller-owned random context.
  var
    p: NtruParams = params(v)
    active: NtruBackend = ntruResolveBackend(backend)
  result.variant = v
  result.backend = active
  result.publicKey = newSeq[byte](p.publicKeyBytes)
  result.secretKey = newSeq[byte](p.secretKeyBytes)
  ntruKemKeypairInto(result.publicKey, result.secretKey, p, R)

proc ntruEncapsWithContext(v: NtruVariant, pk: openArray[byte],
    R: var PqRandomContext, backend: NtruBackend = ntruAuto): NtruTyrCipher {.otterBench, otterTrace.} =
  ## Encapsulate using a caller-owned random context.
  var
    p: NtruParams = params(v)
    active: NtruBackend = ntruResolveBackend(backend)
  if pk.len != p.publicKeyBytes:
    raise newException(ValueError, "invalid NTRU public key length")
  result.variant = v
  result.backend = active
  result.ciphertext = newSeq[byte](p.ciphertextBytes)
  result.sharedSecret = newSeq[byte](p.sharedSecretBytes)
  ntruKemEncInto(result.ciphertext, result.sharedSecret, pk, p, R)

proc ntruKeypairWithActiveFeed*(v: NtruVariant,
    backend: NtruBackend = ntruAuto): NtruTyrKeypair {.otterBench, otterTrace.} =
  ## Compatibility helper; pure Nim code uses a system-random context here.
  var
    R: PqRandomContext
  R = initPqSystemRandomContext()
  try:
    result = ntruKeypairWithContext(v, R, backend)
  finally:
    clearPqRandomContext(R)

proc ntruEncapsWithActiveFeed*(v: NtruVariant, pk: openArray[byte],
    backend: NtruBackend = ntruAuto): NtruTyrCipher {.otterBench, otterTrace.} =
  ## Compatibility helper; pure Nim code uses a system-random context here.
  var
    R: PqRandomContext
  R = initPqSystemRandomContext()
  try:
    result = ntruEncapsWithContext(v, pk, R, backend)
  finally:
    clearPqRandomContext(R)

proc ntruTyrKeypairDerand*(v: NtruVariant, seed: openArray[byte],
    backend: NtruBackend = ntruAuto): NtruTyrKeypair {.otterBench, otterTrace.} =
  ## Generate an NTRU keypair from a 48-byte NIST KAT seed.
  var
    R: PqRandomContext
  R = initPqKatRandomContext(seed)
  try:
    result = ntruKeypairWithContext(v, R, backend)
  finally:
    clearPqRandomContext(R)

proc ntruTyrKeypair*(v: NtruVariant, seed: seq[byte] = @[],
    backend: NtruBackend = ntruAuto): NtruTyrKeypair {.otterBench, otterTrace.} =
  ## Generate a pure-Nim NTRU keypair, optionally from a 48-byte KAT seed.
  var
    R: PqRandomContext
  if seed.len == 0:
    R = initPqSystemRandomContext()
  else:
    R = initPqKatRandomContext(seed)
  try:
    result = ntruKeypairWithContext(v, R, backend)
  finally:
    clearPqRandomContext(R)

proc ntruTyrEncapsDerand*(v: NtruVariant, pk: openArray[byte], seed: openArray[byte],
    backend: NtruBackend = ntruAuto): NtruTyrCipher {.otterBench, otterTrace.} =
  ## Encapsulate from a 48-byte NIST KAT seed.
  var
    R: PqRandomContext
  R = initPqKatRandomContext(seed)
  try:
    result = ntruEncapsWithContext(v, pk, R, backend)
  finally:
    clearPqRandomContext(R)

proc ntruTyrEncaps*(v: NtruVariant, pk: openArray[byte], seed: seq[byte] = @[],
    backend: NtruBackend = ntruAuto): NtruTyrCipher {.otterBench, otterTrace.} =
  ## Encapsulate against an NTRU public key.
  var
    R: PqRandomContext
  if seed.len == 0:
    R = initPqSystemRandomContext()
  else:
    R = initPqKatRandomContext(seed)
  try:
    result = ntruEncapsWithContext(v, pk, R, backend)
  finally:
    clearPqRandomContext(R)

proc ntruTyrDecaps*(v: NtruVariant, sk, ct: openArray[byte],
    backend: NtruBackend = ntruAuto): seq[byte] {.otterBench, otterTrace.} =
  ## Decapsulate an NTRU ciphertext and return the shared secret.
  var
    p: NtruParams = params(v)
  discard ntruResolveBackend(backend)
  if sk.len != p.secretKeyBytes:
    raise newException(ValueError, "invalid NTRU secret key length")
  if ct.len != p.ciphertextBytes:
    raise newException(ValueError, "invalid NTRU ciphertext length")
  result = newSeq[byte](p.sharedSecretBytes)
  ntruKemDecInto(result, sk, ct, p)

proc ntruTyrKatKemFromSeed*(v: NtruVariant, seed: openArray[byte],
    backend: NtruBackend = ntruAuto): tuple[keypair: NtruTyrKeypair,
    cipher: NtruTyrCipher] {.otterBench, otterTrace.} =
  ## Replay the NIST KAT sequence: one seed feeds keypair, then encapsulation.
  var
    R: PqRandomContext
  R = initPqKatRandomContext(seed)
  try:
    result.keypair = ntruKeypairWithContext(v, R, backend)
    result.cipher = ntruEncapsWithContext(v, result.keypair.publicKey, R, backend)
  finally:
    clearPqRandomContext(R)
