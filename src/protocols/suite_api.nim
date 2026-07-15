## -----------------------------------------------------------------------
## Suite API <- authenticated composite encryption compatibility interface
## -----------------------------------------------------------------------

import metaPragmas
import ./algorithms
import ./common
import ./custom_crypto/[aes_ctr, blake3, gimli_sponge, poly1305, xchacha20]

export algorithms

type
  SymAuthState* {.role: {truthState}.} = object
    alg*: CipherSuite
    keys*: seq[seq[uint8]]
    nonce*: seq[uint8]
    tagLen*: uint16

  SymAuthCiphertext* {.role: {preparedData}.} = object
    ciphertext*: seq[uint8]
    auth*: seq[uint8]
    authType*: AuthType

const
  defaultSuiteTagLen = 32'u16

proc keyCount*(a: CipherSuite): int {.role: {parser}.} =
  ## a: authenticated cipher suite.
  case a
  of csXChaCha20Blake3, csAes256Gcm:
    result = 1
  of csXChaCha20Gimli, csAesGimli:
    result = 2
  of csXChaCha20AesGimli:
    result = 3
  of csXChaCha20AesGimliPoly1305:
    result = 4

proc nonceBytes*(a: CipherSuite): int {.role: {parser}.} =
  ## a: authenticated cipher suite.
  case a
  of csAes256Gcm:
    result = 12
  else:
    result = 24

proc initSymAuthState*(a: CipherSuite, K: seq[seq[uint8]], N: seq[uint8],
    t: uint16 = defaultSuiteTagLen): SymAuthState {.role: {truthBuilder}.} =
  ## a: selected cipher suite.
  ## K: ordered 32-byte encryption and authentication keys.
  ## N: suite nonce.
  ## t: requested variable-length authentication tag.
  if K.len != keyCount(a):
    raise newException(ValueError, "cipher suite key count mismatch")
  for key in K:
    if key.len != 32:
      raise newException(ValueError, "cipher suite keys must be 32 bytes")
  if N.len != nonceBytes(a):
    raise newException(ValueError, "cipher suite nonce length mismatch")
  if t == 0'u16:
    raise newException(ValueError, "cipher suite tag length must be positive")
  result.alg = a
  result.keys = K
  result.nonce = N
  result.tagLen = t

proc constantTimeEqual(A, B: openArray[uint8]): bool {.role: {helper}.} =
  ## A/B: authentication tags to compare without content-dependent exits.
  var
    difference: uint8 = 0
    i: int = 0
  if A.len != B.len:
    return false
  while i < A.len:
    difference = difference or (A[i] xor B[i])
    i = i + 1
  result = difference == 0'u8

proc xorLayer(A, key, nonce: openArray[uint8], useAes: bool): seq[uint8]
    {.role: {actor}.} =
  ## A/key/nonce/useAes: bytes, 32-byte key, suite nonce, and transform choice.
  if useAes:
    result = aesCtrXor(key, nonce.toOpenArray(0, 15), A)
  else:
    result = xchacha20Xor(key, nonce, A)

proc suiteCipher(A: openArray[uint8], S: SymAuthState): seq[uint8]
    {.role: {actor}.} =
  ## A/S: bytes and suite state; xor layers are identical for encrypt/decrypt.
  case S.alg
  of csXChaCha20Blake3:
    result = xorLayer(A, S.keys[0], S.nonce, false)
  of csXChaCha20Gimli:
    result = xorLayer(A, S.keys[0], S.nonce, false)
    result = gimliStreamXor(S.keys[1], S.nonce, result)
  of csAesGimli:
    result = xorLayer(A, S.keys[0], S.nonce, true)
    result = gimliStreamXor(S.keys[1], S.nonce, result)
  of csXChaCha20AesGimli, csXChaCha20AesGimliPoly1305:
    result = xorLayer(A, S.keys[0], S.nonce, false)
    result = xorLayer(result, S.keys[1], S.nonce, true)
    result = gimliStreamXor(S.keys[2], S.nonce, result)
  of csAes256Gcm:
    raiseUnavailable("AES-256-GCM", "hasNimcrypto")

proc authTag(A: openArray[uint8], S: SymAuthState): tuple[kind: AuthType,
    bytes: seq[uint8]] {.role: {actor}.} =
  ## A/S: ciphertext and suite state used for encrypt-then-authenticate.
  case S.alg
  of csXChaCha20Blake3:
    result.kind = atBlake3
    result.bytes = blake3Hash(A, int(S.tagLen))
  of csXChaCha20Gimli:
    result.kind = atGimli
    result.bytes = gimliTag(S.keys[1], S.nonce, A, int(S.tagLen))
  of csAesGimli:
    result.kind = atGimli
    result.bytes = gimliTag(S.keys[1], S.nonce, A, int(S.tagLen))
  of csXChaCha20AesGimli:
    result.kind = atGimli
    result.bytes = gimliTag(S.keys[2], S.nonce, A, int(S.tagLen))
  of csXChaCha20AesGimliPoly1305:
    result.kind = atGimliPoly1305
    result.bytes = gimliTag(S.keys[2], S.nonce, A, int(S.tagLen))
    result.bytes.add(poly1305Tag(S.keys[3], A))
  of csAes256Gcm:
    raiseUnavailable("AES-256-GCM", "hasNimcrypto")

proc symAuthEnc*(A: openArray[uint8], S: SymAuthState): SymAuthCiphertext
    {.role: {actor}.} =
  ## A/S: plaintext and initialized suite state.
  var tag: tuple[kind: AuthType, bytes: seq[uint8]]
  result.ciphertext = suiteCipher(A, S)
  tag = authTag(result.ciphertext, S)
  result.authType = tag.kind
  result.auth = tag.bytes

proc symAuthDec*(C: SymAuthCiphertext, S: SymAuthState): seq[uint8]
    {.role: {actor}.} =
  ## C/S: authenticated ciphertext and initialized suite state.
  var expected: tuple[kind: AuthType, bytes: seq[uint8]] = authTag(C.ciphertext, S)
  if C.authType != expected.kind or not constantTimeEqual(C.auth, expected.bytes):
    raise newException(ValueError, "cipher suite authentication failed")
  result = suiteCipher(C.ciphertext, S)
