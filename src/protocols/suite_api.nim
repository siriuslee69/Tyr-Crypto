## -----------------------------------------------------------------------
## Suite API <- authenticated composite encryption compatibility interface
## -----------------------------------------------------------------------

import metaPragmas
import ./algorithms
import ./common
import ./custom_crypto/[aes_ctr, blake3, gimli_sponge, hmac, xchacha20]
when defined(hasNimcrypto):
  import ./bindings/nimcrypto

export algorithms

type
  SymAuthState* {.role: {truthState}.} = ref object
    alg*: CipherSuite
    keys*: seq[seq[uint8]]
    nonce*: seq[uint8]
    tagLen*: uint16
    used: bool

  SymAuthCiphertext* {.role: {preparedData}.} = object
    ciphertext*: seq[uint8]
    auth*: seq[uint8]
    authType*: AuthType

const
  defaultSuiteTagLen = 32'u16

proc keyCount*(a: CipherSuite): int {.role: {parser}.} =
  ## a: authenticated cipher suite.
  case a
  of csAes256Gcm:
    result = 1
  of csXChaCha20Blake3, csXChaCha20Gimli, csAesGimli:
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

proc resolvedSuiteTagLen(a: CipherSuite, t: uint16): uint16 {.role: {parser}.} =
  ## a/t: selected suite and requested tag length; zero selects its safe default.
  if a == csAes256Gcm and t != 0'u16 and t != 16'u16:
    raise newException(ValueError, "AES-256-GCM requires a 16-byte authentication tag")
  if a == csAes256Gcm:
    return 16'u16
  result = if t == 0'u16: defaultSuiteTagLen else: t
  if result < 16'u16 or result > 32'u16:
    raise newException(ValueError, "cipher suite tag length must be between 16 and 32 bytes")

proc copySuiteBytes(A: openArray[uint8]): seq[uint8] {.role: {helper}.} =
  ## A: caller-owned material copied into immutable suite state storage.
  var i: int = 0
  result = newSeq[uint8](A.len)
  while i < A.len:
    result[i] = A[i]
    i = i + 1

proc initSymAuthState*(a: CipherSuite, K: seq[seq[uint8]], N: seq[uint8],
    t: uint16 = 0'u16): SymAuthState {.role: {truthBuilder}.} =
  ## a: selected cipher suite.
  ## K: ordered 32-byte encryption and authentication keys.
  ## N: suite nonce.
  ## t: requested authentication tag, or zero for the suite-safe default.
  var i: int = 0
  if K.len != keyCount(a):
    raise newException(ValueError, "cipher suite key count mismatch")
  for key in K:
    if key.len != 32:
      raise newException(ValueError, "cipher suite keys must be 32 bytes")
  if N.len != nonceBytes(a):
    raise newException(ValueError, "cipher suite nonce length mismatch")
  new(result)
  result.alg = a
  result.keys = newSeq[seq[uint8]](K.len)
  while i < K.len:
    result.keys[i] = copySuiteBytes(K[i])
    i = i + 1
  result.nonce = copySuiteBytes(N)
  result.tagLen = resolvedSuiteTagLen(a, t)
  result.used = false

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

proc appendUint64Le(A: var seq[uint8], v: uint64) {.role: {dataWriter}.} =
  ## A/v: destination frame and fixed-width little-endian integer.
  var i: int = 0
  while i < 8:
    A.add(uint8((v shr uint64(i * 8)) and 0xff'u64))
    i = i + 1

proc authFrame(A: openArray[uint8], S: SymAuthState): seq[uint8]
    {.role: {truthBuilder}.} =
  ## A/S: ciphertext and suite state bound into an unambiguous MAC frame.
  const domain = "Tyr-Crypto authenticated suite v2"
  var i: int = 0
  result = newSeqOfCap[uint8](domain.len + 1 + 16 + S.nonce.len + A.len)
  while i < domain.len:
    result.add(uint8(ord(domain[i])))
    i = i + 1
  result.add(uint8(ord(S.alg)))
  appendUint64Le(result, uint64(S.nonce.len))
  result.add(S.nonce)
  appendUint64Le(result, uint64(A.len))
  result.add(A)

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
    result.bytes = blake3KeyedHash(S.keys[1], authFrame(A, S), int(S.tagLen))
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
    result.bytes.add(poly1305CustomHmac(S.keys[3], authFrame(A, S), 16))
  of csAes256Gcm:
    raiseUnavailable("AES-256-GCM", "hasNimcrypto")

proc symAuthEnc*(A: openArray[uint8], S: SymAuthState): SymAuthCiphertext
    {.role: {actor}.} =
  ## A/S: plaintext and initialized suite state.
  var tag: tuple[kind: AuthType, bytes: seq[uint8]]
  if S == nil:
    raise newException(ValueError, "cipher suite state is not initialized")
  if S.used:
    raise newException(ValueError, "cipher suite nonce has already been used for encryption")
  if S.alg == csAes256Gcm:
    when defined(hasNimcrypto):
      var ctx: Aes256GcmContext
      defer:
        ctx.clear()
      S.used = true
      ctx.init(S.keys[0], S.nonce)
      result.ciphertext = ctx.encrypt(A)
      result.auth = @(ctx.tag())
      result.authType = atAeadTag
    else:
      raiseUnavailable("AES-256-GCM", "hasNimcrypto")
    return
  S.used = true
  result.ciphertext = suiteCipher(A, S)
  tag = authTag(result.ciphertext, S)
  result.authType = tag.kind
  result.auth = tag.bytes

proc symAuthDec*(C: SymAuthCiphertext, S: SymAuthState): seq[uint8]
    {.role: {actor}.} =
  ## C/S: authenticated ciphertext and initialized suite state.
  if S == nil:
    raise newException(ValueError, "cipher suite state is not initialized")
  if S.alg == csAes256Gcm and
      (C.authType != atAeadTag or C.auth.len != 16):
    raise newException(ValueError, "AES-256-GCM authentication tag is invalid")
  if S.alg == csAes256Gcm:
    when defined(hasNimcrypto):
      var ctx: Aes256GcmContext
      defer:
        ctx.clear()
      ctx.init(S.keys[0], S.nonce)
      return ctx.decrypt(C.ciphertext, C.auth)
    else:
      raiseUnavailable("AES-256-GCM", "hasNimcrypto")
  var expected: tuple[kind: AuthType, bytes: seq[uint8]] = authTag(C.ciphertext, S)
  if C.authType != expected.kind or not constantTimeEqual(C.auth, expected.bytes):
    raise newException(ValueError, "cipher suite authentication failed")
  result = suiteCipher(C.ciphertext, S)
