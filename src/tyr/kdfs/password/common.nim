## -----------------------------------------------------------
## Password KDF, shared part <- types, labels, secret holder
## -----------------------------------------------------------
##
## Everything here works with or without libsodium:
##
##   Key / Secret / Derived*     what the password routines hand back
##   kdfContext*                 domain labels: a label is mixed into the
##                               password before hashing, so two uses of
##                               one password never give the same key
##   Secret + withSecret         a password held until one use, then wiped
##   stringToBytes / wipeBytes   byte helpers for the other parts

import ../../aeads/types
import ../../hashes/blake3
import ../../helpers/secure_memory
import runePragmas

type
  ## Secret: secure container for user-provided secrets.
  Secret* = object
    data: seq[uint8]

  ## SecretOp: differentiate derive vs unwrap flows.
  SecretOp* = enum
    soDeriveMasterKey,
    soUnwrapMasterKey

  ## Key: wraps PIN-derived keys + salts + encrypted master key.
  Key* = object
    ## encryptedMasterKey: master key wrapped via XChaCha20-Poly1305.
    encryptedMasterKey*: seq[uint8]
    ## masterKeyNonce: AEAD nonce for encryptedMasterKey.
    masterKeyNonce*: seq[uint8]
    ## pinKdf: derived key material from PIN/password.
    pinKdf*: seq[uint8]
    ## pinSalt: salt for the initial PIN derivation.
    pinSalt*: seq[uint8]
    ## pinOpsLimit: Argon2id CPU cost for the PIN wrapping key.
    pinOpsLimit*: culonglong
    ## pinMemLimit: Argon2id memory cost for the PIN wrapping key.
    pinMemLimit*: csize_t
    ## argon2Salt: salt for Argon2id key derivation.
    argon2Salt*: seq[uint8]
    ## argon2OpsLimit: CPU cost parameter for Argon2id.
    argon2OpsLimit*: culonglong
    ## argon2MemLimit: memory cost parameter for Argon2id.
    argon2MemLimit*: csize_t
    secret: Secret

  ## EncryptedCiphertext: AEAD output with nonce and tag.
  EncryptedCiphertext* = object
    nonce*: seq[uint8]
    ciphertext*: seq[uint8]
    hmac*: seq[uint8]

  ## ArgonKdfParams: parameters needed to reproduce an Argon2id derivation.
  ArgonKdfParams* = object
    argon2Salt*: seq[uint8]
    argon2OpsLimit*: culonglong
    argon2MemLimit*: csize_t

  ## DerivedEncryptionKeys: encryption state derived from a password.
  DerivedEncryptionKeys* = object
    state*: AeadState
    kdf*: ArgonKdfParams

  ## DerivedKexSeed: deterministic X25519 seed derived from a password.
  DerivedKexSeed* = object
    x25519Seed*: seq[uint8]
    kdf*: ArgonKdfParams

  ## DerivedSecretBytes: generic derived byte material plus KDF metadata.
  DerivedSecretBytes* = object
    bytes*: seq[uint8]
    kdf*: ArgonKdfParams

const
  derivedSecretLenDefault* = 32
  ## Labels. Changing a value changes every key derived with it.
  kdfContextPasswordPin* = "pw-pin-secret-v1"  # otter:allow
  kdfContextPatternFragment* = "pattern-fragment-v1"

proc copyBytes*(A: openArray[uint8]): seq[uint8] {.role: {helper}.} =
  ## A: bytes copied into a fresh seq.
  result = @A

proc stringToBytes*(s: string): seq[uint8] {.role: {helper}.} =
  ## s: text; returns its bytes unchanged.
  var
    i: int = 0
  result = newSeq[uint8](s.len)
  while i < s.len:
    result[i] = uint8(s[i])
    i = i + 1

proc wipeBytes*(data: var seq[uint8]) {.role: {helper}.} =
  ## data: secret bytes; overwritten with volatile writes, then emptied.
  secureClearBytes(data)
  data.setLen(0)

proc appendUint32Le(buf: var seq[uint8], v: uint32) {.role: {helper}.} =
  ## buf: grows by v as 4 bytes, least significant first.
  var
    i: int = 0
    x: uint32 = v
  while i < 4:
    buf.add(uint8(x and 255'u32))
    x = x shr 8
    i = i + 1

proc buildPasswordPinInput*(ps, pins: openArray[uint8]): seq[uint8] {.role: {helper}.} =
  ## ps/pins: password and PIN. Returns one 32-byte value that depends on
  ## both and on where one ends and the other starts:
  ##   BLAKE3("joint-password-pin-v1" | len(ps) | ps | len(pins) | pins)
  var
    buf: seq[uint8] = stringToBytes("joint-password-pin-v1")
  defer:
    wipeBytes(buf)
  appendUint32Le(buf, uint32(ps.len))
  buf.add(ps)
  appendUint32Le(buf, uint32(pins.len))
  buf.add(pins)
  result = blake3Hash(buf)

proc initSecretFromBytes*(input: openArray[uint8]): Secret {.role: {helper}.} =
  ## input: secret bytes, copied into the holder.
  result.data = copyBytes(input)

proc initSecretFromString*(input: string): Secret {.role: {helper}.} =
  ## input: secret text, copied into the holder.
  result.data = stringToBytes(input)

proc wipeSecret*(secret: var Secret) {.role: {helper}.} =
  ## secret: wiped and emptied.
  wipeBytes(secret.data)

proc withSecret*[T](secret: var Secret, body: proc (data: openArray[uint8]): T): T {.role: {actor}.} =
  ## secret: handed to body once, then wiped whatever body does.
  if secret.data.len == 0:
    raise newException(ValueError, "secret is empty")
  defer:
    wipeSecret(secret)
  result = body(secret.data)

proc withKeySecret*[T](key: var Key, body: proc (data: openArray[uint8]): T): T {.role: {actor}.} =
  ## key: its stored secret is handed to body once, then wiped.
  if key.secret.data.len == 0:
    raise newException(ValueError, "secret missing")
  result = withSecret(key.secret, body)

proc setSecret*(key: var Key, secret: Secret) {.role: {helper}.} =
  ## key: stores secret for one later withSecret(key, op).
  key.secret = secret

proc setSecretFromBytes*(key: var Key, input: openArray[uint8]) {.role: {helper}.} =
  ## key: stores a copy of input as its secret.
  key.secret = initSecretFromBytes(input)

proc setSecretFromString*(key: var Key, input: string) {.role: {helper}.} =
  ## key: stores the bytes of input as its secret.
  key.secret = initSecretFromString(input)

proc clearSecret*(key: var Key) {.role: {helper}.} =
  ## key: its stored secret is wiped.
  wipeSecret(key.secret)
