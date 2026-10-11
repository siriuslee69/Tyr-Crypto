## -----------------------------------------------------------
## Password KDF, key-wrap part <- PIN-wrapped master key (libsodium)
## -----------------------------------------------------------
##
##   password --Argon2id--> master key (32 bytes, never stored)
##   PIN ------Argon2id--> PIN key ----XChaCha20-Poly1305----> encrypted
##                                     (master key)            master key
##
##   Key holds:  argon2 salt/costs, PIN salt/costs, nonce, encrypted master
##               key, and for a short while the PIN key itself (pinKdf).
##
## Keys made before PIN costs were stored (pinOpsLimit = pinMemLimit = 0)
## used a fast PIN hash instead of Argon2id; unwrapping still accepts them
## and moves them to Argon2id costs.

import ../../helpers/errors
import ../../hashes/blake3
import ../../bindings/libsodium
import ../../ciphers/xchacha20
import ./common
import ./argon
import runePragmas

const
  masterKeyLen = 32
  pinSaltLen = 16
  aeadTagLen = 16
  kdfContextPinWrap = "pin-wrap-key-v2"

proc derivePinKdfLegacy(pin: openArray[uint8], salt: openArray[uint8]): seq[uint8] {.role: {math}.} =
  ## The fast PIN hash of keys made before PIN costs were stored:
  ##   HChaCha20(key = BLAKE3(pin), nonce = salt)
  var
    base: seq[uint8] = @[]
    nonce: array[pinSaltLen, byte] = default(array[pinSaltLen, byte])
  if salt.len != pinSaltLen:
    raise newException(ValueError, "pin salt must be 16 bytes")
  defer:
    wipeBytes(base)
  base = blake3Hash(pin)
  copyMem(addr nonce[0], unsafeAddr salt[0], pinSaltLen)
  result = @(hchacha20(base, nonce))

proc derivePinKdfBytes(pin: openArray[uint8], salt: openArray[uint8],
    opsLimit: culonglong, memLimit: csize_t): seq[uint8] {.role: {math}.} =
  ## pin/salt: PIN and its 16-byte salt. Returns the 32-byte PIN key.
  if salt.len != pinSaltLen:
    raise newException(ValueError, "pin salt must be 16 bytes")
  result = deriveArgonBytes(pin, kdfContextPinWrap, salt, opsLimit, memLimit,
    masterKeyLen).bs

proc ensurePinKdfParams(key: var Key) {.role: {helper}.} =
  ## key: PIN costs left at 0 are set to the moderate ones.
  key.pinOpsLimit = resolveOps(key.pinOpsLimit)
  key.pinMemLimit = resolveMem(key.pinMemLimit)

proc derivePinKdfForKey(key: Key, pin: openArray[uint8]): seq[uint8] {.role: {math}.} =
  ## key: picks the fast legacy hash when no PIN costs are stored.
  if key.pinOpsLimit == 0'u64 and key.pinMemLimit == 0:
    return derivePinKdfLegacy(pin, key.pinSalt)
  result = derivePinKdfBytes(pin, key.pinSalt, resolveOps(key.pinOpsLimit),
    resolveMem(key.pinMemLimit))

proc derivePinKdf*(pin: string, salt: openArray[uint8]): seq[uint8] {.role: {orchestrator}.} =
  ## pin: PIN text. salt: 16 bytes. Returns the PIN key at moderate costs.
  var
    pinBytes: seq[uint8] = stringToBytes(pin)
  defer:
    wipeBytes(pinBytes)
  result = derivePinKdfBytes(pinBytes, salt, resolveOps(0'u64), resolveMem(0))

proc setPinKdfBytes*(key: var Key, pin: openArray[uint8]) {.role: {actor}.} =
  ## key: pinKdf is replaced by the PIN key for pin.
  if key.pinSalt.len == 0:
    raise newException(ValueError, "pin salt missing")
  wipeBytes(key.pinKdf)
  key.pinKdf = derivePinKdfForKey(key, pin)

proc setPinKdf*(key: var Key, pin: string) {.role: {actor}.} =
  ## pin: PIN text; its byte copy is wiped afterwards.
  var
    pinBytes: seq[uint8] = stringToBytes(pin)
  defer:
    wipeBytes(pinBytes)
  setPinKdfBytes(key, pinBytes)

proc requireXChaChaKeyNonce(key, nonce: openArray[uint8]) {.role: {sanitizer}.} =
  ## key/nonce: must have XChaCha20-Poly1305's sizes (32 and 24 bytes).
  if key.len != int(crypto_aead_xchacha20poly1305_ietf_keybytes()):
    raise newException(ValueError, "invalid xchacha20poly1305 key length")
  if nonce.len != int(crypto_aead_xchacha20poly1305_ietf_npubbytes()):
    raise newException(ValueError, "invalid xchacha20poly1305 nonce length")

proc aeadEncrypt(key, nonce, plaintext: openArray[uint8]): seq[uint8] {.role: {encryptor}.} =
  ## Returns XChaCha20-Poly1305(plaintext) as [ciphertext][16-byte tag].
  var
    outLen: culonglong = 0
    status: cint = 0
  requireXChaChaKeyNonce(key, nonce)
  result = newSeq[uint8](plaintext.len + aeadTagLen)
  status = crypto_aead_xchacha20poly1305_ietf_encrypt(
    addr result[0],
    addr outLen,
    if plaintext.len > 0: unsafeAddr plaintext[0] else: nil,
    culonglong(plaintext.len),
    nil,
    0,
    nil,
    unsafeAddr nonce[0],
    unsafeAddr key[0]
  )
  if status != 0:
    raiseOperation("libsodium", "xchacha20poly1305 encryption failed")
  result.setLen(int(outLen))

proc aeadDecrypt(key, nonce, ciphertext: openArray[uint8]): seq[uint8] {.role: {decryptor}.} =
  ## ciphertext: [ciphertext][16-byte tag]. Raises when the tag is wrong.
  var
    outLen: culonglong = 0
    status: cint = 0
  requireXChaChaKeyNonce(key, nonce)
  if ciphertext.len < aeadTagLen:
    raise newException(ValueError, "invalid xchacha20poly1305 ciphertext length")
  result = newSeq[uint8](ciphertext.len - aeadTagLen)
  status = crypto_aead_xchacha20poly1305_ietf_decrypt(
    if result.len > 0: addr result[0] else: nil,
    addr outLen,
    nil,
    unsafeAddr ciphertext[0],
    culonglong(ciphertext.len),
    nil,
    0,
    unsafeAddr nonce[0],
    unsafeAddr key[0]
  )
  if status != 0:
    raiseOperation("libsodium", "xchacha20poly1305 decryption failed")
  result.setLen(int(outLen))

proc newNonce(): seq[uint8] {.role: {dataFetcher}.} =
  ## Returns a fresh random 24-byte XChaCha20 nonce.
  result = randomBytes(int(crypto_aead_xchacha20poly1305_ietf_npubbytes()))

proc deriveMasterKeyFromBytes(password: openArray[uint8]): tuple[key: Key, masterKey: seq[uint8]] {.role: {orchestrator}.} =
  ## password: bytes. Returns a fresh master key (Argon2id at moderate costs,
  ## random salt, no label) and a Key holding how to derive it again.
  var
    opsLimit: culonglong = 0
    memLimit: csize_t = 0
    status: cint = 0
  ensureSodiumInitialised()
  opsLimit = crypto_pwhash_opslimit_moderate()
  memLimit = crypto_pwhash_memlimit_moderate()
  result.key.argon2Salt = randomBytes(int(crypto_pwhash_saltbytes()))
  result.masterKey = newSeq[uint8](masterKeyLen)
  status = crypto_pwhash(
    addr result.masterKey[0],
    culonglong(result.masterKey.len),
    passPtr(password),
    culonglong(password.len),
    addr result.key.argon2Salt[0],
    opsLimit,
    memLimit,
    crypto_pwhash_alg_argon2id13()
  )
  if status != 0:
    raiseOperation("libsodium", "argon2id key derivation failed")
  result.key.argon2OpsLimit = opsLimit
  result.key.argon2MemLimit = memLimit
  result.key.pinSalt = randomBytes(pinSaltLen)
  result.key.pinOpsLimit = resolveOps(0'u64)
  result.key.pinMemLimit = resolveMem(0)

proc deriveMasterKey*(password: string): tuple[key: Key, masterKey: seq[uint8]] {.role: {orchestrator}.} =
  ## password: text; its byte copy is wiped afterwards.
  var
    passwordBytes: seq[uint8] = stringToBytes(password)
  defer:
    wipeBytes(passwordBytes)
  result = deriveMasterKeyFromBytes(passwordBytes)

proc wrapMasterKeyWithPinBytes*(key: var Key, masterKey: openArray[uint8], pin: openArray[uint8]) {.role: {encryptor}.} =
  ## key: receives masterKey encrypted under the PIN key (new nonce; a
  ## PIN salt and costs are filled in when missing). pinKdf is wiped after.
  ensureSodiumInitialised()
  if masterKey.len != masterKeyLen:
    raise newException(ValueError, "invalid master key length")
  if key.pinSalt.len == 0:
    key.pinSalt = randomBytes(pinSaltLen)
  ensurePinKdfParams(key)
  wipeBytes(key.pinKdf)
  key.pinKdf = derivePinKdfBytes(pin, key.pinSalt, key.pinOpsLimit, key.pinMemLimit)
  defer:
    wipeBytes(key.pinKdf)
  key.masterKeyNonce = newNonce()
  key.encryptedMasterKey = aeadEncrypt(key.pinKdf, key.masterKeyNonce, masterKey)

proc wrapMasterKeyWithPin*(key: var Key, masterKey: openArray[uint8], pin: string) {.role: {encryptor}.} =
  ## pin: PIN text; its byte copy is wiped afterwards.
  var
    pinBytes: seq[uint8] = stringToBytes(pin)
  defer:
    wipeBytes(pinBytes)
  wrapMasterKeyWithPinBytes(key, masterKey, pinBytes)

proc unwrapLegacyRetry(key: var Key, pin: openArray[uint8]): seq[uint8] {.role: {decryptor}.} =
  ## A key without stored PIN costs may still have been wrapped at the
  ## moderate Argon2id costs: try those, and store them when they work.
  wipeBytes(key.pinKdf)
  key.pinKdf = derivePinKdfBytes(pin, key.pinSalt, resolveOps(0'u64), resolveMem(0))
  result = aeadDecrypt(key.pinKdf, key.masterKeyNonce, key.encryptedMasterKey)
  key.pinOpsLimit = resolveOps(0'u64)
  key.pinMemLimit = resolveMem(0)

proc unwrapMasterKeyWithPinBytes*(key: var Key, pin: openArray[uint8]): seq[uint8] {.role: {decryptor}.} =
  ## key: wrapped master key. Returns the master key; raises on a wrong PIN.
  ensureSodiumInitialised()
  if key.pinSalt.len == 0:
    raise newException(ValueError, "pin salt missing")
  if key.encryptedMasterKey.len == 0 or key.masterKeyNonce.len == 0:
    raise newException(ValueError, "encrypted master key missing")
  wipeBytes(key.pinKdf)
  key.pinKdf = derivePinKdfForKey(key, pin)
  defer:
    wipeBytes(key.pinKdf)
  try:
    result = aeadDecrypt(key.pinKdf, key.masterKeyNonce, key.encryptedMasterKey)
  except CryptoOperationError:
    if key.pinOpsLimit != 0'u64 or key.pinMemLimit != 0:
      raise
    result = unwrapLegacyRetry(key, pin)
  if result.len != masterKeyLen:
    raise newException(ValueError, "invalid master key length")

proc unwrapMasterKeyWithPin*(key: var Key, pin: string): seq[uint8] {.role: {decryptor}.} =
  ## pin: PIN text; its byte copy is wiped afterwards.
  var
    pinBytes: seq[uint8] = stringToBytes(pin)
  defer:
    wipeBytes(pinBytes)
  result = unwrapMasterKeyWithPinBytes(key, pinBytes)

proc deriveMasterKeyInto(key: var Key, password: openArray[uint8]): seq[uint8] {.role: {orchestrator}.} =
  ## key: takes the salts and costs of a fresh master key from password.
  ## Returns that master key.
  var
    derived: tuple[key: Key, masterKey: seq[uint8]] = deriveMasterKeyFromBytes(password)
  key.argon2Salt = derived.key.argon2Salt
  key.argon2OpsLimit = derived.key.argon2OpsLimit
  key.argon2MemLimit = derived.key.argon2MemLimit
  key.pinSalt = derived.key.pinSalt
  key.pinOpsLimit = derived.key.pinOpsLimit
  key.pinMemLimit = derived.key.pinMemLimit
  result = move(derived.masterKey)

proc withSecret*(key: var Key, op: SecretOp): seq[uint8] {.role: {orchestrator}.} =
  ## key: its stored secret is used once (as password or as PIN), then wiped.
  ##   soDeriveMasterKey  -> fresh master key; key takes its salts and costs
  ##   soUnwrapMasterKey  -> the master key unwrapped with the secret as PIN
  result = withKeySecret(key, proc (data: openArray[uint8]): seq[uint8] =
    case op
    of soDeriveMasterKey:
      deriveMasterKeyInto(key, data)
    of soUnwrapMasterKey:
      unwrapMasterKeyWithPinBytes(key, data)
  )

proc sealWithMasterKey(masterKey, plaintext: openArray[uint8]): EncryptedCiphertext {.role: {encryptor}.} =
  ## Encrypts under a fresh nonce; the result keeps ciphertext and tag apart.
  var
    sealed: seq[uint8] = @[]
    tagStart: int = 0
  result.nonce = newNonce()
  sealed = aeadEncrypt(masterKey, result.nonce, plaintext)
  if sealed.len < aeadTagLen:
    raise newException(ValueError, "invalid ciphertext output")
  tagStart = sealed.len - aeadTagLen
  result.ciphertext = sealed[0 ..< tagStart]
  result.hmac = sealed[tagStart ..< sealed.len]

proc encryptWithMasterKey*(masterKey, plaintext: openArray[uint8]): EncryptedCiphertext {.role: {encryptor}.} =
  ## masterKey: 32 bytes. Returns nonce, ciphertext and tag.
  ensureSodiumInitialised()
  if masterKey.len != masterKeyLen:
    raise newException(ValueError, "invalid master key length")
  result = sealWithMasterKey(masterKey, plaintext)

proc decryptWithMasterKey*(masterKey: openArray[uint8], cipher: EncryptedCiphertext): seq[uint8] {.role: {decryptor}.} =
  ## masterKey: 32 bytes. Raises when the tag does not match.
  ensureSodiumInitialised()
  if masterKey.len != masterKeyLen:
    raise newException(ValueError, "invalid master key length")
  if cipher.nonce.len != int(crypto_aead_xchacha20poly1305_ietf_npubbytes()):
    raise newException(ValueError, "invalid xchacha20poly1305 nonce length")
  if cipher.hmac.len != aeadTagLen:
    raise newException(ValueError, "invalid xchacha20poly1305 tag length")
  result = aeadDecrypt(masterKey, cipher.nonce, cipher.ciphertext & cipher.hmac)

proc deriveKeyFromPasswordBytes(password: openArray[uint8], pin: openArray[uint8]): Key {.role: {orchestrator}.} =
  ## Derives a fresh master key from password and wraps it under pin.
  ## The returned Key still holds pinKdf (the PIN key) for encryptWithKey.
  var
    derived: tuple[key: Key, masterKey: seq[uint8]] = deriveMasterKeyFromBytes(password)
  defer:
    wipeBytes(derived.masterKey)
  result = derived.key
  result.pinKdf = derivePinKdfBytes(pin, result.pinSalt, result.pinOpsLimit, result.pinMemLimit)
  result.masterKeyNonce = newNonce()
  result.encryptedMasterKey = aeadEncrypt(result.pinKdf, result.masterKeyNonce, derived.masterKey)

proc deriveKeyFromPassword*(password: string, pin: string): Key {.role: {orchestrator}.} =
  ## password/pin: text; their byte copies are wiped afterwards.
  var
    passwordBytes: seq[uint8] = stringToBytes(password)
    pinBytes: seq[uint8] = stringToBytes(pin)
  defer:
    wipeBytes(passwordBytes)
    wipeBytes(pinBytes)
  result = deriveKeyFromPasswordBytes(passwordBytes, pinBytes)

proc unwrapMasterKey(key: var Key): seq[uint8] {.role: {decryptor}.} =
  ## key: must still hold pinKdf. Returns the master key.
  if key.pinKdf.len == 0:
    raise newException(ValueError, "pin KDF missing")
  if key.encryptedMasterKey.len == 0 or key.masterKeyNonce.len == 0:
    raise newException(ValueError, "encrypted master key missing")
  result = aeadDecrypt(key.pinKdf, key.masterKeyNonce, key.encryptedMasterKey)
  if result.len != masterKeyLen:
    raise newException(ValueError, "invalid master key length")

proc encryptWithKey*(key: var Key, plaintext: seq[uint8]): EncryptedCiphertext {.role: {encryptor}.} =
  ## key: fresh from deriveKeyFromPassword. Encrypts once with the master
  ## key; pinKdf and the master key are wiped afterwards.
  var
    masterKey: seq[uint8] = @[]
  ensureSodiumInitialised()
  if key.pinKdf.len == 0:
    raise newException(ValueError, "pin KDF missing")
  defer:
    wipeBytes(key.pinKdf)
    wipeBytes(masterKey)
  masterKey = unwrapMasterKey(key)
  result = sealWithMasterKey(masterKey, plaintext)
