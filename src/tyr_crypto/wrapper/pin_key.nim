## -----------------------------------------------------------
## PIN/Password KDF + Key Wrap Interface
## -> Derive keys from user secrets and wrap master keys
## -> Uses Argon2 + XChaCha20-Poly1305 (libsodium)
## -----------------------------------------------------------

import ../common
import ../wrapper/crypto as cryptoWrap
import ../custom_crypto/blake3

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
    state*: cryptoWrap.EncryptionState
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
  derivedSecretLenDefault = 32
  kdfContextPasswordPinSecret* = "pw-pin-secret-v1"
  kdfContextPatternFragment* = "pattern-fragment-v1"

proc copyBytes(input: openArray[uint8]): seq[uint8] =
  result = newSeq[uint8](input.len)
  for i, b in input:
    result[i] = b

proc stringToBytes(s: string): seq[uint8] =
  result = newSeq[uint8](s.len)
  for i, ch in s:
    result[i] = uint8(ch)

proc zeroizeCompat(data: var seq[uint8]) =
  var
    i: int = 0
  while i < data.len:
    data[i] = 0
    i = i + 1
  data.setLen(0)

proc appendUint32Le(buf: var seq[uint8], v: uint32) =
  var
    i: int = 0
    x: uint32 = v
  while i < 4:
    buf.add(uint8(x and 255'u32))
    x = x shr 8
    i = i + 1

proc buildPasswordPinInput(ps, pins: openArray[uint8]): seq[uint8] =
  var
    buf: seq[uint8] = @[]
  buf = stringToBytes("joint-password-pin-v1")
  appendUint32Le(buf, uint32(ps.len))
  buf.add(ps)
  appendUint32Le(buf, uint32(pins.len))
  buf.add(pins)
  result = blake3Hash(buf)

when defined(hasLibsodium):
  import std/sysrand
  import ../bindings/libsodium
  import ../custom_crypto/xchacha20

  const
    masterKeyLen = 32
    pinSaltLen = 16
    aeadTagLen = 16
    kdfContextChacha20 = "sym-chacha20-v1"
    kdfContextXChaGimli = "sym-xchacha20-gimli-v1"
    kdfContextAesGimli = "sym-aes-gimli-v1"
    kdfContextXChaAesGimli = "sym-xchacha20-aes-gimli-v1"
    kdfContextXChaAesGimliPoly1305 = "sym-xchacha20-aes-gimli-poly1305-v1"
    kdfContextAes256 = "sym-aes256-v1"
    kdfContextKexDuo = "kex-duo-x25519-seed-v1"
    kdfContextKexTriple = "kex-triple-x25519-seed-v1"
    kdfContextPinWrap = "pin-wrap-key-v2"

  proc randomBytes(len: int): seq[uint8]
  proc passPtr(pass: openArray[uint8]): cstring

  proc secureZeroizeSeq(data: var seq[uint8]) =
    if data.len == 0:
      return
    sodium_memzero(addr data[0], csize_t(data.len))
    data.setLen(0)

  proc zeroizeSeq(data: var seq[uint8]) =
    secureZeroizeSeq(data)

  proc algoKeyCount(a: cryptoWrap.AlgoType): int =
    ## a: algorithm for which to compute key count.
    case a
    of cryptoWrap.chacha20:
      result = 1
    of cryptoWrap.xchacha20Gimli:
      result = 2
    of cryptoWrap.aesGimli:
      result = 2
    of cryptoWrap.xchacha20AesGimli:
      result = 3
    of cryptoWrap.xchacha20AesGimliPoly1305:
      result = 4
    of cryptoWrap.aes256:
      result = 1

  proc algoKeyBytes(a: cryptoWrap.AlgoType): int =
    ## a: algorithm for which to compute key bytes.
    let c = algoKeyCount(a)
    result = c * 32

  proc algoNonceLen(a: cryptoWrap.AlgoType): int =
    ## a: algorithm for which to compute nonce length.
    case a
    of cryptoWrap.aes256:
      result = 12
    else:
      result = 24

  proc algoContext(a: cryptoWrap.AlgoType): string =
    ## a: algorithm for which to pick a KDF context string.
    case a
    of cryptoWrap.chacha20:
      result = kdfContextChacha20
    of cryptoWrap.xchacha20Gimli:
      result = kdfContextXChaGimli
    of cryptoWrap.aesGimli:
      result = kdfContextAesGimli
    of cryptoWrap.xchacha20AesGimli:
      result = kdfContextXChaAesGimli
    of cryptoWrap.xchacha20AesGimliPoly1305:
      result = kdfContextXChaAesGimliPoly1305
    of cryptoWrap.aes256:
      result = kdfContextAes256

  proc resolveArgonOps(ol: culonglong): culonglong =
    ## ol: requested ops limit (0 to use moderate default).
    if ol == 0'u64:
      result = crypto_pwhash_opslimit_moderate()
    else:
      result = ol

  proc resolveArgonMem(ml: csize_t): csize_t =
    ## ml: requested memory limit (0 to use moderate default).
    if ml == 0:
      result = crypto_pwhash_memlimit_moderate()
    else:
      result = ml

  proc resolvePinOps(ol: culonglong): culonglong =
    ## ol: requested ops limit for PIN wrapping.
    if ol == 0'u64:
      result = crypto_pwhash_opslimit_moderate()
    else:
      result = ol

  proc resolvePinMem(ml: csize_t): csize_t =
    ## ml: requested memory limit for PIN wrapping.
    if ml == 0:
      result = crypto_pwhash_memlimit_moderate()
    else:
      result = ml

  proc argonSaltLen(): int =
    ## argon2 salt length (libsodium).
    result = int(crypto_pwhash_saltbytes())

  proc buildArgonSalt(ss: openArray[uint8]): seq[uint8] =
    ## ss: optional provided salt (must match argon salt length).
    var
      l: int = 0
    l = argonSaltLen()
    if ss.len == 0:
      result = randomBytes(l)
    else:
      if ss.len != l:
        raise newException(ValueError, "argon2 salt length mismatch")
      result = copyBytes(ss)

  proc buildArgonInput(ps: openArray[uint8], cs: string): seq[uint8] =
    ## ps: password bytes.
    ## cs: context string for domain separation.
    var
      buf: seq[uint8] = @[]
      ctxBytes: seq[uint8] = @[]
    ctxBytes = stringToBytes(cs)
    buf.add(ctxBytes)
    buf.add(ps)
    result = blake3Hash(buf)
    zeroizeSeq(ctxBytes)

  proc deriveArgonBytes(ps: openArray[uint8], cs: string, ss: openArray[uint8],
      ol: culonglong, ml: csize_t, l: int): tuple[bs: seq[uint8], k: ArgonKdfParams] =
    ## ps: password bytes.
    ## cs: context string for domain separation.
    ## ss: salt bytes (empty to generate).
    ## ol: ops limit.
    ## ml: memory limit.
    ## l: output length.
    ensureSodiumInitialised()
    if l <= 0:
      raise newException(ValueError, "argon2 output length must be positive")
    var
      salt: seq[uint8] = @[]
      opsLimit: culonglong = 0
      memLimit: csize_t = 0
      passBuf: seq[uint8] = @[]
      outBuf: seq[uint8] = @[]
      status: cint = 0
    salt = buildArgonSalt(ss)
    opsLimit = resolveArgonOps(ol)
    memLimit = resolveArgonMem(ml)
    passBuf = buildArgonInput(ps, cs)
    outBuf.setLen(l)
    status = crypto_pwhash(
      if outBuf.len > 0: addr outBuf[0] else: nil,
      culonglong(outBuf.len),
      passPtr(passBuf),
      culonglong(passBuf.len),
      if salt.len > 0: addr salt[0] else: nil,
      opsLimit,
      memLimit,
      crypto_pwhash_alg_argon2id13()
    )
    zeroizeSeq(passBuf)
    if status != 0:
      raiseOperation("libsodium", "argon2id key derivation failed")
    result.bs = outBuf
    result.k = ArgonKdfParams(
      argon2Salt: salt,
      argon2OpsLimit: opsLimit,
      argon2MemLimit: memLimit
    )

  proc splitSymmetricKeys(ms: seq[uint8], c: int): seq[cryptoWrap.Key] =
    ## ms: raw key material.
    ## c: number of 32-byte keys.
    var
      ks: seq[cryptoWrap.Key] = @[]
      i: int = 0
      offset: int = 0
    if c <= 0:
      return @[]
    ks.setLen(c)
    i = 0
    while i < c:
      offset = i * 32
      ks[i].key = ms[offset ..< offset + 32]
      ks[i].keyType = cryptoWrap.isSym
      i = i + 1
    result = ks

  proc resolveNonce(a: cryptoWrap.AlgoType, ns: openArray[uint8]): seq[uint8] =
    ## a: algorithm for nonce sizing.
    ## ns: optional nonce bytes.
    var
      l: int = 0
    l = algoNonceLen(a)
    if ns.len == 0:
      result = randomBytes(l)
    else:
      if ns.len != l:
        raise newException(ValueError, "nonce length mismatch")
      result = copyBytes(ns)

  proc buildEncryptionState(a: cryptoWrap.AlgoType, ks: seq[uint8],
      ns: seq[uint8], t: uint16): cryptoWrap.EncryptionState =
    ## a: algorithm for the state.
    ## ks: raw key material.
    ## ns: nonce bytes.
    ## t: tag length override (0 for default).
    var
      s: cryptoWrap.EncryptionState
      count: int = 0
    s.algoType = a
    s.nonce = ns
    s.tagLen = t
    count = algoKeyCount(a)
    s.keys = splitSymmetricKeys(ks, count)
    result = s

  proc deriveSymmetricKeysFromBytesWithSalt*(a: cryptoWrap.AlgoType,
      ps, ss: openArray[uint8], ol: culonglong, ml: csize_t,
      ns: openArray[uint8], t: uint16): DerivedEncryptionKeys =
    ## a: symmetric algorithm.
    ## ps: password bytes.
    ## ss: salt bytes.
    ## ol: ops limit for Argon2id.
    ## ml: memory limit for Argon2id.
    ## ns: nonce bytes.
    ## t: tag length override.
    var
      keyLen: int = 0
      derived: tuple[bs: seq[uint8], k: ArgonKdfParams]
      nonceBytes: seq[uint8] = @[]
      state: cryptoWrap.EncryptionState
    keyLen = algoKeyBytes(a)
    derived = deriveArgonBytes(ps, algoContext(a), ss, ol, ml, keyLen)
    nonceBytes = resolveNonce(a, ns)
    state = buildEncryptionState(a, derived.bs, nonceBytes, t)
    result.state = state
    result.kdf = derived.k

  proc deriveSymmetricKeysFromBytes*(a: cryptoWrap.AlgoType,
      ps: openArray[uint8], ns: openArray[uint8], t: uint16): DerivedEncryptionKeys =
    ## a: symmetric algorithm.
    ## ps: password bytes.
    ## ns: nonce bytes (optional).
    ## t: tag length override.
    result = deriveSymmetricKeysFromBytesWithSalt(a, ps, @[], 0'u64, 0, ns, t)

  proc deriveSymmetricKeysFromString*(a: cryptoWrap.AlgoType,
      p: string, ns: openArray[uint8], t: uint16): DerivedEncryptionKeys =
    ## a: symmetric algorithm.
    ## p: password string.
    ## ns: nonce bytes (optional).
    ## t: tag length override.
    var
      ps: seq[uint8] = @[]
    ps = stringToBytes(p)
    defer:
      zeroizeSeq(ps)
    result = deriveSymmetricKeysFromBytes(a, ps, ns, t)

  proc x25519SeedLen(): int =
    ## x25519 seed length from libsodium.
    result = int(crypto_kx_seedbytes())

  proc deriveKexSeedFromBytesWithSalt(ps, ss: openArray[uint8],
      cs: string, ol: culonglong, ml: csize_t): DerivedKexSeed =
    ## ps: password bytes.
    ## ss: salt bytes.
    ## cs: context string for KEX domain separation.
    ## ol: ops limit for Argon2id.
    ## ml: memory limit for Argon2id.
    var
      seedLen: int = 0
      derived: tuple[bs: seq[uint8], k: ArgonKdfParams]
    seedLen = x25519SeedLen()
    derived = deriveArgonBytes(ps, cs, ss, ol, ml, seedLen)
    result.x25519Seed = derived.bs
    result.kdf = derived.k

  proc deriveHybridKexDuoSeedFromBytesWithSalt*(ps, ss: openArray[uint8],
      ol: culonglong, ml: csize_t): DerivedKexSeed =
    ## ps: password bytes.
    ## ss: salt bytes.
    ## ol: ops limit for Argon2id.
    ## ml: memory limit for Argon2id.
    result = deriveKexSeedFromBytesWithSalt(ps, ss, kdfContextKexDuo, ol, ml)

  proc deriveHybridKexTripleSeedFromBytesWithSalt*(ps, ss: openArray[uint8],
      ol: culonglong, ml: csize_t): DerivedKexSeed =
    ## ps: password bytes.
    ## ss: salt bytes.
    ## ol: ops limit for Argon2id.
    ## ml: memory limit for Argon2id.
    result = deriveKexSeedFromBytesWithSalt(ps, ss, kdfContextKexTriple, ol, ml)

  proc deriveHybridKexDuoSeedFromBytes*(ps: openArray[uint8]): DerivedKexSeed =
    ## ps: password bytes.
    result = deriveHybridKexDuoSeedFromBytesWithSalt(ps, @[], 0'u64, 0)

  proc deriveHybridKexTripleSeedFromBytes*(ps: openArray[uint8]): DerivedKexSeed =
    ## ps: password bytes.
    result = deriveHybridKexTripleSeedFromBytesWithSalt(ps, @[], 0'u64, 0)

  proc deriveHybridKexDuoSeedFromString*(p: string): DerivedKexSeed =
    ## p: password string.
    var
      ps: seq[uint8] = @[]
    ps = stringToBytes(p)
    defer:
      zeroizeSeq(ps)
    result = deriveHybridKexDuoSeedFromBytes(ps)

  proc deriveHybridKexTripleSeedFromString*(p: string): DerivedKexSeed =
    ## p: password string.
    var
      ps: seq[uint8] = @[]
    ps = stringToBytes(p)
    defer:
      zeroizeSeq(ps)
    result = deriveHybridKexTripleSeedFromBytes(ps)

  proc derivePasswordPinSecretFromBytesWithSalt*(ps, pins, ss: openArray[uint8],
      cs: string = kdfContextPasswordPinSecret, ol: culonglong = 0'u64,
      ml: csize_t = 0, l: int = derivedSecretLenDefault): DerivedSecretBytes =
    var
      joint: seq[uint8] = @[]
      derived: tuple[bs: seq[uint8], k: ArgonKdfParams]
    joint = buildPasswordPinInput(ps, pins)
    defer:
      zeroizeSeq(joint)
    derived = deriveArgonBytes(joint, cs, ss, ol, ml, l)
    result.bytes = derived.bs
    result.kdf = derived.k

  proc derivePasswordPinSecretFromStringWithSalt*(p: string, pin: string,
      ss: openArray[uint8], cs: string = kdfContextPasswordPinSecret,
      ol: culonglong = 0'u64, ml: csize_t = 0,
      l: int = derivedSecretLenDefault): DerivedSecretBytes =
    var
      ps: seq[uint8] = @[]
      pins: seq[uint8] = @[]
    ps = stringToBytes(p)
    pins = stringToBytes(pin)
    defer:
      zeroizeSeq(ps)
      zeroizeSeq(pins)
    result = derivePasswordPinSecretFromBytesWithSalt(ps, pins, ss, cs, ol, ml, l)

  proc derivePatternBytesFromPasswordPinWithSalt*(p: string, pin: string,
      ss: openArray[uint8], l: int = 16): DerivedSecretBytes =
    result = derivePasswordPinSecretFromStringWithSalt(p, pin, ss,
      kdfContextPatternFragment, 0'u64, 0, l)

  proc initSecretFromBytes*(input: openArray[uint8]): Secret =
    result.data = copyBytes(input)

  proc initSecretFromString*(input: string): Secret =
    result.data = stringToBytes(input)

  proc wipeSecret*(secret: var Secret) =
    secureZeroizeSeq(secret.data)

  proc withSecret*[T](secret: var Secret, body: proc (data: openArray[uint8]): T): T =
    if secret.data.len == 0:
      raise newException(ValueError, "secret is empty")
    defer:
      wipeSecret(secret)
    result = body(secret.data)

  proc setSecret*(key: var Key, secret: Secret) =
    key.secret = secret

  proc setSecretFromBytes*(key: var Key, input: openArray[uint8]) =
    key.secret = initSecretFromBytes(input)

  proc setSecretFromString*(key: var Key, input: string) =
    key.secret = initSecretFromString(input)

  proc clearSecret*(key: var Key) =
    wipeSecret(key.secret)

  proc randomBytes(len: int): seq[uint8] =
    result = urandom(len)

  proc derivePinKdfLegacy(pin: openArray[uint8], salt: openArray[uint8]): seq[uint8] =
    if salt.len != pinSaltLen:
      raise newException(ValueError, "pin salt must be 16 bytes")
    let base = blake3Hash(pin)
    var nonce: array[pinSaltLen, byte]
    for i in 0 ..< nonce.len:
      nonce[i] = salt[i]
    let derived = hchacha20(base, nonce)
    result = newSeq[uint8](derived.len)
    for i, b in derived:
      result[i] = b

  proc derivePinKdfBytes(pin: openArray[uint8], salt: openArray[uint8],
      opsLimit: culonglong, memLimit: csize_t): seq[uint8] =
    var
      derived: tuple[bs: seq[uint8], k: ArgonKdfParams]
    if salt.len != pinSaltLen:
      raise newException(ValueError, "pin salt must be 16 bytes")
    derived = deriveArgonBytes(pin, kdfContextPinWrap, salt, opsLimit, memLimit,
      masterKeyLen)
    result = derived.bs

  proc derivePinKdfBytes(pin: openArray[uint8], salt: openArray[uint8]): seq[uint8] =
    result = derivePinKdfBytes(pin, salt, resolvePinOps(0'u64), resolvePinMem(0))

  proc ensurePinKdfParams(key: var Key) =
    if key.pinOpsLimit == 0'u64:
      key.pinOpsLimit = resolvePinOps(0'u64)
    if key.pinMemLimit == 0:
      key.pinMemLimit = resolvePinMem(0)

  proc derivePinKdfForKey(key: Key, pin: openArray[uint8]): seq[uint8] =
    if key.pinOpsLimit == 0'u64 and key.pinMemLimit == 0:
      result = derivePinKdfLegacy(pin, key.pinSalt)
    else:
      result = derivePinKdfBytes(pin, key.pinSalt, resolvePinOps(key.pinOpsLimit),
        resolvePinMem(key.pinMemLimit))

  proc derivePinKdf*(pin: string, salt: openArray[uint8]): seq[uint8] =
    var pinBytes = stringToBytes(pin)
    defer:
      zeroizeSeq(pinBytes)
    derivePinKdfBytes(pinBytes, salt)

  proc setPinKdfBytes*(key: var Key, pin: openArray[uint8]) =
    if key.pinSalt.len == 0:
      raise newException(ValueError, "pin salt missing")
    if key.pinKdf.len > 0:
      zeroizeSeq(key.pinKdf)
    key.pinKdf = derivePinKdfForKey(key, pin)

  proc setPinKdf*(key: var Key, pin: string) =
    var pinBytes = stringToBytes(pin)
    defer:
      zeroizeSeq(pinBytes)
    setPinKdfBytes(key, pinBytes)

  proc aeadEncrypt(key, nonce, plaintext: openArray[uint8]): seq[uint8] =
    if key.len != int(crypto_aead_xchacha20poly1305_ietf_keybytes()):
      raise newException(ValueError, "invalid xchacha20poly1305 key length")
    if nonce.len != int(crypto_aead_xchacha20poly1305_ietf_npubbytes()):
      raise newException(ValueError, "invalid xchacha20poly1305 nonce length")

    var outBuf = newSeq[uint8](plaintext.len + aeadTagLen)
    var outLen: culonglong = 0
    let status = crypto_aead_xchacha20poly1305_ietf_encrypt(
      if outBuf.len > 0: addr outBuf[0] else: nil,
      addr outLen,
      if plaintext.len > 0: unsafeAddr plaintext[0] else: nil,
      culonglong(plaintext.len),
      nil,
      0,
      nil,
      if nonce.len > 0: unsafeAddr nonce[0] else: nil,
      if key.len > 0: unsafeAddr key[0] else: nil
    )
    if status != 0:
      raiseOperation("libsodium", "xchacha20poly1305 encryption failed")
    outBuf.setLen(int(outLen))
    outBuf

  proc aeadDecrypt(key, nonce, ciphertext: openArray[uint8]): seq[uint8] =
    if key.len != int(crypto_aead_xchacha20poly1305_ietf_keybytes()):
      raise newException(ValueError, "invalid xchacha20poly1305 key length")
    if nonce.len != int(crypto_aead_xchacha20poly1305_ietf_npubbytes()):
      raise newException(ValueError, "invalid xchacha20poly1305 nonce length")
    if ciphertext.len < aeadTagLen:
      raise newException(ValueError, "invalid xchacha20poly1305 ciphertext length")

    let plainLen = ciphertext.len - aeadTagLen
    var outBuf = newSeq[uint8](plainLen)
    var outLen: culonglong = 0
    let status = crypto_aead_xchacha20poly1305_ietf_decrypt(
      if outBuf.len > 0: addr outBuf[0] else: nil,
      addr outLen,
      nil,
      if ciphertext.len > 0: unsafeAddr ciphertext[0] else: nil,
      culonglong(ciphertext.len),
      nil,
      0,
      if nonce.len > 0: unsafeAddr nonce[0] else: nil,
      if key.len > 0: unsafeAddr key[0] else: nil
    )
    if status != 0:
      raiseOperation("libsodium", "xchacha20poly1305 decryption failed")
    outBuf.setLen(int(outLen))
    outBuf

  proc passPtr(pass: openArray[uint8]): cstring =
    if pass.len == 0:
      return cast[cstring](nil)
    cast[cstring](unsafeAddr pass[0])

  proc deriveMasterKeyFromBytes(password: openArray[uint8]): tuple[key: Key, masterKey: seq[uint8]] =
    ensureSodiumInitialised()
    let opsLimit = crypto_pwhash_opslimit_moderate()
    let memLimit = crypto_pwhash_memlimit_moderate()
    let saltLen = int(crypto_pwhash_saltbytes())
    var argon2Salt = randomBytes(saltLen)

    var masterKey = newSeq[uint8](masterKeyLen)
    let status = crypto_pwhash(
      if masterKey.len > 0: addr masterKey[0] else: nil,
      culonglong(masterKey.len),
      passPtr(password),
      culonglong(password.len),
      if argon2Salt.len > 0: addr argon2Salt[0] else: nil,
      opsLimit,
      memLimit,
      crypto_pwhash_alg_argon2id13()
    )
    if status != 0:
      raiseOperation("libsodium", "argon2id key derivation failed")

    var key: Key
    key.argon2Salt = argon2Salt
    key.argon2OpsLimit = opsLimit
    key.argon2MemLimit = memLimit
    key.pinSalt = randomBytes(pinSaltLen)
    key.pinOpsLimit = resolvePinOps(0'u64)
    key.pinMemLimit = resolvePinMem(0)
    (key: key, masterKey: masterKey)

  proc deriveMasterKey*(password: string): tuple[key: Key, masterKey: seq[uint8]] =
    var passwordBytes = stringToBytes(password)
    defer:
      zeroizeSeq(passwordBytes)
    deriveMasterKeyFromBytes(passwordBytes)

  proc wrapMasterKeyWithPinBytes*(key: var Key, masterKey: openArray[uint8], pin: openArray[uint8]) =
    ensureSodiumInitialised()
    if masterKey.len != masterKeyLen:
      raise newException(ValueError, "invalid master key length")
    if key.pinSalt.len == 0:
      key.pinSalt = randomBytes(pinSaltLen)
    ensurePinKdfParams(key)
    if key.pinKdf.len > 0:
      zeroizeSeq(key.pinKdf)
    key.pinKdf = derivePinKdfBytes(pin, key.pinSalt, key.pinOpsLimit,
      key.pinMemLimit)
    defer:
      zeroizeSeq(key.pinKdf)
    key.masterKeyNonce = randomBytes(int(crypto_aead_xchacha20poly1305_ietf_npubbytes()))
    key.encryptedMasterKey = aeadEncrypt(key.pinKdf, key.masterKeyNonce, masterKey)

  proc wrapMasterKeyWithPin*(key: var Key, masterKey: openArray[uint8], pin: string) =
    var pinBytes = stringToBytes(pin)
    defer:
      zeroizeSeq(pinBytes)
    wrapMasterKeyWithPinBytes(key, masterKey, pinBytes)

  proc unwrapMasterKeyWithPinBytes*(key: var Key, pin: openArray[uint8]): seq[uint8] =
    ensureSodiumInitialised()
    if key.pinSalt.len == 0:
      raise newException(ValueError, "pin salt missing")
    if key.encryptedMasterKey.len == 0 or key.masterKeyNonce.len == 0:
      raise newException(ValueError, "encrypted master key missing")
    if key.pinKdf.len > 0:
      zeroizeSeq(key.pinKdf)
    key.pinKdf = derivePinKdfForKey(key, pin)
    defer:
      zeroizeSeq(key.pinKdf)
    try:
      result = aeadDecrypt(key.pinKdf, key.masterKeyNonce, key.encryptedMasterKey)
    except CryptoOperationError:
      if key.pinOpsLimit != 0'u64 or key.pinMemLimit != 0:
        raise
      zeroizeSeq(key.pinKdf)
      key.pinKdf = derivePinKdfBytes(pin, key.pinSalt, resolvePinOps(0'u64),
        resolvePinMem(0))
      result = aeadDecrypt(key.pinKdf, key.masterKeyNonce, key.encryptedMasterKey)
      key.pinOpsLimit = resolvePinOps(0'u64)
      key.pinMemLimit = resolvePinMem(0)
    if result.len != masterKeyLen:
      raise newException(ValueError, "invalid master key length")

  proc unwrapMasterKeyWithPin*(key: var Key, pin: string): seq[uint8] =
    var pinBytes = stringToBytes(pin)
    defer:
      zeroizeSeq(pinBytes)
    unwrapMasterKeyWithPinBytes(key, pinBytes)

  proc withSecret*(key: var Key, op: SecretOp): seq[uint8] =
    if key.secret.data.len == 0:
      raise newException(ValueError, "secret missing")
    withSecret(key.secret, proc (data: openArray[uint8]): seq[uint8] =
      case op:
      of soDeriveMasterKey:
        let derived = deriveMasterKeyFromBytes(data)
        key.argon2Salt = derived.key.argon2Salt
        key.argon2OpsLimit = derived.key.argon2OpsLimit
        key.argon2MemLimit = derived.key.argon2MemLimit
        key.pinSalt = derived.key.pinSalt
        key.pinOpsLimit = derived.key.pinOpsLimit
        key.pinMemLimit = derived.key.pinMemLimit
        derived.masterKey
      of soUnwrapMasterKey:
        unwrapMasterKeyWithPinBytes(key, data)
    )

  proc encryptWithMasterKey*(masterKey, plaintext: openArray[uint8]): EncryptedCiphertext =
    ensureSodiumInitialised()
    if masterKey.len != masterKeyLen:
      raise newException(ValueError, "invalid master key length")

    var nonce = randomBytes(int(crypto_aead_xchacha20poly1305_ietf_npubbytes()))
    let sealed = aeadEncrypt(masterKey, nonce, plaintext)
    if sealed.len < aeadTagLen:
      raise newException(ValueError, "invalid ciphertext output")
    let tagStart = sealed.len - aeadTagLen
    result.nonce = nonce
    result.ciphertext = sealed[0 ..< tagStart]
    result.hmac = sealed[tagStart ..< sealed.len]

  proc decryptWithMasterKey*(masterKey: openArray[uint8], cipher: EncryptedCiphertext): seq[uint8] =
    ensureSodiumInitialised()
    if masterKey.len != masterKeyLen:
      raise newException(ValueError, "invalid master key length")
    if cipher.nonce.len != int(crypto_aead_xchacha20poly1305_ietf_npubbytes()):
      raise newException(ValueError, "invalid xchacha20poly1305 nonce length")
    if cipher.hmac.len != aeadTagLen:
      raise newException(ValueError, "invalid xchacha20poly1305 tag length")

    var sealed = newSeq[uint8](cipher.ciphertext.len + cipher.hmac.len)
    var offset = 0
    for b in cipher.ciphertext:
      sealed[offset] = b
      inc offset
    for b in cipher.hmac:
      sealed[offset] = b
      inc offset
    aeadDecrypt(masterKey, cipher.nonce, sealed)

  proc deriveKeyFromPasswordBytes(password: openArray[uint8], pin: openArray[uint8]): Key =
    var derived = deriveMasterKeyFromBytes(password)
    var key = derived.key
    var masterKey = derived.masterKey
    key.pinKdf = derivePinKdfBytes(pin, key.pinSalt, key.pinOpsLimit,
      key.pinMemLimit)
    key.masterKeyNonce = randomBytes(int(crypto_aead_xchacha20poly1305_ietf_npubbytes()))
    key.encryptedMasterKey = aeadEncrypt(key.pinKdf, key.masterKeyNonce, masterKey)
    zeroizeSeq(masterKey)
    key

  proc deriveKeyFromPassword*(password: string, pin: string): Key =
    var passwordBytes = stringToBytes(password)
    var pinBytes = stringToBytes(pin)
    defer:
      zeroizeSeq(passwordBytes)
      zeroizeSeq(pinBytes)
    deriveKeyFromPasswordBytes(passwordBytes, pinBytes)

  proc unwrapMasterKey(key: var Key): seq[uint8] =
    if key.pinKdf.len == 0:
      raise newException(ValueError, "pin KDF missing")
    if key.encryptedMasterKey.len == 0 or key.masterKeyNonce.len == 0:
      raise newException(ValueError, "encrypted master key missing")
    result = aeadDecrypt(key.pinKdf, key.masterKeyNonce, key.encryptedMasterKey)
    if result.len != masterKeyLen:
      raise newException(ValueError, "invalid master key length")

  proc encryptWithKey*(key: var Key, plaintext: seq[uint8]): EncryptedCiphertext =
    ensureSodiumInitialised()
    if key.pinKdf.len == 0:
      raise newException(ValueError, "pin KDF missing")

    defer:
      zeroizeSeq(key.pinKdf)

    var masterKey = unwrapMasterKey(key)
    defer:
      zeroizeSeq(masterKey)

    var nonce = randomBytes(int(crypto_aead_xchacha20poly1305_ietf_npubbytes()))
    let sealed = aeadEncrypt(masterKey, nonce, plaintext)
    if sealed.len < aeadTagLen:
      raise newException(ValueError, "invalid ciphertext output")
    let tagStart = sealed.len - aeadTagLen
    result.nonce = nonce
    result.ciphertext = sealed[0 ..< tagStart]
    result.hmac = sealed[tagStart ..< sealed.len]

else:
  proc derivePasswordPinSecretFromBytesWithSalt*(ps, pins, ss: openArray[uint8],
      cs: string = kdfContextPasswordPinSecret, ol: culonglong = 0'u64,
      ml: csize_t = 0, l: int = derivedSecretLenDefault): DerivedSecretBytes =
    var
      joint: seq[uint8] = @[]
      buf: seq[uint8] = @[]
    joint = buildPasswordPinInput(ps, pins)
    defer:
      zeroizeCompat(joint)
      zeroizeCompat(buf)
    buf = stringToBytes(cs)
    appendUint32Le(buf, uint32(ss.len))
    buf.add(ss)
    appendUint32Le(buf, uint32(joint.len))
    buf.add(joint)
    result.bytes = blake3Hash(buf, l)
    result.kdf.argon2Salt = copyBytes(ss)
    result.kdf.argon2OpsLimit = ol
    result.kdf.argon2MemLimit = ml

  proc derivePasswordPinSecretFromStringWithSalt*(p: string, pin: string,
      ss: openArray[uint8], cs: string = kdfContextPasswordPinSecret,
      ol: culonglong = 0'u64, ml: csize_t = 0,
      l: int = derivedSecretLenDefault): DerivedSecretBytes =
    var
      ps: seq[uint8] = @[]
      pins: seq[uint8] = @[]
    ps = stringToBytes(p)
    pins = stringToBytes(pin)
    defer:
      zeroizeCompat(ps)
      zeroizeCompat(pins)
    result = derivePasswordPinSecretFromBytesWithSalt(ps, pins, ss, cs, ol, ml, l)

  proc derivePatternBytesFromPasswordPinWithSalt*(p: string, pin: string,
      ss: openArray[uint8], l: int = 16): DerivedSecretBytes =
    result = derivePasswordPinSecretFromStringWithSalt(p, pin, ss,
      kdfContextPatternFragment, 0'u64, 0, l)

  proc initSecretFromBytes*(input: openArray[uint8]): Secret =
    raiseUnavailable("libsodium", "hasLibsodium")
    Secret()

  proc initSecretFromString*(input: string): Secret =
    raiseUnavailable("libsodium", "hasLibsodium")
    Secret()

  proc wipeSecret*(secret: var Secret) =
    raiseUnavailable("libsodium", "hasLibsodium")

  proc withSecret*[T](secret: var Secret, body: proc (data: openArray[uint8]): T): T =
    raiseUnavailable("libsodium", "hasLibsodium")

  proc setSecret*(key: var Key, secret: Secret) =
    raiseUnavailable("libsodium", "hasLibsodium")

  proc setSecretFromBytes*(key: var Key, input: openArray[uint8]) =
    raiseUnavailable("libsodium", "hasLibsodium")

  proc setSecretFromString*(key: var Key, input: string) =
    raiseUnavailable("libsodium", "hasLibsodium")

  proc clearSecret*(key: var Key) =
    raiseUnavailable("libsodium", "hasLibsodium")

  proc withSecret*(key: var Key, op: SecretOp): seq[uint8] =
    raiseUnavailable("libsodium", "hasLibsodium")
    @[]

  proc deriveMasterKey*(password: string): tuple[key: Key, masterKey: seq[uint8]] =
    raiseUnavailable("libsodium", "hasLibsodium")
    (key: Key(), masterKey: @[])

  proc wrapMasterKeyWithPinBytes*(key: var Key, masterKey: openArray[uint8], pin: openArray[uint8]) =
    raiseUnavailable("libsodium", "hasLibsodium")

  proc wrapMasterKeyWithPin*(key: var Key, masterKey: openArray[uint8], pin: string) =
    raiseUnavailable("libsodium", "hasLibsodium")

  proc unwrapMasterKeyWithPinBytes*(key: var Key, pin: openArray[uint8]): seq[uint8] =
    raiseUnavailable("libsodium", "hasLibsodium")
    @[]

  proc unwrapMasterKeyWithPin*(key: var Key, pin: string): seq[uint8] =
    raiseUnavailable("libsodium", "hasLibsodium")
    @[]

  proc encryptWithMasterKey*(masterKey, plaintext: openArray[uint8]): EncryptedCiphertext =
    raiseUnavailable("libsodium", "hasLibsodium")
    EncryptedCiphertext()

  proc decryptWithMasterKey*(masterKey: openArray[uint8], cipher: EncryptedCiphertext): seq[uint8] =
    raiseUnavailable("libsodium", "hasLibsodium")
    @[]

  proc derivePinKdf*(pin: string, salt: openArray[uint8]): seq[uint8] =
    raiseUnavailable("libsodium", "hasLibsodium")
    @[]

  proc setPinKdfBytes*(key: var Key, pin: openArray[uint8]) =
    raiseUnavailable("libsodium", "hasLibsodium")

  proc setPinKdf*(key: var Key, pin: string) =
    raiseUnavailable("libsodium", "hasLibsodium")

  proc deriveKeyFromPassword*(password: string, pin: string): Key =
    raiseUnavailable("libsodium", "hasLibsodium")
    Key()

  proc encryptWithKey*(key: var Key, plaintext: seq[uint8]): EncryptedCiphertext =
    raiseUnavailable("libsodium", "hasLibsodium")
    EncryptedCiphertext()

  proc deriveSymmetricKeysFromBytesWithSalt*(a: cryptoWrap.AlgoType,
      ps, ss: openArray[uint8], ol: culonglong, ml: csize_t,
      ns: openArray[uint8], t: uint16): DerivedEncryptionKeys =
    raiseUnavailable("libsodium", "hasLibsodium")
    DerivedEncryptionKeys()

  proc deriveSymmetricKeysFromBytes*(a: cryptoWrap.AlgoType,
      ps: openArray[uint8], ns: openArray[uint8], t: uint16): DerivedEncryptionKeys =
    raiseUnavailable("libsodium", "hasLibsodium")
    DerivedEncryptionKeys()

  proc deriveSymmetricKeysFromString*(a: cryptoWrap.AlgoType,
      p: string, ns: openArray[uint8], t: uint16): DerivedEncryptionKeys =
    raiseUnavailable("libsodium", "hasLibsodium")
    DerivedEncryptionKeys()

  proc deriveHybridKexDuoSeedFromBytesWithSalt*(ps, ss: openArray[uint8],
      ol: culonglong, ml: csize_t): DerivedKexSeed =
    raiseUnavailable("libsodium", "hasLibsodium")
    DerivedKexSeed()

  proc deriveHybridKexTripleSeedFromBytesWithSalt*(ps, ss: openArray[uint8],
      ol: culonglong, ml: csize_t): DerivedKexSeed =
    raiseUnavailable("libsodium", "hasLibsodium")
    DerivedKexSeed()

  proc deriveHybridKexDuoSeedFromBytes*(ps: openArray[uint8]): DerivedKexSeed =
    raiseUnavailable("libsodium", "hasLibsodium")
    DerivedKexSeed()

  proc deriveHybridKexTripleSeedFromBytes*(ps: openArray[uint8]): DerivedKexSeed =
    raiseUnavailable("libsodium", "hasLibsodium")
    DerivedKexSeed()

  proc deriveHybridKexDuoSeedFromString*(p: string): DerivedKexSeed =
    raiseUnavailable("libsodium", "hasLibsodium")
    DerivedKexSeed()

  proc deriveHybridKexTripleSeedFromString*(p: string): DerivedKexSeed =
    raiseUnavailable("libsodium", "hasLibsodium")
    DerivedKexSeed()
