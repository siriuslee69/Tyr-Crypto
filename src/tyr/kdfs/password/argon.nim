## -----------------------------------------------------------
## Password KDF, Argon2id part <- password -> keys (libsodium)
## -----------------------------------------------------------
##
##   password --BLAKE3(label | password)--> Argon2id(salt, ops, mem) --> bytes
##
##   deriveSymmetricKeys*        bytes split into 32-byte cipher keys + nonce
##   deriveHybridKex*Seed*       bytes = one X25519 seed (duo / triple label)
##   derivePasswordPinSecret*    password and PIN joined first, then as above
##
## An empty salt means "make a fresh random one"; it is handed back in
## `kdf` so the same keys can be derived again later. ops/mem = 0 means
## libsodium's "moderate" cost.

import std/sysrand
import ../../helpers/errors
import ../../aeads/types
import ../../aeads as cryptoApi
import ../../bindings/libsodium
import ../../hashes/blake3
import ./common
import runePragmas

const
  kdfContextChacha20 = "sym-chacha20-v1"
  kdfContextXChaGimli = "sym-xchacha20-gimli-v1"
  kdfContextAesGimli = "sym-aes-gimli-v1"
  kdfContextXChaAesGimli = "sym-xchacha20-aes-gimli-v1"
  kdfContextXChaAesGimliPoly1305 = "sym-xchacha20-aes-gimli-poly1305-v1"  # otter:allow
  kdfContextAes256 = "sym-aes256-v1"
  kdfContextKexDuo = "kex-duo-x25519-seed-v1"
  kdfContextKexTriple = "kex-triple-x25519-seed-v1"

proc randomBytes*(l: int): seq[uint8] {.role: {dataFetcher}.} =
  ## l: length. Returns bytes from the operating system's random source.
  result = urandom(l)

proc passPtr*(pass: openArray[uint8]): cstring {.role: {helper}.} =
  ## pass: bytes handed to libsodium as a C pointer (nil when empty).
  if pass.len == 0:
    return cast[cstring](nil)
  cast[cstring](unsafeAddr pass[0])

proc algoContext(a: CipherSuite): string {.role: {parser}.} =
  ## a: cipher suite. Returns its derivation label.
  case a
  of csXChaCha20Blake3:
    result = kdfContextChacha20
  of csXChaCha20Gimli:
    result = kdfContextXChaGimli
  of csAesGimli:
    result = kdfContextAesGimli
  of csXChaCha20AesGimli:
    result = kdfContextXChaAesGimli
  of csXChaCha20AesGimliPoly1305:
    result = kdfContextXChaAesGimliPoly1305
  of csAes256Gcm:
    result = kdfContextAes256

proc resolveOps*(ol: culonglong): culonglong {.role: {parser}.} =
  ## ol: requested Argon2id ops limit; 0 picks libsodium's moderate one.
  result = (if ol == 0'u64: crypto_pwhash_opslimit_moderate() else: ol)

proc resolveMem*(ml: csize_t): csize_t {.role: {parser}.} =
  ## ml: requested Argon2id memory limit; 0 picks libsodium's moderate one.
  result = (if ml == 0: crypto_pwhash_memlimit_moderate() else: ml)

proc buildArgonSalt(ss: openArray[uint8]): seq[uint8] {.role: {parser}.} =
  ## ss: salt to use, or empty for a fresh random one.
  var
    l: int = int(crypto_pwhash_saltbytes())
  if ss.len == 0:
    return randomBytes(l)
  if ss.len != l:
    raise newException(ValueError, "argon2 salt length mismatch")
  result = copyBytes(ss)

proc buildArgonInput(ps: openArray[uint8], cs: string): seq[uint8] {.role: {helper}.} =
  ## ps: password. cs: label. Returns BLAKE3(label | password).
  var
    buf: seq[uint8] = stringToBytes(cs)
  defer:
    wipeBytes(buf)
  buf.add(ps)
  result = blake3Hash(buf)

proc deriveArgonBytes*(ps: openArray[uint8], cs: string, ss: openArray[uint8],
    ol: culonglong, ml: csize_t, l: int): tuple[bs: seq[uint8], k: ArgonKdfParams] {.role: {math}.} =
  ## ps: password. cs: label. ss: salt (empty = random). ol/ml: Argon2id
  ## costs (0 = moderate). l: output length. Returns the bytes and the
  ## parameters needed to derive them again.
  ## Argon2id gives at least 16 bytes; a shorter l takes the first l of those.
  var
    salt: seq[uint8] = @[]
    opsLimit: culonglong = 0
    memLimit: csize_t = 0
    passBuf: seq[uint8] = @[]
    outBuf: seq[uint8] = @[]
    status: cint = 0
  ensureSodiumInitialised()
  if l <= 0:
    raise newException(ValueError, "argon2 output length must be positive")
  defer:
    wipeBytes(passBuf)
  salt = buildArgonSalt(ss)
  opsLimit = resolveOps(ol)
  memLimit = resolveMem(ml)
  passBuf = buildArgonInput(ps, cs)
  outBuf.setLen(max(l, int(crypto_pwhash_bytes_min())))
  status = crypto_pwhash(
    addr outBuf[0],
    culonglong(outBuf.len),
    passPtr(passBuf),
    culonglong(passBuf.len),
    if salt.len > 0: addr salt[0] else: nil,
    opsLimit,
    memLimit,
    crypto_pwhash_alg_argon2id13()
  )
  if status != 0:
    raiseOperation("libsodium", "argon2id key derivation failed")
  result.bs = outBuf[0 ..< l]
  wipeBytes(outBuf)
  result.k = ArgonKdfParams(argon2Salt: salt, argon2OpsLimit: opsLimit,
    argon2MemLimit: memLimit)

proc splitSymmetricKeys(ms: seq[uint8], c: int): seq[seq[uint8]] {.role: {helper}.} =
  ## ms: key material. Returns it cut into c keys of 32 bytes.
  var
    i: int = 0
  result = newSeq[seq[uint8]](max(c, 0))
  while i < c:
    result[i] = ms[i * 32 ..< i * 32 + 32]
    i = i + 1

proc resolveNonce(a: CipherSuite, ns: openArray[uint8]): seq[uint8] {.role: {parser}.} =
  ## ns: nonce to use, or empty for a fresh random one of the suite's size.
  var
    l: int = cryptoApi.nonceBytes(a)
  if ns.len == 0:
    return randomBytes(l)
  if ns.len != l:
    raise newException(ValueError, "nonce length mismatch")
  result = copyBytes(ns)

proc deriveSymmetricKeysFromBytesWithSalt*(a: CipherSuite,
    ps, ss: openArray[uint8], ol: culonglong, ml: csize_t,
    ns: openArray[uint8], t: uint16): DerivedEncryptionKeys {.role: {orchestrator}.} =
  ## a: cipher suite. ps: password. ss: salt (empty = random). ol/ml:
  ## Argon2id costs. ns: nonce (empty = random). t: tag length (0 = default).
  var
    count: int = cryptoApi.keyCount(a)
    derived: tuple[bs: seq[uint8], k: ArgonKdfParams] = (@[], ArgonKdfParams())
  defer:
    wipeBytes(derived.bs)
  derived = deriveArgonBytes(ps, algoContext(a), ss, ol, ml, count * 32)
  result.state = cryptoApi.initAeadState(a, splitSymmetricKeys(derived.bs, count),
    resolveNonce(a, ns), t)
  result.kdf = derived.k

proc deriveSymmetricKeysFromBytes*(a: CipherSuite,
    ps: openArray[uint8], ns: openArray[uint8], t: uint16): DerivedEncryptionKeys {.role: {orchestrator}.} =
  ## Same as deriveSymmetricKeysFromBytesWithSalt with a fresh salt and
  ## moderate costs.
  result = deriveSymmetricKeysFromBytesWithSalt(a, ps, @[], 0'u64, 0, ns, t)

proc deriveSymmetricKeysFromString*(a: CipherSuite,
    p: string, ns: openArray[uint8], t: uint16): DerivedEncryptionKeys {.role: {orchestrator}.} =
  ## p: password text; its byte copy is wiped afterwards.
  var
    ps: seq[uint8] = stringToBytes(p)
  defer:
    wipeBytes(ps)
  result = deriveSymmetricKeysFromBytes(a, ps, ns, t)

proc deriveKexSeedFromBytesWithSalt(ps, ss: openArray[uint8],
    cs: string, ol: culonglong, ml: csize_t): DerivedKexSeed {.role: {orchestrator}.} =
  ## ps: password. cs: duo or triple label. Returns one X25519 seed.
  var
    derived: tuple[bs: seq[uint8], k: ArgonKdfParams] =
      deriveArgonBytes(ps, cs, ss, ol, ml, int(crypto_kx_seedbytes()))
  result.x25519Seed = derived.bs
  result.kdf = derived.k

proc deriveHybridKexDuoSeedFromBytesWithSalt*(ps, ss: openArray[uint8],
    ol: culonglong, ml: csize_t): DerivedKexSeed {.role: {orchestrator}.} =
  ## ps: password. ss: salt (empty = random). ol/ml: Argon2id costs.
  result = deriveKexSeedFromBytesWithSalt(ps, ss, kdfContextKexDuo, ol, ml)

proc deriveHybridKexTripleSeedFromBytesWithSalt*(ps, ss: openArray[uint8],
    ol: culonglong, ml: csize_t): DerivedKexSeed {.role: {orchestrator}.} =
  ## ps: password. ss: salt (empty = random). ol/ml: Argon2id costs.
  result = deriveKexSeedFromBytesWithSalt(ps, ss, kdfContextKexTriple, ol, ml)

proc deriveHybridKexDuoSeedFromBytes*(ps: openArray[uint8]): DerivedKexSeed {.role: {orchestrator}.} =
  ## ps: password; fresh salt, moderate costs.
  result = deriveHybridKexDuoSeedFromBytesWithSalt(ps, @[], 0'u64, 0)

proc deriveHybridKexTripleSeedFromBytes*(ps: openArray[uint8]): DerivedKexSeed {.role: {orchestrator}.} =
  ## ps: password; fresh salt, moderate costs.
  result = deriveHybridKexTripleSeedFromBytesWithSalt(ps, @[], 0'u64, 0)

proc deriveHybridKexDuoSeedFromString*(p: string): DerivedKexSeed {.role: {orchestrator}.} =
  ## p: password text; its byte copy is wiped afterwards.
  var
    ps: seq[uint8] = stringToBytes(p)
  defer:
    wipeBytes(ps)
  result = deriveHybridKexDuoSeedFromBytes(ps)

proc deriveHybridKexTripleSeedFromString*(p: string): DerivedKexSeed {.role: {orchestrator}.} =
  ## p: password text; its byte copy is wiped afterwards.
  var
    ps: seq[uint8] = stringToBytes(p)
  defer:
    wipeBytes(ps)
  result = deriveHybridKexTripleSeedFromBytes(ps)

proc derivePasswordPinSecretFromBytesWithSalt*(ps, pins, ss: openArray[uint8],
    cs: string = kdfContextPasswordPin, ol: culonglong = 0'u64,
    ml: csize_t = 0, l: int = derivedSecretLenDefault): DerivedSecretBytes {.role: {orchestrator}.} =
  ## ps/pins: password and PIN, joined before Argon2id. cs: label.
  ## l: output length.
  var
    joint: seq[uint8] = buildPasswordPinInput(ps, pins)
    derived: tuple[bs: seq[uint8], k: ArgonKdfParams] = (@[], ArgonKdfParams())
  defer:
    wipeBytes(joint)
  derived = deriveArgonBytes(joint, cs, ss, ol, ml, l)
  result.bytes = derived.bs
  result.kdf = derived.k

proc derivePasswordPinSecretFromStringWithSalt*(p: string, pin: string,
    ss: openArray[uint8], cs: string = kdfContextPasswordPin,
    ol: culonglong = 0'u64, ml: csize_t = 0,
    l: int = derivedSecretLenDefault): DerivedSecretBytes {.role: {orchestrator}.} =
  ## p/pin: password and PIN text; their byte copies are wiped afterwards.
  var
    ps: seq[uint8] = stringToBytes(p)
    pins: seq[uint8] = stringToBytes(pin)
  defer:
    wipeBytes(ps)
    wipeBytes(pins)
  result = derivePasswordPinSecretFromBytesWithSalt(ps, pins, ss, cs, ol, ml, l)

proc derivePatternBytesFromPasswordPinWithSalt*(p: string, pin: string,
    ss: openArray[uint8], l: int = 16): DerivedSecretBytes {.role: {orchestrator}.} =
  ## p/pin: password and PIN text. Returns l bytes under the pattern label.
  result = derivePasswordPinSecretFromStringWithSalt(p, pin, ss,
    kdfContextPatternFragment, 0'u64, 0, l)
