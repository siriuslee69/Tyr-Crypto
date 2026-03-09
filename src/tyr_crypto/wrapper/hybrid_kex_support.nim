import std/[locks, monotimes, os, times]
import ../common
import ../algorithms
import ../bindings/liboqs
import ../bindings/libsodium
import ../custom_crypto/blake3
import ../random

const
  x25519KeyBytes* = 32

type
  LabeledSecret* = tuple[label: string, secret: seq[uint8]]

var
  oqsEntropyLock: Lock
  oqsEntropyExtra: seq[uint8] = @[]
  oqsEntropyCounter: uint64 = 0

discard block:
  initLock(oqsEntropyLock)
  true

proc kyberAlgId*(variant: KyberVariant): string =
  case variant
  of kvKyber768:
    oqsAlgKyber768
  of kvKyber1024:
    oqsAlgKyber1024

proc mcElieceAlgId*(variant: McElieceVariant): string =
  case variant
  of mvClassicMcEliece6688128:
    oqsAlgClassicMcEliece6688128f
  of mvClassicMcEliece6960119:
    oqsAlgClassicMcEliece6960119f
  of mvClassicMcEliece8192128:
    oqsAlgClassicMcEliece8192128f

proc requireHybridKexLibraries*() =
  if not ensureLibOqsLoaded():
    raiseUnavailable("liboqs", "hasLibOqs")
  if not ensureLibSodiumLoaded():
    raiseUnavailable("libsodium", "hasLibsodium")
  ensureSodiumInitialised()

proc toBytes*(s: string): seq[uint8] =
  result = newSeq[uint8](s.len)
  for i, ch in s:
    result[i] = uint8(ord(ch))

proc appendU32*(buf: var seq[uint8], value: uint32) =
  buf.add(uint8(value and 0xff))
  buf.add(uint8((value shr 8) and 0xff))
  buf.add(uint8((value shr 16) and 0xff))
  buf.add(uint8((value shr 24) and 0xff))

proc appendU64*(buf: var seq[uint8], value: uint64) =
  for i in 0 ..< 8:
    buf.add(uint8((value shr (i * 8)) and 0xff'u64))

proc toEntropyBytes*[T](input: openArray[T]): seq[uint8] =
  static:
    doAssert sizeof(T) == 1, "extra entropy must use a 1-byte element type"
  result = newSeq[uint8](input.len)
  for i in 0 ..< input.len:
    result[i] = cast[uint8](input[i])

proc buildOqsEntropyMaterial(extraEntropy: openArray[uint8], bytesToRead: int,
    counter: uint64): seq[uint8] =
  const oqsEntropyContext = "tyr-crypto-oqs-rng-v1"
  var localMarker: uint64 = counter xor uint64(bytesToRead)
  result = newSeqOfCap[uint8](oqsEntropyContext.len + extraEntropy.len + 64)
  result.add(toBytes(oqsEntropyContext))
  appendU64(result, uint64(bytesToRead))
  appendU64(result, counter)
  appendU64(result, uint64(getCurrentProcessId()))
  appendU64(result, uint64(getMonoTime().ticks))
  appendU64(result, uint64(getTime().toUnix))
  appendU64(result, uint64(epochTime() * 1_000_000_000.0))
  appendU64(result, uint64(cpuTime() * 1_000_000_000.0))
  appendU64(result, cast[uint64](addr localMarker))
  result.add(extraEntropy)

proc oqsHybridRandomCallback(random_array: ptr uint8,
    bytes_to_read: csize_t) {.cdecl.} =
  try:
    let counter = oqsEntropyCounter
    inc oqsEntropyCounter
    let mixMaterial = buildOqsEntropyMaterial(oqsEntropyExtra, int(bytes_to_read),
      counter)
    let randomBytes = cryptoRandomBytes(int(bytes_to_read), mixMaterial)
    if random_array != nil and randomBytes.len > 0:
      copyMem(random_array, unsafeAddr randomBytes[0], randomBytes.len)
  except CatchableError:
    quit(1)

proc withOqsHybridEntropy*[T](extraEntropy: openArray[uint8],
    body: proc (): T): T =
  acquire(oqsEntropyLock)
  oqsEntropyExtra = @extraEntropy
  oqsEntropyCounter = 0
  OQS_randombytes_custom_algorithm(oqsHybridRandomCallback)
  try:
    result = body()
  finally:
    discard OQS_randombytes_switch_algorithm(oqsRandAlgSystem.cstring)
    oqsEntropyExtra.setLen(0)
    oqsEntropyCounter = 0
    release(oqsEntropyLock)

proc combineLabeledSecrets*(context: string,
    secrets: openArray[LabeledSecret]): seq[uint8] =
  var buf: seq[uint8] = @[]
  buf.add(toBytes(context))
  for item in secrets:
    let labelBytes = toBytes(item.label)
    appendU32(buf, uint32(labelBytes.len))
    buf.add(labelBytes)
    appendU32(buf, uint32(item.secret.len))
    buf.add(item.secret)
  result = blake3Hash(buf)

when defined(hasLibOqs):
  proc newKem*(algId: string): ptr OqsKem =
    let kem = OQS_KEM_new(algId.cstring)
    if kem == nil:
      raiseOperation("liboqs", "KEM " & algId & " unavailable")
    result = kem

proc kemKeypair*(algId: string,
    extraEntropy: openArray[uint8]): tuple[pk, sk: seq[uint8]] =
  when defined(hasLibOqs):
    result = withOqsHybridEntropy(extraEntropy, proc (): tuple[pk, sk: seq[uint8]] =
      let kem = newKem(algId)
      defer:
        OQS_KEM_free(kem)
      var pk = newSeq[uint8](int kem[].length_public_key)
      var sk = newSeq[uint8](int kem[].length_secret_key)
      requireSuccess(OQS_KEM_keypair(kem, addr pk[0], addr sk[0]),
        "OQS_KEM_keypair(" & algId & ")")
      result = (pk: pk, sk: sk)
    )
  else:
    discard algId
    discard extraEntropy
    raiseUnavailable("liboqs", "hasLibOqs")
    result = (pk: @[], sk: @[])

proc kemKeypair*(algId: string): tuple[pk, sk: seq[uint8]] =
  result = kemKeypair(algId, newSeq[uint8](0))

proc kemEncaps*(algId: string,
    publicKey, extraEntropy: openArray[uint8]): tuple[ciphertext, shared: seq[uint8]] =
  when defined(hasLibOqs):
    let publicKeyBytes = @publicKey
    result = withOqsHybridEntropy(extraEntropy, proc (): tuple[ciphertext, shared: seq[uint8]] =
      let kem = newKem(algId)
      defer:
        OQS_KEM_free(kem)
      if publicKeyBytes.len != int kem[].length_public_key:
        raise newException(ValueError, "invalid " & algId & " public key length")
      var ciphertext = newSeq[uint8](int kem[].length_ciphertext)
      var shared = newSeq[uint8](int kem[].length_shared_secret)
      requireSuccess(
        OQS_KEM_encaps(
          kem,
          addr ciphertext[0],
          addr shared[0],
          if publicKeyBytes.len > 0: unsafeAddr publicKeyBytes[0] else: nil
        ),
        "OQS_KEM_encaps(" & algId & ")"
      )
      result = (ciphertext: ciphertext, shared: shared)
    )
  else:
    discard algId
    discard publicKey
    discard extraEntropy
    raiseUnavailable("liboqs", "hasLibOqs")
    result = (ciphertext: @[], shared: @[])

proc kemEncaps*(algId: string,
    publicKey: openArray[uint8]): tuple[ciphertext, shared: seq[uint8]] =
  result = kemEncaps(algId, publicKey, newSeq[uint8](0))

proc kemDecaps*(algId: string, ciphertext,
    secretKey: openArray[uint8]): seq[uint8] =
  when defined(hasLibOqs):
    let kem = newKem(algId)
    defer:
      OQS_KEM_free(kem)
    if secretKey.len != int kem[].length_secret_key:
      raise newException(ValueError, "invalid " & algId & " secret key length")
    if ciphertext.len != int kem[].length_ciphertext:
      raise newException(ValueError, "invalid " & algId & " ciphertext length")
    var shared = newSeq[uint8](int kem[].length_shared_secret)
    requireSuccess(
      OQS_KEM_decaps(
        kem,
        addr shared[0],
        if ciphertext.len > 0: unsafeAddr ciphertext[0] else: nil,
        if secretKey.len > 0: unsafeAddr secretKey[0] else: nil
      ),
      "OQS_KEM_decaps(" & algId & ")"
    )
    result = shared
  else:
    discard algId
    discard ciphertext
    discard secretKey
    raiseUnavailable("liboqs", "hasLibOqs")
    result = @[]

proc x25519Keypair*(): tuple[pk, sk: seq[uint8]] =
  var pk = newSeq[uint8](x25519KeyBytes)
  var sk = newSeq[uint8](x25519KeyBytes)
  if crypto_kx_keypair(addr pk[0], addr sk[0]) != 0:
    raiseOperation("libsodium", "crypto_kx_keypair failed")
  result = (pk: pk, sk: sk)

proc x25519SeedLen*(): int =
  let l = int(crypto_kx_seedbytes())
  if l <= 0:
    raiseOperation("libsodium", "crypto_kx_seedbytes returned invalid length")
  result = l

proc x25519KeypairFromSeed*(seed: openArray[uint8]): tuple[pk, sk: seq[uint8]] =
  let seedLen = x25519SeedLen()
  if seed.len != seedLen:
    raise newException(ValueError, "invalid X25519 seed length")
  var pk = newSeq[uint8](x25519KeyBytes)
  var sk = newSeq[uint8](x25519KeyBytes)
  if crypto_kx_seed_keypair(
      addr pk[0], addr sk[0],
      if seed.len > 0: unsafeAddr seed[0] else: nil) != 0:
    raiseOperation("libsodium", "crypto_kx_seed_keypair failed")
  result = (pk: pk, sk: sk)

proc x25519Shared*(secretKey, publicKey: openArray[uint8]): seq[uint8] =
  if secretKey.len != x25519KeyBytes or publicKey.len != x25519KeyBytes:
    raise newException(ValueError, "invalid X25519 key length")
  var shared = newSeq[uint8](x25519KeyBytes)
  if crypto_scalarmult_curve25519(
      addr shared[0],
      if secretKey.len > 0: unsafeAddr secretKey[0] else: nil,
      if publicKey.len > 0: unsafeAddr publicKey[0] else: nil) != 0:
    raiseOperation("libsodium", "crypto_scalarmult_curve25519 failed")
  result = shared
