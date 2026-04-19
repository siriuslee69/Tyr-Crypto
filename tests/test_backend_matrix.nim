import std/[monotimes, times, unittest]

import ../src/tyr_crypto
import ../src/protocols/common
import ../src/protocols/bindings/[liboqs, libsodium]
import ./helpers

const
  loopsLibsodium = 200
  loopsKyber = 32
  loopsDilithium = 16
  loopsBike = 8
  loopsFrodo = 4
  loopsMcEliece = 2
  loopsSphincs = 2

proc sodiumAvailable(): bool =
  try:
    if not ensureLibSodiumLoaded():
      return false
    ensureSodiumInitialised()
    result = true
  except LibraryUnavailableError, OSError:
    result = false

proc oqsAvailable(): bool =
  var kem: ptr OqsKem = nil
  try:
    if not ensureLibOqsLoaded():
      return false
    kem = OQS_KEM_new(oqsAlgKyber768)
    result = kem != nil
  except LibraryUnavailableError, OSError, IOError:
    result = false
  finally:
    if kem != nil:
      OQS_KEM_free(kem)

proc oqsKemSupported(algId: string): bool =
  var kem: ptr OqsKem = nil
  try:
    kem = OQS_KEM_new(algId)
    result = kem != nil
  except LibraryUnavailableError, OSError, IOError:
    result = false
  finally:
    if kem != nil:
      OQS_KEM_free(kem)

proc oqsSigSupported(algId: string): bool =
  var sigObj: ptr OqsSig = nil
  try:
    sigObj = OQS_SIG_new(algId)
    result = sigObj != nil
  except LibraryUnavailableError, OSError, IOError:
    result = false
  finally:
    if sigObj != nil:
      OQS_SIG_free(sigObj)

proc benchCase(name: string, loops: int, body: proc()) =
  var
    started: MonoTime
    perLoop: int64 = 0
    i: int = 0
  started = getMonoTime()
  i = 0
  while i < loops:
    body()
    inc i
  var elapsed = getMonoTime() - started
  if loops > 0:
    perLoop = elapsed.inNanoseconds div int64(loops)
  echo name & " avg_ns=" & $perLoop & " loops=" & $loops

proc runSodiumX25519Roundtrip() =
  var
    pkA = newSeq[byte](32)
    skA = newSeq[byte](32)
    pkB = newSeq[byte](32)
    skB = newSeq[byte](32)
    sharedA = newSeq[byte](32)
    sharedB = newSeq[byte](32)
  check crypto_kx_keypair(addr pkA[0], addr skA[0]) == 0
  check crypto_kx_keypair(addr pkB[0], addr skB[0]) == 0
  check crypto_scalarmult_curve25519(addr sharedA[0], addr skA[0], addr pkB[0]) == 0
  check crypto_scalarmult_curve25519(addr sharedB[0], addr skB[0], addr pkA[0]) == 0
  check sharedA == sharedB

proc runBasicApiX25519Roundtrip() =
  var
    receiver: AsymKeypair
    env: AsymCipher
    shared: seq[byte] = @[]
  receiver = asymKeypair(kaX25519)
  env = asymEnc(kaX25519, receiver.publicKey)
  shared = asymDec(kaX25519, receiver.secretKey, env)
  check shared == env.sharedSecret

proc runSodiumEd25519Roundtrip(msg: openArray[byte]) =
  var
    pk = newSeq[byte](32)
    sk = newSeq[byte](64)
    sig = newSeq[byte](64)
    sigLen: culonglong = 0
  check crypto_sign_ed25519_keypair(addr pk[0], addr sk[0]) == 0
  check crypto_sign_ed25519_detached(addr sig[0], addr sigLen,
    unsafeAddr msg[0], culonglong(msg.len), addr sk[0]) == 0
  sig.setLen(int(sigLen))
  check crypto_sign_ed25519_verify_detached(addr sig[0], unsafeAddr msg[0],
    culonglong(msg.len), addr pk[0]) == 0

proc runBasicApiEd25519Roundtrip(msg: openArray[byte]) =
  var
    msgBuf: seq[byte] = @[]
    kp: AsymKeypair
    sig: seq[byte] = @[]
  msgBuf = @msg
  kp = asymKeypair(saEd25519)
  sig = asymSign(saEd25519, msgBuf, kp.secretKey)
  check asymVerify(saEd25519, msgBuf, sig, kp.publicKey)

proc runOqsKemRoundtrip(algId: string) =
  var
    kem: ptr OqsKem = nil
    pk, sk, ct, ssE, ssD: seq[byte] = @[]
  kem = OQS_KEM_new(algId)
  if kem == nil:
    raise newException(ValueError, "liboqs KEM unavailable: " & algId)
  defer:
    if kem != nil:
      OQS_KEM_free(kem)
  pk = newSeq[byte](int kem[].length_public_key)
  sk = newSeq[byte](int kem[].length_secret_key)
  ct = newSeq[byte](int kem[].length_ciphertext)
  ssE = newSeq[byte](int kem[].length_shared_secret)
  ssD = newSeq[byte](int kem[].length_shared_secret)
  requireSuccess(OQS_KEM_keypair(kem, addr pk[0], addr sk[0]), "oqs keypair " & algId)
  requireSuccess(OQS_KEM_encaps(kem, addr ct[0], addr ssE[0], addr pk[0]), "oqs encaps " & algId)
  requireSuccess(OQS_KEM_decaps(kem, addr ssD[0], addr ct[0], addr sk[0]), "oqs decaps " & algId)
  check ssD == ssE

proc runOqsSigRoundtrip(algId: string, msg: openArray[byte]) =
  var
    sigObj: ptr OqsSig = nil
    pk, sk, sig: seq[byte] = @[]
    sigLen: csize_t = 0
  sigObj = OQS_SIG_new(algId)
  if sigObj == nil:
    raise newException(ValueError, "liboqs SIG unavailable: " & algId)
  defer:
    if sigObj != nil:
      OQS_SIG_free(sigObj)
  pk = newSeq[byte](int sigObj[].length_public_key)
  sk = newSeq[byte](int sigObj[].length_secret_key)
  sig = newSeq[byte](int sigObj[].length_signature)
  requireSuccess(OQS_SIG_keypair(sigObj, addr pk[0], addr sk[0]), "oqs sig keypair " & algId)
  requireSuccess(OQS_SIG_sign(sigObj, addr sig[0], addr sigLen, unsafeAddr msg[0],
    csize_t(msg.len), addr sk[0]), "oqs sign " & algId)
  sig.setLen(int(sigLen))
  requireSuccess(OQS_SIG_verify(sigObj, unsafeAddr msg[0], csize_t(msg.len),
    addr sig[0], csize_t(sig.len), addr pk[0]), "oqs verify " & algId)

proc runKyberRoundtrip(v: KyberVariant) =
  var
    kp: KyberTyrKeypair
    env: KyberTyrCipher
    shared: seq[byte] = @[]
  kp = kyberTyrKeypair(v)
  env = kyberTyrEncaps(v, kp.publicKey)
  shared = kyberTyrDecaps(v, kp.secretKey, env.ciphertext)
  check shared == env.sharedSecret

proc runFrodoRoundtrip(v: FrodoVariant) =
  var
    kp: FrodoTyrKeypair
    env: FrodoTyrCipher
    shared: seq[byte] = @[]
  kp = frodoTyrKeypair(v)
  env = frodoTyrEncaps(v, kp.publicKey)
  shared = frodoTyrDecaps(v, kp.secretKey, env.ciphertext)
  check shared == env.sharedSecret

proc runBikeRoundtrip(v: BikeVariant) =
  var
    kp: BikeTyrKeypair
    env: BikeTyrCipher
    shared: seq[byte] = @[]
  kp = bikeTyrKeypair(v)
  env = bikeTyrEncaps(v, kp.publicKey)
  shared = bikeTyrDecaps(v, kp.secretKey, env.ciphertext)
  check shared == env.sharedSecret

proc runMcElieceRoundtrip(v: McElieceVariant) =
  var
    kp: McElieceTyrKeypair
    env: McElieceTyrCipher
    shared: seq[byte] = @[]
  kp = mcelieceTyrKeypair(v)
  env = mcelieceTyrEncaps(v, kp.publicKey)
  shared = mcelieceTyrDecaps(v, kp.secretKey, env.ciphertext)
  check shared == env.sharedSecret

proc runDilithiumRoundtrip(v: DilithiumVariant, msg: openArray[byte]) =
  var
    kp: DilithiumTyrKeypair
    sig: seq[byte] = @[]
  kp = dilithiumTyrKeypair(v)
  sig = dilithiumTyrSign(v, msg, kp.secretKey)
  check dilithiumTyrVerify(v, msg, sig, kp.publicKey)

proc runSphincsRoundtrip(v: SphincsVariant, msg: openArray[byte]) =
  var
    kp: SphincsTyrKeypair
    sig: seq[byte] = @[]
  kp = sphincsTyrKeypair(v)
  sig = sphincsTyrSign(v, msg, kp.secretKey)
  check sphincsTyrVerify(v, msg, sig, kp.publicKey)

suite "backend matrix":
  test "Tyr custom backends match backend health expectations":
    var
      msgShort = toBytes("tyr backend matrix short message")
      msgLong = toBytes("tyr backend matrix long message for signature checks and backend timing")
      hasSodium = false
      hasOqs = false
    hasSodium = sodiumAvailable()
    hasOqs = oqsAvailable()

    if hasSodium:
      benchCase("libsodium_x25519_roundtrip", loopsLibsodium, runSodiumX25519Roundtrip)
      benchCase("basic_api_x25519_roundtrip", loopsLibsodium, runBasicApiX25519Roundtrip)
      benchCase("libsodium_ed25519_roundtrip", loopsLibsodium,
        proc() = runSodiumEd25519Roundtrip(msgShort))
      benchCase("basic_api_ed25519_roundtrip", loopsLibsodium,
        proc() = runBasicApiEd25519Roundtrip(msgShort))
    else:
      checkpoint("libsodium unavailable; skipping libsodium/basic_api classical backend bench")

    benchCase("tyr_kyber768_roundtrip", loopsKyber, proc() = runKyberRoundtrip(kyber768))
    benchCase("tyr_kyber1024_roundtrip", loopsKyber, proc() = runKyberRoundtrip(kyber1024))
    benchCase("tyr_frodo976aes_roundtrip", loopsFrodo, proc() = runFrodoRoundtrip(frodo976aes))
    benchCase("tyr_bike_l1_roundtrip", loopsBike, proc() = runBikeRoundtrip(bikeL1))
    benchCase("tyr_mceliece6688128f_roundtrip", loopsMcEliece,
      proc() = runMcElieceRoundtrip(mceliece6688128f))
    benchCase("tyr_mceliece6960119f_roundtrip", loopsMcEliece,
      proc() = runMcElieceRoundtrip(mceliece6960119f))
    benchCase("tyr_mceliece8192128f_roundtrip", loopsMcEliece,
      proc() = runMcElieceRoundtrip(mceliece8192128f))
    benchCase("tyr_dilithium44_roundtrip", loopsDilithium,
      proc() = runDilithiumRoundtrip(dilithium44, msgLong))
    benchCase("tyr_dilithium65_roundtrip", loopsDilithium,
      proc() = runDilithiumRoundtrip(dilithium65, msgLong))
    benchCase("tyr_dilithium87_roundtrip", loopsDilithium,
      proc() = runDilithiumRoundtrip(dilithium87, msgLong))
    benchCase("tyr_sphincs_shake128f_roundtrip", loopsSphincs,
      proc() = runSphincsRoundtrip(sphincsShake128fSimple, msgShort))

    if hasOqs:
      if oqsKemSupported(oqsAlgKyber768):
        benchCase("oqs_kyber768_roundtrip", loopsKyber,
          proc() = runOqsKemRoundtrip(oqsAlgKyber768))
      else:
        checkpoint("liboqs missing KEM " & oqsAlgKyber768)
      if oqsKemSupported(oqsAlgKyber1024):
        benchCase("oqs_kyber1024_roundtrip", loopsKyber,
          proc() = runOqsKemRoundtrip(oqsAlgKyber1024))
      else:
        checkpoint("liboqs missing KEM " & oqsAlgKyber1024)
      if oqsKemSupported(oqsAlgFrodoKEM976):
        benchCase("oqs_frodo976aes_roundtrip", loopsFrodo,
          proc() = runOqsKemRoundtrip(oqsAlgFrodoKEM976))
      else:
        checkpoint("liboqs missing KEM " & oqsAlgFrodoKEM976)
      if oqsKemSupported(oqsAlgBike0):
        benchCase("oqs_bike_l1_roundtrip", loopsBike,
          proc() = runOqsKemRoundtrip(oqsAlgBike0))
      else:
        checkpoint("liboqs missing KEM " & oqsAlgBike0)
      if oqsKemSupported(oqsAlgClassicMcEliece6688128f):
        benchCase("oqs_mceliece6688128f_roundtrip", loopsMcEliece,
          proc() = runOqsKemRoundtrip(oqsAlgClassicMcEliece6688128f))
      else:
        checkpoint("liboqs missing KEM " & oqsAlgClassicMcEliece6688128f)
      if oqsKemSupported(oqsAlgClassicMcEliece6960119f):
        benchCase("oqs_mceliece6960119f_roundtrip", loopsMcEliece,
          proc() = runOqsKemRoundtrip(oqsAlgClassicMcEliece6960119f))
      else:
        checkpoint("liboqs missing KEM " & oqsAlgClassicMcEliece6960119f)
      if oqsKemSupported(oqsAlgClassicMcEliece8192128f):
        benchCase("oqs_mceliece8192128f_roundtrip", loopsMcEliece,
          proc() = runOqsKemRoundtrip(oqsAlgClassicMcEliece8192128f))
      else:
        checkpoint("liboqs missing KEM " & oqsAlgClassicMcEliece8192128f)
      if oqsSigSupported(oqsSigDilithium0):
        benchCase("oqs_mldsa44_roundtrip", loopsDilithium,
          proc() = runOqsSigRoundtrip(oqsSigDilithium0, msgLong))
      else:
        checkpoint("liboqs missing SIG " & oqsSigDilithium0)
      if oqsSigSupported(oqsSigDilithium1):
        benchCase("oqs_mldsa65_roundtrip", loopsDilithium,
          proc() = runOqsSigRoundtrip(oqsSigDilithium1, msgLong))
      else:
        checkpoint("liboqs missing SIG " & oqsSigDilithium1)
      if oqsSigSupported(oqsSigDilithium2):
        benchCase("oqs_mldsa87_roundtrip", loopsDilithium,
          proc() = runOqsSigRoundtrip(oqsSigDilithium2, msgLong))
      else:
        checkpoint("liboqs missing SIG " & oqsSigDilithium2)
      if oqsSigSupported(oqsSigSphincsShake128fSimple):
        benchCase("oqs_sphincs_shake128f_roundtrip", loopsSphincs,
          proc() = runOqsSigRoundtrip(oqsSigSphincsShake128fSimple, msgShort))
      else:
        checkpoint("liboqs missing SIG " & oqsSigSphincsShake128fSimple)
    else:
      checkpoint("liboqs unavailable; skipping liboqs backend bench")
