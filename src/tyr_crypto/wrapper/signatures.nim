# ==================================================
# | Signature Wrapper                               |
# |-------------------------------------------------|
# | Unified signing interface for supported schemes.|
# ==================================================

import ../common
import ../bindings/liboqs
import ../bindings/libsodium
import ../algorithms

const
  ed25519PublicKeyBytes = 32
  ed25519SecretKeyBytes = 64
  ed25519SignatureBytes = 64

type
  SignatureKeypair* = object
    publicKey*: seq[uint8]
    secretKey*: seq[uint8]
    algorithm*: SignatureAlgorithm

proc isHybridSignatureAlgorithm(alg: SignatureAlgorithm): bool =
  alg in {saEd25519Falcon512Hybrid, saEd25519Falcon1024Hybrid}

proc hybridPqAlgorithm(alg: SignatureAlgorithm): SignatureAlgorithm =
  case alg
  of saEd25519Falcon512Hybrid:
    saFalcon512
  of saEd25519Falcon1024Hybrid:
    saFalcon1024
  else:
    raise newException(ValueError, "algorithm is not a hybrid signature")

proc appendU32(buf: var seq[uint8], value: uint32) =
  buf.add(uint8(value and 0xff))
  buf.add(uint8((value shr 8) and 0xff))
  buf.add(uint8((value shr 16) and 0xff))
  buf.add(uint8((value shr 24) and 0xff))

proc readU32(data: openArray[uint8], offset: var int): uint32 =
  if offset + 4 > data.len:
    raise newException(ValueError, "truncated framed signature payload")
  result = uint32(data[offset]) or
    (uint32(data[offset + 1]) shl 8) or
    (uint32(data[offset + 2]) shl 16) or
    (uint32(data[offset + 3]) shl 24)
  offset = offset + 4

proc framePair(first, second: openArray[uint8]): seq[uint8] =
  result = newSeqOfCap[uint8](8 + first.len + second.len)
  appendU32(result, uint32(first.len))
  result.add(first)
  appendU32(result, uint32(second.len))
  result.add(second)

proc parsePair(data: openArray[uint8]): tuple[first, second: seq[uint8]] =
  var offset = 0
  let firstLen = int(readU32(data, offset))
  if offset + firstLen > data.len:
    raise newException(ValueError, "invalid framed signature payload")
  result.first = @data[offset ..< offset + firstLen]
  offset = offset + firstLen
  let secondLen = int(readU32(data, offset))
  if offset + secondLen > data.len:
    raise newException(ValueError, "invalid framed signature payload")
  result.second = @data[offset ..< offset + secondLen]
  offset = offset + secondLen
  if offset != data.len:
    raise newException(ValueError, "trailing bytes in framed signature payload")

proc requireSignatureLibs(alg: SignatureAlgorithm) =
  ## Ensure backend libraries for the signature algorithm are loaded.
  if isHybridSignatureAlgorithm(alg):
    if not ensureLibSodiumLoaded():
      raiseUnavailable("libsodium", "hasLibsodium")
    ensureSodiumInitialised()
    if not ensureLibOqsLoaded():
      raiseUnavailable("liboqs", "hasLibOqs")
    return
  case alg
  of saEd25519:
    if not ensureLibSodiumLoaded():
      raiseUnavailable("libsodium", "hasLibsodium")
    ensureSodiumInitialised()
  of saEd448:
    raiseUnavailable("OpenSSL", "hasOpenSSL3")
  else:
    if not ensureLibOqsLoaded():
      raiseUnavailable("liboqs", "hasLibOqs")

when defined(hasLibOqs):
  proc sigAlgId(alg: SignatureAlgorithm): string =
    ## Map signature algorithm enum to liboqs algorithm id.
    case alg
    of saDilithium2:
      result = oqsSigDilithium2
    of saDilithium3:
      result = oqsSigDilithium3
    of saDilithium5:
      result = oqsSigDilithium5
    of saFalcon512:
      result = oqsSigFalcon512
    of saFalcon1024:
      result = oqsSigFalcon1024
    of saSPHINCSPlusHaraka128fSimple:
      result = oqsSigSphincsHaraka128fSimple
    else:
      result = ""

proc signatureAvailable*(alg: SignatureAlgorithm): bool =
  ## Check if the signature backend is available for the algorithm.
  try:
    if isHybridSignatureAlgorithm(alg):
      result = signatureAvailable(saEd25519) and
        signatureAvailable(hybridPqAlgorithm(alg))
      return
    case alg
    of saEd25519:
      if not ensureLibSodiumLoaded():
        return false
      ensureSodiumInitialised()
      true
    of saEd448:
      false
    else:
      when defined(hasLibOqs):
        if not ensureLibOqsLoaded():
          return false
        let algId = sigAlgId(alg).cstring
        let sig = OQS_SIG_new(algId)
        if sig == nil:
          return false
        OQS_SIG_free(sig)
        true
      else:
        false
  except LibraryUnavailableError, OSError, IOError, CryptoOperationError:
    false

proc ptrOrZero(buf: seq[uint8]; tmp: var uint8): ptr uint8 =
  ## Return a pointer to buf[0] or a temp byte when buf is empty.
  if buf.len == 0:
    tmp = 0'u8
    result = addr tmp
  else:
    result = unsafeAddr buf[0]

proc signatureKeypair*(alg: SignatureAlgorithm): SignatureKeypair =
  ## Generate a signature keypair for the algorithm.
  requireSignatureLibs(alg)
  result.algorithm = alg
  if isHybridSignatureAlgorithm(alg):
    let classical = signatureKeypair(saEd25519)
    let pq = signatureKeypair(hybridPqAlgorithm(alg))
    result.publicKey = framePair(classical.publicKey, pq.publicKey)
    result.secretKey = framePair(classical.secretKey, pq.secretKey)
    return
  case alg
  of saEd25519:
    result.publicKey = newSeq[uint8](ed25519PublicKeyBytes)
    result.secretKey = newSeq[uint8](ed25519SecretKeyBytes)
    if crypto_sign_ed25519_keypair(addr result.publicKey[0], addr result.secretKey[0]) != 0:
      raiseOperation("libsodium", "crypto_sign_ed25519_keypair failed")
  of saEd448:
    raiseUnavailable("OpenSSL", "hasOpenSSL3")
  else:
    when defined(hasLibOqs):
      let algId = sigAlgId(alg).cstring
      let sig = OQS_SIG_new(algId)
      if sig == nil:
        raiseOperation("liboqs", "SIG " & sigAlgId(alg) & " unavailable")
      defer:
        OQS_SIG_free(sig)
      result.publicKey = newSeq[uint8](int sig[].length_public_key)
      result.secretKey = newSeq[uint8](int sig[].length_secret_key)
      requireSuccess(
        OQS_SIG_keypair(sig, addr result.publicKey[0], addr result.secretKey[0]),
        "OQS_SIG_keypair(" & sigAlgId(alg) & ")"
      )
    else:
      raiseUnavailable("liboqs", "hasLibOqs")

proc signMessage*(alg: SignatureAlgorithm; msg, secretKey: seq[uint8]): seq[uint8] =
  ## Sign a message with the selected algorithm.
  requireSignatureLibs(alg)
  if isHybridSignatureAlgorithm(alg):
    let parts = parsePair(secretKey)
    let classicalSig = signMessage(saEd25519, msg, parts.first)
    let pqSig = signMessage(hybridPqAlgorithm(alg), msg, parts.second)
    result = framePair(classicalSig, pqSig)
    return
  case alg
  of saEd25519:
    if secretKey.len != ed25519SecretKeyBytes:
      raise newException(ValueError, "invalid Ed25519 secret key length")
    result = newSeq[uint8](ed25519SignatureBytes)
    var sigLen: culonglong
    var tmp: uint8
    let msgPtr = ptrOrZero(msg, tmp)
    if crypto_sign_ed25519_detached(addr result[0], addr sigLen, msgPtr, culonglong(msg.len), unsafeAddr secretKey[0]) != 0:
      raiseOperation("libsodium", "crypto_sign_ed25519_detached failed")
  of saEd448:
    raiseUnavailable("OpenSSL", "hasOpenSSL3")
  else:
    when defined(hasLibOqs):
      let algId = sigAlgId(alg).cstring
      let sig = OQS_SIG_new(algId)
      if sig == nil:
        raiseOperation("liboqs", "SIG " & sigAlgId(alg) & " unavailable")
      defer:
        OQS_SIG_free(sig)
      if secretKey.len != int sig[].length_secret_key:
        raise newException(ValueError, "invalid " & sigAlgId(alg) & " secret key length")
      result = newSeq[uint8](int sig[].length_signature)
      var sigLen: csize_t
      var tmp: uint8
      let msgPtr = ptrOrZero(msg, tmp)
      requireSuccess(
        OQS_SIG_sign(sig, addr result[0], addr sigLen, msgPtr, csize_t(msg.len), unsafeAddr secretKey[0]),
        "OQS_SIG_sign(" & sigAlgId(alg) & ")"
      )
      if sigLen < csize_t(result.len):
        result.setLen(int(sigLen))
    else:
      raiseUnavailable("liboqs", "hasLibOqs")

proc verifyMessage*(alg: SignatureAlgorithm; msg, signature, publicKey: seq[uint8]): bool =
  ## Verify a message signature with the selected algorithm.
  requireSignatureLibs(alg)
  if isHybridSignatureAlgorithm(alg):
    let keyParts = parsePair(publicKey)
    let sigParts = parsePair(signature)
    result = verifyMessage(saEd25519, msg, sigParts.first, keyParts.first) and
      verifyMessage(hybridPqAlgorithm(alg), msg, sigParts.second, keyParts.second)
    return
  case alg
  of saEd25519:
    if publicKey.len != ed25519PublicKeyBytes:
      raise newException(ValueError, "invalid Ed25519 public key length")
    if signature.len != ed25519SignatureBytes:
      raise newException(ValueError, "invalid Ed25519 signature length")
    var tmp: uint8
    let msgPtr = ptrOrZero(msg, tmp)
    result = crypto_sign_ed25519_verify_detached(unsafeAddr signature[0], msgPtr, culonglong(msg.len), unsafeAddr publicKey[0]) == 0
  of saEd448:
    raiseUnavailable("OpenSSL", "hasOpenSSL3")
  else:
    when defined(hasLibOqs):
      let algId = sigAlgId(alg).cstring
      let sig = OQS_SIG_new(algId)
      if sig == nil:
        raiseOperation("liboqs", "SIG " & sigAlgId(alg) & " unavailable")
      defer:
        OQS_SIG_free(sig)
      if publicKey.len != int sig[].length_public_key:
        raise newException(ValueError, "invalid " & sigAlgId(alg) & " public key length")
      if signature.len == 0 or signature.len > int sig[].length_signature:
        raise newException(ValueError, "invalid " & sigAlgId(alg) & " signature length")
      var tmp: uint8
      let msgPtr = ptrOrZero(msg, tmp)
      let status = OQS_SIG_verify(sig, msgPtr, csize_t(msg.len), unsafeAddr signature[0], csize_t(signature.len), unsafeAddr publicKey[0])
      result = status == oqsSuccess
    else:
      raiseUnavailable("liboqs", "hasLibOqs")
