## -----------------------------------------------------------------
## Public Key Verify <- OpenSSL-backed RSA/ECDSA and X.509 helpers
## -----------------------------------------------------------------

import std/strutils

import ../common
import ../bindings/openssl

type
  OpenSslPublicKeyVerifyResult* = object
    ok*: bool
    algorithm*: string
    err*: string

  OpenSslX509VerifyResult* = object
    ok*: bool
    err*: string
    subjectPublicKeyDer*: seq[uint8]

proc copyBytes(A: openArray[uint8]): seq[uint8] =
  ## A: input byte view to copy into OpenSSL-owned call buffers.
  var
    i: int = 0
  result = newSeq[uint8](A.len)
  while i < A.len:
    result[i] = A[i]
    i = i + 1

proc equalBytes(A, B: openArray[uint8]): bool =
  ## A/B: byte views to compare.
  var
    i: int = 0
  if A.len != B.len:
    return false
  result = true
  while i < A.len:
    if A[i] != B[i]:
      result = false
    i = i + 1

proc bytePtr(S: var seq[uint8], tmp: var uint8): ptr uint8 =
  ## S: byte sequence that may be empty.
  ## tmp: fallback byte storage for empty sequences.
  if S.len == 0:
    tmp = 0'u8
    return addr tmp
  result = addr S[0]

proc digestNameForOpenSslAlgorithm*(algorithm: string): string =
  ## algorithm: RSA/ECDSA signature label.
  var
    a: string = ""
  a = algorithm.normalize.toLowerAscii
  case a
  of "rsa", "rsa-sha256", "rsa-pkcs1", "rsa-pkcs1-sha256",
      "ecdsa", "ecdsa-sha256", "sha256":
    result = "SHA256"
  of "rsa-sha384", "rsa-pkcs1-sha384", "ecdsa-sha384", "sha384":
    result = "SHA384"
  of "rsa-sha512", "rsa-pkcs1-sha512", "ecdsa-sha512", "sha512":
    result = "SHA512"
  else:
    result = ""

proc loadOpenSslPublicKey(publicKey: openArray[uint8]): ptr EVP_PKEY =
  ## publicKey: PEM or DER SubjectPublicKeyInfo public key.
  var
    B: seq[uint8] = @[]
    bio: ptr BIO = nil
    p: ptr uint8 = nil
  if publicKey.len == 0:
    raise newException(ValueError, "OpenSSL public key must not be empty")
  B = copyBytes(publicKey)
  bio = BIO_new_mem_buf(addr B[0], cint(B.len))
  if bio != nil:
    result = PEM_read_bio_PUBKEY(bio, nil, nil, nil)
    discard BIO_free(bio)
  if result != nil:
    return
  p = addr B[0]
  result = d2i_PUBKEY(nil, addr p, clong(B.len))
  if result == nil:
    raise newException(ValueError, "OpenSSL could not parse public key")

proc loadOpenSslX509(cert: openArray[uint8]): ptr X509 =
  ## cert: PEM or DER encoded X.509 certificate.
  var
    B: seq[uint8] = @[]
    bio: ptr BIO = nil
    p: ptr uint8 = nil
  if cert.len == 0:
    raise newException(ValueError, "OpenSSL X.509 certificate must not be empty")
  B = copyBytes(cert)
  bio = BIO_new_mem_buf(addr B[0], cint(B.len))
  if bio != nil:
    result = PEM_read_bio_X509(bio, nil, nil, nil)
    discard BIO_free(bio)
  if result != nil:
    return
  p = addr B[0]
  result = d2i_X509(nil, addr p, clong(B.len))
  if result == nil:
    raise newException(ValueError, "OpenSSL could not parse X.509 certificate")

proc publicKeyDerFromOpenSslKey(pkey: ptr EVP_PKEY): seq[uint8] =
  ## pkey: OpenSSL public key handle to export as DER SubjectPublicKeyInfo.
  var
    l: cint = 0
    p: ptr uint8 = nil
  if pkey == nil:
    raise newException(ValueError, "OpenSSL public key handle is nil")
  l = i2d_PUBKEY(pkey, nil)
  if l <= 0:
    raiseOperation("OpenSSL", "i2d_PUBKEY length failed")
  result = newSeq[uint8](int(l))
  p = addr result[0]
  if i2d_PUBKEY(pkey, addr p) != l:
    raiseOperation("OpenSSL", "i2d_PUBKEY encode failed")

proc extractOpenSslX509PublicKeyDer*(certificate: openArray[uint8]):
    OpenSslX509VerifyResult =
  ## certificate: PEM or DER encoded X.509 certificate.
  var
    cert: ptr X509 = nil
    pkey: ptr EVP_PKEY = nil
  try:
    cert = loadOpenSslX509(certificate)
    pkey = X509_get_pubkey(cert)
    if pkey == nil:
      result.err = "OpenSSL could not extract X.509 public key"
      return
    result.subjectPublicKeyDer = publicKeyDerFromOpenSslKey(pkey)
    result.ok = true
  except CatchableError as exc:
    result.ok = false
    result.err = exc.msg
  finally:
    if pkey != nil:
      EVP_PKEY_free(pkey)
    if cert != nil:
      X509_free(cert)

proc verifyOpenSslPublicKeySignature*(algorithm: string,
    publicKey, message, signature: openArray[uint8]): OpenSslPublicKeyVerifyResult =
  ## algorithm: rsa-sha256/rsa-sha384/rsa-sha512 or ecdsa-sha256/384/512.
  ## publicKey: PEM or DER SubjectPublicKeyInfo public key.
  ## message: signed message bytes.
  ## signature: detached signature bytes. ECDSA expects ASN.1 DER signature.
  var
    digestName: string = ""
    key: ptr EVP_PKEY = nil
    ctx: ptr EVP_MD_CTX = nil
    pctx: ptr EVP_PKEY_CTX = nil
    M: seq[uint8] = @[]
    S: seq[uint8] = @[]
    tmpM: uint8 = 0
    tmpS: uint8 = 0
    status: cint = 0
  result.algorithm = algorithm
  digestName = digestNameForOpenSslAlgorithm(algorithm)
  if digestName.len == 0:
    result.err = "unsupported OpenSSL public-key signature algorithm"
    return
  if signature.len == 0:
    result.err = "signature must not be empty"
    return
  try:
    key = loadOpenSslPublicKey(publicKey)
    ctx = EVP_MD_CTX_new()
    if ctx == nil:
      result.err = "OpenSSL could not allocate verify context"
      return
    M = copyBytes(message)
    S = copyBytes(signature)
    status = EVP_DigestVerifyInit_ex(ctx, addr pctx, digestName.cstring, nil,
      key)
    if status != 1:
      result.err = "OpenSSL digest verify init failed"
      return
    status = EVP_DigestVerify(ctx, bytePtr(S, tmpS), csize_t(S.len),
      bytePtr(M, tmpM), csize_t(M.len))
    result.ok = status == 1
    if not result.ok:
      result.err = "OpenSSL public-key signature verification failed"
  except CatchableError as exc:
    result.ok = false
    result.err = exc.msg
  finally:
    if ctx != nil:
      EVP_MD_CTX_free(ctx)
    if key != nil:
      EVP_PKEY_free(key)

proc verifyOpenSslX509SubjectPublicKey*(leafCertificate,
    subjectPublicKeyDer: openArray[uint8], trustedRoots: seq[seq[uint8]],
    intermediateCertificates: seq[seq[uint8]] = @[],
    useDefaultPaths: bool = false): OpenSslX509VerifyResult =
  ## leafCertificate: PEM or DER encoded certificate containing the subject key.
  ## subjectPublicKeyDer: expected DER SubjectPublicKeyInfo from the subject.
  ## trustedRoots: PEM/DER trust anchors, e.g. a Microsoft root certificate.
  ## intermediateCertificates: optional PEM/DER chain certificates.
  ## useDefaultPaths: also ask OpenSSL to use its configured trust paths.
  var
    leaf: ptr X509 = nil
    leafKey: ptr EVP_PKEY = nil
    store: ptr X509_STORE = nil
    ctx: ptr X509_STORE_CTX = nil
    chain: ptr OPENSSL_STACK = nil
    rootCerts: seq[ptr X509] = @[]
    chainCerts: seq[ptr X509] = @[]
    cert: ptr X509 = nil
    i: int = 0
    errCode: cint = 0
  if trustedRoots.len == 0 and not useDefaultPaths:
    result.err = "X.509 verification needs trusted roots or default paths"
    return
  if subjectPublicKeyDer.len == 0:
    result.err = "expected subject public key must not be empty"
    return
  try:
    leaf = loadOpenSslX509(leafCertificate)
    leafKey = X509_get_pubkey(leaf)
    if leafKey == nil:
      result.err = "OpenSSL could not extract X.509 public key"
      return
    result.subjectPublicKeyDer = publicKeyDerFromOpenSslKey(leafKey)
    if not equalBytes(result.subjectPublicKeyDer, subjectPublicKeyDer):
      result.err = "X.509 subject public key mismatch"
      return
    store = X509_STORE_new()
    if store == nil:
      result.err = "OpenSSL could not allocate X.509 store"
      return
    if useDefaultPaths and X509_STORE_set_default_paths(store) != 1:
      result.err = "OpenSSL could not load default X.509 trust paths"
      return
    i = 0
    while i < trustedRoots.len:
      cert = loadOpenSslX509(trustedRoots[i])
      rootCerts.add(cert)
      if X509_STORE_add_cert(store, cert) != 1:
        result.err = "OpenSSL could not add trusted X.509 root"
        return
      i = i + 1
    chain = OPENSSL_sk_new_null()
    if chain == nil:
      result.err = "OpenSSL could not allocate X.509 chain stack"
      return
    i = 0
    while i < intermediateCertificates.len:
      cert = loadOpenSslX509(intermediateCertificates[i])
      chainCerts.add(cert)
      if OPENSSL_sk_push(chain, cast[pointer](cert)) <= 0:
        result.err = "OpenSSL could not append intermediate X.509 certificate"
        return
      i = i + 1
    ctx = X509_STORE_CTX_new()
    if ctx == nil:
      result.err = "OpenSSL could not allocate X.509 store context"
      return
    if X509_STORE_CTX_init(ctx, store, leaf, chain) != 1:
      result.err = "OpenSSL could not initialize X.509 store context"
      return
    if X509_verify_cert(ctx) == 1:
      result.ok = true
      return
    errCode = X509_STORE_CTX_get_error(ctx)
    result.err = $X509_verify_cert_error_string(clong(errCode))
  except CatchableError as exc:
    result.ok = false
    result.err = exc.msg
  finally:
    if ctx != nil:
      X509_STORE_CTX_free(ctx)
    if chain != nil:
      OPENSSL_sk_free(chain)
    i = 0
    while i < chainCerts.len:
      if chainCerts[i] != nil:
        X509_free(chainCerts[i])
      i = i + 1
    i = 0
    while i < rootCerts.len:
      if rootCerts[i] != nil:
        X509_free(rootCerts[i])
      i = i + 1
    if store != nil:
      X509_STORE_free(store)
    if leafKey != nil:
      EVP_PKEY_free(leafKey)
    if leaf != nil:
      X509_free(leaf)
