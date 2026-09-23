## -----------------------------------------------------------------
## Public Key Verify <- OpenSSL-backed RSA/ECDSA and X.509 helpers
## -----------------------------------------------------------------

import std/strutils

import ../helpers/errors
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

include ./openssl_verify_api
