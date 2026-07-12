## --------------------------------------------------------
## Certificate Codec Tests <- strict DER and PEM boundaries
## --------------------------------------------------------

import std/unittest
import metaPragmas
import ../src/protocols/certificates
import ../src/protocols/custom_crypto/ed25519

const
  fixtureKey = staticRead(
    "../submodules/cNimWrapper/submodules/openssl/tlslite-ng/tests/serverEd25519Key.pem")
  fixtureCertificate = staticRead(
    "../submodules/cNimWrapper/submodules/openssl/tlslite-ng/tests/serverEd25519Cert.pem")

proc fixtureDer(): seq[byte] {.role: {dataFetcher}.} =
  ## Decode the embedded real certificate for mutation-based parser tests.
  var P: PemReadResult = readPemBlock(fixtureCertificate, "CERTIFICATE")
  doAssert P.ok
  result = P.pemBlock.der

proc fixtureTbsChildren(A: openArray[byte]): seq[DerElement] {.role: {parser}.} =
  ## Return the top-level TBSCertificate fields from the embedded fixture.
  var
    R: DerReadResult = readDerElement(A, 0)
    C, T: tuple[ok: bool, children: seq[DerElement], err: string]
  doAssert R.ok
  C = readDerChildren(A, R.element)
  doAssert C.ok and C.children.len == 3
  T = readDerChildren(A, C.children[0])
  doAssert T.ok
  result = T.children

suite "certificate codecs":
  test "DER reads a bounded sequence and canonical integer":
    var
      A: seq[byte] = @[byte 0x30, 0x03, 0x02, 0x01, 0x05]
      root: DerReadResult = readDerElement(A, 0)
      children: tuple[ok: bool, children: seq[DerElement], err: string]
    check root.ok
    check root.element.endOffset == A.len
    check requireDerShape(root.element, dcUniversal, derTagSequence, true).len == 0
    children = readDerChildren(A, root.element)
    check children.ok
    check children.children.len == 1
    check validateDerInteger(A, children.children[0]).len == 0

  test "DER rejects indefinite and non-minimal lengths":
    check not readDerElement([byte 0x30, 0x80, 0x00, 0x00], 0).ok
    check not readDerElement([byte 0x04, 0x81, 0x01, 0x00], 0).ok
    check not readDerElement([byte 0x04, 0x82, 0x00, 0x80], 0).ok

  test "DER rejects incomplete and oversized elements before copying":
    var L: DerLimits = defaultDerLimits()
    L.maxElementBytes = 2
    check not readDerElement([byte 0x04, 0x03, 1, 2, 3], 0, L).ok
    check not readDerElement([byte 0x04, 0x03, 1], 0).ok

  test "DER integer validation rejects redundant and negative encodings":
    var
      padded: seq[byte] = @[byte 0x02, 0x02, 0x00, 0x01]
      negative: seq[byte] = @[byte 0x02, 0x01, 0x80]
      p: DerReadResult = readDerElement(padded, 0)
      n: DerReadResult = readDerElement(negative, 0)
    check p.ok and validateDerInteger(padded, p.element).len > 0
    check n.ok and validateDerInteger(negative, n.element).len > 0

  test "PEM decodes one matching bounded DER block":
    var
      text = "-----BEGIN CERTIFICATE-----\nMAMCAQU=\n-----END CERTIFICATE-----\n"
      r: PemReadResult = readPemBlock(text, "CERTIFICATE")
    check r.ok
    check r.pemBlock.der == @[byte 0x30, 0x03, 0x02, 0x01, 0x05]

  test "PEM rejects mismatched labels headers and bounds":
    var
      mismatch = "-----BEGIN CERTIFICATE-----\nMAMCAQU=\n-----END PUBLIC KEY-----"
      headers = "-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\nMAMCAQU=\n-----END CERTIFICATE-----"
      valid = "-----BEGIN CERTIFICATE-----\nMAMCAQU=\n-----END CERTIFICATE-----"
    check not readPemBlock(mismatch).ok
    check not readPemBlock(headers).ok
    check not readPemBlock(valid, "CERTIFICATE", 4).ok
    check not readPemBlock(
      "-----BEGIN CERTIFICATE-----\nMAMCAQ=A\n-----END CERTIFICATE-----").ok

  test "OID codec recognizes Ed25519":
    var
      content: seq[byte] = encodeOidContent(oidEd25519)
      A: seq[byte] = @[byte 0x06, byte(content.len)]
      R: DerReadResult
      O: tuple[ok: bool, value, err: string]
    A.add(content)
    R = readDerElement(A, 0)
    O = decodeDerOid(A, R.element)
    check O.ok
    check O.value == oidEd25519

  test "OID encoder roundtrips multi-byte arcs and rejects non-normal form":
    var
      content: seq[byte] = encodeOidContent(oidServerAuth)
      A: seq[byte] = @[byte 0x06, byte(content.len)]
      R: DerReadResult
      O: tuple[ok: bool, value, err: string]
      rejected: bool = false
    A.add(content)
    R = readDerElement(A, 0)
    O = decodeDerOid(A, R.element)
    check O.ok
    check O.value == oidServerAuth
    try:
      discard encodeOidContent("1.03.101.112")
    except ValueError:
      rejected = true
    check rejected

  test "OID decoder rejects uint64 overflow":
    var
      A: seq[byte] = @[byte 0x06, 0x0b, 0x2a, 0x82, 0x80, 0x80, 0x80,
        0x80, 0x80, 0x80, 0x80, 0x80, 0x00]
      R: DerReadResult = readDerElement(A, 0)
    check R.ok
    check not decodeDerOid(A, R.element).ok

  test "PKCS#8 requires a universal SEQUENCE root":
    var
      P: PemReadResult = readPemBlock(fixtureKey, "PRIVATE KEY")
      A: seq[byte] = P.pemBlock.der
    check P.ok
    A[0] = 0xa0'u8
    check not parseEd25519Pkcs8(A).ok

  test "X.509 requires sequence-shaped issuer validity and subject fields":
    var
      A: seq[byte] = fixtureDer()
      T: seq[DerElement] = fixtureTbsChildren(A)
      offsets: array[3, int] = [T[3].headerStart, T[4].headerStart,
        T[5].headerStart]
      i: int = 0
    while i < offsets.len:
      var malformed = A
      malformed[offsets[i]] = 0x31'u8
      check not parseX509CertificateDer(malformed).ok
      i = i + 1

  test "X.509 rejects a zero serial number":
    var
      A: seq[byte] = fixtureDer()
      T: seq[DerElement] = fixtureTbsChildren(A)
      serial: DerElement = T[1]
      i: int = 0
    while i < serial.contentLen:
      A[serial.contentStart + i] = 0'u8
      i = i + 1
    check not parseX509CertificateDer(A).ok

  test "X.509 rejects unsupported optional fields and malformed extensions":
    var
      A: seq[byte] = fixtureDer()
      T: seq[DerElement] = fixtureTbsChildren(A)
      extensionIndex: int = T.len - 1
      Outer, Exts, Fields: tuple[ok: bool, children: seq[DerElement], err: string]
      unsupported, malformedOuter, malformedEntry, explicitFalse: seq[byte]
    check T[extensionIndex].tagClass == dcContext
    check T[extensionIndex].tagNumber == 3'u8
    Outer = readDerChildren(A, T[extensionIndex])
    check Outer.ok and Outer.children.len == 1
    Exts = readDerChildren(A, Outer.children[0])
    check Exts.ok and Exts.children.len > 0
    Fields = readDerChildren(A, Exts.children[^1])
    check Fields.ok and Fields.children.len == 3
    unsupported = A
    unsupported[T[extensionIndex].headerStart] = 0xa1'u8
    check not parseX509CertificateDer(unsupported).ok
    malformedOuter = A
    malformedOuter[Outer.children[0].headerStart] = 0x31'u8
    check not parseX509CertificateDer(malformedOuter).ok
    malformedEntry = A
    malformedEntry[Exts.children[0].headerStart] = 0x31'u8
    check not parseX509CertificateDer(malformedEntry).ok
    explicitFalse = A
    explicitFalse[Fields.children[1].contentStart] = 0'u8
    check not parseX509CertificateDer(explicitFalse).ok

  test "tlslite Ed25519 PKCS#8 fixture matches its certificate key":
    var
      K: Ed25519Pkcs8Result
      X: X509ReadResult
      keyText, certText: string = ""
    keyText = fixtureKey
    certText = fixtureCertificate
    K = parseEd25519PrivateKeyPem(keyText)
    X = parseX509CertificatePem(certText)
    check K.ok
    check K.seed.len == 32
    check X.ok
    check ed25519TyrPublicKey(K.seed) == X.certificate.publicKey
    check X.certificate.signatureAlgorithm == oidEd25519
    check X.certificate.isCa
    check ed25519TyrVerify(X.certificate.tbsCertificate,
      X.certificate.signature, X.certificate.publicKey)
    check verifyPinnedEd25519ServerCertificate(X.certificate,
      X.certificate, 1_627_310_000'i64).ok
    check not verifyPinnedEd25519ServerCertificate(X.certificate,
      X.certificate, 1_627_310_000'i64, "localhost").ok

  test "DNS SAN matching permits only one complete leftmost wildcard label":
    check matchDnsPattern("example.com", "example.com")
    check matchDnsPattern("*.example.com", "www.example.com")
    check not matchDnsPattern("*.example.com", "a.b.example.com")
    check not matchDnsPattern("f*o.example.com", "foo.example.com")
    check not matchDnsPattern("*.com", "example.com")

  test "identity policy keeps DNS and IP SAN namespaces separate":
    var C: X509Certificate
    C.dnsNames = @["127.0.0.1", "example.com"]
    C.ipAddresses = @[@[byte 127, 0, 0, 1]]
    check verifyCertificateIdentity(C, "example.com").ok
    check verifyCertificateIdentity(C, "127.0.0.1").ok
    C.ipAddresses.setLen(0)
    check not verifyCertificateIdentity(C, "127.0.0.1").ok
