## Public X.509 certificate parsers included by x509.nim.
##
## This section shares x509.nim's DER helpers and imports.

proc parseSpkiAlgorithmOid*(A: openArray[byte]): tuple[
    ok: bool, value, err: string] {.role: {parser}.} =
  ## A: complete SubjectPublicKeyInfo DER.
  ## Returns the key algorithm OID without decoding the key itself, so the
  ## caller can dispatch to the matching algorithm-specific parser.
  var
    R: DerReadResult = readDerElement(A, 0)
    C, alg: tuple[ok: bool, children: seq[DerElement], err: string] =
      (ok: false, children: @[], err: "")
  if not R.ok:
    result.err = R.err
    return
  if requireDerShape(R.element, dcUniversal, derTagSequence, true).len > 0:
    result.err = "SubjectPublicKeyInfo is not a SEQUENCE"
    return
  C = readDerChildren(A, R.element)
  if not C.ok or C.children.len != 2:
    result.err = "SubjectPublicKeyInfo must have two fields"
    return
  if requireDerShape(C.children[0], dcUniversal, derTagSequence, true).len > 0:
    result.err = "SubjectPublicKeyInfo algorithm is not a SEQUENCE"
    return
  alg = readDerChildren(A, C.children[0])
  if not alg.ok or alg.children.len < 1:
    result.err = "SubjectPublicKeyInfo algorithm is empty"
    return
  result = decodeDerOid(A, alg.children[0])

proc parseX509CertificateDer*(A: openArray[byte]): X509ReadResult {.role: {truthBuilder}.} =
  ## A: one complete DER X.509 certificate.
  var
    Root: DerReadResult = readDerElement(A, 0)
    Cert, Tbs, Validity: tuple[ok: bool, children: seq[DerElement], err: string] =
      (ok: false, children: @[], err: "")
    outerAlg, innerAlg: tuple[ok: bool, value, err: string] =
      (ok: false, value: "", err: "")
    spki: Ed25519SpkiResult = default(Ed25519SpkiResult)
    spkiAlg: tuple[ok: bool, value, err: string] =
      (ok: false, value: "", err: "")
    sigBits: seq[byte] = @[]
    i, base: int = 0
    extensionsSeen: bool = false
    t0, t1: tuple[ok: bool, unix: int64, err: string] =
      (ok: false, unix: 0'i64, err: "")
  if not Root.ok or Root.element.endOffset != A.len:
    result.err = if Root.err.len > 0: Root.err else: "X.509 certificate has trailing bytes"
    return
  if requireDerShape(Root.element, dcUniversal, derTagSequence, true).len > 0:
    result.err = "X.509 certificate root is not a SEQUENCE"
    return
  Cert = readDerChildren(A, Root.element)
  if not Cert.ok or Cert.children.len != 3:
    result.err = if Cert.err.len > 0: Cert.err else: "X.509 certificate must have three fields"
    return
  if requireDerShape(Cert.children[0], dcUniversal, derTagSequence,
      true).len > 0:
    result.err = "TBSCertificate is not a SEQUENCE"
    return
  Tbs = readDerChildren(A, Cert.children[0])
  if not Tbs.ok or Tbs.children.len < 6:
    result.err = if Tbs.err.len > 0: Tbs.err else: "TBSCertificate is incomplete"
    return
  result.certificate.tbsCertificate = derEncoded(A, Cert.children[0])
  base = 0
  if Tbs.children[0].tagClass == dcContext and Tbs.children[0].tagNumber == 0'u8:
    var versionFields = readDerChildren(A, Tbs.children[0])
    if not versionFields.ok or versionFields.children.len != 1 or
        validateDerInteger(A, versionFields.children[0]).len > 0 or
        derContent(A, versionFields.children[0]) != @[byte 2]:
      result.err = "X.509 certificate version must be v3"
      return
    base = 1
  else:
    result.err = "controlled X.509 profile requires explicit v3"
    return
  if Tbs.children.len < base + 6:
    result.err = "TBSCertificate required fields are incomplete"
    return
  result.err = validateDerInteger(A, Tbs.children[base])
  if result.err.len > 0:
    return
  result.certificate.serialNumber = derContent(A, Tbs.children[base])
  if result.certificate.serialNumber.len == 1 and
      result.certificate.serialNumber[0] == 0'u8:
    result.err = "X.509 serial number must be positive"
    return
  if result.certificate.serialNumber.len > 20:
    result.err = "X.509 serial number exceeds 20 bytes"
    return
  innerAlg = parseAlgorithmOid(A, Tbs.children[base + 1])
  outerAlg = parseAlgorithmOid(A, Cert.children[1])
  if not innerAlg.ok or not outerAlg.ok or innerAlg.value != outerAlg.value:
    result.err = "X.509 inner and outer signature algorithms disagree"
    return
  if outerAlg.value notin supportedX509SignatureOids:
    result.err = "X.509 signature algorithm is unsupported: " & outerAlg.value
    return
  result.certificate.signatureAlgorithm = outerAlg.value
  if requireDerShape(Tbs.children[base + 2], dcUniversal, derTagSequence,
      true).len > 0:
    result.err = "X.509 issuer Name is not a SEQUENCE"
    return
  result.certificate.issuerDer = derEncoded(A, Tbs.children[base + 2])
  if requireDerShape(Tbs.children[base + 3], dcUniversal, derTagSequence,
      true).len > 0:
    result.err = "X.509 validity is not a SEQUENCE"
    return
  Validity = readDerChildren(A, Tbs.children[base + 3])
  if not Validity.ok or Validity.children.len != 2:
    result.err = "X.509 validity must have two times"
    return
  t0 = parseX509Time(A, Validity.children[0])
  t1 = parseX509Time(A, Validity.children[1])
  if not t0.ok or not t1.ok or t1.unix <= t0.unix:
    result.err = if not t0.ok: t0.err elif not t1.ok: t1.err else: "X.509 validity range is invalid"
    return
  result.certificate.notBeforeUnix = t0.unix
  result.certificate.notAfterUnix = t1.unix
  if requireDerShape(Tbs.children[base + 4], dcUniversal, derTagSequence,
      true).len > 0:
    result.err = "X.509 subject Name is not a SEQUENCE"
    return
  result.certificate.subjectDer = derEncoded(A, Tbs.children[base + 4])
  result.certificate.publicKeySpki = derEncoded(A, Tbs.children[base + 5])
  spkiAlg = parseSpkiAlgorithmOid(result.certificate.publicKeySpki)
  if not spkiAlg.ok:
    result.err = spkiAlg.err
    return
  result.certificate.publicKeyAlgorithm = spkiAlg.value
  if spkiAlg.value == oidEd25519:
    # Keep the raw 32-byte form so the pinned Ed25519 path stays unchanged.
    spki = parseEd25519Spki(result.certificate.publicKeySpki)
    if not spki.ok:
      result.err = spki.err
      return
    result.certificate.publicKey = spki.publicKey
  elif spkiAlg.value == oidRsaEncryption or spkiAlg.value == oidEcPublicKey:
    # RSA and EC keys stay in SPKI form; the chain verifier decodes them.
    result.certificate.publicKey = @[]
  else:
    result.err = "X.509 public-key algorithm is unsupported: " & spkiAlg.value
    return
  i = base + 6
  while i < Tbs.children.len:
    if Tbs.children[i].tagClass != dcContext or
        Tbs.children[i].tagNumber != 3'u8 or not Tbs.children[i].constructed:
      result.err = "controlled X.509 profile has an unsupported optional field"
      return
    if extensionsSeen:
      result.err = "X.509 extensions wrapper is duplicated"
      return
    extensionsSeen = true
    result.err = parseExtensions(A, Tbs.children[i], result.certificate)
    if result.err.len > 0:
      return
    i = i + 1
  if requireDerShape(Cert.children[2], dcUniversal, derTagBitString,
      false).len > 0:
    result.err = "X.509 signature is not a BIT STRING"
    return
  sigBits = derContent(A, Cert.children[2])
  if sigBits.len < 2 or sigBits[0] != 0'u8:
    result.err = "X.509 signature BIT STRING must be octet aligned"
    return
  if outerAlg.value == oidEd25519 and sigBits.len != 65:
    result.err = "Ed25519 X.509 signature must be 64 aligned bytes"
    return
  result.certificate.signature = sigBits[1 .. ^1]
  result.ok = true

proc parseX509CertificatePem*(s: string): X509ReadResult {.role: {orchestrator}.} =
  ## s: RFC 7468 CERTIFICATE armor.
  var P: PemReadResult = readPemBlock(s, "CERTIFICATE")
  if not P.ok:
    result.err = P.err
    return
  result = parseX509CertificateDer(P.pemBlock.der)
