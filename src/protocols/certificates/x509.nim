## -----------------------------------------------------------------------
## X.509 Reader <- controlled Ed25519 certificate truth-state construction
## -----------------------------------------------------------------------

import std/[strutils, times]
import metaPragmas
import ./[der, keys, oid, pem]

type
  X509Certificate* = object
    tbsCertificate*: seq[byte]
    serialNumber*: seq[byte]
    signatureAlgorithm*: string
    issuerDer*: seq[byte]
    subjectDer*: seq[byte]
    notBeforeUnix*: int64
    notAfterUnix*: int64
    publicKey*: seq[byte]
    signature*: seq[byte]
    isCa*: bool
    hasBasicConstraints*: bool
    hasKeyUsage*: bool
    canDigitalSignature*: bool
    canKeyCertSign*: bool
    dnsNames*: seq[string]
    ipAddresses*: seq[seq[byte]]
    hasExtendedKeyUsage*: bool
    hasServerAuth*: bool

  X509ReadResult* = object
    ok*: bool
    certificate*: X509Certificate
    err*: string

proc parseDigits(s: string, o, n: int, v: var int): bool {.role: {parser}.} =
  var i: int = 0
  v = 0
  if o < 0 or n <= 0 or o > s.len - n:
    return false
  while i < n:
    if s[o + i] < '0' or s[o + i] > '9':
      return false
    v = v * 10 + ord(s[o + i]) - ord('0')
    i = i + 1
  result = true

proc parseX509Time(A: openArray[byte], E: DerElement): tuple[
    ok: bool, unix: int64, err: string] {.role: {parser}.} =
  var
    B: seq[byte] = derContent(A, E)
    s: string = newString(B.len)
    year, month, day, hour, minute, second, o: int = 0
    dt: DateTime
    i: int = 0
  if E.tagClass != dcUniversal or E.constructed or
      E.tagNumber notin {derTagUtcTime, derTagGeneralizedTime}:
    result.err = "X.509 validity field is not a supported time"
    return
  while i < B.len:
    s[i] = char(B[i])
    i = i + 1
  if s.len == 13 and E.tagNumber == derTagUtcTime:
    if not parseDigits(s, 0, 2, year):
      result.err = "X.509 UTC time year is invalid"
      return
    if year >= 50: year = year + 1900
    else: year = year + 2000
    o = 2
  elif s.len == 15 and E.tagNumber == derTagGeneralizedTime:
    if not parseDigits(s, 0, 4, year):
      result.err = "X.509 generalized time year is invalid"
      return
    o = 4
  else:
    result.err = "X.509 time must use seconds and UTC Z form"
    return
  if s[^1] != 'Z' or not parseDigits(s, o, 2, month) or
      not parseDigits(s, o + 2, 2, day) or
      not parseDigits(s, o + 4, 2, hour) or
      not parseDigits(s, o + 6, 2, minute) or
      not parseDigits(s, o + 8, 2, second):
    result.err = "X.509 time fields are invalid"
    return
  try:
    dt = dateTime(year, Month(month), MonthdayRange(day), HourRange(hour),
      MinuteRange(minute), SecondRange(second), 0, utc())
  except RangeDefect, ValueError:
    result.err = "X.509 time is outside calendar bounds"
    return
  result.unix = dt.toTime().toUnix()
  result.ok = true

proc parseAlgorithmOid(A: openArray[byte], E: DerElement): tuple[
    ok: bool, value, err: string] {.role: {parser}.} =
  var C: tuple[ok: bool, children: seq[DerElement], err: string]
  if requireDerShape(E, dcUniversal, derTagSequence, true).len > 0:
    result.err = "X.509 algorithm identifier is invalid"
    return
  C = readDerChildren(A, E)
  if not C.ok or C.children.len != 1:
    result.err = "Ed25519 algorithm parameters must be absent"
    return
  result = decodeDerOid(A, C.children[0])

proc parseBasicConstraints(B: openArray[byte], isCa: var bool): string {.role: {parser}.} =
  var
    R: DerReadResult = readDerElement(B, 0)
    C: tuple[ok: bool, children: seq[DerElement], err: string]
    V: seq[byte] = @[]
  if not R.ok or R.element.endOffset != B.len or
      requireDerShape(R.element, dcUniversal, derTagSequence, true).len > 0:
    return "Basic Constraints value is invalid"
  C = readDerChildren(B, R.element)
  if not C.ok:
    return C.err
  if C.children.len > 1:
    return "Basic Constraints path length is unsupported"
  if C.children.len == 0:
    isCa = false
    return ""
  if requireDerShape(C.children[0], dcUniversal, derTagBoolean, false).len > 0:
    return "Basic Constraints CA field is invalid"
  V = derContent(B, C.children[0])
  if V.len != 1 or V[0] notin {0'u8, 0xff'u8}:
    return "DER BOOLEAN is not canonical"
  isCa = V[0] == 0xff'u8
  result = ""

proc parseKeyUsage(B: openArray[byte], canDigitalSignature,
    canKeyCertSign: var bool): string {.role: {parser}.} =
  var
    R: DerReadResult = readDerElement(B, 0)
    V: seq[byte] = @[]
  if not R.ok or R.element.endOffset != B.len or
      requireDerShape(R.element, dcUniversal, derTagBitString, false).len > 0:
    return "Key Usage value is invalid"
  V = derContent(B, R.element)
  if V.len < 2 or V[0] > 7'u8:
    return "Key Usage BIT STRING is invalid"
  if V.len > 3:
    return "Key Usage BIT STRING is too long"
  if V[0] > 0'u8 and (V[^1] and byte((1'u16 shl V[0]) - 1'u16)) != 0'u8:
    return "Key Usage BIT STRING has nonzero unused bits"
  if V.len > 2 and V[^1] == 0'u8:
    return "Key Usage BIT STRING is not minimally encoded"
  canDigitalSignature = (V[1] and 0x80'u8) != 0'u8
  canKeyCertSign = (V[1] and 0x04'u8) != 0'u8
  result = ""

proc parseSubjectAltName(B: openArray[byte], C: var X509Certificate): string {.role: {truthBuilder}.} =
  var
    R: DerReadResult = readDerElement(B, 0)
    G: tuple[ok: bool, children: seq[DerElement], err: string]
    V: seq[byte] = @[]
    s: string = ""
    i, j: int = 0
  if not R.ok or R.element.endOffset != B.len or
      requireDerShape(R.element, dcUniversal, derTagSequence, true).len > 0:
    return "Subject Alternative Name value is invalid"
  G = readDerChildren(B, R.element)
  if not G.ok:
    return G.err
  while i < G.children.len:
    if G.children[i].tagClass != dcContext or G.children[i].constructed:
      return "Subject Alternative Name entry form is unsupported"
    V = derContent(B, G.children[i])
    case G.children[i].tagNumber
    of 2'u8:
      if V.len == 0:
        return "DNS Subject Alternative Name is empty"
      s = newString(V.len)
      j = 0
      while j < V.len:
        if V[j] < 0x21'u8 or V[j] > 0x7e'u8:
          return "DNS Subject Alternative Name is not visible ASCII"
        s[j] = char(V[j])
        j = j + 1
      C.dnsNames.add(s.toLowerAscii())
    of 7'u8:
      if V.len notin {4, 16}:
        return "IP Subject Alternative Name length is invalid"
      C.ipAddresses.add(V)
    else:
      discard
    i = i + 1
  result = ""

proc parseExtendedKeyUsage(B: openArray[byte], hasServerAuth: var bool): string {.role: {parser}.} =
  var
    R: DerReadResult = readDerElement(B, 0)
    U: tuple[ok: bool, children: seq[DerElement], err: string]
    O: tuple[ok: bool, value, err: string]
    i: int = 0
  if not R.ok or R.element.endOffset != B.len or
      requireDerShape(R.element, dcUniversal, derTagSequence, true).len > 0:
    return "Extended Key Usage value is invalid"
  U = readDerChildren(B, R.element)
  if not U.ok:
    return U.err
  while i < U.children.len:
    O = decodeDerOid(B, U.children[i])
    if not O.ok:
      return O.err
    if O.value == oidServerAuth:
      hasServerAuth = true
    i = i + 1
  result = ""

proc parseExtensions(A: openArray[byte], E: DerElement,
    C: var X509Certificate): string {.role: {truthBuilder}.} =
  var
    Outer, Exts, Fields: tuple[ok: bool, children: seq[DerElement], err: string]
    O: tuple[ok: bool, value, err: string]
    critical: bool = false
    valueIndex, i: int = 0
    V, BoolBytes: seq[byte] = @[]
    known: bool = false
    seenOids: seq[string] = @[]
  if E.tagClass != dcContext or E.tagNumber != 3'u8 or not E.constructed:
    return "X.509 extensions wrapper is invalid"
  Outer = readDerChildren(A, E)
  if not Outer.ok or Outer.children.len != 1:
    return "X.509 extensions wrapper must contain one sequence"
  if requireDerShape(Outer.children[0], dcUniversal, derTagSequence,
      true).len > 0:
    return "X.509 extensions value is not a SEQUENCE"
  Exts = readDerChildren(A, Outer.children[0])
  if not Exts.ok:
    return Exts.err
  while i < Exts.children.len:
    if requireDerShape(Exts.children[i], dcUniversal, derTagSequence,
        true).len > 0:
      return "X.509 extension is not a SEQUENCE"
    Fields = readDerChildren(A, Exts.children[i])
    if not Fields.ok or Fields.children.len < 2 or Fields.children.len > 3:
      return "X.509 extension has invalid fields"
    O = decodeDerOid(A, Fields.children[0])
    if not O.ok:
      return O.err
    if O.value in seenOids:
      return "X.509 extension is duplicated: " & O.value
    seenOids.add(O.value)
    critical = false
    valueIndex = 1
    if Fields.children.len == 3:
      if requireDerShape(Fields.children[1], dcUniversal, derTagBoolean,
          false).len > 0:
        return "X.509 extension critical flag is invalid"
      BoolBytes = derContent(A, Fields.children[1])
      if BoolBytes.len != 1 or BoolBytes[0] notin {0'u8, 0xff'u8}:
        return "X.509 extension critical flag is not canonical"
      if BoolBytes[0] == 0'u8:
        return "X.509 extension DEFAULT FALSE must be absent"
      critical = BoolBytes[0] == 0xff'u8
      valueIndex = 2
    if requireDerShape(Fields.children[valueIndex], dcUniversal,
        derTagOctetString, false).len > 0:
      return "X.509 extension value is not an OCTET STRING"
    V = derContent(A, Fields.children[valueIndex])
    known = true
    case O.value
    of oidBasicConstraints:
      C.hasBasicConstraints = true
      result = parseBasicConstraints(V, C.isCa)
    of oidSubjectAltName:
      result = parseSubjectAltName(V, C)
    of oidExtendedKeyUsage:
      C.hasExtendedKeyUsage = true
      result = parseExtendedKeyUsage(V, C.hasServerAuth)
    of oidKeyUsage:
      C.hasKeyUsage = true
      result = parseKeyUsage(V, C.canDigitalSignature, C.canKeyCertSign)
    of "2.5.29.14", "2.5.29.35":
      discard
    else:
      known = false
    if result.len > 0:
      return
    if critical and not known:
      return "X.509 certificate has an unsupported critical extension: " & O.value
    i = i + 1
  result = ""

proc parseX509CertificateDer*(A: openArray[byte]): X509ReadResult {.role: {truthBuilder}.} =
  ## A: one complete DER X.509 certificate.
  var
    Root: DerReadResult = readDerElement(A, 0)
    Cert, Tbs, Validity: tuple[ok: bool, children: seq[DerElement], err: string]
    outerAlg, innerAlg: tuple[ok: bool, value, err: string]
    spki: Ed25519SpkiResult
    sigBits: seq[byte] = @[]
    i, base: int = 0
    extensionsSeen: bool = false
    t0, t1: tuple[ok: bool, unix: int64, err: string]
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
  if not innerAlg.ok or not outerAlg.ok or innerAlg.value != outerAlg.value or
      outerAlg.value != oidEd25519:
    result.err = "X.509 signature algorithm is not matching Ed25519"
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
  spki = parseEd25519Spki(derEncoded(A, Tbs.children[base + 5]))
  if not spki.ok:
    result.err = spki.err
    return
  result.certificate.publicKey = spki.publicKey
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
  if sigBits.len != 65 or sigBits[0] != 0'u8:
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
