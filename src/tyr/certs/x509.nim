## -----------------------------------------------------------------------
## X.509 Reader <- controlled Ed25519 certificate truth-state construction
## -----------------------------------------------------------------------

import std/[strutils, times]
import runePragmas
import ./[der, keys, oid, pem]

const
  supportedX509SignatureOids* = [
    oidEd25519, oidSha256WithRsa, oidSha384WithRsa, oidSha512WithRsa,
    oidRsassaPss, oidEcdsaWithSha256, oidEcdsaWithSha384
  ] ## signature algorithms this profile is willing to parse and verify

type
  X509Certificate* = object
    tbsCertificate*: seq[byte]
    serialNumber*: seq[byte]
    signatureAlgorithm*: string
    issuerDer*: seq[byte]
    subjectDer*: seq[byte]
    notBeforeUnix*: int64
    notAfterUnix*: int64
    publicKey*: seq[byte]      # raw key bits; Ed25519 keeps its 32-byte form
    publicKeyAlgorithm*: string # SPKI algorithm OID
    publicKeySpki*: seq[byte]   # complete SubjectPublicKeyInfo DER
    signature*: seq[byte]
    isCa*: bool
    hasBasicConstraints*: bool
    hasPathLen*: bool
    pathLen*: int
      ## pathLenConstraint from Basic Constraints: how many CA certificates
      ## may appear BELOW this one. Present on almost every real intermediate,
      ## so a parser that cannot read it cannot read the web PKI.
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
    dt: DateTime = default(DateTime)
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
  var C: tuple[ok: bool, children: seq[DerElement], err: string] =
    (ok: false, children: @[], err: "")
  if requireDerShape(E, dcUniversal, derTagSequence, true).len > 0:
    result.err = "X.509 algorithm identifier is invalid"
    return
  C = readDerChildren(A, E)
  # Ed25519 and ECDSA omit parameters; RSA carries an explicit NULL, and
  # RSASSA-PSS carries a parameter SEQUENCE.
  if not C.ok or C.children.len < 1 or C.children.len > 2:
    result.err = "X.509 algorithm identifier has an unexpected shape"
    return
  result = decodeDerOid(A, C.children[0])

include ./x509_extensions
include ./x509_certificate
