## --------------------------------------------------------------------
## Certificate Keys <- RFC 8410 Ed25519 SPKI and PKCS#8 strict readers
## --------------------------------------------------------------------

import metaPragmas
import ./[der, oid, pem]

type
  Ed25519SpkiResult* = object
    ok*: bool
    publicKey*: seq[byte]
    err*: string

  Ed25519Pkcs8Result* = object
    ok*: bool
    seed*: seq[byte]
    err*: string

proc requireEd25519Algorithm(A: openArray[byte], E: DerElement): string {.role: {parser}.} =
  var
    C: tuple[ok: bool, children: seq[DerElement], err: string]
    O: tuple[ok: bool, value, err: string]
  result = requireDerShape(E, dcUniversal, derTagSequence, true)
  if result.len > 0:
    return
  C = readDerChildren(A, E)
  if not C.ok:
    return C.err
  if C.children.len != 1:
    return "Ed25519 AlgorithmIdentifier parameters must be absent"
  O = decodeDerOid(A, C.children[0])
  if not O.ok:
    return O.err
  if O.value != oidEd25519:
    return "public-key algorithm is not Ed25519"
  result = ""

proc parseEd25519Spki*(A: openArray[byte]): Ed25519SpkiResult {.role: {truthBuilder}.} =
  ## A: DER SubjectPublicKeyInfo bytes.
  var
    R: DerReadResult = readDerElement(A, 0)
    C: tuple[ok: bool, children: seq[DerElement], err: string]
    B: seq[byte] = @[]
  if not R.ok or R.element.endOffset != A.len:
    result.err = if R.err.len > 0: R.err else: "SPKI has trailing bytes"
    return
  result.err = requireDerShape(R.element, dcUniversal, derTagSequence, true)
  if result.err.len > 0:
    return
  C = readDerChildren(A, R.element)
  if not C.ok or C.children.len != 2:
    result.err = if C.err.len > 0: C.err else: "SPKI must have two fields"
    return
  result.err = requireEd25519Algorithm(A, C.children[0])
  if result.err.len > 0:
    return
  result.err = requireDerShape(C.children[1], dcUniversal, derTagBitString,
    false)
  if result.err.len > 0:
    return
  B = derContent(A, C.children[1])
  if B.len != 33 or B[0] != 0'u8:
    result.err = "Ed25519 SPKI BIT STRING must contain 32 aligned key bytes"
    return
  result.publicKey = B[1 .. ^1]
  result.ok = true

proc parseEd25519PublicKeyPem*(s: string): Ed25519SpkiResult {.role: {orchestrator}.} =
  ## s: RFC 7468 PUBLIC KEY armor.
  var P: PemReadResult = readPemBlock(s, "PUBLIC KEY")
  if not P.ok:
    result.err = P.err
    return
  result = parseEd25519Spki(P.pemBlock.der)

proc parseEd25519Pkcs8*(A: openArray[byte]): Ed25519Pkcs8Result {.role: {truthBuilder}.} =
  ## A: unencrypted RFC 5958/RFC 8410 PrivateKeyInfo bytes.
  var
    R: DerReadResult = readDerElement(A, 0)
    C: tuple[ok: bool, children: seq[DerElement], err: string]
    V, K: seq[byte] = @[]
    nested: DerReadResult
  if not R.ok or R.element.endOffset != A.len:
    result.err = if R.err.len > 0: R.err else: "PKCS#8 has trailing bytes"
    return
  result.err = requireDerShape(R.element, dcUniversal, derTagSequence, true)
  if result.err.len > 0:
    return
  C = readDerChildren(A, R.element)
  if not C.ok or C.children.len != 3:
    result.err = if C.err.len > 0: C.err else: "Ed25519 PKCS#8 must have three fields"
    return
  result.err = validateDerInteger(A, C.children[0])
  if result.err.len > 0:
    return
  V = derContent(A, C.children[0])
  if V.len != 1 or V[0] != 0'u8:
    result.err = "Ed25519 PKCS#8 version must be zero"
    return
  result.err = requireEd25519Algorithm(A, C.children[1])
  if result.err.len > 0:
    return
  result.err = requireDerShape(C.children[2], dcUniversal, derTagOctetString,
    false)
  if result.err.len > 0:
    return
  K = derContent(A, C.children[2])
  nested = readDerElement(K, 0)
  if not nested.ok or nested.element.endOffset != K.len:
    result.err = "Ed25519 PKCS#8 private key wrapper is invalid"
    return
  result.err = requireDerShape(nested.element, dcUniversal,
    derTagOctetString, false)
  if result.err.len > 0:
    return
  result.seed = derContent(K, nested.element)
  if result.seed.len != 32:
    result.seed.setLen(0)
    result.err = "Ed25519 PKCS#8 seed must be 32 bytes"
    return
  result.ok = true

proc parseEd25519PrivateKeyPem*(s: string): Ed25519Pkcs8Result {.role: {orchestrator}.} =
  ## s: unencrypted RFC 7468 PRIVATE KEY armor.
  var P: PemReadResult = readPemBlock(s, "PRIVATE KEY")
  if not P.ok:
    result.err = P.err
    return
  result = parseEd25519Pkcs8(P.pemBlock.der)
