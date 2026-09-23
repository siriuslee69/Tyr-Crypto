## X.509 extension parsers included by x509.nim.
##
## These helpers share x509.nim's certificate types and DER imports.

proc parseBasicConstraints(B: openArray[byte], isCa: var bool,
    hasPathLen: var bool, pathLen: var int): string {.role: {parser}.} =
  ## BasicConstraints ::= SEQUENCE {
  ##   cA                 BOOLEAN DEFAULT FALSE,
  ##   pathLenConstraint  INTEGER (0..MAX) OPTIONAL }
  ##
  ## Both fields are optional, so the children are identified by tag rather
  ## than by position.
  var
    R: DerReadResult = readDerElement(B, 0)
    C: tuple[ok: bool, children: seq[DerElement], err: string] =
      (ok: false, children: @[], err: "")
    V: seq[byte] = @[]
    i: int = 0
    shape: string = ""
  isCa = false
  hasPathLen = false
  pathLen = 0
  if not R.ok or R.element.endOffset != B.len or
      requireDerShape(R.element, dcUniversal, derTagSequence, true).len > 0:
    return "Basic Constraints value is invalid"
  C = readDerChildren(B, R.element)
  if not C.ok:
    return C.err
  if C.children.len > 2:
    return "Basic Constraints has too many fields"
  while i < C.children.len:
    if requireDerShape(C.children[i], dcUniversal, derTagBoolean,
        false).len == 0:
      if i != 0 or isCa:
        return "Basic Constraints CA field is out of order"
      V = derContent(B, C.children[i])
      if V.len != 1 or V[0] notin {0'u8, 0xff'u8}:
        return "DER BOOLEAN is not canonical"
      ## DEFAULT FALSE means an encoder must omit the field when it is false.
      if V[0] == 0'u8:
        return "Basic Constraints encodes a defaulted CA field"
      isCa = true
      i = i + 1
      continue
    shape = validateDerInteger(B, C.children[i])
    if shape.len > 0:
      return "Basic Constraints path length is invalid: " & shape
    if hasPathLen:
      return "Basic Constraints repeats the path length"
    V = derContent(B, C.children[i])
    ## A path length no chain can reach is not worth representing exactly;
    ## anything past the depth limit is clamped rather than rejected, since
    ## it constrains nothing this library would ever accept.
    if V.len > 4:
      pathLen = high(int32)
    else:
      pathLen = 0
      for b in V:
        pathLen = (pathLen shl 8) or int(b)
    hasPathLen = true
    i = i + 1
  if hasPathLen and not isCa:
    return "Basic Constraints sets a path length on a non-CA"
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
    G: tuple[ok: bool, children: seq[DerElement], err: string] =
      (ok: false, children: @[], err: "")
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
    U: tuple[ok: bool, children: seq[DerElement], err: string] =
      (ok: false, children: @[], err: "")
    O: tuple[ok: bool, value, err: string] = (ok: false, value: "", err: "")
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
    Outer, Exts, Fields: tuple[ok: bool, children: seq[DerElement], err: string] =
      (ok: false, children: @[], err: "")
    O: tuple[ok: bool, value, err: string] = (ok: false, value: "", err: "")
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
      result = parseBasicConstraints(V, C.isCa, C.hasPathLen, C.pathLen)
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
