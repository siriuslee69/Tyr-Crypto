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
