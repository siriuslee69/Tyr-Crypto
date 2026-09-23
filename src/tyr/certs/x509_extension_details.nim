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
