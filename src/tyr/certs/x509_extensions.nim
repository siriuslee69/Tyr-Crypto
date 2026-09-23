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

include "x509_extension_details.nim"
include "x509_extension_parser.nim"
