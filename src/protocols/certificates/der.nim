## ------------------------------------------------------------------
## DER Reader <- strict bounded ASN.1 tag-length-value byte perception
## ------------------------------------------------------------------

import metaPragmas

type
  DerClass* = enum
    dcUniversal,
    dcApplication,
    dcContext,
    dcPrivate

  DerLimits* = object
    maxElementBytes*: int
    maxDepth*: int

  DerElement* = object
    tagClass*: DerClass
    constructed*: bool
    tagNumber*: uint8
    headerStart*: int
    contentStart*: int
    contentLen*: int
    endOffset*: int

  DerReadResult* = object
    ok*: bool
    element*: DerElement
    err*: string

const
  derTagBoolean* = 1'u8
  derTagInteger* = 2'u8
  derTagBitString* = 3'u8
  derTagOctetString* = 4'u8
  derTagNull* = 5'u8
  derTagObjectIdentifier* = 6'u8
  derTagSequence* = 16'u8
  derTagSet* = 17'u8
  derTagUtcTime* = 23'u8
  derTagGeneralizedTime* = 24'u8

proc defaultDerLimits*(): DerLimits {.role: {helper}.} =
  ## Return conservative limits for one certificate or private-key structure.
  result.maxElementBytes = 4 * 1024 * 1024
  result.maxDepth = 32

proc readDerLength(A: openArray[byte], o: var int, n: var int,
    maxBytes: int): string {.role: {parser}.} =
  ## A/o/n/maxBytes: source, mutable offset, decoded length, and allocation bound.
  var
    first: byte = 0
    count, i: int = 0
    value: uint64 = 0
  if o >= A.len:
    return "DER length is missing"
  first = A[o]
  o = o + 1
  if (first and 0x80'u8) == 0'u8:
    n = int(first)
    if n > maxBytes:
      return "DER element exceeds maximum"
    return ""
  count = int(first and 0x7f'u8)
  if count == 0:
    return "DER indefinite length is forbidden"
  if count > 4:
    return "DER length uses too many bytes"
  if o > A.len - count:
    return "DER long length is incomplete"
  if A[o] == 0'u8:
    return "DER length has a leading zero"
  i = 0
  while i < count:
    value = (value shl 8) or uint64(A[o + i])
    i = i + 1
  o = o + count
  if value < 128'u64:
    return "DER length is not minimally encoded"
  if value > uint64(maxBytes) or value > uint64(high(int)):
    return "DER element exceeds maximum"
  n = int(value)
  result = ""

proc readDerElement*(A: openArray[byte], offset: int,
    L: DerLimits = defaultDerLimits()): DerReadResult {.role: {parser}.} =
  ## A/offset/L: untrusted DER bytes, element start, and resource limits.
  var
    o, n: int = 0
    tagByte: byte = 0
  if L.maxElementBytes < 0 or L.maxDepth < 1:
    result.err = "DER limits are invalid"
    return
  if offset < 0 or offset >= A.len:
    result.err = "DER tag is missing"
    return
  o = offset
  tagByte = A[o]
  o = o + 1
  if (tagByte and 0x1f'u8) == 0x1f'u8:
    result.err = "DER high-tag-number form is unsupported"
    return
  result.element.tagClass = DerClass(int(tagByte shr 6))
  result.element.constructed = (tagByte and 0x20'u8) != 0'u8
  result.element.tagNumber = tagByte and 0x1f'u8
  result.err = readDerLength(A, o, n, L.maxElementBytes)
  if result.err.len > 0:
    return
  if n > A.len - o:
    result.err = "DER content is incomplete"
    return
  result.element.headerStart = offset
  result.element.contentStart = o
  result.element.contentLen = n
  result.element.endOffset = o + n
  result.ok = true

proc requireDerShape*(E: DerElement, c: DerClass, tag: uint8,
    constructed: bool): string {.role: {parser}.} =
  ## E/c/tag/constructed: parsed element and required ASN.1 shape.
  if E.tagClass != c or E.tagNumber != tag or E.constructed != constructed:
    return "DER element has an unexpected tag or form"
  result = ""

proc derContent*(A: openArray[byte], E: DerElement): seq[byte] {.role: {parser}.} =
  ## A/E: complete source and previously bounded element.
  var i: int = 0
  if E.contentStart < 0 or E.contentLen < 0 or E.contentStart > A.len or
      E.contentLen > A.len - E.contentStart:
    raise newException(ValueError, "DER content span is invalid")
  result = newSeq[byte](E.contentLen)
  while i < result.len:
    result[i] = A[E.contentStart + i]
    i = i + 1

proc derEncoded*(A: openArray[byte], E: DerElement): seq[byte] {.role: {parser}.} =
  ## A/E: complete source and exact encoded element span.
  var
    n: int = E.endOffset - E.headerStart
    i: int = 0
  if E.headerStart < 0 or n < 0 or E.headerStart > A.len or
      n > A.len - E.headerStart:
    raise newException(ValueError, "DER encoded span is invalid")
  result = newSeq[byte](n)
  while i < n:
    result[i] = A[E.headerStart + i]
    i = i + 1

proc readDerChildren*(A: openArray[byte], E: DerElement,
    L: DerLimits = defaultDerLimits(), depth: int = 1): tuple[
    ok: bool, children: seq[DerElement], err: string] {.role: {parser}.} =
  ## A/E/L/depth: source, constructed parent, limits, and current nesting level.
  var
    o: int = E.contentStart
    R: DerReadResult
  if not E.constructed:
    result.err = "DER primitive element has no children"
    return
  if depth < 1 or depth > L.maxDepth:
    result.err = "DER nesting exceeds maximum"
    return
  while o < E.endOffset:
    R = readDerElement(A, o, L)
    if not R.ok:
      result.err = R.err
      return
    if R.element.endOffset > E.endOffset:
      result.err = "DER child exceeds parent boundary"
      return
    result.children.add(R.element)
    o = R.element.endOffset
  if o != E.endOffset:
    result.err = "DER children do not fill parent"
    return
  result.ok = true

proc validateDerInteger*(A: openArray[byte], E: DerElement,
    allowNegative: bool = false): string {.role: {parser}.} =
  ## A/E/allowNegative: INTEGER bytes and sign policy.
  var first, second: byte = 0
  result = requireDerShape(E, dcUniversal, derTagInteger, false)
  if result.len > 0:
    return
  if E.contentLen == 0:
    return "DER INTEGER is empty"
  first = A[E.contentStart]
  if not allowNegative and (first and 0x80'u8) != 0'u8:
    return "DER INTEGER is negative"
  if E.contentLen > 1:
    second = A[E.contentStart + 1]
    if first == 0'u8 and (second and 0x80'u8) == 0'u8:
      return "DER INTEGER has redundant positive padding"
    if first == 0xff'u8 and (second and 0x80'u8) != 0'u8:
      return "DER INTEGER has redundant negative padding"
  result = ""
