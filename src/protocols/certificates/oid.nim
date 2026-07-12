## ---------------------------------------------------------------
## OID Reader <- strict ASN.1 object identifier text normalization
## ---------------------------------------------------------------

import std/strutils
import metaPragmas
import ./der

const
  oidEd25519* = "1.3.101.112"
  oidCommonName* = "2.5.4.3"
  oidSubjectAltName* = "2.5.29.17"
  oidBasicConstraints* = "2.5.29.19"
  oidKeyUsage* = "2.5.29.15"
  oidExtendedKeyUsage* = "2.5.29.37"
  oidServerAuth* = "1.3.6.1.5.5.7.3.1"

proc decodeOidContent(A: openArray[byte]): tuple[ok: bool, value, err: string] {.role: {parser}.} =
  ## A: OBJECT IDENTIFIER content bytes.
  var
    first, arc: uint64 = 0
    i: int = 0
    inArc: bool = false
  if A.len == 0:
    result.err = "OID content is empty"
    return
  while i < A.len:
    if i == 0 and A[i] == 0x80'u8:
      result.err = "OID first arc is not minimally encoded"
      return
    if first > ((uint64.high - uint64(A[i] and 0x7f'u8)) shr 7):
      result.err = "OID first arc overflows uint64"
      return
    first = (first shl 7) or uint64(A[i] and 0x7f'u8)
    i = i + 1
    if (A[i - 1] and 0x80'u8) == 0'u8:
      break
  if i == A.len and (A[i - 1] and 0x80'u8) != 0'u8:
    result.err = "OID first arc is incomplete"
    return
  if first < 40'u64:
    result.value = "0." & $first
  elif first < 80'u64:
    result.value = "1." & $(first - 40'u64)
  else:
    result.value = "2." & $(first - 80'u64)
  while i < A.len:
    if not inArc and A[i] == 0x80'u8:
      result.err = "OID arc is not minimally encoded"
      return
    if arc > ((uint64.high - uint64(A[i] and 0x7f'u8)) shr 7):
      result.err = "OID arc overflows uint64"
      return
    arc = (arc shl 7) or uint64(A[i] and 0x7f'u8)
    inArc = true
    if (A[i] and 0x80'u8) == 0'u8:
      result.value.add("." & $arc)
      arc = 0'u64
      inArc = false
    i = i + 1
  if inArc:
    result.err = "OID arc is incomplete"
    return
  result.ok = true

proc decodeDerOid*(A: openArray[byte], E: DerElement): tuple[
    ok: bool, value, err: string] {.role: {parser}.} =
  ## A/E: complete DER source and OBJECT IDENTIFIER element.
  var shape: string = requireDerShape(E, dcUniversal, derTagObjectIdentifier,
    false)
  if shape.len > 0:
    result.err = shape
    return
  result = decodeOidContent(derContent(A, E))

proc encodeOidArc(v: uint64, A: var seq[byte]) {.role: {dataWriter}.} =
  var
    T: array[10, byte]
    n, i: int = 0
    x: uint64 = v
  T[n] = byte(x and 0x7f'u64)
  n = n + 1
  x = x shr 7
  while x > 0:
    T[n] = byte(x and 0x7f'u64) or 0x80'u8
    n = n + 1
    x = x shr 7
  i = n
  while i > 0:
    i = i - 1
    A.add(T[i])

proc encodeOidContent*(s: string): seq[byte] {.role: {dataWriter}.} =
  ## s: normalized dotted-decimal OID.
  var
    P: seq[string] = s.split('.')
    X: seq[uint64] = @[]
    i: int = 0
  if P.len < 2:
    raise newException(ValueError, "OID needs at least two arcs")
  while i < P.len:
    if P[i].len == 0:
      raise newException(ValueError, "OID arc is empty")
    if P[i].len > 1 and P[i][0] == '0':
      raise newException(ValueError, "OID arc is not normalized")
    for c in P[i]:
      if c < '0' or c > '9':
        raise newException(ValueError, "OID arc is invalid")
    try:
      X.add(uint64(parseBiggestUInt(P[i])))
    except ValueError:
      raise newException(ValueError, "OID arc is invalid")
    i = i + 1
  if X[0] > 2'u64 or (X[0] < 2'u64 and X[1] > 39'u64):
    raise newException(ValueError, "OID first arcs are invalid")
  if X[0] == 2'u64 and X[1] > uint64.high - 80'u64:
    raise newException(ValueError, "OID first arcs overflow uint64")
  encodeOidArc(X[0] * 40'u64 + X[1], result)
  i = 2
  while i < X.len:
    encodeOidArc(X[i], result)
    i = i + 1
