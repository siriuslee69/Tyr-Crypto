## ---------------------------------------------------------------
## PEM Reader <- strict bounded base64 armor for DER certificates
## ---------------------------------------------------------------

import std/[base64, strutils]
import metaPragmas

type
  PemBlock* = object
    label*: string
    der*: seq[byte]

  PemReadResult* = object
    ok*: bool
    pemBlock*: PemBlock
    err*: string

proc isPemLabelChar(c: char): bool {.role: {parser}.} =
  result = (c >= 'A' and c <= 'Z') or (c >= '0' and c <= '9') or
    c == ' ' or c == '-'

proc validatePemLabel(s: string): bool {.role: {parser}.} =
  var i: int = 0
  if s.len == 0 or s[0] == ' ' or s[^1] == ' ':
    return false
  while i < s.len:
    if not isPemLabelChar(s[i]):
      return false
    i = i + 1
  result = true

proc readPemBlock*(s: string, expectedLabel: string = "",
    maxDerBytes: int = 4 * 1024 * 1024): PemReadResult {.role: {parser}.} =
  ## s/expectedLabel/maxDerBytes: one armor block, optional label, and byte bound.
  var
    lines: seq[string] = s.strip().splitLines()
    beginPrefix: string = "-----BEGIN "
    endPrefix: string = "-----END "
    label, endLine, encoded, decoded: string = ""
    i, estimated: int = 0
  if maxDerBytes < 0:
    result.err = "PEM byte limit is invalid"
    return
  if lines.len < 3 or not lines[0].startsWith(beginPrefix) or
      not lines[0].endsWith("-----"):
    result.err = "PEM begin line is invalid"
    return
  label = lines[0][beginPrefix.len ..< lines[0].len - 5]
  if not validatePemLabel(label):
    result.err = "PEM label is invalid"
    return
  if expectedLabel.len > 0 and label != expectedLabel:
    result.err = "PEM label does not match expected type"
    return
  endLine = endPrefix & label & "-----"
  if lines[^1] != endLine:
    result.err = "PEM end line does not match begin line"
    return
  i = 1
  while i < lines.len - 1:
    if lines[i].len == 0 or lines[i].find(':') >= 0:
      result.err = "PEM headers and blank body lines are unsupported"
      return
    encoded.add(lines[i].strip())
    i = i + 1
  if encoded.len == 0 or encoded.len mod 4 != 0:
    result.err = "PEM base64 body length is invalid"
    return
  estimated = (encoded.len div 4) * 3
  if estimated > maxDerBytes + 2:
    result.err = "PEM decoded body exceeds maximum"
    return
  try:
    decoded = base64.decode(encoded)
  except ValueError:
    result.err = "PEM base64 body is invalid"
    return
  if decoded.len > maxDerBytes:
    result.err = "PEM decoded body exceeds maximum"
    return
  result.pemBlock.label = label
  result.pemBlock.der = newSeq[byte](decoded.len)
  i = 0
  while i < decoded.len:
    result.pemBlock.der[i] = byte(ord(decoded[i]))
    i = i + 1
  result.ok = true
