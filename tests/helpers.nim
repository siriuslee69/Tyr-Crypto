proc toBytes*(s: string): seq[byte] =
  ## Convert a string into raw byte sequence.
  result = newSeq[byte](s.len)
  for i, ch in s:
    result[i] = byte(ord(ch))

proc toHex*(data: openArray[byte]): string =
  ## Render the byte sequence as a lowercase hexadecimal string.
  result = newString(data.len * 2)
  const digits = "0123456789abcdef"
  for i, b in data:
    let hi = int((b shr 4) and 0xF)
    let lo = int(b and 0xF)
    result[2 * i] = digits[hi]
    result[2 * i + 1] = digits[lo]

proc hexToBytes*(hex: string): seq[byte] =
  ## Decode a hexadecimal string into raw bytes.
  proc hexValue(ch: char): int =
    if ch >= '0' and ch <= '9':
      return ord(ch) - ord('0')
    if ch >= 'a' and ch <= 'f':
      return ord(ch) - ord('a') + 10
    if ch >= 'A' and ch <= 'F':
      return ord(ch) - ord('A') + 10
    return -1

  var clean = newStringOfCap(hex.len)
  for ch in hex:
    if ch notin {' ', '\n', '\r', '\t'}:
      clean.add(ch)
  if clean.len mod 2 != 0:
    raise newException(ValueError, "hex string must have even length")

  result = newSeq[byte](clean.len div 2)
  for i in 0 ..< result.len:
    let hi = hexValue(clean[2 * i])
    let lo = hexValue(clean[2 * i + 1])
    if hi < 0 or lo < 0:
      raise newException(ValueError, "invalid hex character")
    result[i] = byte((hi shl 4) or lo)
