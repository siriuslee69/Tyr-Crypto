## ---------------------------------------------------------------
## Frodo Util <- packing, endian, and constant-time Frodo helpers
## ---------------------------------------------------------------

import ../../helpers/otter_support

proc frodoPackInto*(dst: var openArray[byte], input: openArray[uint16], lsb: int)
proc frodoUnpackInto*(dst: var openArray[uint16], input: openArray[byte], lsb: int)

proc loadU16Le*(A: openArray[byte], o: int = 0): uint16 {.inline.} =
  ## Load one 16-bit little-endian word.
  result = uint16(A[o]) or (uint16(A[o + 1]) shl 8)

proc storeU16Le*(A: var openArray[byte], o: int, v: uint16) {.inline.} =
  ## Store one 16-bit little-endian word.
  A[o] = byte(v and 0xff'u16)
  A[o + 1] = byte((v shr 8) and 0xff'u16)

proc wordsToBytesLe*(W: openArray[uint16]): seq[byte] =
  ## Serialize a word vector in little-endian order.
  otterSpan("frodo.wordsToBytesLe"):
    var
      i: int = 0
    result = newSeq[byte](W.len * 2)
    i = 0
    while i < W.len:
      storeU16Le(result, i * 2, W[i])
      i = i + 1

proc wordsToBytesLeInto*(dst: var openArray[byte], W: openArray[uint16]) =
  ## Serialize a word vector into a preallocated little-endian byte buffer.
  otterSpan("frodo.wordsToBytesLeInto"):
    var
      i: int = 0
    if dst.len != W.len * 2:
      raise newException(ValueError, "Frodo wordsToBytesLeInto length mismatch")
    i = 0
    while i < W.len:
      storeU16Le(dst, i * 2, W[i])
      i = i + 1

proc bytesToWordsLe*(A: openArray[byte]): seq[uint16] =
  ## Deserialize a byte vector into little-endian words.
  otterSpan("frodo.bytesToWordsLe"):
    var
      i: int = 0
    if (A.len and 1) != 0:
      raise newException(ValueError, "Frodo byte input must have even length")
    result = newSeq[uint16](A.len div 2)
    i = 0
    while i < result.len:
      result[i] = loadU16Le(A, i * 2)
      i = i + 1

proc bytesToWordsLeInto*(dst: var openArray[uint16], A: openArray[byte]) =
  ## Deserialize bytes into a preallocated little-endian word buffer.
  otterSpan("frodo.bytesToWordsLeInto"):
    var
      i: int = 0
    if (A.len and 1) != 0:
      raise newException(ValueError, "Frodo byte input must have even length")
    if dst.len != A.len div 2:
      raise newException(ValueError, "Frodo bytesToWordsLeInto length mismatch")
    i = 0
    while i < dst.len:
      dst[i] = loadU16Le(A, i * 2)
      i = i + 1

proc clearBytes*(A: var seq[byte]) =
  ## Zero a byte sequence in place.
  var
    i: int = 0
  i = 0
  while i < A.len:
    A[i] = 0'u8
    i = i + 1

proc clearWords*(W: var seq[uint16]) =
  ## Zero a word sequence in place.
  var
    i: int = 0
  i = 0
  while i < W.len:
    W[i] = 0'u16
    i = i + 1

proc frodoPack*(outLen: int, input: openArray[uint16], lsb: int): seq[byte] =
  ## Pack `lsb` low bits from each Frodo word into a byte string.
  otterSpan("frodo.frodoPack"):
    result = newSeq[byte](outLen)
    frodoPackInto(result, input, lsb)

proc frodoPackInto*(dst: var openArray[byte], input: openArray[uint16], lsb: int) =
  ## Pack `lsb` low bits from each Frodo word into a preallocated byte string.
  otterSpan("frodo.frodoPackInto"):
    var
      i: int = 0
      j: int = 0
      w: uint16 = 0
      bits: int = 0
      b: int = 0
      nbits: int = 0
      mask: uint16 = 0
      t: uint8 = 0
    if lsb == 16:
      if dst.len != input.len * 2:
        raise newException(ValueError, "Frodo packed byte length mismatch")
      i = 0
      while i < input.len:
        dst[i * 2] = byte((input[i] shr 8) and 0xff'u16)
        dst[i * 2 + 1] = byte(input[i] and 0xff'u16)
        i = i + 1
      return
    i = 0
    while i < dst.len:
      dst[i] = 0'u8
      i = i + 1
    i = 0
    j = 0
    while i < dst.len and (j < input.len or (j == input.len and bits > 0)):
      b = 0
      while b < 8:
        nbits = min(8 - b, bits)
        mask = uint16((1 shl nbits) - 1)
        t = uint8((w shr (bits - nbits)) and mask)
        dst[i] = dst[i] + (t shl (8 - b - nbits))
        b = b + nbits
        bits = bits - nbits
        w = w and not (mask shl bits)
        if bits == 0:
          if j < input.len:
            w = input[j]
            bits = lsb
            j = j + 1
          else:
            break
      if b == 8:
        i = i + 1

proc frodoUnpack*(outLen: int, input: openArray[byte], lsb: int): seq[uint16] =
  ## Unpack Frodo words from a packed byte string.
  otterSpan("frodo.frodoUnpack"):
    result = newSeq[uint16](outLen)
    frodoUnpackInto(result, input, lsb)

proc frodoUnpackInto*(dst: var openArray[uint16], input: openArray[byte], lsb: int) =
  ## Unpack Frodo words into a preallocated word buffer.
  otterSpan("frodo.frodoUnpackInto"):
    var
      i: int = 0
      j: int = 0
      w: uint8 = 0
      bits: int = 0
      b: int = 0
      nbits: int = 0
      mask: uint16 = 0
      t: uint8 = 0
    if lsb == 16:
      if input.len != dst.len * 2:
        raise newException(ValueError, "Frodo packed word length mismatch")
      i = 0
      while i < dst.len:
        dst[i] = (uint16(input[i * 2]) shl 8) or uint16(input[i * 2 + 1])
        i = i + 1
      return
    i = 0
    while i < dst.len:
      dst[i] = 0'u16
      i = i + 1
    i = 0
    j = 0
    while i < dst.len and (j < input.len or (j == input.len and bits > 0)):
      b = 0
      while b < lsb:
        nbits = min(lsb - b, bits)
        mask = uint16((1 shl nbits) - 1)
        t = uint8((w shr (bits - nbits)) and uint8(mask))
        dst[i] = dst[i] + (uint16(t) shl (lsb - b - nbits))
        b = b + nbits
        bits = bits - nbits
        w = w and not (uint8(mask) shl bits)
        if bits == 0:
          if j < input.len:
            w = input[j]
            bits = 8
            j = j + 1
          else:
            break
      if b == lsb:
        i = i + 1

proc ctVerifyWords*(A, B: openArray[uint16]): int8 =
  ## Return `0` when arrays match, else `-1`, in constant time.
  otterSpan("frodo.ctVerifyWords"):
    var
      r: uint16 = 0
      i: int = 0
    if A.len != B.len:
      return -1'i8
    i = 0
    while i < A.len:
      r = r or (A[i] xor B[i])
      i = i + 1
    r = cast[uint16]((-(cast[int16](r shr 1)) or -(cast[int16](r and 1'u16))) shr 15)
    result = cast[int8](r)

proc ctSelectBytes*(dst: var openArray[byte], A, B: openArray[byte], selector: int8) =
  ## Copy `A` into `dst` when selector is `0`, else copy `B`.
  var
    i: int = 0
    mask: uint8 = cast[uint8](selector)
  if dst.len != A.len or A.len != B.len:
    raise newException(ValueError, "ctSelect byte arrays must have matching lengths")
  i = 0
  while i < dst.len:
    dst[i] = ((not mask) and A[i]) or (mask and B[i])
    i = i + 1
