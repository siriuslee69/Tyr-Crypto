## ------------------------------------------------------------
## Falcon Codec <- key and signature bit-packing helpers
## ------------------------------------------------------------

import ./util

const
  falconMaxSmallBits*: array[11, uint8] = [
    0'u8, 8'u8, 8'u8, 8'u8, 8'u8, 8'u8, 7'u8, 7'u8, 6'u8, 6'u8, 5'u8
  ]

  falconMaxLargeBits*: array[11, uint8] = [
    0'u8, 8'u8, 8'u8, 8'u8, 8'u8, 8'u8, 8'u8, 8'u8, 8'u8, 8'u8, 8'u8
  ]

  falconMaxSigBits*: array[11, uint8] = [
    0'u8, 10'u8, 11'u8, 11'u8, 12'u8, 12'u8, 12'u8, 12'u8, 12'u8, 12'u8, 12'u8
  ]

proc modQEncodeLen*(logn: int): int {.inline.} =
  ((mkn(logn) * 14) + 7) shr 3

proc trimEncodeLen*(logn, bits: int): int {.inline.} =
  ((mkn(logn) * bits) + 7) shr 3

proc modQEncode*(dst: var openArray[byte], x: openArray[uint16], logn: int): int =
  var
    n = mkn(logn)
    outLen = modQEncodeLen(logn)
    acc: uint32 = 0
    accLen: int = 0
    u: int = 0
    v: int = 0
  if x.len != n or dst.len < outLen:
    return 0
  while u < n:
    if x[u] >= 12289'u16:
      return 0
    u = u + 1
  u = 0
  while u < n:
    acc = (acc shl 14) or uint32(x[u])
    accLen = accLen + 14
    while accLen >= 8:
      accLen = accLen - 8
      dst[v] = byte(acc shr accLen)
      v = v + 1
    u = u + 1
  if accLen > 0:
    dst[v] = byte(acc shl (8 - accLen))
  outLen

proc modQDecode*(dst: var openArray[uint16], src: openArray[byte], logn: int): int =
  var
    n = mkn(logn)
    inLen = modQEncodeLen(logn)
    acc: uint32 = 0
    accLen: int = 0
    u: int = 0
    v: int = 0
  if dst.len < n or src.len < inLen:
    return 0
  while u < n:
    acc = (acc shl 8) or uint32(src[v])
    accLen = accLen + 8
    v = v + 1
    if accLen >= 14:
      var w = (acc shr (accLen - 14)) and 0x3FFF'u32
      accLen = accLen - 14
      if w >= 12289'u32:
        return 0
      dst[u] = uint16(w)
      u = u + 1
  if (acc and ((1'u32 shl accLen) - 1'u32)) != 0'u32:
    return 0
  inLen

proc trimI16Encode*(dst: var openArray[byte], x: openArray[int16], logn, bits: int): int =
  var
    n = mkn(logn)
    maxv = (1 shl (bits - 1)) - 1
    minv = -maxv
    outLen = trimEncodeLen(logn, bits)
    acc: uint32 = 0
    accLen: int = 0
    mask = (1'u32 shl bits) - 1'u32
    u: int = 0
    v: int = 0
  if x.len != n or dst.len < outLen:
    return 0
  while u < n:
    if x[u] < int16(minv) or x[u] > int16(maxv):
      return 0
    u = u + 1
  u = 0
  while u < n:
    acc = (acc shl bits) or (uint32(cast[uint16](x[u])) and mask)
    accLen = accLen + bits
    while accLen >= 8:
      accLen = accLen - 8
      dst[v] = byte(acc shr accLen)
      v = v + 1
    u = u + 1
  if accLen > 0:
    dst[v] = byte(acc shl (8 - accLen))
  outLen

proc trimI16Decode*(dst: var openArray[int16], src: openArray[byte], logn, bits: int): int =
  var
    n = mkn(logn)
    inLen = trimEncodeLen(logn, bits)
    acc: uint32 = 0
    accLen: int = 0
    mask1 = (1'u32 shl bits) - 1'u32
    mask2 = 1'u32 shl (bits - 1)
    u: int = 0
    v: int = 0
  if dst.len < n or src.len < inLen:
    return 0
  while u < n:
    acc = (acc shl 8) or uint32(src[v])
    accLen = accLen + 8
    v = v + 1
    while accLen >= bits and u < n:
      var w = (acc shr (accLen - bits)) and mask1
      accLen = accLen - bits
      w = w or (0'u32 - (w and mask2))
      if w == (0'u32 - mask2):
        return 0
      dst[u] = cast[int16](cast[int32](w))
      u = u + 1
  if (acc and ((1'u32 shl accLen) - 1'u32)) != 0'u32:
    return 0
  inLen

proc trimI8Encode*(dst: var openArray[byte], x: openArray[int8], logn, bits: int): int =
  var
    n = mkn(logn)
    maxv = (1 shl (bits - 1)) - 1
    minv = -maxv
    outLen = trimEncodeLen(logn, bits)
    acc: uint32 = 0
    accLen: int = 0
    mask = (1'u32 shl bits) - 1'u32
    u: int = 0
    v: int = 0
  if x.len != n or dst.len < outLen:
    return 0
  while u < n:
    if x[u] < int8(minv) or x[u] > int8(maxv):
      return 0
    u = u + 1
  u = 0
  while u < n:
    acc = (acc shl bits) or (uint32(cast[uint8](x[u])) and mask)
    accLen = accLen + bits
    while accLen >= 8:
      accLen = accLen - 8
      dst[v] = byte(acc shr accLen)
      v = v + 1
    u = u + 1
  if accLen > 0:
    dst[v] = byte(acc shl (8 - accLen))
  outLen

proc trimI8Decode*(dst: var openArray[int8], src: openArray[byte], logn, bits: int): int =
  var
    n = mkn(logn)
    inLen = trimEncodeLen(logn, bits)
    acc: uint32 = 0
    accLen: int = 0
    mask1 = (1'u32 shl bits) - 1'u32
    mask2 = 1'u32 shl (bits - 1)
    u: int = 0
    v: int = 0
  if dst.len < n or src.len < inLen:
    return 0
  while u < n:
    acc = (acc shl 8) or uint32(src[v])
    accLen = accLen + 8
    v = v + 1
    while accLen >= bits and u < n:
      var w = (acc shr (accLen - bits)) and mask1
      accLen = accLen - bits
      w = w or (0'u32 - (w and mask2))
      if w == (0'u32 - mask2):
        return 0
      dst[u] = cast[int8](cast[int32](w))
      u = u + 1
  if (acc and ((1'u32 shl accLen) - 1'u32)) != 0'u32:
    return 0
  inLen

proc compEncode*(dst: var openArray[byte], x: openArray[int16], logn: int): int =
  var
    n = mkn(logn)
    acc: uint32 = 0
    accLen: int = 0
    u: int = 0
    v: int = 0
  if x.len != n:
    return 0
  while u < n:
    if x[u] < -2047'i16 or x[u] > 2047'i16:
      return 0
    u = u + 1
  u = 0
  while u < n:
    var
      t = int(x[u])
      w: int
    acc = acc shl 1
    if t < 0:
      t = -t
      acc = acc or 1'u32
    w = t
    acc = acc shl 7
    acc = acc or uint32(w and 127)
    w = w shr 7
    accLen = accLen + 8
    acc = acc shl (w + 1)
    acc = acc or 1'u32
    accLen = accLen + w + 1
    while accLen >= 8:
      accLen = accLen - 8
      if v >= dst.len:
        return 0
      dst[v] = byte(acc shr accLen)
      v = v + 1
    u = u + 1
  if accLen > 0:
    if v >= dst.len:
      return 0
    dst[v] = byte(acc shl (8 - accLen))
    v = v + 1
  v

proc compDecode*(dst: var openArray[int16], src: openArray[byte], logn: int): int =
  var
    n = mkn(logn)
    acc: uint32 = 0
    accLen: int = 0
    u: int = 0
    v: int = 0
  if dst.len < n:
    return 0
  while u < n:
    var
      b: uint32
      s: uint32
      m: uint32
    if v >= src.len:
      return 0
    acc = (acc shl 8) or uint32(src[v])
    b = acc shr accLen
    s = b and 128'u32
    m = b and 127'u32
    v = v + 1
    while true:
      if accLen == 0:
        if v >= src.len:
          return 0
        acc = (acc shl 8) or uint32(src[v])
        accLen = 8
        v = v + 1
      accLen = accLen - 1
      if ((acc shr accLen) and 1'u32) != 0'u32:
        break
      m = m + 128'u32
      if m > 2047'u32:
        return 0
    if s != 0'u32 and m == 0'u32:
      return 0
    dst[u] = if s != 0'u32: -int16(m) else: int16(m)
    u = u + 1
  if (acc and ((1'u32 shl accLen) - 1'u32)) != 0'u32:
    return 0
  v
