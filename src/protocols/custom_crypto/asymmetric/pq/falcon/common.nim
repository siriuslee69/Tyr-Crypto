## ----------------------------------------------------------
## Falcon Common <- hash-to-point and norm acceptance helpers
## ----------------------------------------------------------

import ./shake
import ./util

const
  falconL2Bound*: array[11, uint32] = [
    0'u32,
    101498'u32,
    208714'u32,
    428865'u32,
    892039'u32,
    1852696'u32,
    3842630'u32,
    7959734'u32,
    16468416'u32,
    34034726'u32,
    70265242'u32
  ]

  falconOversampling*: array[11, uint16] = [
    0'u16,
    65'u16,
    67'u16,
    71'u16,
    77'u16,
    86'u16,
    100'u16,
    122'u16,
    154'u16,
    205'u16,
    287'u16
  ]

proc hashToPointVarTime*(ctx: var FalconShake256, x: var openArray[uint16], logn: int) =
  var
    n = mkn(logn)
    remaining = n
    buf: array[2, byte]
  if x.len < n:
    raise newException(ValueError, "Falcon hash-to-point output is too small")
  while remaining > 0:
    extractFalconShake256(ctx, buf)
    var w = (uint32(buf[0]) shl 8) or uint32(buf[1])
    if w < 61445'u32:
      while w >= 12289'u32:
        w = w - 12289'u32
      x[n - remaining] = uint16(w)
      remaining = remaining - 1

proc hashToPointCt*(ctx: var FalconShake256, x: var openArray[uint16], logn: int) =
  var
    n = mkn(logn)
    n2 = n shl 1
    over = int(falconOversampling[logn])
    m = n + over
    tt1 = newSeq[uint16](max(n, 1))
    tt2 = newSeq[uint16](max(m - n2, 0))
    u: int = 0
  if x.len < n:
    raise newException(ValueError, "Falcon hash-to-point output is too small")
  while u < m:
    var
      buf: array[2, byte]
      w: uint32
      wr: uint32
    extractFalconShake256(ctx, buf)
    w = (uint32(buf[0]) shl 8) or uint32(buf[1])
    wr = w - (24578'u32 and (((w - 24578'u32) shr 31) - 1'u32))
    wr = wr - (24578'u32 and (((wr - 24578'u32) shr 31) - 1'u32))
    wr = wr - (12289'u32 and (((wr - 12289'u32) shr 31) - 1'u32))
    wr = wr or (((w - 61445'u32) shr 31) - 1'u32)
    if u < n:
      x[u] = uint16(wr)
    elif u < n2:
      tt1[u - n] = uint16(wr)
    else:
      tt2[u - n2] = uint16(wr)
    u = u + 1
  var p = 1
  while p <= over:
    var
      v: int = 0
      src: ptr uint16
      dst: ptr uint16
      u2: int = 0
    while u2 < m:
      if u2 < n:
        src = addr x[u2]
      elif u2 < n2:
        src = addr tt1[u2 - n]
      else:
        src = addr tt2[u2 - n2]
      let sv = src[]
      let j = u2 - v
      var mk = (uint(sv) shr 15) - 1'u
      v = v + int(mk and 1'u)
      if u2 >= p:
        if (u2 - p) < n:
          dst = addr x[u2 - p]
        elif (u2 - p) < n2:
          dst = addr tt1[(u2 - p) - n]
        else:
          dst = addr tt2[(u2 - p) - n2]
        let dv = dst[]
        mk = mk and (0'u - uint((((j and p) + 0x1FF) shr 9)))
        src[] = uint16(uint(sv) xor (mk and uint(sv xor dv)))
        dst[] = uint16(uint(dv) xor (mk and uint(sv xor dv)))
      u2 = u2 + 1
    p = p shl 1

proc isShort*(s1, s2: openArray[int16], logn: int): bool =
  var
    n = mkn(logn)
    s: uint32 = 0
    ng: uint32 = 0
    u: int = 0
  if s1.len < n or s2.len < n:
    return false
  while u < n:
    var z = int32(s1[u])
    s = s + uint32(z * z)
    ng = ng or s
    z = int32(s2[u])
    s = s + uint32(z * z)
    ng = ng or s
    u = u + 1
  s = s or (0'u32 - (ng shr 31))
  s <= falconL2Bound[logn]

proc isShortHalf*(sqn: uint32, s2: openArray[int16], logn: int): bool =
  var
    n = mkn(logn)
    total = sqn
    ng = 0'u32 - (sqn shr 31)
    u: int = 0
  if s2.len < n:
    return false
  while u < n:
    let z = int32(s2[u])
    total = total + uint32(z * z)
    ng = ng or total
    u = u + 1
  total = total or (0'u32 - (ng shr 31))
  total <= falconL2Bound[logn]
