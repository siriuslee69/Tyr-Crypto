## -------------------------------------------------------------------
## Falcon Vrfy <- NTT/public-key verification helpers for the Nim port
## -------------------------------------------------------------------

import ./common
import ./util

const
  falconMqQ* = 12289'u32
  falconMqQ0I = 12287'u32
  falconMqR = 4091'u32
  falconMqR2 = 10952'u32

include ./vrfy_tables

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; decoding, malformed-input rejection, and verification rules for `mqConvSmall`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc mqConvSmall(x: int): uint32 {.inline.} =
  var y = uint32(x)
  y = y + (falconMqQ and (0'u32 - (y shr 31)))
  y

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; decoding, malformed-input rejection, and verification rules for `mqAdd`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc mqAdd(x, y: uint32): uint32 {.inline.} =
  var d = x + y - falconMqQ
  d = d + (falconMqQ and (0'u32 - (d shr 31)))
  d

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; decoding, malformed-input rejection, and verification rules for `mqSub`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc mqSub(x, y: uint32): uint32 {.inline.} =
  var d = x - y
  d = d + (falconMqQ and (0'u32 - (d shr 31)))
  d

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; decoding, malformed-input rejection, and verification rules for `mqRshift1`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc mqRshift1(x: uint32): uint32 {.inline.} =
  (x + (falconMqQ and (0'u32 - (x and 1'u32)))) shr 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; decoding, malformed-input rejection, and verification rules for `mqMontyMul`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc mqMontyMul(x, y: uint32): uint32 {.inline.} =
  var
    z = x * y
    w = ((z * falconMqQ0I) and 0xFFFF'u32) * falconMqQ
  z = (z + w) shr 16
  z = z - falconMqQ
  z = z + (falconMqQ and (0'u32 - (z shr 31)))
  z

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; decoding, malformed-input rejection, and verification rules for `mqMontySqr`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc mqMontySqr(x: uint32): uint32 {.inline.} =
  mqMontyMul(x, x)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; decoding, malformed-input rejection, and verification rules for `mqDiv12289`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc mqDiv12289(x, y: uint32): uint32 =
  var
    y0 = mqMontyMul(y, falconMqR2)
    y1 = mqMontySqr(y0)
    y2 = mqMontyMul(y1, y0)
    y3 = mqMontyMul(y2, y1)
    y4 = mqMontySqr(y3)
    y5 = mqMontySqr(y4)
    y6 = mqMontySqr(y5)
    y7 = mqMontySqr(y6)
    y8 = mqMontySqr(y7)
    y9 = mqMontyMul(y8, y2)
    y10 = mqMontyMul(y9, y8)
    y11 = mqMontySqr(y10)
    y12 = mqMontySqr(y11)
    y13 = mqMontyMul(y12, y9)
    y14 = mqMontySqr(y13)
    y15 = mqMontySqr(y14)
    y16 = mqMontyMul(y15, y10)
    y17 = mqMontySqr(y16)
    y18 = mqMontyMul(y17, y0)
  mqMontyMul(y18, x)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; decoding, malformed-input rejection, and verification rules for `mqNTT`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc mqNTT(a: var openArray[uint16], logn: int) =
  let n = mkn(logn)
  var
    t = n
    m = 1
  while m < n:
    let ht = t shr 1
    var
      i = 0
      j1 = 0
    while i < m:
      let
        s = uint32(gmbTable[m + i])
        j2 = j1 + ht
      var j = j1
      while j < j2:
        let
          u = uint32(a[j])
          v = mqMontyMul(uint32(a[j + ht]), s)
        a[j] = uint16(mqAdd(u, v))
        a[j + ht] = uint16(mqSub(u, v))
        inc j
      inc i
      j1 += t
    t = ht
    m = m shl 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; decoding, malformed-input rejection, and verification rules for `mqINTT`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc mqINTT(a: var openArray[uint16], logn: int) =
  let n = mkn(logn)
  var
    t = 1
    m = n
  while m > 1:
    let
      hm = m shr 1
      dt = t shl 1
    var
      i = 0
      j1 = 0
    while i < hm:
      let
        j2 = j1 + t
        s = uint32(igmbTable[hm + i])
      var j = j1
      while j < j2:
        let
          u = uint32(a[j])
          v = uint32(a[j + t])
          w = mqSub(u, v)
        a[j] = uint16(mqAdd(u, v))
        a[j + t] = uint16(mqMontyMul(w, s))
        inc j
      inc i
      j1 += dt
    t = dt
    m = hm
  var ni = falconMqR
  var mm = n
  while mm > 1:
    ni = mqRshift1(ni)
    mm = mm shr 1
  var u = 0
  while u < n:
    a[u] = uint16(mqMontyMul(uint32(a[u]), ni))
    inc u

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; decoding, malformed-input rejection, and verification rules for `mqPolyToMonty`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc mqPolyToMonty(f: var openArray[uint16], logn: int) =
  let n = mkn(logn)
  var u = 0
  while u < n:
    f[u] = uint16(mqMontyMul(uint32(f[u]), falconMqR2))
    inc u

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; decoding, malformed-input rejection, and verification rules for `mqPolyMontyMulNtt`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc mqPolyMontyMulNtt(f: var openArray[uint16], g: openArray[uint16], logn: int) =
  let n = mkn(logn)
  var u = 0
  while u < n:
    f[u] = uint16(mqMontyMul(uint32(f[u]), uint32(g[u])))
    inc u

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; decoding, malformed-input rejection, and verification rules for `mqPolySub`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc mqPolySub(f: var openArray[uint16], g: openArray[uint16], logn: int) =
  let n = mkn(logn)
  var u = 0
  while u < n:
    f[u] = uint16(mqSub(uint32(f[u]), uint32(g[u])))
    inc u

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; decoding, malformed-input rejection, and verification rules for `mqNormalizeSigned`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc mqNormalizeSigned(w: uint32): int16 {.inline.} =
  var t = w
  let mask = 0'u32 - ((((falconMqQ shr 1) - t) shr 31) and 1'u32)
  t = t - (falconMqQ and mask)
  cast[int16](cast[int32](t))

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; decoding, malformed-input rejection, and verification rules for `mqNormalizeCenteredByte`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc mqNormalizeCenteredByte(w: uint32): int32 {.inline.} =
  var t = w
  let mask = not (0'u32 - (((t - (falconMqQ shr 1)) shr 31) and 1'u32))
  t = t - (falconMqQ and mask)
  cast[int32](t)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; decoding, malformed-input rejection, and verification rules for `toNttMonty`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc toNttMonty*(h: var openArray[uint16], logn: int) =
  mqNTT(h, logn)
  mqPolyToMonty(h, logn)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; decoding, malformed-input rejection, and verification rules for `verifyRaw`; pitfall: fail closed and preserve canonical, constant-time comparison where secrets are involved.
proc verifyRaw*(c0: openArray[uint16], s2: openArray[int16], h: openArray[uint16], logn: int): bool =
  let n = mkn(logn)
  if c0.len < n or s2.len < n or h.len < n:
    return false
  var
    tt = newSeq[uint16](n)
    s1 = newSeq[int16](n)
    u = 0
  while u < n:
    var w = uint32(s2[u])
    w = w + (falconMqQ and (0'u32 - (w shr 31)))
    tt[u] = uint16(w)
    inc u
  mqNTT(tt, logn)
  mqPolyMontyMulNtt(tt, h, logn)
  mqINTT(tt, logn)
  mqPolySub(tt, c0, logn)
  u = 0
  while u < n:
    s1[u] = mqNormalizeSigned(uint32(tt[u]))
    inc u
  isShort(s1, s2, logn)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; decoding, malformed-input rejection, and verification rules for `computePublic`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc computePublic*(h: var openArray[uint16], f, g: openArray[int8], logn: int): bool =
  let n = mkn(logn)
  if h.len < n or f.len < n or g.len < n:
    return false
  var
    tt = newSeq[uint16](n)
    u = 0
  while u < n:
    tt[u] = uint16(mqConvSmall(f[u]))
    h[u] = uint16(mqConvSmall(g[u]))
    inc u
  mqNTT(h, logn)
  mqNTT(tt, logn)
  u = 0
  while u < n:
    if tt[u] == 0'u16:
      return false
    h[u] = uint16(mqDiv12289(uint32(h[u]), uint32(tt[u])))
    inc u
  mqINTT(h, logn)
  true

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; decoding, malformed-input rejection, and verification rules for `completePrivate`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc completePrivate*(G: var openArray[int8], f, g, F: openArray[int8], logn: int): bool =
  let n = mkn(logn)
  if G.len < n or f.len < n or g.len < n or F.len < n:
    return false
  var
    t1 = newSeq[uint16](n)
    t2 = newSeq[uint16](n)
    u = 0
  while u < n:
    t1[u] = uint16(mqConvSmall(g[u]))
    t2[u] = uint16(mqConvSmall(F[u]))
    inc u
  mqNTT(t1, logn)
  mqNTT(t2, logn)
  mqPolyToMonty(t1, logn)
  mqPolyMontyMulNtt(t1, t2, logn)
  u = 0
  while u < n:
    t2[u] = uint16(mqConvSmall(f[u]))
    inc u
  mqNTT(t2, logn)
  u = 0
  while u < n:
    if t2[u] == 0'u16:
      return false
    t1[u] = uint16(mqDiv12289(uint32(t1[u]), uint32(t2[u])))
    inc u
  mqINTT(t1, logn)
  u = 0
  while u < n:
    let gi = mqNormalizeCenteredByte(uint32(t1[u]))
    if gi < -127 or gi > 127:
      return false
    G[u] = int8(gi)
    inc u
  true

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; decoding, malformed-input rejection, and verification rules for `isInvertible`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc isInvertible*(s2: openArray[int16], logn: int): bool =
  let n = mkn(logn)
  if s2.len < n:
    return false
  var
    tt = newSeq[uint16](n)
    r = 0'u32
    u = 0
  while u < n:
    var w = uint32(s2[u])
    w = w + (falconMqQ and (0'u32 - (w shr 31)))
    tt[u] = uint16(w)
    inc u
  mqNTT(tt, logn)
  u = 0
  while u < n:
    r = r or (uint32(tt[u]) - 1'u32)
    inc u
  (1'u32 - (r shr 31)) != 0'u32

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; decoding, malformed-input rejection, and verification rules for `verifyRecover`; pitfall: fail closed and preserve canonical, constant-time comparison where secrets are involved.
proc verifyRecover*(h: var openArray[uint16], c0: openArray[uint16], s1, s2: openArray[int16], logn: int): bool =
  let n = mkn(logn)
  if h.len < n or c0.len < n or s1.len < n or s2.len < n:
    return false
  var
    tt = newSeq[uint16](n)
    r = 0'u32
    u = 0
  while u < n:
    var w = uint32(s2[u])
    w = w + (falconMqQ and (0'u32 - (w shr 31)))
    tt[u] = uint16(w)
    w = uint32(s1[u])
    w = w + (falconMqQ and (0'u32 - (w shr 31)))
    h[u] = uint16(mqSub(c0[u], w))
    inc u
  mqNTT(tt, logn)
  mqNTT(h, logn)
  u = 0
  while u < n:
    r = r or (uint32(tt[u]) - 1'u32)
    h[u] = uint16(mqDiv12289(uint32(h[u]), uint32(tt[u])))
    inc u
  mqINTT(h, logn)
  r = (not r) and (0'u32 - uint32(ord(isShort(s1, s2, logn))))
  (r shr 31) != 0'u32

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; decoding, malformed-input rejection, and verification rules for `countNttZero`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc countNttZero*(sig: openArray[int16], logn: int): int =
  let n = mkn(logn)
  if sig.len < n:
    return 0
  var
    s2 = newSeq[uint16](n)
    r = 0'u32
    u = 0
  while u < n:
    var w = uint32(sig[u])
    w = w + (falconMqQ and (0'u32 - (w shr 31)))
    s2[u] = uint16(w)
    inc u
  mqNTT(s2, logn)
  u = 0
  while u < n:
    let w = uint32(s2[u]) - 1'u32
    r = r + (w shr 31)
    inc u
  int(r)
