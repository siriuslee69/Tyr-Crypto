## --------------------------------------------------------------
## X25519 Template <- shared implementation body for pass modules
## --------------------------------------------------------------

import ../../../helpers/otter_support
import ./x25519_common

when defined(amd64) or defined(i386) or defined(neon) or defined(arm64) or defined(aarch64):
  import simd_nexus/simd/base_operations
  import protocols/simd/generic_u64

when defined(avx2):
  {.passC: "-mavx2".}

const
  x25519Basepoint = [
    9'u8, 0'u8, 0'u8, 0'u8, 0'u8, 0'u8, 0'u8, 0'u8,
    0'u8, 0'u8, 0'u8, 0'u8, 0'u8, 0'u8, 0'u8, 0'u8,
    0'u8, 0'u8, 0'u8, 0'u8, 0'u8, 0'u8, 0'u8, 0'u8,
    0'u8, 0'u8, 0'u8, 0'u8, 0'u8, 0'u8, 0'u8, 0'u8
  ]
  feMask = 0x7ffffffffffff'u64

proc load64Le(input: openArray[byte], offset: int): uint64 {.inline.} =
  result = uint64(input[offset + 0])
  result = result or (uint64(input[offset + 1]) shl 8)
  result = result or (uint64(input[offset + 2]) shl 16)
  result = result or (uint64(input[offset + 3]) shl 24)
  result = result or (uint64(input[offset + 4]) shl 32)
  result = result or (uint64(input[offset + 5]) shl 40)
  result = result or (uint64(input[offset + 6]) shl 48)
  result = result or (uint64(input[offset + 7]) shl 56)

proc store64Le(output: var X25519Bytes32, offset: int, value: uint64) {.inline.} =
  output[offset + 0] = byte(value and 0xff'u64)
  output[offset + 1] = byte((value shr 8) and 0xff'u64)
  output[offset + 2] = byte((value shr 16) and 0xff'u64)
  output[offset + 3] = byte((value shr 24) and 0xff'u64)
  output[offset + 4] = byte((value shr 32) and 0xff'u64)
  output[offset + 5] = byte((value shr 40) and 0xff'u64)
  output[offset + 6] = byte((value shr 48) and 0xff'u64)
  output[offset + 7] = byte((value shr 56) and 0xff'u64)

proc mulWideFallback(a, b: uint64, lo, hi: var uint64) {.inline.} =
  let
    a0 = a and 0xffff_ffff'u64
    a1 = a shr 32
    b0 = b and 0xffff_ffff'u64
    b1 = b shr 32
    p00 = a0 * b0
    p01 = a0 * b1
    p10 = a1 * b0
    p11 = a1 * b1
  var middle = (p00 shr 32) + (p01 and 0xffff_ffff'u64) + (p10 and 0xffff_ffff'u64)
  lo = (p00 and 0xffff_ffff'u64) or (middle shl 32)
  hi = p11 + (p01 shr 32) + (p10 shr 32) + (middle shr 32)

proc mulWide(a, b: uint64, lo, hi: var uint64) {.inline.} =
  when defined(sizeof_Int128):
    type
      uint128T = uint128
    let p = uint128T(a) * uint128T(b)
    lo = cast[uint64](p)
    hi = cast[uint64](p shr 64)
  else:
    mulWideFallback(a, b, lo, hi)

proc add64To128(lo, hi: var uint64, value: uint64) {.inline.} =
  let prev = lo
  lo += value
  hi += uint64(lo < prev)

proc add128(lo, hi: var uint64, addLo, addHi: uint64) {.inline.} =
  add64To128(lo, hi, addLo)
  hi += addHi

proc addMul(lo, hi: var uint64, a, b: uint64) {.inline.} =
  var prodLo: uint64 = 0
  var prodHi: uint64 = 0
  mulWide(a, b, prodLo, prodHi)
  add128(lo, hi, prodLo, prodHi)

proc shift51(lo, hi: uint64): uint64 {.inline.} =
  result = (lo shr 51) or (hi shl 13)

proc fe0(h: var X25519Field) {.inline.} =
  zeroMem(addr h[0], sizeof(X25519Field))

proc fe1(h: var X25519Field) {.inline.} =
  zeroMem(addr h[0], sizeof(X25519Field))
  h[0] = 1'u64

proc feAddRaw(h: ptr X25519Field, f, g: ptr X25519Field) {.inline.} =
  h[][0] = f[][0] + g[][0]
  h[][1] = f[][1] + g[][1]
  h[][2] = f[][2] + g[][2]
  h[][3] = f[][3] + g[][3]
  h[][4] = f[][4] + g[][4]

template feAdd(h, f, g: untyped) =
  feAddRaw(addr h, unsafeAddr f, unsafeAddr g)

proc feSubRaw(h: ptr X25519Field, f, g: ptr X25519Field) {.inline.} =
  var
    h0 = g[][0]
    h1 = g[][1]
    h2 = g[][2]
    h3 = g[][3]
    h4 = g[][4]
  h1 += h0 shr 51
  h0 = h0 and feMask
  h2 += h1 shr 51
  h1 = h1 and feMask
  h3 += h2 shr 51
  h2 = h2 and feMask
  h4 += h3 shr 51
  h3 = h3 and feMask
  h0 += 19'u64 * (h4 shr 51)
  h4 = h4 and feMask
  h[][0] = (f[][0] + 0x00ff_ffff_ffff_fda'u64) - h0
  h[][1] = (f[][1] + 0x00ff_ffff_ffff_ffe'u64) - h1
  h[][2] = (f[][2] + 0x00ff_ffff_ffff_ffe'u64) - h2
  h[][3] = (f[][3] + 0x00ff_ffff_ffff_ffe'u64) - h3
  h[][4] = (f[][4] + 0x00ff_ffff_ffff_ffe'u64) - h4

template feSub(h, f, g: untyped) =
  feSubRaw(addr h, unsafeAddr f, unsafeAddr g)

proc feCopyRaw(h: ptr X25519Field, f: ptr X25519Field) {.inline.} =
  copyMem(addr h[][0], unsafeAddr f[][0], sizeof(X25519Field))

template feCopy(h, f: untyped) =
  feCopyRaw(addr h, unsafeAddr f)

proc feCswap(f, g: var X25519Field, b: uint32) {.inline.} =
  let mask = uint64(-int64(b))
  var
    x0 = (f[0] xor g[0]) and mask
    x1 = (f[1] xor g[1]) and mask
    x2 = (f[2] xor g[2]) and mask
    x3 = (f[3] xor g[3]) and mask
    x4 = (f[4] xor g[4]) and mask
  f[0] = f[0] xor x0
  f[1] = f[1] xor x1
  f[2] = f[2] xor x2
  f[3] = f[3] xor x3
  f[4] = f[4] xor x4
  g[0] = g[0] xor x0
  g[1] = g[1] xor x1
  g[2] = g[2] xor x2
  g[3] = g[3] xor x3
  g[4] = g[4] xor x4

when x25519SplitHelpers:
  proc reduceMulAcc(r0lo, r0hi, r1lo, r1hi, r2lo, r2hi, r3lo, r3hi, r4lo, r4hi: uint64,
      outH: var X25519Field) {.inline.} =
    var
      a0lo = r0lo
      a0hi = r0hi
      a1lo = r1lo
      a1hi = r1hi
      a2lo = r2lo
      a2hi = r2hi
      a3lo = r3lo
      a3hi = r3hi
      a4lo = r4lo
      a4hi = r4hi
      carry: uint64 = 0
    outH[0] = a0lo and feMask
    carry = shift51(a0lo, a0hi)
    add64To128(a1lo, a1hi, carry)
    outH[1] = a1lo and feMask
    carry = shift51(a1lo, a1hi)
    add64To128(a2lo, a2hi, carry)
    outH[2] = a2lo and feMask
    carry = shift51(a2lo, a2hi)
    add64To128(a3lo, a3hi, carry)
    outH[3] = a3lo and feMask
    carry = shift51(a3lo, a3hi)
    add64To128(a4lo, a4hi, carry)
    outH[4] = a4lo and feMask
    carry = shift51(a4lo, a4hi)
    outH[0] += 19'u64 * carry
    carry = outH[0] shr 51
    outH[0] = outH[0] and feMask
    outH[1] += carry
    carry = outH[1] shr 51
    outH[1] = outH[1] and feMask
    outH[2] += carry

  proc feMulRaw(h: ptr X25519Field, f, g: ptr X25519Field) {.inline.} =
    otterSpan(x25519BenchTag & ".feMul"):
      let
        f0 = f[][0]
        f1 = f[][1]
        f2 = f[][2]
        f3 = f[][3]
        f4 = f[][4]
        g0 = g[][0]
        g1 = g[][1]
        g2 = g[][2]
        g3 = g[][3]
        g4 = g[][4]
        f1_19 = 19'u64 * f1
        f2_19 = 19'u64 * f2
        f3_19 = 19'u64 * f3
        f4_19 = 19'u64 * f4
      var
        r0lo, r0hi, r1lo, r1hi, r2lo, r2hi, r3lo, r3hi, r4lo, r4hi: uint64
      addMul(r0lo, r0hi, f0, g0)
      addMul(r0lo, r0hi, f1_19, g4)
      addMul(r0lo, r0hi, f2_19, g3)
      addMul(r0lo, r0hi, f3_19, g2)
      addMul(r0lo, r0hi, f4_19, g1)
      addMul(r1lo, r1hi, f0, g1)
      addMul(r1lo, r1hi, f1, g0)
      addMul(r1lo, r1hi, f2_19, g4)
      addMul(r1lo, r1hi, f3_19, g3)
      addMul(r1lo, r1hi, f4_19, g2)
      addMul(r2lo, r2hi, f0, g2)
      addMul(r2lo, r2hi, f1, g1)
      addMul(r2lo, r2hi, f2, g0)
      addMul(r2lo, r2hi, f3_19, g4)
      addMul(r2lo, r2hi, f4_19, g3)
      addMul(r3lo, r3hi, f0, g3)
      addMul(r3lo, r3hi, f1, g2)
      addMul(r3lo, r3hi, f2, g1)
      addMul(r3lo, r3hi, f3, g0)
      addMul(r3lo, r3hi, f4_19, g4)
      addMul(r4lo, r4hi, f0, g4)
      addMul(r4lo, r4hi, f1, g3)
      addMul(r4lo, r4hi, f2, g2)
      addMul(r4lo, r4hi, f3, g1)
      addMul(r4lo, r4hi, f4, g0)
      reduceMulAcc(r0lo, r0hi, r1lo, r1hi, r2lo, r2hi, r3lo, r3hi, r4lo, r4hi, h[])

  template feMul(h, f, g: untyped) =
    feMulRaw(addr h, unsafeAddr f, unsafeAddr g)

  proc feSqRaw(h: ptr X25519Field, f: ptr X25519Field) {.inline.} =
    otterSpan(x25519BenchTag & ".feSq"):
      let
        f0 = f[][0]
        f1 = f[][1]
        f2 = f[][2]
        f3 = f[][3]
        f4 = f[][4]
        f0_2 = f0 shl 1
        f1_2 = f1 shl 1
        f1_38 = 38'u64 * f1
        f2_38 = 38'u64 * f2
        f3_38 = 38'u64 * f3
        f3_19 = 19'u64 * f3
        f4_19 = 19'u64 * f4
      var
        r0lo, r0hi, r1lo, r1hi, r2lo, r2hi, r3lo, r3hi, r4lo, r4hi: uint64
      addMul(r0lo, r0hi, f0, f0)
      addMul(r0lo, r0hi, f1_38, f4)
      addMul(r0lo, r0hi, f2_38, f3)
      addMul(r1lo, r1hi, f0_2, f1)
      addMul(r1lo, r1hi, f2_38, f4)
      addMul(r1lo, r1hi, f3_19, f3)
      addMul(r2lo, r2hi, f0_2, f2)
      addMul(r2lo, r2hi, f1, f1)
      addMul(r2lo, r2hi, f3_38, f4)
      addMul(r3lo, r3hi, f0_2, f3)
      addMul(r3lo, r3hi, f1_2, f2)
      addMul(r3lo, r3hi, f4_19, f4)
      addMul(r4lo, r4hi, f0_2, f4)
      addMul(r4lo, r4hi, f1_2, f3)
      addMul(r4lo, r4hi, f2, f2)
      reduceMulAcc(r0lo, r0hi, r1lo, r1hi, r2lo, r2hi, r3lo, r3hi, r4lo, r4hi, h[])

  template feSq(h, f: untyped) =
    feSqRaw(addr h, unsafeAddr f)

else:
  proc feMulRaw(h: ptr X25519Field, f, g: ptr X25519Field) {.inline.} =
    otterSpan(x25519BenchTag & ".feMul"):
      let
        f0 = f[][0]
        f1 = f[][1]
        f2 = f[][2]
        f3 = f[][3]
        f4 = f[][4]
        g0 = g[][0]
        g1 = g[][1]
        g2 = g[][2]
        g3 = g[][3]
        g4 = g[][4]
        f1_19 = 19'u64 * f1
        f2_19 = 19'u64 * f2
        f3_19 = 19'u64 * f3
        f4_19 = 19'u64 * f4
      var
        r0lo, r0hi, r1lo, r1hi, r2lo, r2hi, r3lo, r3hi, r4lo, r4hi: uint64
        carry: uint64 = 0
      addMul(r0lo, r0hi, f0, g0)
      addMul(r0lo, r0hi, f1_19, g4)
      addMul(r0lo, r0hi, f2_19, g3)
      addMul(r0lo, r0hi, f3_19, g2)
      addMul(r0lo, r0hi, f4_19, g1)
      addMul(r1lo, r1hi, f0, g1)
      addMul(r1lo, r1hi, f1, g0)
      addMul(r1lo, r1hi, f2_19, g4)
      addMul(r1lo, r1hi, f3_19, g3)
      addMul(r1lo, r1hi, f4_19, g2)
      addMul(r2lo, r2hi, f0, g2)
      addMul(r2lo, r2hi, f1, g1)
      addMul(r2lo, r2hi, f2, g0)
      addMul(r2lo, r2hi, f3_19, g4)
      addMul(r2lo, r2hi, f4_19, g3)
      addMul(r3lo, r3hi, f0, g3)
      addMul(r3lo, r3hi, f1, g2)
      addMul(r3lo, r3hi, f2, g1)
      addMul(r3lo, r3hi, f3, g0)
      addMul(r3lo, r3hi, f4_19, g4)
      addMul(r4lo, r4hi, f0, g4)
      addMul(r4lo, r4hi, f1, g3)
      addMul(r4lo, r4hi, f2, g2)
      addMul(r4lo, r4hi, f3, g1)
      addMul(r4lo, r4hi, f4, g0)
      h[][0] = r0lo and feMask
      carry = shift51(r0lo, r0hi)
      add64To128(r1lo, r1hi, carry)
      h[][1] = r1lo and feMask
      carry = shift51(r1lo, r1hi)
      add64To128(r2lo, r2hi, carry)
      h[][2] = r2lo and feMask
      carry = shift51(r2lo, r2hi)
      add64To128(r3lo, r3hi, carry)
      h[][3] = r3lo and feMask
      carry = shift51(r3lo, r3hi)
      add64To128(r4lo, r4hi, carry)
      h[][4] = r4lo and feMask
      carry = shift51(r4lo, r4hi)
      h[][0] += 19'u64 * carry
      carry = h[][0] shr 51
      h[][0] = h[][0] and feMask
      h[][1] += carry
      carry = h[][1] shr 51
      h[][1] = h[][1] and feMask
      h[][2] += carry

  template feMul(h, f, g: untyped) =
    feMulRaw(addr h, unsafeAddr f, unsafeAddr g)

  proc feSqRaw(h: ptr X25519Field, f: ptr X25519Field) {.inline.} =
    otterSpan(x25519BenchTag & ".feSq"):
      let
        f0 = f[][0]
        f1 = f[][1]
        f2 = f[][2]
        f3 = f[][3]
        f4 = f[][4]
        f0_2 = f0 shl 1
        f1_2 = f1 shl 1
        f1_38 = 38'u64 * f1
        f2_38 = 38'u64 * f2
        f3_38 = 38'u64 * f3
        f3_19 = 19'u64 * f3
        f4_19 = 19'u64 * f4
      var
        r0lo, r0hi, r1lo, r1hi, r2lo, r2hi, r3lo, r3hi, r4lo, r4hi: uint64
        carry: uint64 = 0
      addMul(r0lo, r0hi, f0, f0)
      addMul(r0lo, r0hi, f1_38, f4)
      addMul(r0lo, r0hi, f2_38, f3)
      addMul(r1lo, r1hi, f0_2, f1)
      addMul(r1lo, r1hi, f2_38, f4)
      addMul(r1lo, r1hi, f3_19, f3)
      addMul(r2lo, r2hi, f0_2, f2)
      addMul(r2lo, r2hi, f1, f1)
      addMul(r2lo, r2hi, f3_38, f4)
      addMul(r3lo, r3hi, f0_2, f3)
      addMul(r3lo, r3hi, f1_2, f2)
      addMul(r3lo, r3hi, f4_19, f4)
      addMul(r4lo, r4hi, f0_2, f4)
      addMul(r4lo, r4hi, f1_2, f3)
      addMul(r4lo, r4hi, f2, f2)
      h[][0] = r0lo and feMask
      carry = shift51(r0lo, r0hi)
      add64To128(r1lo, r1hi, carry)
      h[][1] = r1lo and feMask
      carry = shift51(r1lo, r1hi)
      add64To128(r2lo, r2hi, carry)
      h[][2] = r2lo and feMask
      carry = shift51(r2lo, r2hi)
      add64To128(r3lo, r3hi, carry)
      h[][3] = r3lo and feMask
      carry = shift51(r3lo, r3hi)
      add64To128(r4lo, r4hi, carry)
      h[][4] = r4lo and feMask
      carry = shift51(r4lo, r4hi)
      h[][0] += 19'u64 * carry
      carry = h[][0] shr 51
      h[][0] = h[][0] and feMask
      h[][1] += carry
      carry = h[][1] shr 51
      h[][1] = h[][1] and feMask
      h[][2] += carry

  template feSq(h, f: untyped) =
    feSqRaw(addr h, unsafeAddr f)

proc feMul32Raw(h: ptr X25519Field, f: ptr X25519Field, n: uint32) {.inline.} =
  let sn = uint64(n)
  var
    lo: uint64 = 0
    hi: uint64 = 0
    carry: uint64 = 0
  mulWide(f[][0], sn, lo, hi)
  h[][0] = lo and feMask
  carry = shift51(lo, hi)
  mulWide(f[][1], sn, lo, hi)
  add64To128(lo, hi, carry)
  h[][1] = lo and feMask
  carry = shift51(lo, hi)
  mulWide(f[][2], sn, lo, hi)
  add64To128(lo, hi, carry)
  h[][2] = lo and feMask
  carry = shift51(lo, hi)
  mulWide(f[][3], sn, lo, hi)
  add64To128(lo, hi, carry)
  h[][3] = lo and feMask
  carry = shift51(lo, hi)
  mulWide(f[][4], sn, lo, hi)
  add64To128(lo, hi, carry)
  h[][4] = lo and feMask
  h[][0] += 19'u64 * shift51(lo, hi)

template feMul32(h, f, n: untyped) =
  feMul32Raw(addr h, unsafeAddr f, n)

proc feFromBytes(h: var X25519Field, s: X25519Bytes32) {.inline.} =
  h[0] = load64Le(s, 0) and feMask
  h[1] = (load64Le(s, 6) shr 3) and feMask
  h[2] = (load64Le(s, 12) shr 6) and feMask
  h[3] = (load64Le(s, 19) shr 1) and feMask
  h[4] = (load64Le(s, 24) shr 12) and feMask

proc feReduce(h: var X25519Field, f: X25519Field) {.inline.} =
  var
    t0 = f[0]
    t1 = f[1]
    t2 = f[2]
    t3 = f[3]
    t4 = f[4]
  t1 += t0 shr 51
  t0 = t0 and feMask
  t2 += t1 shr 51
  t1 = t1 and feMask
  t3 += t2 shr 51
  t2 = t2 and feMask
  t4 += t3 shr 51
  t3 = t3 and feMask
  t0 += 19'u64 * (t4 shr 51)
  t4 = t4 and feMask
  t1 += t0 shr 51
  t0 = t0 and feMask
  t2 += t1 shr 51
  t1 = t1 and feMask
  t3 += t2 shr 51
  t2 = t2 and feMask
  t4 += t3 shr 51
  t3 = t3 and feMask
  t0 += 19'u64 * (t4 shr 51)
  t4 = t4 and feMask
  t0 += 19'u64
  t1 += t0 shr 51
  t0 = t0 and feMask
  t2 += t1 shr 51
  t1 = t1 and feMask
  t3 += t2 shr 51
  t2 = t2 and feMask
  t4 += t3 shr 51
  t3 = t3 and feMask
  t0 += 19'u64 * (t4 shr 51)
  t4 = t4 and feMask
  t0 += 0x8000000000000'u64 - 19'u64
  t1 += 0x8000000000000'u64 - 1'u64
  t2 += 0x8000000000000'u64 - 1'u64
  t3 += 0x8000000000000'u64 - 1'u64
  t4 += 0x8000000000000'u64 - 1'u64
  t1 += t0 shr 51
  t0 = t0 and feMask
  t2 += t1 shr 51
  t1 = t1 and feMask
  t3 += t2 shr 51
  t2 = t2 and feMask
  t4 += t3 shr 51
  t3 = t3 and feMask
  t4 = t4 and feMask
  h[0] = t0
  h[1] = t1
  h[2] = t2
  h[3] = t3
  h[4] = t4

proc feToBytes(outBytes: var X25519Bytes32, h: X25519Field) {.inline.} =
  var t: X25519Field
  when x25519SecureWipe:
    defer:
      secureClearPod(t)
  feReduce(t, h)
  let
    t0 = t[0] or (t[1] shl 51)
    t1 = (t[1] shr 13) or (t[2] shl 38)
    t2 = (t[2] shr 26) or (t[3] shl 25)
    t3 = (t[3] shr 39) or (t[4] shl 12)
  store64Le(outBytes, 0, t0)
  store64Le(outBytes, 8, t1)
  store64Le(outBytes, 16, t2)
  store64Le(outBytes, 24, t3)

when x25519SplitHelpers:
  proc feSqRepeat(h: var X25519Field, count: int) {.inline.} =
    var i: int = 0
    while i < count:
      feSq(h, h)
      inc i

proc feInvert(outField: var X25519Field, z: X25519Field) {.inline.} =
  otterSpan(x25519BenchTag & ".feInvert"):
    var
      t0: X25519Field
      t1: X25519Field
      t2: X25519Field
      t3: X25519Field
    when not x25519SplitHelpers:
      var i: int = 0
    when x25519SecureWipe:
      defer:
        secureClearPod(t0)
        secureClearPod(t1)
        secureClearPod(t2)
        secureClearPod(t3)
    feSq(t0, z)
    feSq(t1, t0)
    feSq(t1, t1)
    feMul(t1, z, t1)
    feMul(t0, t0, t1)
    feSq(t2, t0)
    feMul(t1, t1, t2)
    feSq(t2, t1)
    when x25519SplitHelpers:
      feSqRepeat(t2, 4)
    else:
      i = 1
      while i < 5:
        feSq(t2, t2)
        inc i
    feMul(t1, t2, t1)
    feSq(t2, t1)
    when x25519SplitHelpers:
      feSqRepeat(t2, 9)
    else:
      i = 1
      while i < 10:
        feSq(t2, t2)
        inc i
    feMul(t2, t2, t1)
    feSq(t3, t2)
    when x25519SplitHelpers:
      feSqRepeat(t3, 19)
    else:
      i = 1
      while i < 20:
        feSq(t3, t3)
        inc i
    feMul(t2, t3, t2)
    when x25519SplitHelpers:
      feSqRepeat(t2, 10)
    else:
      i = 1
      while i < 11:
        feSq(t2, t2)
        inc i
    feMul(t1, t2, t1)
    feSq(t2, t1)
    when x25519SplitHelpers:
      feSqRepeat(t2, 49)
    else:
      i = 1
      while i < 50:
        feSq(t2, t2)
        inc i
    feMul(t2, t2, t1)
    feSq(t3, t2)
    when x25519SplitHelpers:
      feSqRepeat(t3, 99)
    else:
      i = 1
      while i < 100:
        feSq(t3, t3)
        inc i
    feMul(t2, t3, t2)
    when x25519SplitHelpers:
      feSqRepeat(t2, 50)
    else:
      i = 1
      while i < 51:
        feSq(t2, t2)
        inc i
    feMul(t1, t2, t1)
    when x25519SplitHelpers:
      feSqRepeat(t1, 5)
    else:
      i = 1
      while i < 6:
        feSq(t1, t1)
        inc i
    feMul(outField, t1, t0)

when x25519SplitHelpers:
  proc scalarBit(t: X25519Bytes32, pos: int): uint32 {.inline.} =
    result = uint32((t[pos div 8] shr (pos and 7)) and 1'u8)

  proc initScalarmultState(publicKey: X25519Bytes32, x1, x2, x3, z2, z3: var X25519Field) {.inline.} =
    feFromBytes(x1, publicKey)
    fe1(x2)
    fe0(z2)
    feCopy(x3, x1)
    fe1(z3)

  proc ladderStep(x1: X25519Field, x2, x3, z2, z3, a, b, aa, bb, e, da, cb: var X25519Field) {.inline.} =
    feAdd(a, x2, z2)
    feSub(b, x2, z2)
    feSq(aa, a)
    feSq(bb, b)
    feMul(x2, aa, bb)
    feSub(e, aa, bb)
    feSub(da, x3, z3)
    feMul(da, da, a)
    feAdd(cb, x3, z3)
    feMul(cb, cb, b)
    feAdd(x3, da, cb)
    feSq(x3, x3)
    feSub(z3, da, cb)
    feSq(z3, z3)
    feMul(z3, z3, x1)
    feMul32(z2, e, 121_666'u32)
    feAdd(z2, z2, bb)
    feMul(z2, z2, e)

  proc finalizeScalarmult(outShared: var X25519Bytes32, x2, z2: var X25519Field, outResult: var bool) {.inline.} =
    feInvert(z2, z2)
    feMul(x2, x2, z2)
    feToBytes(outShared, x2)
    outResult = not isAllZero(outShared)

proc x25519ScalarmultRaw*(outShared: var X25519Bytes32, secretKey,
    publicKey: X25519Bytes32): bool =
  otterSpan(x25519BenchTag & ".scalarmult"):
    var
      t: X25519Bytes32
      x1, x2, x3, z2, z3: X25519Field
      a, b, aa, bb, e, da, cb: X25519Field
      pos: int = 254
      swap: uint32 = 0
      bit: uint32 = 0
    if hasSmallOrder(publicKey):
      return false
    clampScalar(t, secretKey)
    when x25519SecureWipe:
      defer:
        secureClearPod(t)
        secureClearPod(x1)
        secureClearPod(x2)
        secureClearPod(x3)
        secureClearPod(z2)
        secureClearPod(z3)
        secureClearPod(a)
        secureClearPod(b)
        secureClearPod(aa)
        secureClearPod(bb)
        secureClearPod(e)
        secureClearPod(da)
        secureClearPod(cb)
    when x25519SplitHelpers:
      initScalarmultState(publicKey, x1, x2, x3, z2, z3)
    else:
      feFromBytes(x1, publicKey)
      fe1(x2)
      fe0(z2)
      feCopy(x3, x1)
      fe1(z3)
    while pos >= 0:
      when x25519SplitHelpers:
        bit = scalarBit(t, pos)
      else:
        bit = uint32((t[pos div 8] shr (pos and 7)) and 1'u8)
      swap = swap xor bit
      feCswap(x2, x3, swap)
      feCswap(z2, z3, swap)
      swap = bit
      when x25519SplitHelpers:
        ladderStep(x1, x2, x3, z2, z3, a, b, aa, bb, e, da, cb)
      else:
        feAdd(a, x2, z2)
        feSub(b, x2, z2)
        feSq(aa, a)
        feSq(bb, b)
        feMul(x2, aa, bb)
        feSub(e, aa, bb)
        feSub(da, x3, z3)
        feMul(da, da, a)
        feAdd(cb, x3, z3)
        feMul(cb, cb, b)
        feAdd(x3, da, cb)
        feSq(x3, x3)
        feSub(z3, da, cb)
        feSq(z3, z3)
        feMul(z3, z3, x1)
        feMul32(z2, e, 121_666'u32)
        feAdd(z2, z2, bb)
        feMul(z2, z2, e)
      dec pos
    feCswap(x2, x3, swap)
    feCswap(z2, z3, swap)
    when x25519SplitHelpers:
      finalizeScalarmult(outShared, x2, z2, result)
    else:
      feInvert(z2, z2)
      feMul(x2, x2, z2)
      feToBytes(outShared, x2)
      result = not isAllZero(outShared)

proc x25519ScalarmultBaseRaw*(publicKey: var X25519Bytes32,
    secretKey: X25519Bytes32): bool =
  result = x25519ScalarmultRaw(publicKey, secretKey, x25519Basepoint)

proc x25519TyrShared*(secretKey, publicKey: openArray[byte]): seq[byte] =
  when x25519SecureWipe:
    var
      sk = toFixed32(secretKey)
      pk = toFixed32(publicKey)
      shared: X25519Bytes32
    defer:
      secureClearPod(sk)
      secureClearPod(pk)
      secureClearPod(shared)
    if not x25519ScalarmultRaw(shared, sk, pk):
      raise newException(ValueError, "X25519 shared secret derivation failed")
    result = toSeqBytes(shared)
  else:
    result = buildShared(x25519ScalarmultRaw, secretKey, publicKey)

proc x25519TyrPublicKey*(secretKey: openArray[byte]): seq[byte] =
  when x25519SecureWipe:
    var
      sk = toFixed32(secretKey)
      pk: X25519Bytes32
    defer:
      secureClearPod(sk)
      secureClearPod(pk)
    if not x25519ScalarmultBaseRaw(pk, sk):
      raise newException(ValueError, "X25519 public key derivation failed")
    result = toSeqBytes(pk)
  else:
    result = buildPublicKey(x25519ScalarmultBaseRaw, secretKey)

proc x25519TyrKeypair*(): X25519TyrKeypair =
  when x25519SecureWipe:
    var
      sk = randomSecret32()
      pk: X25519Bytes32
    defer:
      secureClearPod(sk)
      secureClearPod(pk)
    if not x25519ScalarmultBaseRaw(pk, sk):
      raise newException(ValueError, "X25519 public key derivation failed")
    result.publicKey = toSeqBytes(pk)
    result.secretKey = toSeqBytes(sk)
  else:
    result = buildRandomKeypair(x25519ScalarmultBaseRaw)

proc x25519TyrKeypairFromSeed*(seed: openArray[byte]): X25519TyrKeypair =
  when x25519SecureWipe:
    var
      sk = deriveSeedSecretCompat(seed)
      pk: X25519Bytes32
    defer:
      secureClearPod(sk)
      secureClearPod(pk)
    if not x25519ScalarmultBaseRaw(pk, sk):
      raise newException(ValueError, "X25519 public key derivation failed")
    result.publicKey = toSeqBytes(pk)
    result.secretKey = toSeqBytes(sk)
  else:
    result = buildSeededKeypair(x25519ScalarmultBaseRaw, seed)

when defined(amd64) or defined(i386) or defined(neon) or defined(arm64) or defined(aarch64):
  type
    X25519FieldVec[T: SimdU64] = array[5, T]

  when defined(neon) or defined(arm64) or defined(aarch64):
    proc loadLaneVec(vals: array[2, uint64]): uint64x2 {.inline.} =
      result = loadU64x2[uint64x2](vals)

    proc storeLaneVec(v: uint64x2): array[2, uint64] {.inline.} =
      result = storeU64x2(v)
  else:
    proc loadLaneVec(vals: array[2, uint64]): u64x2 {.inline.} =
      result = loadU64x2[u64x2](vals)

    proc storeLaneVec(v: u64x2): array[2, uint64] {.inline.} =
      result = storeU64x2(v)

  when defined(avx2):
    proc loadLaneVec(vals: array[4, uint64]): u64x4 {.inline.} =
      result = loadU64x4[u64x4](vals)

    proc storeLaneVec(v: u64x4): array[4, uint64] {.inline.} =
      result = storeU64x4(v)

  proc subVec[T: SimdU64](a, b: T): T {.inline.} =
    result = a + (not b) + set1U64[T](1'u64)

  proc mulBy19Vec[T: SimdU64](a: T): T {.inline.} =
    result = a + (a shl 1) + (a shl 4)

  proc fe0Vec[T: SimdU64](h: var X25519FieldVec[T]) {.inline.} =
    let zero = set1U64[T](0'u64)
    h[0] = zero
    h[1] = zero
    h[2] = zero
    h[3] = zero
    h[4] = zero

  proc fe1Vec[T: SimdU64](h: var X25519FieldVec[T]) {.inline.} =
    let
      zero = set1U64[T](0'u64)
      one = set1U64[T](1'u64)
    h[0] = one
    h[1] = zero
    h[2] = zero
    h[3] = zero
    h[4] = zero

  proc packMaskVec[T: SimdU64](bits: openArray[uint32]): T {.inline.} =
    const lanes = lanesU64[T]()
    var
      maskVals: array[lanes, uint64]
      lane: int = 0
    if bits.len != lanes:
      raise newException(ValueError, "invalid X25519 SIMD mask lane count")
    while lane < lanes:
      maskVals[lane] = 0'u64 - uint64(bits[lane] and 1'u32)
      inc lane
    result = loadLaneVec(maskVals)

  proc packFieldVec[T: SimdU64](fields: array[lanesU64[T](), X25519Field]): X25519FieldVec[T] {.inline.} =
    const lanes = lanesU64[T]()
    var
      limbVals: array[lanes, uint64]
      limb: int = 0
      lane: int = 0
    limb = 0
    while limb < 5:
      lane = 0
      while lane < lanes:
        limbVals[lane] = fields[lane][limb]
        inc lane
      result[limb] = loadLaneVec(limbVals)
      inc limb

  proc unpackFieldVec[T: SimdU64](v: X25519FieldVec[T]): array[lanesU64[T](), X25519Field] {.inline.} =
    const lanes = lanesU64[T]()
    var
      limbVals: array[lanes, uint64]
      limb: int = 0
      lane: int = 0
    limb = 0
    while limb < 5:
      limbVals = storeLaneVec(v[limb])
      lane = 0
      while lane < lanes:
        result[lane][limb] = limbVals[lane]
        inc lane
      inc limb

  proc feAddVec[T: SimdU64](h: var X25519FieldVec[T], f, g: X25519FieldVec[T]) {.inline.} =
    h[0] = f[0] + g[0]
    h[1] = f[1] + g[1]
    h[2] = f[2] + g[2]
    h[3] = f[3] + g[3]
    h[4] = f[4] + g[4]

  proc feSubVec[T: SimdU64](h: var X25519FieldVec[T], f, g: X25519FieldVec[T]) {.inline.} =
    let
      mask = set1U64[T](feMask)
      bias0 = set1U64[T](0x00ff_ffff_ffff_fda'u64)
      bias = set1U64[T](0x00ff_ffff_ffff_ffe'u64)
    var
      h0 = g[0]
      h1 = g[1]
      h2 = g[2]
      h3 = g[3]
      h4 = g[4]
    h1 = h1 + (h0 shr 51)
    h0 = h0 and mask
    h2 = h2 + (h1 shr 51)
    h1 = h1 and mask
    h3 = h3 + (h2 shr 51)
    h2 = h2 and mask
    h4 = h4 + (h3 shr 51)
    h3 = h3 and mask
    h0 = h0 + mulBy19Vec(h4 shr 51)
    h4 = h4 and mask
    h[0] = subVec(f[0] + bias0, h0)
    h[1] = subVec(f[1] + bias, h1)
    h[2] = subVec(f[2] + bias, h2)
    h[3] = subVec(f[3] + bias, h3)
    h[4] = subVec(f[4] + bias, h4)

  proc feCswapVec[T: SimdU64](f, g: var X25519FieldVec[T],
      bits: openArray[uint32]) {.inline.} =
    let mask = packMaskVec[T](bits)
    var
      x0 = (f[0] xor g[0]) and mask
      x1 = (f[1] xor g[1]) and mask
      x2 = (f[2] xor g[2]) and mask
      x3 = (f[3] xor g[3]) and mask
      x4 = (f[4] xor g[4]) and mask
    f[0] = f[0] xor x0
    f[1] = f[1] xor x1
    f[2] = f[2] xor x2
    f[3] = f[3] xor x3
    f[4] = f[4] xor x4
    g[0] = g[0] xor x0
    g[1] = g[1] xor x1
    g[2] = g[2] xor x2
    g[3] = g[3] xor x3
    g[4] = g[4] xor x4

  proc feMulVec[T: SimdU64](h: var X25519FieldVec[T], f, g: X25519FieldVec[T]) {.inline.} =
    const lanes = lanesU64[T]()
    var
      sf = unpackFieldVec(f)
      sg = unpackFieldVec(g)
      sh: array[lanes, X25519Field]
      lane: int = 0
    while lane < lanes:
      feMul(sh[lane], sf[lane], sg[lane])
      inc lane
    h = packFieldVec[T](sh)

  proc feSqVec[T: SimdU64](h: var X25519FieldVec[T], f: X25519FieldVec[T]) {.inline.} =
    const lanes = lanesU64[T]()
    var
      sf = unpackFieldVec(f)
      sh: array[lanes, X25519Field]
      lane: int = 0
    while lane < lanes:
      feSq(sh[lane], sf[lane])
      inc lane
    h = packFieldVec[T](sh)

  proc feMul32Vec[T: SimdU64](h: var X25519FieldVec[T], f: X25519FieldVec[T],
      n: uint32) {.inline.} =
    const lanes = lanesU64[T]()
    var
      sf = unpackFieldVec(f)
      sh: array[lanes, X25519Field]
      lane: int = 0
    while lane < lanes:
      feMul32(sh[lane], sf[lane], n)
      inc lane
    h = packFieldVec[T](sh)

  proc feInvertBatchFields[L: static[int]](outInv, zs: var array[L, X25519Field]) {.inline.} =
    var
      prefix: array[L, X25519Field]
      running: X25519Field
      invAll: X25519Field
      lane: int = 0
    when x25519SecureWipe:
      defer:
        secureClearPod(prefix)
        secureClearPod(running)
        secureClearPod(invAll)
    feCopy(prefix[0], zs[0])
    lane = 1
    while lane < L:
      feMul(prefix[lane], prefix[lane - 1], zs[lane])
      inc lane
    feInvert(invAll, prefix[L - 1])
    lane = L - 1
    while lane > 0:
      feMul(outInv[lane], invAll, prefix[lane - 1])
      feMul(running, invAll, zs[lane])
      feCopy(invAll, running)
      dec lane
    feCopy(outInv[0], invAll)

  proc x25519ScalarmultBatchRaw*[T: SimdU64](outShared: var array[lanesU64[T](), X25519Bytes32],
      secretKeys, publicKeys: array[lanesU64[T](), X25519Bytes32]): array[lanesU64[T](), bool] =
    otterSpan(x25519BenchTag & ".scalarmultBatch"):
      const lanes = lanesU64[T]()
      var
        t: array[lanes, X25519Bytes32]
        x1Fields: array[lanes, X25519Field]
        x1, x2, x3, z2, z3: X25519FieldVec[T]
        a, b, aa, bb, e, da, cb: X25519FieldVec[T]
        swapBits: array[lanes, uint32]
        bits: array[lanes, uint32]
        x2Fields, z2Fields, invZ: array[lanes, X25519Field]
        affine: X25519Field
        lane: int = 0
        pos: int = 254
        allValid: bool = true
        runScalarFallback: bool = false
      when x25519SecureWipe:
        defer:
          secureClearPod(t)
          secureClearPod(x1Fields)
          secureZeroMem(addr x1, sizeof(x1))
          secureZeroMem(addr x2, sizeof(x2))
          secureZeroMem(addr x3, sizeof(x3))
          secureZeroMem(addr z2, sizeof(z2))
          secureZeroMem(addr z3, sizeof(z3))
          secureZeroMem(addr a, sizeof(a))
          secureZeroMem(addr b, sizeof(b))
          secureZeroMem(addr aa, sizeof(aa))
          secureZeroMem(addr bb, sizeof(bb))
          secureZeroMem(addr e, sizeof(e))
          secureZeroMem(addr da, sizeof(da))
          secureZeroMem(addr cb, sizeof(cb))
          secureClearPod(swapBits)
          secureClearPod(bits)
          secureClearPod(x2Fields)
          secureClearPod(z2Fields)
          secureClearPod(invZ)
          secureClearPod(affine)
      lane = 0
      while lane < lanes:
        result[lane] = not hasSmallOrder(publicKeys[lane])
        if result[lane]:
          clampScalar(t[lane], secretKeys[lane])
          feFromBytes(x1Fields[lane], publicKeys[lane])
        else:
          allValid = false
          secureClearPod(t[lane])
          fe0(x1Fields[lane])
          secureClearPod(outShared[lane])
        inc lane
      when x25519BatchInversion:
        runScalarFallback = not allValid
      if runScalarFallback:
        lane = 0
        while lane < lanes:
          if result[lane]:
            result[lane] = x25519ScalarmultRaw(outShared[lane], secretKeys[lane], publicKeys[lane])
          else:
            secureClearPod(outShared[lane])
          inc lane
      else:
        x1 = packFieldVec[T](x1Fields)
        fe1Vec(x2)
        fe0Vec(z2)
        x3 = x1
        fe1Vec(z3)
        while pos >= 0:
          lane = 0
          while lane < lanes:
            bits[lane] = uint32((t[lane][pos div 8] shr (pos and 7)) and 1'u8)
            swapBits[lane] = swapBits[lane] xor bits[lane]
            inc lane
          feCswapVec(x2, x3, swapBits)
          feCswapVec(z2, z3, swapBits)
          swapBits = bits
          feAddVec(a, x2, z2)
          feSubVec(b, x2, z2)
          feSqVec(aa, a)
          feSqVec(bb, b)
          feMulVec(x2, aa, bb)
          feSubVec(e, aa, bb)
          feSubVec(da, x3, z3)
          feMulVec(da, da, a)
          feAddVec(cb, x3, z3)
          feMulVec(cb, cb, b)
          feAddVec(x3, da, cb)
          feSqVec(x3, x3)
          feSubVec(z3, da, cb)
          feSqVec(z3, z3)
          feMulVec(z3, z3, x1)
          feMul32Vec(z2, e, 121_666'u32)
          feAddVec(z2, z2, bb)
          feMulVec(z2, z2, e)
          dec pos
        feCswapVec(x2, x3, swapBits)
        feCswapVec(z2, z3, swapBits)
        x2Fields = unpackFieldVec(x2)
        z2Fields = unpackFieldVec(z2)
        when x25519BatchInversion:
          feInvertBatchFields(invZ, z2Fields)
        else:
          lane = 0
          while lane < lanes:
            feInvert(invZ[lane], z2Fields[lane])
            inc lane
        lane = 0
        while lane < lanes:
          feMul(affine, x2Fields[lane], invZ[lane])
          feToBytes(outShared[lane], affine)
          result[lane] = not isAllZero(outShared[lane])
          inc lane

  proc x25519ScalarmultBatch2Impl[T: SimdU64](outShared: var array[2, X25519Bytes32],
      secretKeys, publicKeys: array[2, X25519Bytes32]): array[2, bool] =
    when x25519BatchInversion:
      var
        lane: int = 0
        allValid: bool = true
      while lane < 2:
        allValid = allValid and not hasSmallOrder(publicKeys[lane])
        inc lane
      if not allValid:
        lane = 0
        while lane < 2:
          if hasSmallOrder(publicKeys[lane]):
            result[lane] = false
            secureClearPod(outShared[lane])
          else:
            result[lane] = x25519ScalarmultRaw(outShared[lane], secretKeys[lane], publicKeys[lane])
          inc lane
        return
    result = x25519ScalarmultBatchRaw[T](outShared, secretKeys, publicKeys)

  when defined(amd64) or defined(i386):
    proc x25519ScalarmultBatchSse2x*(outShared: var array[2, X25519Bytes32],
        secretKeys, publicKeys: array[2, X25519Bytes32]): array[2, bool] =
      result = x25519ScalarmultBatch2Impl[u64x2](outShared, secretKeys, publicKeys)

    proc x25519TyrSharedSse2x*(secretKeys, publicKeys: array[2, seq[byte]]): array[2, seq[byte]] =
      var
        sk: array[2, X25519Bytes32]
        pk: array[2, X25519Bytes32]
        shared: array[2, X25519Bytes32]
        ok: array[2, bool]
        lane: int = 0
      while lane < 2:
        sk[lane] = toFixed32(secretKeys[lane])
        pk[lane] = toFixed32(publicKeys[lane])
        inc lane
      ok = x25519ScalarmultBatchSse2x(shared, sk, pk)
      lane = 0
      while lane < 2:
        if not ok[lane]:
          raise newException(ValueError, "X25519 SIMD batch shared secret derivation failed")
        result[lane] = toSeqBytes(shared[lane])
        inc lane

  when defined(neon) or defined(arm64) or defined(aarch64):
    proc x25519ScalarmultBatchNeon2x*(outShared: var array[2, X25519Bytes32],
        secretKeys, publicKeys: array[2, X25519Bytes32]): array[2, bool] =
      result = x25519ScalarmultBatch2Impl[uint64x2](outShared, secretKeys, publicKeys)

    proc x25519TyrSharedNeon2x*(secretKeys, publicKeys: array[2, seq[byte]]): array[2, seq[byte]] =
      var
        sk: array[2, X25519Bytes32]
        pk: array[2, X25519Bytes32]
        shared: array[2, X25519Bytes32]
        ok: array[2, bool]
        lane: int = 0
      while lane < 2:
        sk[lane] = toFixed32(secretKeys[lane])
        pk[lane] = toFixed32(publicKeys[lane])
        inc lane
      ok = x25519ScalarmultBatchNeon2x(shared, sk, pk)
      lane = 0
      while lane < 2:
        if not ok[lane]:
          raise newException(ValueError, "X25519 NEON batch shared secret derivation failed")
        result[lane] = toSeqBytes(shared[lane])
        inc lane

  when defined(avx2):
    proc x25519ScalarmultBatchAvx4x*(outShared: var array[4, X25519Bytes32],
        secretKeys, publicKeys: array[4, X25519Bytes32]): array[4, bool] =
      when x25519BatchInversion:
        var
          lane: int = 0
          allValid: bool = true
        while lane < 4:
          allValid = allValid and not hasSmallOrder(publicKeys[lane])
          inc lane
        if not allValid:
          lane = 0
          while lane < 4:
            if hasSmallOrder(publicKeys[lane]):
              result[lane] = false
              secureClearPod(outShared[lane])
            else:
              result[lane] = x25519ScalarmultRaw(outShared[lane], secretKeys[lane], publicKeys[lane])
            inc lane
          return
      result = x25519ScalarmultBatchRaw[u64x4](outShared, secretKeys, publicKeys)

    proc x25519TyrSharedAvx4x*(secretKeys, publicKeys: array[4, seq[byte]]): array[4, seq[byte]] =
      var
        sk: array[4, X25519Bytes32]
        pk: array[4, X25519Bytes32]
        shared: array[4, X25519Bytes32]
        ok: array[4, bool]
        lane: int = 0
      while lane < 4:
        sk[lane] = toFixed32(secretKeys[lane])
        pk[lane] = toFixed32(publicKeys[lane])
        inc lane
      ok = x25519ScalarmultBatchAvx4x(shared, sk, pk)
      lane = 0
      while lane < 4:
        if not ok[lane]:
          raise newException(ValueError, "X25519 SIMD batch shared secret derivation failed")
        result[lane] = toSeqBytes(shared[lane])
        inc lane
