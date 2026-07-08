## --------------------------------------------------------------
## Ed25519 Impl <- pure Nim RFC 8032 signing and verification
## --------------------------------------------------------------
##
## Flow:
##   seed -> SHA-512 -> clamped scalar -> [scalar]B -> public key
##   msg  -> SHA-512(prefix || msg) -> R -> S -> signature
##
## This module is intentionally self-contained.  It does not call C
## crypto backends, so the wrapper can use Ed25519 without libsodium.

import ./x25519_common
import ../../random

const
  ed25519SeedBytes* = 32
  ed25519PublicKeyBytes* = 32
  ed25519SecretKeyBytes* = 64
  ed25519SignatureBytes* = 64
  feMask = 0x7ffffffffffff'u64
  l0 = 0x5812631a5cf5d3ed'u64
  l1 = 0x14def9dea2f79cd6'u64
  l2 = 0x0000000000000000'u64
  l3 = 0x1000000000000000'u64

type
  Ed25519Bytes32* = array[ed25519SeedBytes, byte]
  Ed25519Bytes64* = array[ed25519SignatureBytes, byte]
  Ed25519Field = array[5, uint64]
  Ed25519Point = object
    x, y, z, t: Ed25519Field
  Ed25519Keypair* = object
    publicKey*: seq[byte]
    secretKey*: seq[byte]

const
  sha512K: array[80, uint64] = [
    0x428a2f98d728ae22'u64, 0x7137449123ef65cd'u64,
    0xb5c0fbcfec4d3b2f'u64, 0xe9b5dba58189dbbc'u64,
    0x3956c25bf348b538'u64, 0x59f111f1b605d019'u64,
    0x923f82a4af194f9b'u64, 0xab1c5ed5da6d8118'u64,
    0xd807aa98a3030242'u64, 0x12835b0145706fbe'u64,
    0x243185be4ee4b28c'u64, 0x550c7dc3d5ffb4e2'u64,
    0x72be5d74f27b896f'u64, 0x80deb1fe3b1696b1'u64,
    0x9bdc06a725c71235'u64, 0xc19bf174cf692694'u64,
    0xe49b69c19ef14ad2'u64, 0xefbe4786384f25e3'u64,
    0x0fc19dc68b8cd5b5'u64, 0x240ca1cc77ac9c65'u64,
    0x2de92c6f592b0275'u64, 0x4a7484aa6ea6e483'u64,
    0x5cb0a9dcbd41fbd4'u64, 0x76f988da831153b5'u64,
    0x983e5152ee66dfab'u64, 0xa831c66d2db43210'u64,
    0xb00327c898fb213f'u64, 0xbf597fc7beef0ee4'u64,
    0xc6e00bf33da88fc2'u64, 0xd5a79147930aa725'u64,
    0x06ca6351e003826f'u64, 0x142929670a0e6e70'u64,
    0x27b70a8546d22ffc'u64, 0x2e1b21385c26c926'u64,
    0x4d2c6dfc5ac42aed'u64, 0x53380d139d95b3df'u64,
    0x650a73548baf63de'u64, 0x766a0abb3c77b2a8'u64,
    0x81c2c92e47edaee6'u64, 0x92722c851482353b'u64,
    0xa2bfe8a14cf10364'u64, 0xa81a664bbc423001'u64,
    0xc24b8b70d0f89791'u64, 0xc76c51a30654be30'u64,
    0xd192e819d6ef5218'u64, 0xd69906245565a910'u64,
    0xf40e35855771202a'u64, 0x106aa07032bbd1b8'u64,
    0x19a4c116b8d2d0c8'u64, 0x1e376c085141ab53'u64,
    0x2748774cdf8eeb99'u64, 0x34b0bcb5e19b48a8'u64,
    0x391c0cb3c5c95a63'u64, 0x4ed8aa4ae3418acb'u64,
    0x5b9cca4f7763e373'u64, 0x682e6ff3d6b2b8a3'u64,
    0x748f82ee5defb2fc'u64, 0x78a5636f43172f60'u64,
    0x84c87814a1f0ab72'u64, 0x8cc702081a6439ec'u64,
    0x90befffa23631e28'u64, 0xa4506cebde82bde9'u64,
    0xbef9a3f7b2c67915'u64, 0xc67178f2e372532b'u64,
    0xca273eceea26619c'u64, 0xd186b8c721c0c207'u64,
    0xeada7dd6cde0eb1e'u64, 0xf57d4f7fee6ed178'u64,
    0x06f067aa72176fba'u64, 0x0a637dc5a2c898a6'u64,
    0x113f9804bef90dae'u64, 0x1b710b35131c471b'u64,
    0x28db77f523047d84'u64, 0x32caab7b40c72493'u64,
    0x3c9ebe0a15c9bebc'u64, 0x431d67c49c100d4c'u64,
    0x4cc5d4becb3e42b6'u64, 0x597f299cfc657e2a'u64,
    0x5fcb6fab3ad6faec'u64, 0x6c44198c4a475817'u64
  ]

  fieldD: Ed25519Field = [
    929955233495203'u64, 466365720129213'u64, 1662059464998953'u64,
    2033849074728123'u64, 1442794654840575'u64
  ]
  fieldD2: Ed25519Field = [
    1859910466990425'u64, 932731440258426'u64, 1072319116312658'u64,
    1815898335770999'u64, 633789495995903'u64
  ]
  fieldSqrtM1: Ed25519Field = [
    1718705420411056'u64, 234908883556509'u64, 2233514472574048'u64,
    2117202627021982'u64, 765476049583133'u64
  ]
  sqrtExp: Ed25519Bytes32 = [
    0xfe'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8,
    0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8,
    0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8,
    0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0x0f'u8
  ]
  invExp: Ed25519Bytes32 = [
    0xeb'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8,
    0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8,
    0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8,
    0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0x7f'u8
  ]
  basePointCompressed: Ed25519Bytes32 = [
    0x58'u8, 0x66'u8, 0x66'u8, 0x66'u8, 0x66'u8, 0x66'u8, 0x66'u8, 0x66'u8,
    0x66'u8, 0x66'u8, 0x66'u8, 0x66'u8, 0x66'u8, 0x66'u8, 0x66'u8, 0x66'u8,
    0x66'u8, 0x66'u8, 0x66'u8, 0x66'u8, 0x66'u8, 0x66'u8, 0x66'u8, 0x66'u8,
    0x66'u8, 0x66'u8, 0x66'u8, 0x66'u8, 0x66'u8, 0x66'u8, 0x66'u8, 0x66'u8
  ]

proc rotr64(x: uint64, n: int): uint64 {.inline.} =
  result = (x shr n) or (x shl (64 - n))

proc load64Be(A: openArray[byte], o: int): uint64 {.inline.} =
  result = (uint64(A[o]) shl 56) or (uint64(A[o + 1]) shl 48) or
    (uint64(A[o + 2]) shl 40) or (uint64(A[o + 3]) shl 32) or
    (uint64(A[o + 4]) shl 24) or (uint64(A[o + 5]) shl 16) or
    (uint64(A[o + 6]) shl 8) or uint64(A[o + 7])

proc store64Be(A: var openArray[byte], o: int, v: uint64) {.inline.} =
  A[o] = byte((v shr 56) and 0xff'u64)
  A[o + 1] = byte((v shr 48) and 0xff'u64)
  A[o + 2] = byte((v shr 40) and 0xff'u64)
  A[o + 3] = byte((v shr 32) and 0xff'u64)
  A[o + 4] = byte((v shr 24) and 0xff'u64)
  A[o + 5] = byte((v shr 16) and 0xff'u64)
  A[o + 6] = byte((v shr 8) and 0xff'u64)
  A[o + 7] = byte(v and 0xff'u64)

proc sha512Hash*(A: openArray[byte]): Ed25519Bytes64 =
  var
    h: array[8, uint64] = [
      0x6a09e667f3bcc908'u64, 0xbb67ae8584caa73b'u64,
      0x3c6ef372fe94f82b'u64, 0xa54ff53a5f1d36f1'u64,
      0x510e527fade682d1'u64, 0x9b05688c2b3e6c1f'u64,
      0x1f83d9abfb41bd6b'u64, 0x5be0cd19137e2179'u64
    ]
    msg: seq[byte] = @[]
    bitLen: uint64 = uint64(A.len) * 8'u64
    w: array[80, uint64]
    offset: int = 0
    i: int = 0
  msg = newSeqOfCap[byte](A.len + 128)
  for b in A:
    msg.add(b)
  msg.add(0x80'u8)
  while (msg.len mod 128) != 112:
    msg.add(0'u8)
  i = 0
  while i < 8:
    msg.add(0'u8)
    inc i
  i = 7
  while i >= 0:
    msg.add(byte((bitLen shr (8 * i)) and 0xff'u64))
    dec i
  while offset < msg.len:
    i = 0
    while i < 16:
      w[i] = load64Be(msg, offset + 8 * i)
      inc i
    while i < 80:
      var s0 = rotr64(w[i - 15], 1) xor rotr64(w[i - 15], 8) xor (w[i - 15] shr 7)
      var s1 = rotr64(w[i - 2], 19) xor rotr64(w[i - 2], 61) xor (w[i - 2] shr 6)
      w[i] = w[i - 16] + s0 + w[i - 7] + s1
      inc i
    var
      a = h[0]
      b = h[1]
      c = h[2]
      d = h[3]
      e = h[4]
      f = h[5]
      g = h[6]
      hh = h[7]
    i = 0
    while i < 80:
      var s1 = rotr64(e, 14) xor rotr64(e, 18) xor rotr64(e, 41)
      var ch = (e and f) xor ((not e) and g)
      var temp1 = hh + s1 + ch + sha512K[i] + w[i]
      var s0 = rotr64(a, 28) xor rotr64(a, 34) xor rotr64(a, 39)
      var maj = (a and b) xor (a and c) xor (b and c)
      var temp2 = s0 + maj
      hh = g
      g = f
      f = e
      e = d + temp1
      d = c
      c = b
      b = a
      a = temp1 + temp2
      inc i
    h[0] = h[0] + a
    h[1] = h[1] + b
    h[2] = h[2] + c
    h[3] = h[3] + d
    h[4] = h[4] + e
    h[5] = h[5] + f
    h[6] = h[6] + g
    h[7] = h[7] + hh
    offset = offset + 128
  i = 0
  while i < 8:
    store64Be(result, i * 8, h[i])
    inc i

proc load64Le(A: openArray[byte], offset: int): uint64 {.inline.} =
  result = uint64(A[offset]) or (uint64(A[offset + 1]) shl 8) or
    (uint64(A[offset + 2]) shl 16) or (uint64(A[offset + 3]) shl 24) or
    (uint64(A[offset + 4]) shl 32) or (uint64(A[offset + 5]) shl 40) or
    (uint64(A[offset + 6]) shl 48) or (uint64(A[offset + 7]) shl 56)

proc store64Le(A: var Ed25519Bytes32, offset: int, v: uint64) {.inline.} =
  A[offset] = byte(v and 0xff'u64)
  A[offset + 1] = byte((v shr 8) and 0xff'u64)
  A[offset + 2] = byte((v shr 16) and 0xff'u64)
  A[offset + 3] = byte((v shr 24) and 0xff'u64)
  A[offset + 4] = byte((v shr 32) and 0xff'u64)
  A[offset + 5] = byte((v shr 40) and 0xff'u64)
  A[offset + 6] = byte((v shr 48) and 0xff'u64)
  A[offset + 7] = byte((v shr 56) and 0xff'u64)

proc mulWide(a, b: uint64, lo, hi: var uint64) {.inline.} =
  when defined(sizeof_Int128):
    type
      UInt128T = uint128
    var p = UInt128T(a) * UInt128T(b)
    lo = uint64(p)
    hi = uint64(p shr 64)
  else:
    var
      a0 = a and 0xffff_ffff'u64
      a1 = a shr 32
      b0 = b and 0xffff_ffff'u64
      b1 = b shr 32
      p00 = a0 * b0
      p01 = a0 * b1
      p10 = a1 * b0
      p11 = a1 * b1
      middle = (p00 shr 32) + (p01 and 0xffff_ffff'u64) + (p10 and 0xffff_ffff'u64)
    lo = (p00 and 0xffff_ffff'u64) or (middle shl 32)
    hi = p11 + (p01 shr 32) + (p10 shr 32) + (middle shr 32)

proc add64To128(lo, hi: var uint64, v: uint64) {.inline.} =
  var prev = lo
  lo = lo + v
  hi = hi + uint64(lo < prev)

proc addMul(lo, hi: var uint64, a, b: uint64) {.inline.} =
  var
    prodLo: uint64 = 0
    prodHi: uint64 = 0
  mulWide(a, b, prodLo, prodHi)
  add64To128(lo, hi, prodLo)
  hi = hi + prodHi

proc shift51(lo, hi: uint64): uint64 {.inline.} =
  result = (lo shr 51) or (hi shl 13)

proc fe0(h: var Ed25519Field) {.inline.} =
  h = [0'u64, 0, 0, 0, 0]

proc fe1(h: var Ed25519Field) {.inline.} =
  h = [1'u64, 0, 0, 0, 0]

proc feAdd(h: var Ed25519Field, f, g: Ed25519Field) {.inline.} =
  h[0] = f[0] + g[0]
  h[1] = f[1] + g[1]
  h[2] = f[2] + g[2]
  h[3] = f[3] + g[3]
  h[4] = f[4] + g[4]

proc feSub(h: var Ed25519Field, f, g: Ed25519Field) {.inline.} =
  var
    h0 = g[0]
    h1 = g[1]
    h2 = g[2]
    h3 = g[3]
    h4 = g[4]
  h1 = h1 + (h0 shr 51)
  h0 = h0 and feMask
  h2 = h2 + (h1 shr 51)
  h1 = h1 and feMask
  h3 = h3 + (h2 shr 51)
  h2 = h2 and feMask
  h4 = h4 + (h3 shr 51)
  h3 = h3 and feMask
  h0 = h0 + 19'u64 * (h4 shr 51)
  h4 = h4 and feMask
  h[0] = (f[0] + 0x00ff_ffff_ffff_fda'u64) - h0
  h[1] = (f[1] + 0x00ff_ffff_ffff_ffe'u64) - h1
  h[2] = (f[2] + 0x00ff_ffff_ffff_ffe'u64) - h2
  h[3] = (f[3] + 0x00ff_ffff_ffff_ffe'u64) - h3
  h[4] = (f[4] + 0x00ff_ffff_ffff_ffe'u64) - h4

proc feNeg(h: var Ed25519Field, f: Ed25519Field) {.inline.} =
  var z: Ed25519Field
  fe0(z)
  feSub(h, z, f)

proc reduceMulAcc(r0lo, r0hi, r1lo, r1hi, r2lo, r2hi, r3lo, r3hi,
    r4lo, r4hi: uint64, h: var Ed25519Field) {.inline.} =
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
  h[0] = a0lo and feMask
  carry = shift51(a0lo, a0hi)
  add64To128(a1lo, a1hi, carry)
  h[1] = a1lo and feMask
  carry = shift51(a1lo, a1hi)
  add64To128(a2lo, a2hi, carry)
  h[2] = a2lo and feMask
  carry = shift51(a2lo, a2hi)
  add64To128(a3lo, a3hi, carry)
  h[3] = a3lo and feMask
  carry = shift51(a3lo, a3hi)
  add64To128(a4lo, a4hi, carry)
  h[4] = a4lo and feMask
  carry = shift51(a4lo, a4hi)
  h[0] = h[0] + 19'u64 * carry
  carry = h[0] shr 51
  h[0] = h[0] and feMask
  h[1] = h[1] + carry

proc feMul(h: var Ed25519Field, f, g: Ed25519Field) {.inline.} =
  var
    f1_19 = 19'u64 * f[1]
    f2_19 = 19'u64 * f[2]
    f3_19 = 19'u64 * f[3]
    f4_19 = 19'u64 * f[4]
    r0lo, r0hi, r1lo, r1hi, r2lo, r2hi, r3lo, r3hi, r4lo, r4hi: uint64
  addMul(r0lo, r0hi, f[0], g[0])
  addMul(r0lo, r0hi, f1_19, g[4])
  addMul(r0lo, r0hi, f2_19, g[3])
  addMul(r0lo, r0hi, f3_19, g[2])
  addMul(r0lo, r0hi, f4_19, g[1])
  addMul(r1lo, r1hi, f[0], g[1])
  addMul(r1lo, r1hi, f[1], g[0])
  addMul(r1lo, r1hi, f2_19, g[4])
  addMul(r1lo, r1hi, f3_19, g[3])
  addMul(r1lo, r1hi, f4_19, g[2])
  addMul(r2lo, r2hi, f[0], g[2])
  addMul(r2lo, r2hi, f[1], g[1])
  addMul(r2lo, r2hi, f[2], g[0])
  addMul(r2lo, r2hi, f3_19, g[4])
  addMul(r2lo, r2hi, f4_19, g[3])
  addMul(r3lo, r3hi, f[0], g[3])
  addMul(r3lo, r3hi, f[1], g[2])
  addMul(r3lo, r3hi, f[2], g[1])
  addMul(r3lo, r3hi, f[3], g[0])
  addMul(r3lo, r3hi, f4_19, g[4])
  addMul(r4lo, r4hi, f[0], g[4])
  addMul(r4lo, r4hi, f[1], g[3])
  addMul(r4lo, r4hi, f[2], g[2])
  addMul(r4lo, r4hi, f[3], g[1])
  addMul(r4lo, r4hi, f[4], g[0])
  reduceMulAcc(r0lo, r0hi, r1lo, r1hi, r2lo, r2hi, r3lo, r3hi, r4lo, r4hi, h)

proc feSq(h: var Ed25519Field, f: Ed25519Field) {.inline.} =
  feMul(h, f, f)

proc feFromBytes(h: var Ed25519Field, s: Ed25519Bytes32) {.inline.} =
  var t = s
  t[31] = t[31] and 0x7f'u8
  h[0] = load64Le(t, 0) and feMask
  h[1] = (load64Le(t, 6) shr 3) and feMask
  h[2] = (load64Le(t, 12) shr 6) and feMask
  h[3] = (load64Le(t, 19) shr 1) and feMask
  h[4] = (load64Le(t, 24) shr 12) and feMask

proc feReduce(h: var Ed25519Field, f: Ed25519Field) {.inline.} =
  var
    t0 = f[0]
    t1 = f[1]
    t2 = f[2]
    t3 = f[3]
    t4 = f[4]
  t1 = t1 + (t0 shr 51)
  t0 = t0 and feMask
  t2 = t2 + (t1 shr 51)
  t1 = t1 and feMask
  t3 = t3 + (t2 shr 51)
  t2 = t2 and feMask
  t4 = t4 + (t3 shr 51)
  t3 = t3 and feMask
  t0 = t0 + 19'u64 * (t4 shr 51)
  t4 = t4 and feMask
  t1 = t1 + (t0 shr 51)
  t0 = t0 and feMask
  t2 = t2 + (t1 shr 51)
  t1 = t1 and feMask
  t3 = t3 + (t2 shr 51)
  t2 = t2 and feMask
  t4 = t4 + (t3 shr 51)
  t3 = t3 and feMask
  t0 = t0 + 19'u64 * (t4 shr 51)
  t4 = t4 and feMask
  t0 = t0 + 19'u64
  t1 = t1 + (t0 shr 51)
  t0 = t0 and feMask
  t2 = t2 + (t1 shr 51)
  t1 = t1 and feMask
  t3 = t3 + (t2 shr 51)
  t2 = t2 and feMask
  t4 = t4 + (t3 shr 51)
  t3 = t3 and feMask
  t0 = t0 + 19'u64 * (t4 shr 51)
  t4 = t4 and feMask
  t0 = t0 + 0x8000000000000'u64 - 19'u64
  t1 = t1 + 0x8000000000000'u64 - 1'u64
  t2 = t2 + 0x8000000000000'u64 - 1'u64
  t3 = t3 + 0x8000000000000'u64 - 1'u64
  t4 = t4 + 0x8000000000000'u64 - 1'u64
  t1 = t1 + (t0 shr 51)
  t0 = t0 and feMask
  t2 = t2 + (t1 shr 51)
  t1 = t1 and feMask
  t3 = t3 + (t2 shr 51)
  t2 = t2 and feMask
  t4 = t4 + (t3 shr 51)
  t3 = t3 and feMask
  h[0] = t0
  h[1] = t1
  h[2] = t2
  h[3] = t3
  h[4] = t4 and feMask

proc feToBytes(h: Ed25519Field): Ed25519Bytes32 {.inline.} =
  var t: Ed25519Field
  feReduce(t, h)
  store64Le(result, 0, t[0] or (t[1] shl 51))
  store64Le(result, 8, (t[1] shr 13) or (t[2] shl 38))
  store64Le(result, 16, (t[2] shr 26) or (t[3] shl 25))
  store64Le(result, 24, (t[3] shr 39) or (t[4] shl 12))

proc feIsZero(f: Ed25519Field): bool {.inline.} =
  result = isAllZero(feToBytes(f))

proc feIsNegative(f: Ed25519Field): bool {.inline.} =
  result = (feToBytes(f)[0] and 1'u8) == 1'u8

proc fePow(h: var Ed25519Field, z: Ed25519Field, e: Ed25519Bytes32) =
  var
    r: Ed25519Field
    i: int = 255
  fe1(r)
  while i >= 0:
    feSq(r, r)
    if ((e[i div 8] shr (i and 7)) and 1'u8) == 1'u8:
      feMul(r, r, z)
    dec i
  h = r

proc feInvert(h: var Ed25519Field, z: Ed25519Field) {.inline.} =
  fePow(h, z, invExp)

proc bytesLessThanP(s: Ed25519Bytes32): bool =
  var
    p: Ed25519Bytes32 = [
      0xed'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8,
      0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8,
      0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8,
      0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0x7f'u8]
    i: int = 31
  while i >= 0:
    if s[i] < p[i]:
      return true
    if s[i] > p[i]:
      return false
    dec i
  result = false

proc pointIdentity(p: var Ed25519Point) {.inline.} =
  fe0(p.x)
  fe1(p.y)
  fe1(p.z)
  fe0(p.t)

proc pointAdd(r: var Ed25519Point, p, q: Ed25519Point) =
  var a, b, c, d, e, f, g, h, t0, t1: Ed25519Field
  feSub(t0, p.y, p.x)
  feSub(t1, q.y, q.x)
  feMul(a, t0, t1)
  feAdd(t0, p.y, p.x)
  feAdd(t1, q.y, q.x)
  feMul(b, t0, t1)
  feMul(t0, p.t, q.t)
  feMul(c, t0, fieldD2)
  feMul(t0, p.z, q.z)
  feAdd(d, t0, t0)
  feSub(e, b, a)
  feSub(f, d, c)
  feAdd(g, d, c)
  feAdd(h, b, a)
  feMul(r.x, e, f)
  feMul(r.y, g, h)
  feMul(r.t, e, h)
  feMul(r.z, f, g)

proc pointDouble(r: var Ed25519Point, p: Ed25519Point) =
  var a, b, c, e, f, g, h, t0: Ed25519Field
  feSq(a, p.x)
  feSq(b, p.y)
  feSq(t0, p.z)
  feAdd(c, t0, t0)
  feAdd(h, a, b)
  feAdd(t0, p.x, p.y)
  feSq(t0, t0)
  feSub(e, h, t0)
  feSub(g, a, b)
  feAdd(f, c, g)
  feMul(r.x, e, f)
  feMul(r.y, g, h)
  feMul(r.t, e, h)
  feMul(r.z, f, g)

proc pointEncode(p: Ed25519Point): Ed25519Bytes32 =
  var
    zi, x, y: Ed25519Field
  feInvert(zi, p.z)
  feMul(x, p.x, zi)
  feMul(y, p.y, zi)
  result = feToBytes(y)
  if feIsNegative(x):
    result[31] = result[31] or 0x80'u8

proc pointDecode(p: var Ed25519Point, s: Ed25519Bytes32): bool =
  var
    yBytes = s
    sign: byte = (s[31] shr 7) and 1'u8
    y, y2, u, v, vInv, x2, x, check, negX2: Ed25519Field
    one: Ed25519Field
  yBytes[31] = yBytes[31] and 0x7f'u8
  if not bytesLessThanP(yBytes):
    return false
  fe1(one)
  feFromBytes(y, yBytes)
  feSq(y2, y)
  feSub(u, y2, one)
  feMul(v, fieldD, y2)
  feAdd(v, v, one)
  feInvert(vInv, v)
  feMul(x2, u, vInv)
  fePow(x, x2, sqrtExp)
  feSq(check, x)
  feSub(check, check, x2)
  if not feIsZero(check):
    feMul(x, x, fieldSqrtM1)
  feSq(check, x)
  feSub(check, check, x2)
  if not feIsZero(check):
    return false
  if feIsZero(x) and sign == 1'u8:
    return false
  if byte(feIsNegative(x)) != sign:
    feNeg(x, x)
  p.x = x
  p.y = y
  fe1(p.z)
  feMul(p.t, x, y)
  discard negX2
  result = true

proc basePoint(): Ed25519Point =
  if not pointDecode(result, basePointCompressed):
    raise newException(ValueError, "invalid Ed25519 base point")

proc pointScalarMult(p: Ed25519Point, scalar: Ed25519Bytes32): Ed25519Point =
  var
    q: Ed25519Point
    n = p
    tmp: Ed25519Point
    i: int = 0
  pointIdentity(q)
  while i < 256:
    if ((scalar[i div 8] shr (i and 7)) and 1'u8) == 1'u8:
      pointAdd(tmp, q, n)
      q = tmp
    pointDouble(tmp, n)
    n = tmp
    inc i
  result = q

proc geBase(scalar: Ed25519Bytes32): Ed25519Point =
  result = pointScalarMult(basePoint(), scalar)

proc scalarBytesToLimbs(s: Ed25519Bytes32): array[4, uint64] {.inline.} =
  result[0] = load64Le(s, 0)
  result[1] = load64Le(s, 8)
  result[2] = load64Le(s, 16)
  result[3] = load64Le(s, 24)

proc scalarCmpL(a: array[4, uint64]): int {.inline.} =
  var L: array[4, uint64] = [l0, l1, l2, l3]
  var i: int = 3
  while i >= 0:
    if a[i] > L[i]: return 1
    if a[i] < L[i]: return -1
    dec i
  result = 0

proc scalarSubL(a: var array[4, uint64]) {.inline.} =
  var L: array[4, uint64] = [l0, l1, l2, l3]
  var
    i: int = 0
    borrow: uint64 = 0
  while i < 4:
    var sub = L[i] + borrow
    var nextBorrow = uint64(a[i] < sub)
    if borrow == 1'u64 and sub == 0'u64:
      nextBorrow = 1'u64
    a[i] = a[i] - sub
    borrow = nextBorrow
    inc i

proc scalarAddMod(a: var array[4, uint64], b: array[4, uint64]) {.inline.} =
  var
    i: int = 0
    carry: uint64 = 0
  while i < 4:
    var old = a[i]
    a[i] = a[i] + b[i]
    var c0 = uint64(a[i] < old)
    old = a[i]
    a[i] = a[i] + carry
    carry = c0 or uint64(a[i] < old)
    inc i
  if carry != 0'u64 or scalarCmpL(a) >= 0:
    scalarSubL(a)

proc scalarDoubleMod(a: var array[4, uint64]) {.inline.} =
  var b = a
  scalarAddMod(a, b)

proc scalarToBytes(a: array[4, uint64]): Ed25519Bytes32 {.inline.} =
  store64Le(result, 0, a[0])
  store64Le(result, 8, a[1])
  store64Le(result, 16, a[2])
  store64Le(result, 24, a[3])

proc getBitWide(A: array[8, uint64], pos: int): uint64 {.inline.} =
  result = (A[pos div 64] shr (pos and 63)) and 1'u64

proc reduceWide(A: array[8, uint64]): Ed25519Bytes32 =
  var
    rem: array[4, uint64]
    i: int = 511
  while i >= 0:
    scalarDoubleMod(rem)
    if getBitWide(A, i) == 1'u64:
      var one: array[4, uint64] = [1'u64, 0, 0, 0]
      scalarAddMod(rem, one)
    dec i
  result = scalarToBytes(rem)

proc reduce64(A: Ed25519Bytes64): Ed25519Bytes32 =
  var wide: array[8, uint64]
  var i: int = 0
  while i < 8:
    wide[i] = load64Le(A, i * 8)
    inc i
  result = reduceWide(wide)

proc reduce32(A: Ed25519Bytes32): Ed25519Bytes32 =
  var wide: array[8, uint64]
  var i: int = 0
  while i < 4:
    wide[i] = load64Le(A, i * 8)
    inc i
  result = reduceWide(wide)

proc scalarIsCanonical(s: Ed25519Bytes32): bool =
  result = scalarCmpL(scalarBytesToLimbs(s)) < 0

proc scalarMulAdd(k, s, r: Ed25519Bytes32): Ed25519Bytes32 =
  var
    acc = scalarBytesToLimbs(reduce32(r))
    cur = scalarBytesToLimbs(reduce32(s))
    kk = reduce32(k)
    one: array[4, uint64]
    i: int = 0
  discard one
  while i < 256:
    if ((kk[i div 8] shr (i and 7)) and 1'u8) == 1'u8:
      scalarAddMod(acc, cur)
    scalarDoubleMod(cur)
    inc i
  result = scalarToBytes(acc)

proc toFixed32Ed(input: openArray[byte], label: string): Ed25519Bytes32 =
  var i: int = 0
  if input.len != 32:
    raise newException(ValueError, "invalid Ed25519 " & label & " length")
  while i < 32:
    result[i] = input[i]
    inc i

proc toSeq32(input: Ed25519Bytes32): seq[byte] =
  var i: int = 0
  result = newSeq[byte](32)
  while i < 32:
    result[i] = input[i]
    inc i

proc toSeq64(input: Ed25519Bytes64): seq[byte] =
  var i: int = 0
  result = newSeq[byte](64)
  while i < 64:
    result[i] = input[i]
    inc i

proc clampDigestScalar(h: Ed25519Bytes64): Ed25519Bytes32 =
  var i: int = 0
  while i < 32:
    result[i] = h[i]
    inc i
  result[0] = result[0] and 248'u8
  result[31] = (result[31] and 63'u8) or 64'u8

proc publicKeyFromSeed(seed: Ed25519Bytes32): Ed25519Bytes32 =
  var h = sha512Hash(seed)
  var a = clampDigestScalar(h)
  result = pointEncode(geBase(a))

proc ed25519TyrPublicKey*(seed: openArray[byte]): seq[byte] =
  var s = toFixed32Ed(seed, "seed")
  result = toSeq32(publicKeyFromSeed(s))

proc ed25519TyrKeypairFromSeed*(seed: openArray[byte]): Ed25519Keypair =
  var
    s = toFixed32Ed(seed, "seed")
    pk = publicKeyFromSeed(s)
    i: int = 0
  result.publicKey = toSeq32(pk)
  result.secretKey = newSeq[byte](64)
  while i < 32:
    result.secretKey[i] = s[i]
    result.secretKey[i + 32] = pk[i]
    inc i

proc ed25519TyrKeypair*(): Ed25519Keypair =
  var seed = cryptoRandomBytes(32)
  defer:
    secureClearBytes(seed)
  result = ed25519TyrKeypairFromSeed(seed)

proc ed25519TyrSign*(message, secretKey: openArray[byte]): seq[byte] =
  var
    seed: Ed25519Bytes32
    publicKey: Ed25519Bytes32
    h: Ed25519Bytes64
    a: Ed25519Bytes32
    prefixMsg: seq[byte]
    rDigest: Ed25519Bytes64
    r: Ed25519Bytes32
    rPoint: Ed25519Point
    rEncoded: Ed25519Bytes32
    hramInput: seq[byte]
    hramDigest: Ed25519Bytes64
    hram: Ed25519Bytes32
    s: Ed25519Bytes32
    sig: Ed25519Bytes64
    i: int = 0
  if secretKey.len != 64:
    raise newException(ValueError, "invalid Ed25519 secret key length")
  while i < 32:
    seed[i] = secretKey[i]
    publicKey[i] = secretKey[i + 32]
    inc i
  h = sha512Hash(seed)
  a = clampDigestScalar(h)
  prefixMsg = newSeqOfCap[byte](32 + message.len)
  i = 32
  while i < 64:
    prefixMsg.add(h[i])
    inc i
  for b in message:
    prefixMsg.add(b)
  rDigest = sha512Hash(prefixMsg)
  r = reduce64(rDigest)
  rPoint = geBase(r)
  rEncoded = pointEncode(rPoint)
  hramInput = newSeqOfCap[byte](64 + message.len)
  i = 0
  while i < 32:
    hramInput.add(rEncoded[i])
    inc i
  i = 0
  while i < 32:
    hramInput.add(publicKey[i])
    inc i
  for b in message:
    hramInput.add(b)
  hramDigest = sha512Hash(hramInput)
  hram = reduce64(hramDigest)
  s = scalarMulAdd(hram, a, r)
  i = 0
  while i < 32:
    sig[i] = rEncoded[i]
    sig[i + 32] = s[i]
    inc i
  result = toSeq64(sig)

proc ed25519TyrVerify*(message, signature, publicKey: openArray[byte]): bool =
  var
    sigR: Ed25519Bytes32
    sigS: Ed25519Bytes32
    pk: Ed25519Bytes32
    aPoint, rPoint, sB, hA, rhs: Ed25519Point
    hramInput: seq[byte]
    hramDigest: Ed25519Bytes64
    hram: Ed25519Bytes32
    i: int = 0
  if signature.len != 64 or publicKey.len != 32:
    return false
  while i < 32:
    sigR[i] = signature[i]
    sigS[i] = signature[i + 32]
    pk[i] = publicKey[i]
    inc i
  if not scalarIsCanonical(sigS):
    return false
  if not pointDecode(aPoint, pk):
    return false
  if not pointDecode(rPoint, sigR):
    return false
  hramInput = newSeqOfCap[byte](64 + message.len)
  i = 0
  while i < 32:
    hramInput.add(sigR[i])
    inc i
  i = 0
  while i < 32:
    hramInput.add(pk[i])
    inc i
  for b in message:
    hramInput.add(b)
  hramDigest = sha512Hash(hramInput)
  hram = reduce64(hramDigest)
  sB = geBase(sigS)
  hA = pointScalarMult(aPoint, hram)
  pointAdd(rhs, rPoint, hA)
  result = pointEncode(sB) == pointEncode(rhs)

when defined(amd64) or defined(i386):
  proc ed25519TyrSignSse2x*(messages: array[2, seq[byte]],
      secretKeys: array[2, seq[byte]]): array[2, seq[byte]] =
    var lane: int = 0
    while lane < 2:
      result[lane] = ed25519TyrSign(messages[lane], secretKeys[lane])
      inc lane

  proc ed25519TyrVerifySse2x*(messages, signatures, publicKeys: array[2, seq[byte]]): array[2, bool] =
    var lane: int = 0
    while lane < 2:
      result[lane] = ed25519TyrVerify(messages[lane], signatures[lane], publicKeys[lane])
      inc lane

when defined(avx2):
  proc ed25519TyrSignAvx4x*(messages: array[4, seq[byte]],
      secretKeys: array[4, seq[byte]]): array[4, seq[byte]] =
    var lane: int = 0
    while lane < 4:
      result[lane] = ed25519TyrSign(messages[lane], secretKeys[lane])
      inc lane

  proc ed25519TyrVerifyAvx4x*(messages, signatures, publicKeys: array[4, seq[byte]]): array[4, bool] =
    var lane: int = 0
    while lane < 4:
      result[lane] = ed25519TyrVerify(messages[lane], signatures[lane], publicKeys[lane])
      inc lane
