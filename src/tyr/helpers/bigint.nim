## ---------------------------------------------------------------------
## BigInt <- bounded unsigned multiprecision integers for RSA and ECDSA
## ---------------------------------------------------------------------
##
## Limbs are little-endian `uint32` so every intermediate fits a `uint64`.
## Values are kept normalized: no trailing zero limbs, and zero is `@[]`.
## Modular exponentiation uses Montgomery arithmetic and requires an odd
## modulus, which is always true for RSA moduli and their CRT factors.
##
## This representation is variable-time and heap-backed. It is suitable for
## public verification arithmetic, but private-key operations need a separate
## fixed-width, constant-time backend before production use.

import tyrPragmas

type
  BigInt* {.role: {rawData}.} = object
    limbs*: seq[uint32]

  MontContext* {.role: {truthState}.} = object
    m*: BigInt      # odd modulus
    n0inv*: uint32  # -m^-1 mod 2^32
    rr*: BigInt     # R^2 mod m, R = 2^(32*len(m))
    len*: int       # limb count of the modulus

const
  bigMaxLimbs* = 512 ## 16384-bit ceiling; rejects hostile key material early

proc trimBig(x: var BigInt) {.role: {helper}.} =
  ## x: value whose trailing zero limbs are dropped to restore normal form.
  var n: int = x.limbs.len
  while n > 0 and x.limbs[n - 1] == 0'u32:
    n = n - 1
  x.limbs.setLen(n)

proc bigZero*(): BigInt {.role: {helper}.} =
  ## Return the canonical zero value.
  result.limbs = @[]

proc bigIsZero*(x: BigInt): bool {.role: {helper}.} =
  ## x: value to test against zero.
  result = x.limbs.len == 0

proc bigIsOdd*(x: BigInt): bool {.role: {helper}.} =
  ## x: value whose least significant bit is inspected.
  result = x.limbs.len > 0 and (x.limbs[0] and 1'u32) != 0'u32

proc bigFromUint32*(v: uint32): BigInt {.role: {helper}.} =
  ## v: single-limb seed value.
  if v != 0'u32:
    result.limbs = @[v]

proc bigBitLen*(x: BigInt): int {.role: {helper}.} =
  ## x: value whose significant bit count is returned.
  var
    top: uint32 = 0
    n: int = 0
  if x.limbs.len == 0:
    return 0
  top = x.limbs[x.limbs.len - 1]
  n = (x.limbs.len - 1) * 32
  while top != 0'u32:
    n = n + 1
    top = top shr 1
  result = n

proc bigTestBit*(x: BigInt, i: int): bool {.role: {helper}.} =
  ## x: value to inspect.
  ## i: zero-based bit index.
  var limb: int = i shr 5
  if i < 0 or limb >= x.limbs.len:
    return false
  result = ((x.limbs[limb] shr uint32(i and 31)) and 1'u32) != 0'u32

proc bigFromBytesBe*(A: openArray[byte]): BigInt {.role: {parser}.} =
  ## A: big-endian unsigned magnitude, leading zeros permitted.
  var
    i: int = 0
    shift: int = 0
    limb: int = 0
    n: int = A.len
  if n == 0:
    return bigZero()
  result.limbs = newSeq[uint32]((n + 3) div 4)
  i = n - 1
  while i >= 0:
    limb = (n - 1 - i) shr 2
    shift = ((n - 1 - i) and 3) * 8
    result.limbs[limb] = result.limbs[limb] or (uint32(A[i]) shl uint32(shift))
    i = i - 1
  trimBig(result)

proc bigToBytesBe*(x: BigInt, width: int): seq[byte] {.role: {dataWriter}.} =
  ## x: value to serialize.
  ## width: fixed output length; the value is left-padded with zero bytes.
  var
    i: int = 0
    limb: int = 0
    shift: int = 0
  result = newSeq[byte](width)
  i = 0
  while i < width:
    limb = i shr 2
    shift = (i and 3) * 8
    if limb < x.limbs.len:
      result[width - 1 - i] = byte((x.limbs[limb] shr uint32(shift)) and 0xff'u32)
    i = i + 1

proc bigByteLen*(x: BigInt): int {.role: {helper}.} =
  ## x: value whose minimal big-endian byte length is returned.
  result = (bigBitLen(x) + 7) div 8

proc bigCmp*(a, b: BigInt): int {.role: {math}.} =
  ## a/b: values compared as unsigned magnitudes.
  ## Returns -1, 0, or 1.
  var i: int = 0
  if a.limbs.len != b.limbs.len:
    return if a.limbs.len < b.limbs.len: -1 else: 1
  i = a.limbs.len - 1
  while i >= 0:
    if a.limbs[i] != b.limbs[i]:
      return if a.limbs[i] < b.limbs[i]: -1 else: 1
    i = i - 1
  result = 0

proc bigAdd*(a, b: BigInt): BigInt {.role: {math}.} =
  ## a/b: addends.
  var
    n: int = max(a.limbs.len, b.limbs.len)
    carry: uint64 = 0
    t: uint64 = 0
    i: int = 0
  result.limbs = newSeq[uint32](n + 1)
  while i < n:
    t = carry
    if i < a.limbs.len:
      t = t + uint64(a.limbs[i])
    if i < b.limbs.len:
      t = t + uint64(b.limbs[i])
    result.limbs[i] = uint32(t and 0xffffffff'u64)
    carry = t shr 32
    i = i + 1
  result.limbs[n] = uint32(carry)
  trimBig(result)

proc bigSub*(a, b: BigInt): BigInt {.role: {math}.} =
  ## a/b: minuend and subtrahend; `a` must be greater than or equal to `b`.
  var
    borrow: uint64 = 0
    t: uint64 = 0
    bv: uint64 = 0
    i: int = 0
  if bigCmp(a, b) < 0:
    raise newException(ValueError, "bigSub underflow")
  result.limbs = newSeq[uint32](a.limbs.len)
  while i < a.limbs.len:
    bv = 0
    if i < b.limbs.len:
      bv = uint64(b.limbs[i])
    t = uint64(a.limbs[i]) - bv - borrow
    result.limbs[i] = uint32(t and 0xffffffff'u64)
    borrow = (t shr 63) and 1'u64
    i = i + 1
  trimBig(result)

proc bigMul*(a, b: BigInt): BigInt {.role: {math}.} =
  ## a/b: factors multiplied with schoolbook accumulation.
  var
    i, j: int = 0
    carry, t: uint64 = 0
  if a.limbs.len == 0 or b.limbs.len == 0:
    return bigZero()
  result.limbs = newSeq[uint32](a.limbs.len + b.limbs.len)
  i = 0
  while i < a.limbs.len:
    carry = 0
    j = 0
    while j < b.limbs.len:
      t = uint64(a.limbs[i]) * uint64(b.limbs[j]) +
        uint64(result.limbs[i + j]) + carry
      result.limbs[i + j] = uint32(t and 0xffffffff'u64)
      carry = t shr 32
      j = j + 1
    result.limbs[i + b.limbs.len] = uint32(carry)
    i = i + 1
  trimBig(result)

proc bigShlBits(x: BigInt, s: int): BigInt {.role: {math}.} =
  ## x: value to shift left.
  ## s: bit count in the range 0..31.
  var
    carry: uint32 = 0
    t: uint64 = 0
    i: int = 0
  if s == 0:
    return x
  result.limbs = newSeq[uint32](x.limbs.len + 1)
  while i < x.limbs.len:
    t = (uint64(x.limbs[i]) shl uint64(s)) or uint64(carry)
    result.limbs[i] = uint32(t and 0xffffffff'u64)
    carry = uint32(t shr 32)
    i = i + 1
  result.limbs[x.limbs.len] = carry
  trimBig(result)

proc bigShrBits(x: BigInt, s: int): BigInt {.role: {math}.} =
  ## x: value to shift right.
  ## s: bit count in the range 0..31.
  var
    i: int = 0
    lo, hi: uint32 = 0
  if s == 0:
    return x
  result.limbs = newSeq[uint32](x.limbs.len)
  i = 0
  while i < x.limbs.len:
    lo = x.limbs[i] shr uint32(s)
    hi = 0
    if i + 1 < x.limbs.len:
      hi = x.limbs[i + 1] shl uint32(32 - s)
    result.limbs[i] = lo or hi
    i = i + 1
  trimBig(result)

proc bigShrBitsPublic*(x: BigInt, s: int): BigInt {.role: {math}.} =
  ## x: value to shift right.
  ## s: arbitrary non-negative bit count.
  var
    drop: int = s shr 5
    rest: int = s and 31
  if s <= 0:
    return x
  if drop >= x.limbs.len:
    return bigZero()
  result.limbs = x.limbs[drop .. ^1]
  trimBig(result)
  result = bigShrBits(result, rest)

proc bigShiftLeftLimbs(x: BigInt, k: int): BigInt {.role: {math}.} =
  ## x: value to scale by 2^(32*k).
  ## k: limb count to prepend.
  if x.limbs.len == 0 or k <= 0:
    return x
  result.limbs = newSeq[uint32](k)
  result.limbs.add(x.limbs)

proc bigDivMod*(a, m: BigInt): tuple[q, r: BigInt] {.role: {math}.} =
  ## a/m: dividend and non-zero divisor.
  ## Returns the quotient and remainder using Knuth algorithm D.
  var
    shift, i, j, n, mlen: int = 0
    u, v: BigInt
    qhat, rhat, num, p: uint64 = 0
    t, k: int64 = 0
    carry: uint64 = 0
    top: uint32 = 0
  if m.limbs.len == 0:
    raise newException(DivByZeroDefect, "bigDivMod by zero")
  if bigCmp(a, m) < 0:
    return (q: bigZero(), r: a)
  if m.limbs.len == 1:
    # Single-limb fast path keeps the general loop free of degenerate cases.
    var
      rem: uint64 = 0
      d: uint64 = uint64(m.limbs[0])
    result.q.limbs = newSeq[uint32](a.limbs.len)
    i = a.limbs.len - 1
    while i >= 0:
      num = (rem shl 32) or uint64(a.limbs[i])
      result.q.limbs[i] = uint32(num div d)
      rem = num mod d
      i = i - 1
    trimBig(result.q)
    result.r = bigFromUint32(uint32(rem))
    return
  # Normalize so the divisor's top limb has its high bit set.
  top = m.limbs[m.limbs.len - 1]
  shift = 0
  while (top and 0x80000000'u32) == 0'u32:
    top = top shl 1
    shift = shift + 1
  u = bigShlBits(a, shift)
  v = bigShlBits(m, shift)
  n = v.limbs.len
  mlen = a.limbs.len - n
  # Algorithm D wants exactly (mlen + n + 1) dividend limbs, top one possibly zero.
  u.limbs.setLen(a.limbs.len + 1)
  result.q.limbs = newSeq[uint32](mlen + 1)
  j = mlen
  while j >= 0:
    num = (uint64(u.limbs[j + n]) shl 32) or uint64(u.limbs[j + n - 1])
    qhat = num div uint64(v.limbs[n - 1])
    rhat = num mod uint64(v.limbs[n - 1])
    while qhat > 0xffffffff'u64 or
        (qhat * uint64(v.limbs[n - 2])) >
          ((rhat shl 32) or uint64(u.limbs[j + n - 2])):
      qhat = qhat - 1
      rhat = rhat + uint64(v.limbs[n - 1])
      if rhat > 0xffffffff'u64:
        break
    # Multiply and subtract qhat*v from the window u[j .. j+n].
    k = 0
    i = 0
    while i < n:
      p = qhat * uint64(v.limbs[i])
      t = int64(uint64(u.limbs[i + j])) - k - int64(p and 0xffffffff'u64)
      u.limbs[i + j] = uint32(uint64(t) and 0xffffffff'u64)
      k = int64(p shr 32) - (t shr 32)
      i = i + 1
    t = int64(uint64(u.limbs[j + n])) - k
    u.limbs[j + n] = uint32(uint64(t) and 0xffffffff'u64)
    # qhat was at most one too large; add v back when the window went negative.
    if t < 0:
      qhat = qhat - 1
      carry = 0
      i = 0
      while i < n:
        carry = carry + uint64(u.limbs[i + j]) + uint64(v.limbs[i])
        u.limbs[i + j] = uint32(carry and 0xffffffff'u64)
        carry = carry shr 32
        i = i + 1
      u.limbs[j + n] = uint32((uint64(u.limbs[j + n]) + carry) and 0xffffffff'u64)
    result.q.limbs[j] = uint32(qhat)
    j = j - 1
  trimBig(result.q)
  u.limbs.setLen(n)
  trimBig(u)
  result.r = bigShrBits(u, shift)

proc bigMod*(a, m: BigInt): BigInt {.role: {math}.} =
  ## a/m: value and non-zero modulus.
  result = bigDivMod(a, m).r

proc bigModAdd*(a, b, m: BigInt): BigInt {.role: {math}.} =
  ## a/b/m: addends already reduced mod `m`, and the modulus.
  result = bigAdd(a, b)
  if bigCmp(result, m) >= 0:
    result = bigSub(result, m)

proc bigModSub*(a, b, m: BigInt): BigInt {.role: {math}.} =
  ## a/b/m: values already reduced mod `m`, and the modulus.
  if bigCmp(a, b) >= 0:
    result = bigSub(a, b)
  else:
    result = bigSub(bigAdd(a, m), b)

proc bigModInv*(a, m: BigInt): tuple[ok: bool, value: BigInt] {.role: {math}.} =
  ## a/m: value to invert and the modulus.
  ## Returns the inverse when `a` and `m` are coprime, using the extended
  ## binary GCD on non-negative representatives only.
  var
    u, v, x1, x2: BigInt
    one: BigInt = bigFromUint32(1'u32)
  if bigIsZero(m) or bigIsZero(a):
    return (ok: false, value: bigZero())
  u = bigMod(a, m)
  if bigIsZero(u):
    return (ok: false, value: bigZero())
  v = m
  x1 = one
  x2 = bigZero()
  while not bigIsZero(u) and not bigIsZero(v):
    while not bigIsOdd(u):
      u = bigShrBits(u, 1)
      if bigIsOdd(x1):
        x1 = bigAdd(x1, m)
      x1 = bigShrBits(x1, 1)
    while not bigIsOdd(v):
      v = bigShrBits(v, 1)
      if bigIsOdd(x2):
        x2 = bigAdd(x2, m)
      x2 = bigShrBits(x2, 1)
    if bigCmp(u, v) >= 0:
      u = bigSub(u, v)
      x1 = bigModSub(x1, x2, m)
    else:
      v = bigSub(v, u)
      x2 = bigModSub(x2, x1, m)
  if bigIsZero(u):
    if bigCmp(v, one) != 0:
      return (ok: false, value: bigZero())
    return (ok: true, value: bigMod(x2, m))
  if bigCmp(u, one) != 0:
    return (ok: false, value: bigZero())
  result = (ok: true, value: bigMod(x1, m))

proc invLimb(n0: uint32): uint32 {.role: {math}.} =
  ## n0: least significant limb of an odd modulus.
  ## Returns -n0^-1 mod 2^32 via Newton iteration.
  var
    x: uint32 = 1'u32
    i: int = 0
  while i < 5:
    x = x * (2'u32 - n0 * x)
    i = i + 1
  result = not x + 1'u32

proc newMontContext*(m: BigInt): tuple[ok: bool, ctx: MontContext] {.
    role: {truthBuilder}.} =
  ## m: odd modulus with at most `bigMaxLimbs` limbs.
  var
    rsq: BigInt
    i: int = 0
  if m.limbs.len == 0 or m.limbs.len > bigMaxLimbs or not bigIsOdd(m):
    return (ok: false, ctx: result.ctx)
  result.ctx.m = m
  result.ctx.len = m.limbs.len
  result.ctx.n0inv = invLimb(m.limbs[0])
  # R^2 mod m by repeated doubling of R mod m, avoiding a 2*len-limb divide.
  rsq = bigMod(bigShiftLeftLimbs(bigFromUint32(1'u32), m.limbs.len), m)
  i = 0
  while i < m.limbs.len * 32:
    rsq = bigModAdd(rsq, rsq, m)
    i = i + 1
  result.ctx.rr = rsq
  result.ok = true

proc montMul*(ctx: MontContext, a, b: BigInt): BigInt {.role: {math}.} =
  ## ctx: Montgomery parameters for an odd modulus.
  ## a/b: values in Montgomery form, each reduced mod the modulus.
  ## Returns a*b*R^-1 mod m using the CIOS reduction.
  var
    n: int = ctx.len
    T: seq[uint64] = newSeq[uint64](n + 2)
    i, j: int = 0
    carry, t, mv: uint64 = 0
    ai, mi: uint32 = 0
    r: BigInt
  i = 0
  while i < n:
    ai = if i < a.limbs.len: a.limbs[i] else: 0'u32
    carry = 0
    j = 0
    while j < n:
      mv = if j < b.limbs.len: uint64(b.limbs[j]) else: 0'u64
      t = T[j] + uint64(ai) * mv + carry
      T[j] = t and 0xffffffff'u64
      carry = t shr 32
      j = j + 1
    t = T[n] + carry
    T[n] = t and 0xffffffff'u64
    T[n + 1] = T[n + 1] + (t shr 32)
    mi = uint32((T[0] * uint64(ctx.n0inv)) and 0xffffffff'u64)
    carry = 0
    j = 0
    while j < n:
      t = T[j] + uint64(mi) * uint64(ctx.m.limbs[j]) + carry
      T[j] = t and 0xffffffff'u64
      carry = t shr 32
      j = j + 1
    t = T[n] + carry
    T[n] = t and 0xffffffff'u64
    T[n + 1] = T[n + 1] + (t shr 32)
    j = 0
    while j <= n:
      T[j] = T[j + 1]
      j = j + 1
    T[n + 1] = 0
    i = i + 1
  r.limbs = newSeq[uint32](n + 1)
  j = 0
  while j <= n:
    r.limbs[j] = uint32(T[j] and 0xffffffff'u64)
    j = j + 1
  trimBig(r)
  if bigCmp(r, ctx.m) >= 0:
    r = bigSub(r, ctx.m)
  result = r

proc toMont(ctx: MontContext, a: BigInt): BigInt {.role: {math}.} =
  ## ctx: Montgomery parameters.
  ## a: ordinary residue to convert into Montgomery form.
  result = montMul(ctx, bigMod(a, ctx.m), ctx.rr)

proc fromMont(ctx: MontContext, a: BigInt): BigInt {.role: {math}.} =
  ## ctx: Montgomery parameters.
  ## a: Montgomery-form residue converted back to an ordinary residue.
  result = montMul(ctx, a, bigFromUint32(1'u32))

proc bigModExp*(base, exp, m: BigInt): tuple[ok: bool, value: BigInt] {.
    role: {math}.} =
  ## base/exp/m: exponentiation inputs; `m` must be odd and non-zero.
  ## Computes modular exponentiation for public values. Normalized limbs,
  ## exponent length, and result selection make this routine variable-time.
  var
    built: tuple[ok: bool, ctx: MontContext]
    x, acc, prod: BigInt
    i: int = 0
  if bigIsZero(m):
    return (ok: false, value: bigZero())
  if bigCmp(m, bigFromUint32(1'u32)) == 0:
    return (ok: true, value: bigZero())
  built = newMontContext(m)
  if not built.ok:
    return (ok: false, value: bigZero())
  x = toMont(built.ctx, base)
  acc = toMont(built.ctx, bigFromUint32(1'u32))
  i = bigBitLen(exp) - 1
  while i >= 0:
    acc = montMul(built.ctx, acc, acc)
    prod = montMul(built.ctx, acc, x)
    if bigTestBit(exp, i):
      acc = prod
    i = i - 1
  result = (ok: true, value: fromMont(built.ctx, acc))
