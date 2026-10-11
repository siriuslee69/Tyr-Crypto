## -------------------------------------------------------------------
## Falcon Keygen, level 1 <- exact signed big numbers (sign + magnitude)
## -------------------------------------------------------------------
##
## The two smallest solver levels (degree 2 and 4) reduce with exact
## integers instead of floating point. A FalconSigned31 is
##
##   neg    sign
##   words  magnitude in 31-bit words, least significant first,
##          with no zero word on top
##
## Unlike keygen_zint, these routines skip zero words and branch on
## values, so their time depends on the numbers. They only run on the
## two smallest levels.
##
##   addSigned31 / mulSigned31 / roundDivSigned31   +  ·  rounded /
##   divRemAbs31                                    long division (Knuth D)
##   polyMulModXn1Small31 / det4Small31             degree-4 algebra

import ./keygen_modp
import runePragmas

type
  FalconSigned31* = object
    neg*: bool
    words*: seq[uint32]

  FalconSigned31Mat4* = array[4, array[4, FalconSigned31]]

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `trimAbs31`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc trimAbs31(A: var seq[uint32]) {.role: {helper}.} =
  ## A: magnitude; zero words at the top are dropped.
  while A.len > 0 and A[^1] == 0'u32:
    A.setLen(A.len - 1)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `cmpAbs31`; pitfall: fail closed and preserve canonical, constant-time comparison where secrets are involved.
proc cmpAbs31(A, B: openArray[uint32]): int {.role: {math}.} =
  ## A/B: magnitudes. Returns -1, 0 or 1 like A <=> B.
  var
    al: int = A.len
    bl: int = B.len
    i: int = 0
  while al > 0 and A[al - 1] == 0'u32:
    al = al - 1
  while bl > 0 and B[bl - 1] == 0'u32:
    bl = bl - 1
  if al < bl:
    return -1
  if al > bl:
    return 1
  i = al
  while i > 0:
    i = i - 1
    if A[i] < B[i]:
      return -1
    if A[i] > B[i]:
      return 1
  0

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `addAbs31`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc addAbs31(A, B: openArray[uint32]): seq[uint32] {.role: {math}.} =
  ## A/B: magnitudes. Returns A + B.
  var
    n: int = max(A.len, B.len)
    carry: uint32 = 0'u32
    aw: uint32 = 0'u32
    bw: uint32 = 0'u32
    z: uint64 = 0'u64
    i: int = 0
  result = newSeq[uint32](n + 1)
  while i < n:
    aw = (if i < A.len: A[i] else: 0'u32)
    bw = (if i < B.len: B[i] else: 0'u32)
    z = uint64(aw) + uint64(bw) + uint64(carry)
    result[i] = uint32(z) and falconWordMask
    carry = uint32(z shr 31)
    i = i + 1
  result[n] = carry
  trimAbs31(result)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `subAbs31`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc subAbs31(A, B: openArray[uint32]): seq[uint32] {.role: {math}.} =
  ## A/B: magnitudes with A >= B. Returns A - B.
  var
    borrow: uint32 = 0'u32
    bw: uint32 = 0'u32
    z: uint32 = 0'u32
    i: int = 0
  result = newSeq[uint32](A.len)
  while i < A.len:
    bw = (if i < B.len: B[i] else: 0'u32)
    z = A[i] - bw - borrow
    result[i] = z and falconWordMask
    borrow = z shr 31
    i = i + 1
  trimAbs31(result)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `addSigned31`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc addSigned31*(a, b: FalconSigned31): FalconSigned31 {.role: {math}.} =
  ## a/b: signed big numbers. Returns a + b (zero is never negative).
  var
    c: int = 0
  if a.neg == b.neg:
    result.neg = a.neg
    result.words = addAbs31(a.words, b.words)
  else:
    c = cmpAbs31(a.words, b.words)
    if c == 0:
      result.words = @[]
      result.neg = false
    elif c > 0:
      result.neg = a.neg
      result.words = subAbs31(a.words, b.words)
    else:
      result.neg = b.neg
      result.words = subAbs31(b.words, a.words)
  if result.words.len == 0:
    result.neg = false

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `negSigned31`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc negSigned31*(a: FalconSigned31): FalconSigned31 {.inline, role: {math}.} =
  ## a: signed big number. Returns -a.
  result = a
  if result.words.len != 0:
    result.neg = not result.neg

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `subSigned31`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc subSigned31*(a, b: FalconSigned31): FalconSigned31 {.inline, role: {math}.} =
  ## a/b: signed big numbers. Returns a - b.
  addSigned31(a, negSigned31(b))

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `mulAddRow`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc mulAddRow(R: var seq[uint32], a: uint32, B: openArray[uint32], i: int)
    {.inline, role: {math}.} =
  ## R += a·B·2^(31·i); the carry runs on as far as it needs to.
  var
    carry: uint64 = 0'u64
    z: uint64 = 0'u64
    j: int = 0
    idx: int = i + B.len
  while j < B.len:
    z = uint64(R[i + j]) + uint64(a) * uint64(B[j]) + carry
    R[i + j] = uint32(z) and falconWordMask
    carry = z shr 31
    j = j + 1
  while carry != 0'u64:
    z = uint64(R[idx]) + carry
    R[idx] = uint32(z) and falconWordMask
    carry = z shr 31
    idx = idx + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `mulAbs31`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc mulAbs31(A, B: openArray[uint32]): seq[uint32] {.role: {math}.} =
  ## A/B: magnitudes. Returns A·B (schoolbook, one row per word of A).
  var
    i: int = 0
  if A.len == 0 or B.len == 0:
    return @[]
  result = newSeq[uint32](A.len + B.len)
  while i < A.len:
    mulAddRow(result, A[i], B, i)
    i = i + 1
  trimAbs31(result)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `mulSigned31`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc mulSigned31*(a, b: FalconSigned31): FalconSigned31 {.role: {math}.} =
  ## a/b: signed big numbers. Returns a·b.
  result.neg = a.neg xor b.neg
  result.words = mulAbs31(a.words, b.words)
  if result.words.len == 0:
    result.neg = false

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `shiftLeftAbs31`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc shiftLeftAbs31*(A: openArray[uint32], scale: int): seq[uint32] {.role: {math}.} =
  ## A: magnitude. Returns A·2^scale.
  var
    sch: int = scale div 31
    scl: int = scale mod 31
    carry: uint32 = 0'u32
    w: uint32 = 0'u32
    i: int = 0
  if A.len == 0:
    return @[]
  result = newSeq[uint32](A.len + sch + (if scl == 0: 0 else: 1))
  while i < A.len:
    w = A[i]
    result[sch + i] = ((w shl scl) and falconWordMask) or carry
    carry = (if scl == 0: 0'u32 else: w shr (31 - scl))
    i = i + 1
  if scl != 0:
    result[sch + A.len] = carry
  trimAbs31(result)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `decodeCoeff31`; pitfall: reject malformed or non-canonical input before indexed access.
proc decodeCoeff31*(poly: RnsPoly, coeff, wordLen: int): FalconSigned31 {.role: {parser}.} =
  ## poly/coeff: one two's-complement coefficient of wordLen words, returned
  ## as sign + magnitude.
  var
    off: int = 0
    negMask: uint32 = 0'u32
    xm: uint32 = 0'u32
    cc: uint32 = 0'u32
    w: uint32 = 0'u32
    i: int = 0
  if wordLen <= 0:
    return
  off = coeffOffset(poly, coeff)
  negMask = 0'u32 - (poly.coeffs[off + wordLen - 1] shr 30)
  xm = negMask shr 1
  cc = negMask and 1'u32
  result.neg = negMask != 0'u32
  result.words = newSeq[uint32](wordLen)
  while i < wordLen:
    w = (poly.coeffs[off + i] xor xm) + cc
    cc = w shr 31
    result.words[i] = w and falconWordMask
    i = i + 1
  trimAbs31(result.words)
  if result.words.len == 0:
    result.neg = false

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `cloneWords31`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc cloneWords31(A: openArray[uint32]): seq[uint32] {.role: {helper}.} =
  ## A: words copied into a fresh seq.
  result = newSeq[uint32](A.len)
  if A.len > 0:
    copyMem(addr result[0], unsafeAddr A[0], A.len * sizeof(uint32))

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `bitLen31`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc bitLen31(w: uint32): int {.inline, role: {math}.} =
  ## w: word. Returns the position of its highest set bit plus one.
  var
    x: uint32 = w
  while x != 0'u32:
    result = result + 1
    x = x shr 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `divRemOneWord`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc divRemOneWord(num: openArray[uint32], d: uint32): tuple[q, r: seq[uint32]]
    {.role: {math}.} =
  ## num: magnitude. d: one-word divisor. Returns quotient and remainder.
  var
    rem: uint64 = 0'u64
    cur: uint64 = 0'u64
    i: int = num.len
  result.q = newSeq[uint32](num.len)
  while i > 0:
    i = i - 1
    cur = (rem shl 31) + uint64(num[i])
    result.q[i] = uint32(cur div uint64(d))
    rem = cur mod uint64(d)
  if rem != 0'u64:
    result.r = @[uint32(rem)]
  trimAbs31(result.q)
  trimAbs31(result.r)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `estimateQhat`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc estimateQhat(un, vn: openArray[uint32], j, n: int): uint64 {.role: {math}.} =
  ## Long division step (Knuth D3): guesses quotient word j from the top
  ## words of un and vn. The guess is never too small and at most 2 too big.
  const
    base: uint64 = 1'u64 shl 31
  var
    top: uint64 = (uint64(un[j + n]) shl 31) + uint64(un[j + n - 1])
    rhat: uint64 = top mod uint64(vn[n - 1])
    check: bool = n > 1
  result = top div uint64(vn[n - 1])
  if result >= base:
    result = base - 1
    rhat = top - result * uint64(vn[n - 1])
  while check and result * uint64(vn[n - 2]) > (rhat shl 31) + uint64(un[j + n - 2]):
    result = result - 1
    rhat = rhat + uint64(vn[n - 1])
    check = rhat < base

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `mulSubWords`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc mulSubWords(un: var seq[uint32], vn: openArray[uint32], j, n: int,
    qhat: uint64): uint64 {.role: {math}.} =
  ## Long division step (Knuth D4): un[j ..< j + n] -= qhat·vn.
  ## Returns what word j + n still has to give up.
  const
    base: uint64 = 1'u64 shl 31
  var
    borrow: uint64 = 0'u64
    carry: uint64 = 0'u64
    prod: uint64 = 0'u64
    sub: uint64 = 0'u64
    i: int = 0
  while i < n:
    prod = qhat * uint64(vn[i]) + carry
    carry = prod shr 31
    sub = uint64(uint32(prod) and falconWordMask) + borrow
    if uint64(un[j + i]) < sub:
      un[j + i] = uint32(uint64(un[j + i]) + base - sub)
      borrow = 1'u64
    else:
      un[j + i] = uint32(uint64(un[j + i]) - sub)
      borrow = 0'u64
    i = i + 1
  result = carry + borrow

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `addBackWords`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc addBackWords(un: var seq[uint32], vn: openArray[uint32], j, n: int) {.role: {math}.} =
  ## Long division step (Knuth D6): the guess was one too big, so vn is
  ## added back once to un[j ..< j + n].
  var
    carry: uint64 = 0'u64
    z: uint64 = 0'u64
    i: int = 0
  while i < n:
    z = uint64(un[j + i]) + uint64(vn[i]) + carry
    un[j + i] = uint32(z and falconWordMask)
    carry = z shr 31
    i = i + 1
  un[j + n] = uint32(uint64(un[j + n]) + carry)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `divRemAbs31`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc divRemAbs31(num, den: openArray[uint32]): tuple[q, r: seq[uint32]] {.gcsafe, role: {math}.} =
  ## num/den: magnitudes. Long division (Knuth algorithm D): den is shifted
  ## until its top word is full, then each quotient word is guessed and fixed.
  ## Note: the remainder is returned still shifted (times 2^shift).
  var
    numCmp: int = cmpAbs31(num, den)
    shift: int = 0
    vn: seq[uint32] = @[]
    un: seq[uint32] = @[]
    n: int = 0
    m: int = 0
    qhat: uint64 = 0'u64
    topSub: uint64 = 0'u64
    j: int = 0
  if den.len == 0:
    raise newException(ValueError, "division by zero")
  if numCmp < 0:
    result.q = @[]
    result.r = cloneWords31(num)
    trimAbs31(result.r)
    return
  if den.len == 1:
    return divRemOneWord(num, den[0])
  shift = 31 - bitLen31(den[^1])
  vn = (if shift == 0: cloneWords31(den) else: shiftLeftAbs31(den, shift))
  un = (if shift == 0: cloneWords31(num) else: shiftLeftAbs31(num, shift))
  if un.len == num.len:
    un.add(0'u32)
  n = vn.len
  m = un.len - n - 1
  result.q = newSeq[uint32](m + 1)
  j = m + 1
  while j > 0:
    j = j - 1
    qhat = estimateQhat(un, vn, j, n)
    topSub = mulSubWords(un, vn, j, n, qhat)
    if uint64(un[j + n]) < topSub:
      qhat = qhat - 1
      addBackWords(un, vn, j, n)
    else:
      un[j + n] = uint32(uint64(un[j + n]) - topSub)
    result.q[j] = uint32(qhat)
  result.r = un[0 ..< n]
  trimAbs31(result.q)
  trimAbs31(result.r)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `roundDivAbs31`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc roundDivAbs31(num, den: openArray[uint32]): uint32 {.role: {math}.} =
  ## num/den: magnitudes. Returns num/den rounded to nearest (ties to even),
  ## or 0x80000000 when the quotient needs more than one word.
  var
    qr: tuple[q, r: seq[uint32]] = divRemAbs31(num, den)
    q: uint32 = 0'u32
    cmp: int = 0
  if qr.q.len > 1:
    return 0x80000000'u32
  q = (if qr.q.len == 0: 0'u32 else: qr.q[0])
  cmp = cmpAbs31(addAbs31(qr.r, qr.r), den)
  if cmp > 0 or (cmp == 0 and (q and 1'u32) != 0'u32):
    return q + 1'u32
  q

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `roundDivSigned31`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc roundDivSigned31*(num: FalconSigned31, den: openArray[uint32]): int32 {.role: {math}.} =
  ## num: signed big number. den: magnitude. Returns round(num/den).
  var
    q: uint32 = 0'u32
  if num.words.len == 0:
    return 0'i32
  q = roundDivAbs31(num.words, den)
  if q >= 0x80000000'u32:
    raise newException(ValueError, "Falcon exact reducer overflow")
  if num.neg:
    return -cast[int32](q)
  cast[int32](q)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `polyAdjSmall31`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyAdjSmall31*(a: openArray[FalconSigned31]): seq[FalconSigned31] {.role: {math}.} =
  ## a: polynomial mod x^n + 1. Returns its adjoint a(1/x).
  var
    i: int = 1
  result = newSeq[FalconSigned31](a.len)
  if a.len == 0:
    return
  result[0] = a[0]
  while i < a.len:
    result[i] = negSigned31(a[a.len - i])
    i = i + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `polyAddSmall31`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyAddSmall31*(a, b: openArray[FalconSigned31]): seq[FalconSigned31] {.role: {math}.} =
  ## a/b: polynomials. Returns a + b.
  var
    i: int = 0
  result = newSeq[FalconSigned31](a.len)
  while i < a.len:
    result[i] = addSigned31(a[i], b[i])
    i = i + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `addTermModXn1`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc addTermModXn1(R: var seq[FalconSigned31], k: int, term: FalconSigned31)
    {.inline, role: {math}.} =
  ## R: product being built. term lands on x^k; past degree n-1 it wraps
  ## around with a minus sign, because x^n = -1.
  if k < R.len:
    R[k] = addSigned31(R[k], term)
  else:
    R[k - R.len] = subSigned31(R[k - R.len], term)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `polyMulModXn1Small31`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc polyMulModXn1Small31*(a, b: openArray[FalconSigned31]): seq[FalconSigned31] {.role: {math}.} =
  ## a/b: polynomials of n coefficients. Returns a·b mod x^n + 1.
  var
    n: int = a.len
    i: int = 0
    j: int = 0
  result = newSeq[FalconSigned31](n)
  while i < n:
    addTermModXn1(result, i + j, mulSigned31(a[i], b[j]))
    j = j + 1
    if j == n:
      j = 0
      i = i + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `mulMat4FromPoly`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc mulMat4FromPoly*(poly: openArray[FalconSigned31]): FalconSigned31Mat4 {.role: {math}.} =
  ## poly: 4 coefficients. Returns the matrix of "multiply by poly mod x^4 + 1".
  result[0][0] = poly[0]
  result[0][1] = negSigned31(poly[3])
  result[0][2] = negSigned31(poly[2])
  result[0][3] = negSigned31(poly[1])
  result[1][0] = poly[1]
  result[1][1] = poly[0]
  result[1][2] = negSigned31(poly[3])
  result[1][3] = negSigned31(poly[2])
  result[2][0] = poly[2]
  result[2][1] = poly[1]
  result[2][2] = poly[0]
  result[2][3] = negSigned31(poly[3])
  result[3][0] = poly[3]
  result[3][1] = poly[2]
  result[3][2] = poly[1]
  result[3][3] = poly[0]

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `replaceMat4Column`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc replaceMat4Column*(M: FalconSigned31Mat4, col: int,
    v: openArray[FalconSigned31]): FalconSigned31Mat4 {.role: {math}.} =
  ## M: matrix. Returns M with column col replaced by v.
  var
    row: int = 0
  result = M
  while row < 4:
    result[row][col] = v[row]
    row = row + 1

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `det2Small31`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc det2Small31(a00, a01, a10, a11: FalconSigned31): FalconSigned31 {.inline, role: {math}.} =
  ## Determinant of [[a00 a01] [a10 a11]].
  subSigned31(mulSigned31(a00, a11), mulSigned31(a01, a10))

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `det3Small31`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc det3Small31(a00, a01, a02, a10, a11, a12, a20, a21, a22: FalconSigned31): FalconSigned31 {.role: {math}.} =
  ## Determinant of a 3x3 matrix, expanded along the first row.
  var
    t0: FalconSigned31 = mulSigned31(a00, det2Small31(a11, a12, a21, a22))
    t1: FalconSigned31 = mulSigned31(a01, det2Small31(a10, a12, a20, a22))
    t2: FalconSigned31 = mulSigned31(a02, det2Small31(a10, a11, a20, a21))
  addSigned31(subSigned31(t0, t1), t2)

## Reference: [FALCON-SPEC] sections 2-3 and the keygen, signing, verification, and encoding algorithms; key-generation algorithms for `det4Small31`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc det4Small31*(M: FalconSigned31Mat4): FalconSigned31 {.role: {math}.} =
  ## Determinant of a 4x4 matrix, expanded along the first row.
  var
    t0: FalconSigned31 = mulSigned31(M[0][0], det3Small31(
      M[1][1], M[1][2], M[1][3],
      M[2][1], M[2][2], M[2][3],
      M[3][1], M[3][2], M[3][3]))
    t1: FalconSigned31 = mulSigned31(M[0][1], det3Small31(
      M[1][0], M[1][2], M[1][3],
      M[2][0], M[2][2], M[2][3],
      M[3][0], M[3][2], M[3][3]))
    t2: FalconSigned31 = mulSigned31(M[0][2], det3Small31(
      M[1][0], M[1][1], M[1][3],
      M[2][0], M[2][1], M[2][3],
      M[3][0], M[3][1], M[3][3]))
    t3: FalconSigned31 = mulSigned31(M[0][3], det3Small31(
      M[1][0], M[1][1], M[1][2],
      M[2][0], M[2][1], M[2][2],
      M[3][0], M[3][1], M[3][2]))
  addSigned31(subSigned31(addSigned31(t0, t2), t1), negSigned31(t3))

