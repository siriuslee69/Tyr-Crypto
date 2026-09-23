## Ed25519 point operations and sign/verify API included by ed25519_impl.nim.
##
## This section shares the implementation module's field helpers and imports.

## Reference: [RFC-8032] sections 5.1.1-5.1.7, Ed25519 arithmetic, encoding, signing, and verification; implementation support for the family algorithms for `basePoint`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc basePoint(): Ed25519Point =
  if not pointDecode(result, basePointCompressed):
    raise newException(ValueError, "invalid Ed25519 base point")

## Reference: [RFC-8032] sections 5.1.1-5.1.7, Ed25519 arithmetic, encoding, signing, and verification; implementation support for the family algorithms for `pointScalarMultVartime`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc pointScalarMultVartime(p: Ed25519Point, scalar: Ed25519Bytes32): Ed25519Point =
  ## Variable-time double-and-add.  ONLY for public scalars
  ## (verification); the branch per bit leaks the scalar via timing.
  var
    q: Ed25519Point = default(Ed25519Point)
    n = p
    tmp: Ed25519Point = default(Ed25519Point)
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

## Reference: [RFC-8032] sections 5.1.1-5.1.7, Ed25519 arithmetic, encoding, signing, and verification; implementation support for the family algorithms for `pointIsInPrimeSubgroup`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc pointIsInPrimeSubgroup(p: Ed25519Point): bool =
  ## Reference: RFC 8032 sections 3.4 and 5.1.7; strict subgroup policy
  ## follows `Taming the many EdDSAs`, section 3. Checking [L]P = identity
  ## rejects every mixed-order point, not only pure torsion points killed
  ## by the cofactor. The identity itself is rejected separately.
  var
    encoded: Ed25519Bytes32 = pointEncode(p)
    multiplied: Ed25519Point = default(Ed25519Point)
  if encoded == identityCompressed:
    return false
  multiplied = pointScalarMultVartime(p, scalarOrderBytes)
  result = pointEncode(multiplied) == identityCompressed

## Reference: [RFC-8032] sections 5.1.1-5.1.7, Ed25519 arithmetic, encoding, signing, and verification; implementation support for the family algorithms for `pointScalarMultCt`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc pointScalarMultCt(p: Ed25519Point, scalar: Ed25519Bytes32): Ed25519Point =
  ## Constant-time ladder for secret scalars (signing, key derivation).
  ## Every bit runs the exact same add + select + double sequence, so
  ## runtime and access pattern are independent of the scalar.  The
  ## extended-coordinate addition used by pointAdd is complete on this
  ## curve, so adding the identity in the "bit = 0" lanes is safe.
  var
    q: Ed25519Point = default(Ed25519Point)
    n = p
    stepped: Ed25519Point = default(Ed25519Point)
    mask: uint64 = 0
    i: int = 0
  defer:
    secureClearPod(n)
    secureClearPod(stepped)
    secureClearPod(mask)
  pointIdentity(q)
  while i < 256:
    pointAdd(stepped, q, n)
    mask = 0'u64 - uint64((scalar[i div 8] shr (i and 7)) and 1'u8)
    pointCmov(q, stepped, mask)
    pointDouble(stepped, n)
    n = stepped
    inc i
  result = q

## Reference: [RFC-8032] sections 5.1.1-5.1.7, Ed25519 arithmetic, encoding, signing, and verification; implementation support for the family algorithms for `geBase`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc geBase(scalar: Ed25519Bytes32): Ed25519Point =
  ## [scalar]B - the scalar is secret in every caller (signing nonce,
  ## clamped secret scalar), so this always uses the constant-time ladder.
  result = pointScalarMultCt(basePoint(), scalar)

## Reference: [RFC-8032] sections 5.1.1-5.1.7, Ed25519 arithmetic, encoding, signing, and verification; implementation support for the family algorithms for `scalarBytesToLimbs`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc scalarBytesToLimbs(s: Ed25519Bytes32): array[4, uint64] {.inline.} =
  result[0] = load64Le(s, 0)
  result[1] = load64Le(s, 8)
  result[2] = load64Le(s, 16)
  result[3] = load64Le(s, 24)

## Reference: [RFC-8032] sections 5.1.1-5.1.7, Ed25519 arithmetic, encoding, signing, and verification; implementation support for the family algorithms for `scalarCmpL`; pitfall: fail closed and preserve canonical, constant-time comparison where secrets are involved.
proc scalarCmpL(a: array[4, uint64]): int {.inline.} =
  var
    L: array[4, uint64] = [l0, l1, l2, l3]
    i: int = 3
  while i >= 0:
    if a[i] > L[i]: return 1
    if a[i] < L[i]: return -1
    dec i
  result = 0

## Reference: [RFC-8032] sections 5.1.1-5.1.7, Ed25519 arithmetic, encoding, signing, and verification; implementation support for the family algorithms for `scalarGeLMask`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc scalarGeLMask(a: array[4, uint64]): uint64 {.inline.} =
  ## Constant-time: all-ones when a >= L, zero otherwise.  Runs the
  ## full borrow chain of a - L instead of comparing limbs with
  ## early exits, so timing never depends on the (secret) value.
  var
    L: array[4, uint64] = [l0, l1, l2, l3]
    borrow: uint64 = 0
    d: uint64 = 0
    b0: uint64 = 0
    b1: uint64 = 0
    i: int = 0
  while i < 4:
    d = a[i] - L[i]
    b0 = uint64(a[i] < L[i])
    b1 = uint64(d < borrow)
    borrow = b0 or b1
    inc i
  result = borrow - 1'u64

## Reference: [RFC-8032] sections 5.1.1-5.1.7, Ed25519 arithmetic, encoding, signing, and verification; implementation support for the family algorithms for `scalarCondSubL`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc scalarCondSubL(a: var array[4, uint64], mask: uint64) {.inline.} =
  ## Constant-time: subtract L where mask is all-ones, no-op where zero.
  var
    L: array[4, uint64] = [l0, l1, l2, l3]
    borrow: uint64 = 0
    sub: uint64 = 0
    d: uint64 = 0
    b0: uint64 = 0
    b1: uint64 = 0
    i: int = 0
  while i < 4:
    sub = L[i] and mask
    d = a[i] - sub
    b0 = uint64(a[i] < sub)
    b1 = uint64(d < borrow)
    a[i] = d - borrow
    borrow = b0 or b1
    inc i

## Reference: [RFC-8032] sections 5.1.1-5.1.7, Ed25519 arithmetic, encoding, signing, and verification; implementation support for the family algorithms for `scalarAddMod`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc scalarAddMod(a: var array[4, uint64], b: array[4, uint64]) {.inline.} =
  ## Constant-time a = (a + b) mod L: the final reduction is a masked
  ## subtraction instead of a branch on the (secret) sum.
  var
    i: int = 0
    carry: uint64 = 0
    old: uint64 = 0
    c0: uint64 = 0
  while i < 4:
    old = a[i]
    a[i] = a[i] + b[i]
    c0 = uint64(a[i] < old)
    old = a[i]
    a[i] = a[i] + carry
    carry = c0 or uint64(a[i] < old)
    inc i
  scalarCondSubL(a, (0'u64 - carry) or scalarGeLMask(a))

## Reference: [RFC-8032] sections 5.1.1-5.1.7, Ed25519 arithmetic, encoding, signing, and verification; implementation support for the family algorithms for `scalarDoubleMod`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc scalarDoubleMod(a: var array[4, uint64]) {.inline.} =
  var b = a
  scalarAddMod(a, b)

## Reference: [RFC-8032] sections 5.1.1-5.1.7, Ed25519 arithmetic, encoding, signing, and verification; implementation support for the family algorithms for `scalarToBytes`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc scalarToBytes(a: array[4, uint64]): Ed25519Bytes32 {.inline.} =
  store64Le(result, 0, a[0])
  store64Le(result, 8, a[1])
  store64Le(result, 16, a[2])
  store64Le(result, 24, a[3])

## Reference: [RFC-8032] sections 5.1.1-5.1.7, Ed25519 arithmetic, encoding, signing, and verification; implementation support for the family algorithms for `getBitWide`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc getBitWide(A: array[8, uint64], pos: int): uint64 {.inline.} =
  result = (A[pos div 64] shr (pos and 63)) and 1'u64

## Reference: [RFC-8032] sections 5.1.1-5.1.7, Ed25519 arithmetic, encoding, signing, and verification; implementation support for the family algorithms for `reduceWide`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc reduceWide(A: array[8, uint64]): Ed25519Bytes32 =
  ## Constant-time bit-serial reduction mod L.  Every bit adds a masked
  ## 0/1 value instead of branching, because A is secret in the nonce
  ## path (r = SHA-512(prefix || msg) mod L) and a timing leak of the
  ## nonce recovers the private key.
  var
    rem: array[4, uint64] = default(array[4, uint64])
    bitAdd: array[4, uint64] = default(array[4, uint64])
    i: int = 511
  defer:
    secureClearPod(rem)
    secureClearPod(bitAdd)
  while i >= 0:
    scalarDoubleMod(rem)
    bitAdd[0] = getBitWide(A, i)
    scalarAddMod(rem, bitAdd)
    dec i
  result = scalarToBytes(rem)

## Reference: [RFC-8032] sections 5.1.1-5.1.7, Ed25519 arithmetic, encoding, signing, and verification; implementation support for the family algorithms for `reduce64`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc reduce64(A: Ed25519Bytes64): Ed25519Bytes32 =
  var
    wide: array[8, uint64] = default(array[8, uint64])
    i: int = 0
  defer:
    secureClearPod(wide)
  while i < 8:
    wide[i] = load64Le(A, i * 8)
    inc i
  result = reduceWide(wide)

## Reference: [RFC-8032] sections 5.1.1-5.1.7, Ed25519 arithmetic, encoding, signing, and verification; implementation support for the family algorithms for `reduce32`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc reduce32(A: Ed25519Bytes32): Ed25519Bytes32 =
  var
    wide: array[8, uint64] = default(array[8, uint64])
    i: int = 0
  defer:
    secureClearPod(wide)
  while i < 4:
    wide[i] = load64Le(A, i * 8)
    inc i
  result = reduceWide(wide)

## Reference: [RFC-8032] sections 5.1.1-5.1.7, Ed25519 arithmetic, encoding, signing, and verification; implementation support for the family algorithms for `scalarIsCanonical`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc scalarIsCanonical(s: Ed25519Bytes32): bool =
  result = scalarCmpL(scalarBytesToLimbs(s)) < 0

## Reference: [RFC-8032] sections 5.1.1-5.1.7, Ed25519 arithmetic, encoding, signing, and verification; implementation support for the family algorithms for `scalarMulAdd`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc scalarMulAdd(k, s, r: Ed25519Bytes32): Ed25519Bytes32 =
  ## Constant-time r + k*s (mod L).  s (clamped secret scalar) and
  ## r (nonce) are secret, so every bit adds a masked copy of the
  ## running multiple instead of branching.
  var
    acc = scalarBytesToLimbs(reduce32(r))
    cur = scalarBytesToLimbs(reduce32(s))
    kk = reduce32(k)
    masked: array[4, uint64] = default(array[4, uint64])
    mask: uint64 = 0
    i: int = 0
  defer:
    secureClearPod(acc)
    secureClearPod(cur)
    secureClearPod(kk)
    secureClearPod(masked)
    secureClearPod(mask)
  while i < 256:
    mask = 0'u64 - uint64((kk[i div 8] shr (i and 7)) and 1'u8)
    masked[0] = cur[0] and mask
    masked[1] = cur[1] and mask
    masked[2] = cur[2] and mask
    masked[3] = cur[3] and mask
    scalarAddMod(acc, masked)
    scalarDoubleMod(cur)
    inc i
  result = scalarToBytes(acc)

## Reference: [RFC-8032] sections 5.1.1-5.1.7, Ed25519 arithmetic, encoding, signing, and verification; implementation support for the family algorithms for `toFixed32Ed`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc toFixed32Ed(input: openArray[byte], label: string): Ed25519Bytes32 =
  var i: int = 0
  if input.len != 32:
    raise newException(ValueError, "invalid Ed25519 " & label & " length")
  while i < 32:
    result[i] = input[i]
    inc i

## Reference: [RFC-8032] sections 5.1.1-5.1.7, Ed25519 arithmetic, encoding, signing, and verification; implementation support for the family algorithms for `toSeq32`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc toSeq32(input: Ed25519Bytes32): seq[byte] =
  var i: int = 0
  result = newSeq[byte](32)
  while i < 32:
    result[i] = input[i]
    inc i

## Reference: [RFC-8032] sections 5.1.1-5.1.7, Ed25519 arithmetic, encoding, signing, and verification; implementation support for the family algorithms for `toSeq64`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc toSeq64(input: Ed25519Bytes64): seq[byte] =
  var i: int = 0
  result = newSeq[byte](64)
  while i < 64:
    result[i] = input[i]
    inc i

## Reference: [RFC-8032] sections 5.1.1-5.1.7, Ed25519 arithmetic, encoding, signing, and verification; implementation support for the family algorithms for `clampDigestScalar`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc clampDigestScalar(h: Ed25519Bytes64): Ed25519Bytes32 =
  var i: int = 0
  while i < 32:
    result[i] = h[i]
    inc i
  result[0] = result[0] and 248'u8
  result[31] = (result[31] and 63'u8) or 64'u8

## Reference: [RFC-8032] sections 5.1.1-5.1.7, Ed25519 arithmetic, encoding, signing, and verification; implementation support for the family algorithms for `publicKeyFromSeed`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc publicKeyFromSeed(seed: Ed25519Bytes32): Ed25519Bytes32 =
  var
    h = ed25519Sha512Hash(seed)
    a = clampDigestScalar(h)
  defer:
    secureClearPod(h)
    secureClearPod(a)
  result = pointEncode(geBase(a))

## Reference: [RFC-8032] sections 5.1.1-5.1.7, Ed25519 arithmetic, encoding, signing, and verification; implementation support for the family algorithms for `ed25519TyrPublicKey`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc ed25519TyrPublicKey*(seed: openArray[byte]): seq[byte] =
  var s = toFixed32Ed(seed, "seed")
  defer:
    secureClearPod(s)
  result = toSeq32(publicKeyFromSeed(s))

## Reference: [RFC-8032] sections 5.1.1-5.1.7, Ed25519 arithmetic, encoding, signing, and verification; implementation support for the family algorithms for `ed25519TyrKeypairFromSeed`; pitfall: keep transcript order, domain separation, sizes, and secret wiping exact.
proc ed25519TyrKeypairFromSeed*(seed: openArray[byte]): Ed25519Keypair =
  var
    s = toFixed32Ed(seed, "seed")
    pk = publicKeyFromSeed(s)
    i: int = 0
  defer:
    secureClearPod(s)
  result.publicKey = toSeq32(pk)
  result.secretKey = newSeq[byte](64)
  while i < 32:
    result.secretKey[i] = s[i]
    result.secretKey[i + 32] = pk[i]
    inc i

## Reference: [RFC-8032] sections 5.1.1-5.1.7, Ed25519 arithmetic, encoding, signing, and verification; implementation support for the family algorithms for `ed25519TyrKeypair`; pitfall: keep transcript order, domain separation, sizes, and secret wiping exact.
proc ed25519TyrKeypair*(): Ed25519Keypair =
  var seed = cryptoRandomBytes(32)
  defer:
    secureClearBytes(seed)
  result = ed25519TyrKeypairFromSeed(seed)

## Reference: [RFC-8032] sections 5.1.1-5.1.7, Ed25519 arithmetic, encoding, signing, and verification; implementation support for the family algorithms for `ed25519TyrSign`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc ed25519TyrSign*(message, secretKey: openArray[byte]): seq[byte] =
  var
    seed: Ed25519Bytes32 = default(Ed25519Bytes32)
    publicKey: Ed25519Bytes32 = default(Ed25519Bytes32)
    expectedPublicKey: Ed25519Bytes32 = default(Ed25519Bytes32)
    h: Ed25519Bytes64 = default(Ed25519Bytes64)
    a: Ed25519Bytes32 = default(Ed25519Bytes32)
    prefixMsg: seq[byte] = default(seq[byte])
    rDigest: Ed25519Bytes64 = default(Ed25519Bytes64)
    r: Ed25519Bytes32 = default(Ed25519Bytes32)
    rPoint: Ed25519Point = default(Ed25519Point)
    rEncoded: Ed25519Bytes32 = default(Ed25519Bytes32)
    hramInput: seq[byte] = default(seq[byte])
    hramDigest: Ed25519Bytes64 = default(Ed25519Bytes64)
    hram: Ed25519Bytes32 = default(Ed25519Bytes32)
    s: Ed25519Bytes32 = default(Ed25519Bytes32)
    sig: Ed25519Bytes64 = default(Ed25519Bytes64)
    i: int = 0
    publicDiff: uint8 = 0'u8
  defer:
    secureClearPod(seed)
    secureClearPod(expectedPublicKey)
    secureClearPod(h)
    secureClearPod(a)
    secureClearBytes(prefixMsg)
    secureClearPod(rDigest)
    secureClearPod(r)
  if secretKey.len != 64:
    raise newException(ValueError, "invalid Ed25519 secret key length")
  if message.len > high(int) - 64:
    raise newException(ValueError, "Ed25519 message is too large")
  while i < 32:
    seed[i] = secretKey[i]
    publicKey[i] = secretKey[i + 32]
    inc i
  expectedPublicKey = publicKeyFromSeed(seed)
  i = 0
  while i < expectedPublicKey.len:
    publicDiff = publicDiff or (expectedPublicKey[i] xor publicKey[i])
    inc i
  if publicDiff != 0'u8:
    raise newException(ValueError,
      "Ed25519 secret key public half does not match its seed")
  h = ed25519Sha512Hash(seed)
  a = clampDigestScalar(h)
  prefixMsg = newSeqOfCap[byte](32 + message.len)
  i = 32
  while i < 64:
    prefixMsg.add(h[i])
    inc i
  for b in message:
    prefixMsg.add(b)
  rDigest = ed25519Sha512Hash(prefixMsg)
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
  hramDigest = ed25519Sha512Hash(hramInput)
  hram = reduce64(hramDigest)
  s = scalarMulAdd(hram, a, r)
  i = 0
  while i < 32:
    sig[i] = rEncoded[i]
    sig[i + 32] = s[i]
    inc i
  result = toSeq64(sig)

## Reference: [RFC-8032] sections 5.1.1-5.1.7, Ed25519 arithmetic, encoding, signing, and verification; implementation support for the family algorithms for `ed25519TyrVerify`; pitfall: fail closed and preserve canonical, constant-time comparison where secrets are involved.
proc ed25519TyrVerify*(message, signature, publicKey: openArray[byte]): bool =
  ## Reference: RFC 8032 section 5.1.7, with the strict subgroup policy
  ## analyzed in `Taming the many EdDSAs`, section 3. Canonical encodings,
  ## S < L, and non-identity prime-subgroup A/R are all required before the
  ## group equation. This is intentionally stricter than RFC 8032's permitted
  ## cofactored equation and rejects mixed-order encodings.
  var
    sigR: Ed25519Bytes32 = default(Ed25519Bytes32)
    sigS: Ed25519Bytes32 = default(Ed25519Bytes32)
    pk: Ed25519Bytes32 = default(Ed25519Bytes32)
    aPoint, rPoint, sB, hA, rhs: Ed25519Point = default(Ed25519Point)
    hramInput: seq[byte] = default(seq[byte])
    hramDigest: Ed25519Bytes64 = default(Ed25519Bytes64)
    hram: Ed25519Bytes32 = default(Ed25519Bytes32)
    i: int = 0
  if signature.len != 64 or publicKey.len != 32:
    return false
  if message.len > high(int) - 64:
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
  if not pointIsInPrimeSubgroup(aPoint) or not pointIsInPrimeSubgroup(rPoint):
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
  hramDigest = ed25519Sha512Hash(hramInput)
  hram = reduce64(hramDigest)
  sB = pointScalarMultVartime(basePoint(), sigS)
  hA = pointScalarMultVartime(aPoint, hram)
  pointAdd(rhs, rPoint, hA)
  result = pointEncode(sB) == pointEncode(rhs)

when defined(amd64) or defined(i386):
  ## Reference: [RFC-8032] sections 5.1.1-5.1.7, Ed25519 arithmetic, encoding, signing, and verification; implementation support for the family algorithms for `ed25519TyrSignSse2x`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
  proc ed25519TyrSignSse2x*(messages: array[2, seq[byte]],
      secretKeys: array[2, seq[byte]]): array[2, seq[byte]] =
    var lane: int = 0
    while lane < 2:
      result[lane] = ed25519TyrSign(messages[lane], secretKeys[lane])
      inc lane

  ## Reference: [RFC-8032] sections 5.1.1-5.1.7, Ed25519 arithmetic, encoding, signing, and verification; implementation support for the family algorithms for `ed25519TyrVerifySse2x`; pitfall: fail closed and preserve canonical, constant-time comparison where secrets are involved.
  proc ed25519TyrVerifySse2x*(messages, signatures, publicKeys: array[2, seq[byte]]): array[2, bool] =
    var lane: int = 0
    while lane < 2:
      result[lane] = ed25519TyrVerify(messages[lane], signatures[lane], publicKeys[lane])
      inc lane

when defined(avx2):
  ## Reference: [RFC-8032] sections 5.1.1-5.1.7, Ed25519 arithmetic, encoding, signing, and verification; implementation support for the family algorithms for `ed25519TyrSignAvx4x`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
  proc ed25519TyrSignAvx4x*(messages: array[4, seq[byte]],
      secretKeys: array[4, seq[byte]]): array[4, seq[byte]] =
    var lane: int = 0
    while lane < 4:
      result[lane] = ed25519TyrSign(messages[lane], secretKeys[lane])
      inc lane

  ## Reference: [RFC-8032] sections 5.1.1-5.1.7, Ed25519 arithmetic, encoding, signing, and verification; implementation support for the family algorithms for `ed25519TyrVerifyAvx4x`; pitfall: fail closed and preserve canonical, constant-time comparison where secrets are involved.
  proc ed25519TyrVerifyAvx4x*(messages, signatures, publicKeys: array[4, seq[byte]]): array[4, bool] =
    var lane: int = 0
    while lane < 4:
      result[lane] = ed25519TyrVerify(messages[lane], signatures[lane], publicKeys[lane])
      inc lane
