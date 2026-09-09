## ---------------------------------------------------------------------
## ECDSA P-256 <- NIST secp256r1 signatures and ECDH over the Tyr bignum
## ---------------------------------------------------------------------
##
## Supplies what WebPKI certificate chains and the TLS 1.3 `secp256r1`
## key share need: point arithmetic on the short Weierstrass curve with
## a = -3, ECDSA signing and verification, and the ECDH shared secret.
##
## Signing derives its nonce with RFC 6979, preventing repeated-nonce key
## recovery. The current bigint representation remains variable-time and is
## suitable for public verification only until a fixed-width private backend
## replaces the direct-import signing and ECDH paths.

import runePragmas
import ../../helpers/bigint
import ../../hashes/sha256
import ../../certs/der
import ../../certs/oid
import ../../certs/pem

type
  P256Point* {.role: {truthState}.} = object
    x*: BigInt
    y*: BigInt
    z*: BigInt   # Jacobian; z == 0 marks the point at infinity

  P256AffinePoint* {.role: {truthState}.} = object
    x*: BigInt
    y*: BigInt
    infinity*: bool

  EcdsaSignature* {.role: {truthState}.} = object
    r*: BigInt
    s*: BigInt

  P256PublicKeyResult* {.role: {truthBuilder}.} = object
    ok*: bool
    point*: P256AffinePoint
    err*: string

  P256PrivateKeyResult* {.role: {truthBuilder}.} = object
    ok*: bool
    scalar*: BigInt
    public*: P256AffinePoint
    err*: string

  EcdsaSignResult* {.role: {truthBuilder}.} = object
    ok*: bool
    signature*: EcdsaSignature
    err*: string

const
  p256FieldBytes* = 32
  p256PHex = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
  p256NHex = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
  p256BHex = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"  # otter:allow
  p256GxHex = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"  # otter:allow
  p256GyHex = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"  # otter:allow

## Reference: [FIPS-186-5] section 6 and appendix D.1.2, ECDSA over P-256; curve arithmetic, key generation, signing, and verification algorithms for `hexToBig`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc hexToBig(s: string): BigInt {.role: {parser}.} =
  ## s: even-length lowercase hex constant from this module.
  var
    b: seq[byte] = newSeq[byte](s.len div 2)
    i, hi, lo: int = 0
  ## Reference: [FIPS-186-5] section 6 and appendix D.1.2, ECDSA over P-256; curve arithmetic, key generation, signing, and verification algorithms for `nib`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
  proc nib(c: char): int =
    if c >= '0' and c <= '9': int(c) - int('0')
    elif c >= 'a' and c <= 'f': int(c) - int('a') + 10
    else: 0
  while i < b.len:
    hi = nib(s[i * 2])
    lo = nib(s[i * 2 + 1])
    b[i] = byte(hi * 16 + lo)
    i = i + 1
  result = bigFromBytesBe(b)

# `const` rather than `let`: these hold BigInt values whose limbs are a seq,
# and a mutable global seq would make every signing path GC-unsafe, which in
# turn blocks use from a threaded server. Compile-time evaluation puts them in
# static storage instead.
const
  p256P* = hexToBig(p256PHex)   ## field prime
  p256N* = hexToBig(p256NHex)   ## group order
  p256B* = hexToBig(p256BHex)   ## curve b coefficient
  p256Gx* = hexToBig(p256GxHex)
  p256Gy* = hexToBig(p256GyHex)

## Reference: [FIPS-186-5] section 6 and appendix D.1.2, ECDSA over P-256; curve arithmetic, key generation, signing, and verification algorithms for `fMul`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc fMul(a, b: BigInt): BigInt {.role: {math}.} =
  ## a/b: field elements reduced mod p.
  result = bigMod(bigMul(a, b), p256P)

## Reference: [FIPS-186-5] section 6 and appendix D.1.2, ECDSA over P-256; curve arithmetic, key generation, signing, and verification algorithms for `fAdd`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc fAdd(a, b: BigInt): BigInt {.role: {math}.} =
  ## a/b: field elements reduced mod p.
  result = bigModAdd(a, b, p256P)

## Reference: [FIPS-186-5] section 6 and appendix D.1.2, ECDSA over P-256; curve arithmetic, key generation, signing, and verification algorithms for `fSub`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc fSub(a, b: BigInt): BigInt {.role: {math}.} =
  ## a/b: field elements reduced mod p.
  result = bigModSub(a, b, p256P)

## Reference: [FIPS-186-5] section 6 and appendix D.1.2, ECDSA over P-256; curve arithmetic, key generation, signing, and verification algorithms for `fSqr`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc fSqr(a: BigInt): BigInt {.role: {math}.} =
  ## a: field element reduced mod p.
  result = fMul(a, a)

## Reference: [FIPS-186-5] section 6 and appendix D.1.2, ECDSA over P-256; curve arithmetic, key generation, signing, and verification algorithms for `fInv`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc fInv(a: BigInt): BigInt {.role: {math}.} =
  ## a: non-zero field element.
  ## Inverts by Fermat exponentiation so the trace stays independent of `a`.
  result = bigModExp(a, bigSub(p256P, bigFromUint32(2'u32)), p256P).value

## Reference: [FIPS-186-5] section 6 and appendix D.1.2, ECDSA over P-256; curve arithmetic, key generation, signing, and verification algorithms for `p256Infinity`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc p256Infinity*(): P256Point {.role: {helper}.} =
  ## Return the Jacobian point at infinity.
  result.x = bigFromUint32(1'u32)
  result.y = bigFromUint32(1'u32)
  result.z = bigZero()

## Reference: [FIPS-186-5] section 6 and appendix D.1.2, ECDSA over P-256; curve arithmetic, key generation, signing, and verification algorithms for `isInfinity`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc isInfinity*(P: P256Point): bool {.role: {helper}.} =
  ## P: Jacobian point to test.
  result = bigIsZero(P.z)

## Reference: [FIPS-186-5] section 6 and appendix D.1.2, ECDSA over P-256; curve arithmetic, key generation, signing, and verification algorithms for `p256Generator`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc p256Generator*(): P256Point {.role: {helper}.} =
  ## Return the standard base point in Jacobian coordinates.
  result.x = p256Gx
  result.y = p256Gy
  result.z = bigFromUint32(1'u32)

## Reference: [FIPS-186-5] section 6 and appendix D.1.2, ECDSA over P-256; curve arithmetic, key generation, signing, and verification algorithms for `fromAffine`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc fromAffine(A: P256AffinePoint): P256Point {.role: {helper}.} =
  ## A: affine point to lift into Jacobian coordinates.
  if A.infinity:
    return p256Infinity()
  result.x = A.x
  result.y = A.y
  result.z = bigFromUint32(1'u32)

## Reference: [FIPS-186-5] section 6 and appendix D.1.2, ECDSA over P-256; curve arithmetic, key generation, signing, and verification algorithms for `toAffine`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc toAffine*(P: P256Point): P256AffinePoint {.role: {math}.} =
  ## P: Jacobian point to normalize.
  var zInv, zInv2: BigInt
  if isInfinity(P):
    result.infinity = true
    result.x = bigZero()
    result.y = bigZero()
    return
  zInv = fInv(P.z)
  zInv2 = fSqr(zInv)
  result.x = fMul(P.x, zInv2)
  result.y = fMul(P.y, fMul(zInv2, zInv))

## Reference: [FIPS-186-5] section 6 and appendix D.1.2, ECDSA over P-256; curve arithmetic, key generation, signing, and verification algorithms for `pointDouble`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc pointDouble*(P: P256Point): P256Point {.role: {math}.} =
  ## P: Jacobian point to double, using the a = -3 formulas.
  var delta, gamma, beta, alpha, t: BigInt
  if isInfinity(P) or bigIsZero(P.y):
    return p256Infinity()
  delta = fSqr(P.z)
  gamma = fSqr(P.y)
  beta = fMul(P.x, gamma)
  alpha = fMul(bigFromUint32(3'u32), fMul(fSub(P.x, delta), fAdd(P.x, delta)))
  result.x = fSub(fSqr(alpha), fMul(bigFromUint32(8'u32), beta))
  t = fSub(fSqr(fAdd(P.y, P.z)), gamma)
  result.z = fSub(t, delta)
  result.y = fSub(
    fMul(alpha, fSub(fMul(bigFromUint32(4'u32), beta), result.x)),
    fMul(bigFromUint32(8'u32), fSqr(gamma)))

## Reference: [FIPS-186-5] section 6 and appendix D.1.2, ECDSA over P-256; curve arithmetic, key generation, signing, and verification algorithms for `pointAdd`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc pointAdd*(P, Q: P256Point): P256Point {.role: {math}.} =
  ## P/Q: Jacobian points to add; handles the doubling and infinity cases.
  var
    z1z1, z2z2, u1, u2, s1, s2, h, r, i, j, v, t: BigInt
  if isInfinity(P):
    return Q
  if isInfinity(Q):
    return P
  z1z1 = fSqr(P.z)
  z2z2 = fSqr(Q.z)
  u1 = fMul(P.x, z2z2)
  u2 = fMul(Q.x, z1z1)
  s1 = fMul(P.y, fMul(Q.z, z2z2))
  s2 = fMul(Q.y, fMul(P.z, z1z1))
  h = fSub(u2, u1)
  r = fSub(s2, s1)
  if bigIsZero(h):
    if bigIsZero(r):
      return pointDouble(P)
    return p256Infinity()
  r = fAdd(r, r)
  t = fAdd(h, h)
  i = fSqr(t)
  j = fMul(h, i)
  v = fMul(u1, i)
  result.x = fSub(fSub(fSqr(r), j), fAdd(v, v))
  result.y = fSub(fMul(r, fSub(v, result.x)), fMul(fAdd(s1, s1), j))
  t = fSub(fSqr(fAdd(P.z, Q.z)), z1z1)
  result.z = fMul(fSub(t, z2z2), h)

## Reference: [FIPS-186-5] section 6 and appendix D.1.2, ECDSA over P-256; curve arithmetic, key generation, signing, and verification algorithms for `scalarMulPublic`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc scalarMulPublic(k: BigInt, P: P256Point): P256Point {.role: {math}.} =
  ## k/P: public scalar and point; plain double-and-add is safe here.
  var i: int = bigBitLen(k) - 1
  result = p256Infinity()
  while i >= 0:
    result = pointDouble(result)
    if bigTestBit(k, i):
      result = pointAdd(result, P)
    i = i - 1

## Reference: [FIPS-186-5] section 6 and appendix D.1.2, ECDSA over P-256; curve arithmetic, key generation, signing, and verification algorithms for `scalarMulSecret`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc scalarMulSecret(k: BigInt, P: P256Point): P256Point {.role: {math}.} =
  ## k/P: secret scalar and point.
  ## Computes both candidates per bit, but bigint normalization, point special
  ## cases, and selection remain variable-time. Do not expose this path to
  ## attacker-observable private-key workloads.
  var
    acc, sum: P256Point
    i: int = 255
  acc = p256Infinity()
  while i >= 0:
    acc = pointDouble(acc)
    sum = pointAdd(acc, P)
    if bigTestBit(k, i):
      acc = sum
    i = i - 1
  result = acc

## Reference: [FIPS-186-5] section 6 and appendix D.1.2, ECDSA over P-256; curve arithmetic, key generation, signing, and verification algorithms for `isOnCurve`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc isOnCurve*(A: P256AffinePoint): bool {.role: {math}.} =
  ## A: candidate affine point checked against y^2 = x^3 - 3x + b.
  var lhs, rhs: BigInt
  if A.infinity:
    return false
  if bigCmp(A.x, p256P) >= 0 or bigCmp(A.y, p256P) >= 0:
    return false
  lhs = fSqr(A.y)
  rhs = fAdd(fSub(fMul(fSqr(A.x), A.x), fMul(bigFromUint32(3'u32), A.x)), p256B)
  result = bigCmp(lhs, rhs) == 0

## Reference: [FIPS-186-5] section 6 and appendix D.1.2, ECDSA over P-256; curve arithmetic, key generation, signing, and verification algorithms for `encodeUncompressedPoint`; pitfall: match scalar ranges, reductions, lane order, and fixed public loop bounds.
proc encodeUncompressedPoint*(A: P256AffinePoint): seq[byte] {.
    role: {dataWriter}.} =
  ## A: affine point serialized as the SEC 1 uncompressed encoding.
  if A.infinity:
    return @[0'u8]
  result = @[0x04'u8]
  result.add(bigToBytesBe(A.x, p256FieldBytes))
  result.add(bigToBytesBe(A.y, p256FieldBytes))

## Reference: [FIPS-186-5] section 6 and appendix D.1.2, ECDSA over P-256; curve arithmetic, key generation, signing, and verification algorithms for `decodeUncompressedPoint`; pitfall: reject malformed or non-canonical input before indexed access.
proc decodeUncompressedPoint*(A: openArray[byte]): P256PublicKeyResult {.
    role: {parser}.} =
  ## A: SEC 1 uncompressed point, validated against the curve equation.
  if A.len != 1 + 2 * p256FieldBytes:
    result.err = "P-256 point must be 65 uncompressed bytes"
    return
  if A[0] != 0x04'u8:
    result.err = "only uncompressed P-256 points are accepted"
    return
  result.point.x = bigFromBytesBe(A[1 .. p256FieldBytes])
  result.point.y = bigFromBytesBe(A[1 + p256FieldBytes .. 2 * p256FieldBytes])
  if not isOnCurve(result.point):
    result.err = "P-256 point is not on the curve"
    return
  result.ok = true

## Reference: [FIPS-186-5] section 6 and appendix D.1.2, ECDSA over P-256; curve arithmetic, key generation, signing, and verification algorithms for `parseP256Spki`; pitfall: reject malformed or non-canonical input before indexed access.
proc parseP256Spki*(A: openArray[byte]): P256PublicKeyResult {.
    role: {truthBuilder}.} =
  ## A: DER SubjectPublicKeyInfo carrying an `id-ecPublicKey` prime256v1 key.
  var
    R: DerReadResult
    C, alg: tuple[ok: bool, children: seq[DerElement], err: string]
    O, curve: tuple[ok: bool, value, err: string]
    shape: string = ""
  R = readDerElement(A, 0)
  if not R.ok:
    result.err = R.err
    return
  if R.element.endOffset != A.len:
    result.err = "SubjectPublicKeyInfo has trailing bytes"
    return
  shape = requireDerShape(R.element, dcUniversal, derTagSequence, true)
  if shape.len > 0:
    result.err = shape
    return
  C = readDerChildren(A, R.element)
  if not C.ok:
    result.err = C.err
    return
  if C.children.len != 2:
    result.err = "SubjectPublicKeyInfo must have two fields"
    return
  alg = readDerChildren(A, C.children[0])
  if not alg.ok:
    result.err = alg.err
    return
  if alg.children.len != 2:
    result.err = "EC AlgorithmIdentifier needs an explicit named curve"
    return
  O = decodeDerOid(A, alg.children[0])
  if not O.ok:
    result.err = O.err
    return
  if O.value != oidEcPublicKey:
    result.err = "public-key algorithm is not id-ecPublicKey"
    return
  curve = decodeDerOid(A, alg.children[1])
  if not curve.ok:
    result.err = curve.err
    return
  if curve.value != oidPrime256v1:
    result.err = "only the prime256v1 named curve is supported"
    return
  shape = requireDerShape(C.children[1], dcUniversal, derTagBitString, false)
  if shape.len > 0:
    result.err = shape
    return
  if C.children[1].contentLen < 1 or A[C.children[1].contentStart] != 0'u8:
    result.err = "EC public key BIT STRING must be octet aligned"
    return
  result = decodeUncompressedPoint(
    A[C.children[1].contentStart + 1 ..< C.children[1].endOffset])

## Reference: [FIPS-186-5] section 6 and appendix D.1.2, ECDSA over P-256; curve arithmetic, key generation, signing, and verification algorithms for `parseP256PublicKeyPem`; pitfall: reject malformed or non-canonical input before indexed access.
proc parseP256PublicKeyPem*(s: string): P256PublicKeyResult {.
    role: {orchestrator}.} =
  ## s: PEM text holding a `PUBLIC KEY` SPKI block.
  var P = readPemBlock(s, "PUBLIC KEY")
  if not P.ok:
    result.err = P.err
    return
  result = parseP256Spki(P.pemBlock.der)

## Reference: [FIPS-186-5] section 6 and appendix D.1.2, ECDSA over P-256; curve arithmetic, key generation, signing, and verification algorithms for `parseEcdsaSignatureDer`; pitfall: reject malformed or non-canonical input before indexed access.
proc parseEcdsaSignatureDer*(A: openArray[byte]): tuple[
    ok: bool, sig: EcdsaSignature, err: string] {.role: {parser}.} =
  ## A: DER `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }`.
  var
    R: DerReadResult
    C: tuple[ok: bool, children: seq[DerElement], err: string]
    shape: string = ""
  R = readDerElement(A, 0)
  if not R.ok:
    result.err = R.err
    return
  if R.element.endOffset != A.len:
    result.err = "ECDSA signature has trailing bytes"
    return
  shape = requireDerShape(R.element, dcUniversal, derTagSequence, true)
  if shape.len > 0:
    result.err = shape
    return
  C = readDerChildren(A, R.element)
  if not C.ok:
    result.err = C.err
    return
  if C.children.len != 2:
    result.err = "ECDSA signature must have r and s"
    return
  shape = validateDerInteger(A, C.children[0], false)
  if shape.len > 0:
    result.err = shape
    return
  shape = validateDerInteger(A, C.children[1], false)
  if shape.len > 0:
    result.err = shape
    return
  result.sig.r = bigFromBytesBe(derContent(A, C.children[0]))
  result.sig.s = bigFromBytesBe(derContent(A, C.children[1]))
  result.ok = true

## Reference: [FIPS-186-5] section 6 and appendix D.1.2, ECDSA over P-256; curve arithmetic, key generation, signing, and verification algorithms for `encodeDerInteger`; pitfall: emit the unique canonical wire representation and enforce exact bounds.
proc encodeDerInteger(v: BigInt): seq[byte] {.role: {dataWriter}.} =
  ## v: non-negative value encoded as a minimal DER INTEGER.
  var
    body: seq[byte] = bigToBytesBe(v, max(1, bigByteLen(v)))
    i: int = 0
  while i + 1 < body.len and body[i] == 0'u8 and (body[i + 1] and 0x80'u8) == 0'u8:
    i = i + 1
  body = body[i .. ^1]
  if (body[0] and 0x80'u8) != 0'u8:
    body.insert(0'u8, 0)
  result = @[derTagInteger, byte(body.len)]
  result.add(body)

## Reference: [FIPS-186-5] section 6 and appendix D.1.2, ECDSA over P-256; curve arithmetic, key generation, signing, and verification algorithms for `encodeEcdsaSignatureDer`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc encodeEcdsaSignatureDer*(S: EcdsaSignature): seq[byte] {.
    role: {dataWriter}.} =
  ## S: signature serialized as a DER Ecdsa-Sig-Value.
  var body: seq[byte] = encodeDerInteger(S.r)
  body.add(encodeDerInteger(S.s))
  result = @[byte(0x30'u8), byte(body.len)]
  result.add(body)

## Reference: [FIPS-186-5] section 6 and appendix D.1.2, ECDSA over P-256; curve arithmetic, key generation, signing, and verification algorithms for `bitsToInt`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc bitsToInt(digest: openArray[byte]): BigInt {.role: {math}.} =
  ## digest: hash converted to an integer per SEC 1 section 4.1.3.
  ## When the hash is wider than the 256-bit group order it is truncated to
  ## the leftmost 256 bits, which is what SHA-384 with P-256 requires.
  result = bigFromBytesBe(digest)
  if digest.len * 8 > 256:
    result = bigShrBitsPublic(result, digest.len * 8 - 256)

## Reference: [FIPS-186-5] section 6 and appendix D.1.2, ECDSA over P-256; curve arithmetic, key generation, signing, and verification algorithms for `ecdsaVerifyP256WithDigest`; pitfall: fail closed and preserve canonical, constant-time comparison where secrets are involved.
proc ecdsaVerifyP256WithDigest*(pub: P256AffinePoint, digest: openArray[byte],
    sig: EcdsaSignature): bool {.role: {math}.} =
  ## pub/digest/sig: public key, pre-computed message hash, and signature.
  ## Lets callers verify chains whose signature hash is not SHA-256.
  var
    e, w, u1, u2: BigInt
    R: P256Point
    A: P256AffinePoint
    inv: tuple[ok: bool, value: BigInt]
  if pub.infinity or not isOnCurve(pub):
    return false
  if bigIsZero(sig.r) or bigIsZero(sig.s):
    return false
  if bigCmp(sig.r, p256N) >= 0 or bigCmp(sig.s, p256N) >= 0:
    return false
  e = bigMod(bitsToInt(digest), p256N)
  inv = bigModInv(sig.s, p256N)
  if not inv.ok:
    return false
  w = inv.value
  u1 = bigMod(bigMul(e, w), p256N)
  u2 = bigMod(bigMul(sig.r, w), p256N)
  R = pointAdd(scalarMulPublic(u1, p256Generator()),
    scalarMulPublic(u2, fromAffine(pub)))
  if isInfinity(R):
    return false
  A = toAffine(R)
  result = bigCmp(bigMod(A.x, p256N), sig.r) == 0

## Reference: [FIPS-186-5] section 6 and appendix D.1.2, ECDSA over P-256; curve arithmetic, key generation, signing, and verification algorithms for `ecdsaVerifyP256`; pitfall: fail closed and preserve canonical, constant-time comparison where secrets are involved.
proc ecdsaVerifyP256*(pub: P256AffinePoint, msg: openArray[byte],
    sig: EcdsaSignature): bool {.role: {math}.} =
  ## pub/msg/sig: public key, signed message, and candidate signature.
  ## The ordinary case: hash the message with SHA-256, then run the one
  ## verification above. Only the hash differs between the two, so only
  ## the hash is written twice.
  result = ecdsaVerifyP256WithDigest(pub, sha256Hash(msg), sig)

## Reference: [FIPS-186-5] section 6 and appendix D.1.2, ECDSA over P-256; curve arithmetic, key generation, signing, and verification algorithms for `rfc6979Nonce`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc rfc6979Nonce(d: BigInt, digest: Sha256Digest): BigInt {.role: {math}.} =
  ## d/digest: private scalar and message hash.
  ## Derives `k` with the RFC 6979 HMAC-SHA-256 construction so a repeated
  ## nonce cannot arise from a degraded RNG.
  var
    V, K: array[sha256DigestBytes, byte]
    buf: seq[byte] = @[]
    i: int = 0
    cand: BigInt
    hv: Sha256Digest
  i = 0
  while i < sha256DigestBytes:
    V[i] = 0x01'u8
    K[i] = 0x00'u8
    i = i + 1
  buf = @V
  buf.add(0x00'u8)
  buf.add(bigToBytesBe(d, p256FieldBytes))
  buf.add(digest)
  K = hmacSha256(K, buf)
  V = hmacSha256(K, V)
  buf = @V
  buf.add(0x01'u8)
  buf.add(bigToBytesBe(d, p256FieldBytes))
  buf.add(digest)
  K = hmacSha256(K, buf)
  V = hmacSha256(K, V)
  while true:
    V = hmacSha256(K, V)
    hv = V
    cand = bigFromBytesBe(hv)
    if not bigIsZero(cand) and bigCmp(cand, p256N) < 0:
      return cand
    buf = @V
    buf.add(0x00'u8)
    K = hmacSha256(K, buf)
    V = hmacSha256(K, V)

## Reference: [FIPS-186-5] section 6 and appendix D.1.2, ECDSA over P-256; curve arithmetic, key generation, signing, and verification algorithms for `ecdsaSignP256`; pitfall: avoid secret-dependent branches, indices, and unbounded secret lifetimes.
proc ecdsaSignP256*(d: BigInt, msg: openArray[byte]): EcdsaSignResult {.
    role: {math}.} =
  ## d/msg: private scalar and the message to sign.
  var
    e, k, r, s: BigInt
    R: P256Point
    A: P256AffinePoint
    kInv: tuple[ok: bool, value: BigInt]
    digest: Sha256Digest
    guard: int = 0
  if bigIsZero(d) or bigCmp(d, p256N) >= 0:
    result.err = "P-256 private scalar is out of range"
    return
  digest = sha256Hash(msg)
  e = bigMod(bitsToInt(digest), p256N)
  k = rfc6979Nonce(d, digest)
  while guard < 8:
    R = scalarMulSecret(k, p256Generator())
    if not isInfinity(R):
      A = toAffine(R)
      r = bigMod(A.x, p256N)
      if not bigIsZero(r):
        kInv = bigModInv(k, p256N)
        if kInv.ok:
          s = bigMod(bigMul(kInv.value,
            bigModAdd(e, bigMod(bigMul(r, d), p256N), p256N)), p256N)
          if not bigIsZero(s):
            # Low-S normalization: many verifiers reject the malleable form.
            if bigCmp(bigAdd(s, s), p256N) > 0:
              s = bigSub(p256N, s)
            result.signature.r = r
            result.signature.s = s
            result.ok = true
            return
    k = rfc6979Nonce(k, digest)
    guard = guard + 1
  result.err = "failed to derive a usable ECDSA nonce"

## Reference: [FIPS-186-5] section 6 and appendix D.1.2, ECDSA over P-256; curve arithmetic, key generation, signing, and verification algorithms for `p256PublicFromScalar`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc p256PublicFromScalar*(d: BigInt): P256AffinePoint {.role: {math}.} =
  ## d: private scalar whose public point is derived.
  if bigIsZero(d) or bigCmp(d, p256N) >= 0:
    raise newException(ValueError, "P-256 private scalar is out of range")
  result = toAffine(scalarMulSecret(d, p256Generator()))

## Reference: [FIPS-186-5] section 6 and appendix D.1.2, ECDSA over P-256; curve arithmetic, key generation, signing, and verification algorithms for `p256Ecdh`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc p256Ecdh*(d: BigInt, peer: P256AffinePoint): tuple[
    ok: bool, secret: seq[byte]] {.role: {math}.} =
  ## d/peer: local private scalar and the validated peer public point.
  ## Returns the big-endian X coordinate, which is the TLS 1.3 shared secret.
  var
    R: P256Point
    A: P256AffinePoint
  if peer.infinity or not isOnCurve(peer):
    return (ok: false, secret: @[])
  if bigIsZero(d) or bigCmp(d, p256N) >= 0:
    return (ok: false, secret: @[])
  R = scalarMulSecret(d, fromAffine(peer))
  if isInfinity(R):
    return (ok: false, secret: @[])
  A = toAffine(R)
  result = (ok: true, secret: bigToBytesBe(A.x, p256FieldBytes))
