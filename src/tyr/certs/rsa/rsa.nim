## ---------------------------------------------------------------------
## RSA <- PKCS#1 v1.5 and RSASSA-PSS signatures over the Tyr bignum core
## ---------------------------------------------------------------------
##
## Covers what DKIM (RFC 6376 `rsa-sha256`) and TLS 1.3 CertificateVerify
## (`rsa_pkcs1_sha256` for certificates, `rsa_pss_rsae_sha256` for the
## handshake signature) require. Private operations use the CRT form when
## the key carries its factors, and fall back to the plain exponent when
## it does not.
##
## Public verification is the production path. The current heap-backed
## bigint makes direct-import private signing variable-time until a dedicated
## fixed-width private-key backend replaces it.

import metaPragmas
import ../../helpers/bigint
import ../../hashes/sha256
import ../../hashes/sha512
import ../../helpers/random
import ../der
import ../oid
import ../pem

type
  RsaPublicKey* {.role: {truthState}.} = object
    n*: BigInt
    e*: BigInt
    bits*: int

  RsaPrivateKey* {.role: {memory}.} = object
    n*: BigInt
    e*: BigInt
    d*: BigInt
    p*: BigInt
    q*: BigInt
    dp*: BigInt
    dq*: BigInt
    qinv*: BigInt
    hasCrt*: bool
    bits*: int

  RsaKeyResult* {.role: {truthBuilder}.} = object
    ok*: bool
    err*: string

  RsaPublicKeyResult* {.role: {truthBuilder}.} = object
    ok*: bool
    key*: RsaPublicKey
    err*: string

  RsaPrivateKeyResult* {.role: {truthBuilder}.} = object
    ok*: bool
    key*: RsaPrivateKey
    err*: string

  RsaSignResult* {.role: {truthBuilder}.} = object
    ok*: bool
    signature*: seq[byte]
    err*: string

  RsaHash* {.role: {helper}.} = enum
    rhSha256, rhSha384, rhSha512

const
  rsaMinBits* = 1024   ## reject weak moduli outright
  rsaMaxBits* = 16384  ## bounds attacker-supplied key material
  sha256DigestInfoPrefix: array[19, byte] = [
    0x30'u8, 0x31'u8, 0x30'u8, 0x0d'u8, 0x06'u8, 0x09'u8, 0x60'u8, 0x86'u8,
    0x48'u8, 0x01'u8, 0x65'u8, 0x03'u8, 0x04'u8, 0x02'u8, 0x01'u8, 0x05'u8,
    0x00'u8, 0x04'u8, 0x20'u8
  ]
  sha384DigestInfoPrefix: array[19, byte] = [
    0x30'u8, 0x41'u8, 0x30'u8, 0x0d'u8, 0x06'u8, 0x09'u8, 0x60'u8, 0x86'u8,
    0x48'u8, 0x01'u8, 0x65'u8, 0x03'u8, 0x04'u8, 0x02'u8, 0x02'u8, 0x05'u8,
    0x00'u8, 0x04'u8, 0x30'u8
  ]
  sha512DigestInfoPrefix: array[19, byte] = [
    0x30'u8, 0x51'u8, 0x30'u8, 0x0d'u8, 0x06'u8, 0x09'u8, 0x60'u8, 0x86'u8,
    0x48'u8, 0x01'u8, 0x65'u8, 0x03'u8, 0x04'u8, 0x02'u8, 0x03'u8, 0x05'u8,
    0x00'u8, 0x04'u8, 0x40'u8
  ]

proc rsaModulusBytes*(k: RsaPublicKey): int {.role: {helper}.} =
  ## k: parsed public key.
  ## Returns the octet width every RSA primitive output must have.
  result = (bigBitLen(k.n) + 7) div 8

proc rsaPrivateModulusBytes*(k: RsaPrivateKey): int {.role: {helper}.} =
  ## k: parsed private key.
  result = (bigBitLen(k.n) + 7) div 8

proc ctEqualBytes(a, b: openArray[byte]): bool {.role: {math}.} =
  ## a/b: buffers compared without an early exit on the first difference.
  var
    diff: byte = 0
    i: int = 0
  if a.len != b.len:
    return false
  while i < a.len:
    diff = diff or (a[i] xor b[i])
    i = i + 1
  result = diff == 0'u8

proc readDerBigInt(A: openArray[byte], E: DerElement): tuple[
    ok: bool, value: BigInt, err: string] {.role: {parser}.} =
  ## A/E: source bytes and an INTEGER element holding an unsigned magnitude.
  var shape: string = validateDerInteger(A, E, false)
  if shape.len > 0:
    result.err = shape
    return
  result.value = bigFromBytesBe(derContent(A, E))
  result.ok = true

proc validateRsaModulus(n: BigInt): string {.role: {parser}.} =
  ## n: candidate RSA modulus.
  var bits: int = bigBitLen(n)
  if bits < rsaMinBits:
    return "RSA modulus is shorter than " & $rsaMinBits & " bits"
  if bits > rsaMaxBits:
    return "RSA modulus exceeds " & $rsaMaxBits & " bits"
  if not bigIsOdd(n):
    return "RSA modulus is even"
  result = ""

proc validateRsaExponent(e: BigInt): string {.role: {parser}.} =
  ## e: candidate public exponent.
  if bigIsZero(e) or not bigIsOdd(e):
    return "RSA public exponent must be odd and non-zero"
  if bigCmp(e, bigFromUint32(3'u32)) < 0:
    return "RSA public exponent is too small"
  if bigBitLen(e) > 64:
    return "RSA public exponent is unreasonably large"
  result = ""

proc parseRsaPkcs1PublicKey*(A: openArray[byte]): RsaPublicKeyResult {.
    role: {truthBuilder}.} =
  ## A: DER `RSAPublicKey ::= SEQUENCE { modulus, publicExponent }`.
  var
    R: DerReadResult
    C: tuple[ok: bool, children: seq[DerElement], err: string]
    n, e: tuple[ok: bool, value: BigInt, err: string]
    shape: string = ""
  R = readDerElement(A, 0)
  if not R.ok:
    result.err = R.err
    return
  if R.element.endOffset != A.len:
    result.err = "RSAPublicKey has trailing bytes"
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
    result.err = "RSAPublicKey must have two fields"
    return
  n = readDerBigInt(A, C.children[0])
  if not n.ok:
    result.err = n.err
    return
  e = readDerBigInt(A, C.children[1])
  if not e.ok:
    result.err = e.err
    return
  shape = validateRsaModulus(n.value)
  if shape.len > 0:
    result.err = shape
    return
  shape = validateRsaExponent(e.value)
  if shape.len > 0:
    result.err = shape
    return
  result.key.n = n.value
  result.key.e = e.value
  result.key.bits = bigBitLen(n.value)
  result.ok = true

proc parseRsaSpki*(A: openArray[byte]): RsaPublicKeyResult {.
    role: {truthBuilder}.} =
  ## A: DER SubjectPublicKeyInfo carrying an `rsaEncryption` key.
  var
    R: DerReadResult
    C, alg: tuple[ok: bool, children: seq[DerElement], err: string]
    O: tuple[ok: bool, value, err: string]
    shape: string = ""
    inner: seq[byte] = @[]
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
  if alg.children.len < 1:
    result.err = "AlgorithmIdentifier is empty"
    return
  O = decodeDerOid(A, alg.children[0])
  if not O.ok:
    result.err = O.err
    return
  if O.value != oidRsaEncryption:
    result.err = "public-key algorithm is not rsaEncryption"
    return
  # RFC 4055: the rsaEncryption parameter field must be present and NULL.
  if alg.children.len != 2:
    result.err = "rsaEncryption parameters must be NULL"
    return
  shape = requireDerShape(alg.children[1], dcUniversal, derTagNull, false)
  if shape.len > 0 or alg.children[1].contentLen != 0:
    result.err = "rsaEncryption parameters must be NULL"
    return
  shape = requireDerShape(C.children[1], dcUniversal, derTagBitString, false)
  if shape.len > 0:
    result.err = shape
    return
  if C.children[1].contentLen < 1 or A[C.children[1].contentStart] != 0'u8:
    result.err = "SubjectPublicKey BIT STRING must be octet aligned"
    return
  inner = A[C.children[1].contentStart + 1 ..< C.children[1].endOffset]
  result = parseRsaPkcs1PublicKey(inner)

proc parseRsaPublicKeyPem*(s: string): RsaPublicKeyResult {.
    role: {orchestrator}.} =
  ## s: PEM text holding a `PUBLIC KEY` (SPKI) or `RSA PUBLIC KEY` block.
  var P = readPemBlock(s, "PUBLIC KEY")
  if P.ok:
    return parseRsaSpki(P.pemBlock.der)
  P = readPemBlock(s, "RSA PUBLIC KEY")
  if not P.ok:
    result.err = P.err
    return
  result = parseRsaPkcs1PublicKey(P.pemBlock.der)

proc parseRsaPkcs1PrivateKey*(A: openArray[byte]): RsaPrivateKeyResult {.
    role: {truthBuilder}.} =
  ## A: DER `RSAPrivateKey` (PKCS#1) with the two-prime CRT fields.
  var
    R: DerReadResult
    C: tuple[ok: bool, children: seq[DerElement], err: string]
    F: array[9, BigInt]
    got: tuple[ok: bool, value: BigInt, err: string]
    one, pMinusOne, qMinusOne: BigInt
    shape: string = ""
    i: int = 0
  R = readDerElement(A, 0)
  if not R.ok:
    result.err = R.err
    return
  shape = requireDerShape(R.element, dcUniversal, derTagSequence, true)
  if shape.len > 0:
    result.err = shape
    return
  C = readDerChildren(A, R.element)
  if not C.ok:
    result.err = C.err
    return
  if R.element.endOffset != A.len:
    result.err = "RSAPrivateKey has trailing bytes"
    return
  if C.children.len != 9:
    result.err = "RSAPrivateKey must carry exactly nine two-prime fields"
    return
  while i < 9:
    got = readDerBigInt(A, C.children[i])
    if not got.ok:
      result.err = got.err
      return
    F[i] = got.value
    i = i + 1
  if not bigIsZero(F[0]):
    result.err = "only two-prime RSAPrivateKey version 0 is supported"
    return
  shape = validateRsaModulus(F[1])
  if shape.len > 0:
    result.err = shape
    return
  shape = validateRsaExponent(F[2])
  if shape.len > 0:
    result.err = shape
    return
  if bigIsZero(F[3]) or bigCmp(F[4], bigFromUint32(3'u32)) < 0 or
      bigCmp(F[5], bigFromUint32(3'u32)) < 0 or bigIsZero(F[6]) or
      bigIsZero(F[7]) or bigIsZero(F[8]):
    result.err = "RSA private and CRT values must be non-zero"
    return
  result.key.n = F[1]
  result.key.e = F[2]
  result.key.d = F[3]
  result.key.p = F[4]
  result.key.q = F[5]
  result.key.dp = F[6]
  result.key.dq = F[7]
  result.key.qinv = F[8]
  result.key.bits = bigBitLen(F[1])
  result.key.hasCrt = bigIsOdd(F[4]) and bigIsOdd(F[5])
  if not result.key.hasCrt:
    result.err = "RSA CRT factors must be odd"
    return
  if bigCmp(bigMul(F[4], F[5]), F[1]) != 0:
    result.err = "RSA CRT primes do not multiply to the modulus"
    return
  one = bigFromUint32(1'u32)
  pMinusOne = bigSub(F[4], one)
  qMinusOne = bigSub(F[5], one)
  if bigCmp(F[6], bigMod(F[3], pMinusOne)) != 0 or
      bigCmp(F[7], bigMod(F[3], qMinusOne)) != 0:
    result.err = "RSA CRT exponents do not match the private exponent"
    return
  if bigCmp(bigMod(bigMul(F[8], F[5]), F[4]), one) != 0:
    result.err = "RSA CRT coefficient is not q^-1 mod p"
    return
  if bigCmp(bigMod(bigMul(F[2], F[3]), pMinusOne), one) != 0 or
      bigCmp(bigMod(bigMul(F[2], F[3]), qMinusOne), one) != 0:
    result.err = "RSA private exponent does not match the public exponent"
    return
  result.ok = true

proc parseRsaPkcs8PrivateKey*(A: openArray[byte]): RsaPrivateKeyResult {.
    role: {truthBuilder}.} =
  ## A: DER PKCS#8 PrivateKeyInfo wrapping an `rsaEncryption` private key.
  var
    R: DerReadResult
    C, alg: tuple[ok: bool, children: seq[DerElement], err: string]
    O: tuple[ok: bool, value, err: string]
    version: tuple[ok: bool, value: BigInt, err: string]
    shape: string = ""
  R = readDerElement(A, 0)
  if not R.ok:
    result.err = R.err
    return
  if R.element.endOffset != A.len:
    result.err = "PKCS#8 PrivateKeyInfo has trailing bytes"
    return
  shape = requireDerShape(R.element, dcUniversal, derTagSequence, true)
  if shape.len > 0:
    result.err = shape
    return
  C = readDerChildren(A, R.element)
  if not C.ok:
    result.err = C.err
    return
  if C.children.len != 3:
    result.err = "PKCS#8 PrivateKeyInfo must have exactly three fields"
    return
  version = readDerBigInt(A, C.children[0])
  if not version.ok or not bigIsZero(version.value):
    result.err = "only PKCS#8 PrivateKeyInfo version 0 is supported"
    return
  alg = readDerChildren(A, C.children[1])
  if not alg.ok:
    result.err = alg.err
    return
  if alg.children.len != 2:
    result.err = "PKCS#8 rsaEncryption parameters must be NULL"
    return
  O = decodeDerOid(A, alg.children[0])
  if not O.ok:
    result.err = O.err
    return
  if O.value != oidRsaEncryption:
    result.err = "PKCS#8 key algorithm is not rsaEncryption"
    return
  shape = requireDerShape(alg.children[1], dcUniversal, derTagNull, false)
  if shape.len > 0 or alg.children[1].contentLen != 0:
    result.err = "PKCS#8 rsaEncryption parameters must be NULL"
    return
  shape = requireDerShape(C.children[2], dcUniversal, derTagOctetString, false)
  if shape.len > 0:
    result.err = shape
    return
  result = parseRsaPkcs1PrivateKey(A[C.children[2].contentStart ..<
    C.children[2].endOffset])

proc parseRsaPrivateKeyPem*(s: string): RsaPrivateKeyResult {.
    role: {orchestrator}.} =
  ## s: PEM text holding a `PRIVATE KEY` (PKCS#8) or `RSA PRIVATE KEY` block.
  var P = readPemBlock(s, "PRIVATE KEY")
  if P.ok:
    return parseRsaPkcs8PrivateKey(P.pemBlock.der)
  P = readPemBlock(s, "RSA PRIVATE KEY")
  if not P.ok:
    result.err = P.err
    return
  result = parseRsaPkcs1PrivateKey(P.pemBlock.der)

proc rsaPublicOp(k: RsaPublicKey, m: BigInt): tuple[ok: bool, value: BigInt] {.
    role: {math}.} =
  ## k/m: public key and an integer already reduced below the modulus.
  if bigCmp(m, k.n) >= 0:
    return (ok: false, value: bigZero())
  result = bigModExp(m, k.e, k.n)

proc rsaPrivateOp(k: RsaPrivateKey, m: BigInt): tuple[ok: bool, value: BigInt] {.
    role: {math}.} =
  ## k/m: private key and an integer already reduced below the modulus.
  ## Uses the CRT path when the key carries usable factors.
  var
    m1, m2, h, diff: BigInt
    e1, e2: tuple[ok: bool, value: BigInt]
    check: tuple[ok: bool, value: BigInt]
  if bigCmp(m, k.n) >= 0:
    return (ok: false, value: bigZero())
  if not k.hasCrt:
    result = bigModExp(m, k.d, k.n)
    if not result.ok:
      return
    check = bigModExp(result.value, k.e, k.n)
    if not check.ok or bigCmp(check.value, m) != 0:
      return (ok: false, value: bigZero())
    return
  e1 = bigModExp(bigMod(m, k.p), k.dp, k.p)
  if not e1.ok:
    return (ok: false, value: bigZero())
  e2 = bigModExp(bigMod(m, k.q), k.dq, k.q)
  if not e2.ok:
    return (ok: false, value: bigZero())
  m1 = e1.value
  m2 = e2.value
  diff = bigModSub(m1, m2, k.p)
  h = bigMod(bigMul(diff, k.qinv), k.p)
  result.value = bigAdd(m2, bigMul(h, k.q))
  # Verify the CRT result against the public exponent. A faulty computation
  # would otherwise leak the factorization (Boneh-DeMillo-Lipton).
  check = bigModExp(result.value, k.e, k.n)
  if not check.ok or bigCmp(check.value, m) != 0:
    return (ok: false, value: bigZero())
  result.ok = true

proc rsaDigest*(h: RsaHash, msg: openArray[byte]): seq[byte] {.role: {math}.} =
  ## h/msg: hash selector and the message to digest.
  case h
  of rhSha256:
    result = @(sha256Hash(msg))
  of rhSha384:
    result = @(sha384Hash(msg))
  of rhSha512:
    result = @(sha512Hash(msg))

proc digestInfoPrefix(h: RsaHash): seq[byte] {.role: {helper}.} =
  ## h: hash selector whose PKCS#1 DigestInfo prefix is returned.
  case h
  of rhSha256:
    result = @sha256DigestInfoPrefix
  of rhSha384:
    result = @sha384DigestInfoPrefix
  of rhSha512:
    result = @sha512DigestInfoPrefix

proc emsaPkcs1v15(h: RsaHash, digest: openArray[byte], emLen: int): tuple[
    ok: bool, em: seq[byte]] {.role: {math}.} =
  ## h/digest/emLen: hash selector, message hash, and encoded-message width.
  var
    prefix: seq[byte] = digestInfoPrefix(h)
    tLen: int = prefix.len + digest.len
    i: int = 0
  if emLen < tLen + 11:
    return (ok: false, em: @[])
  result.em = newSeq[byte](emLen)
  result.em[0] = 0x00'u8
  result.em[1] = 0x01'u8
  i = 2
  while i < emLen - tLen - 1:
    result.em[i] = 0xff'u8
    i = i + 1
  result.em[emLen - tLen - 1] = 0x00'u8
  i = 0
  while i < prefix.len:
    result.em[emLen - tLen + i] = prefix[i]
    i = i + 1
  i = 0
  while i < digest.len:
    result.em[emLen - digest.len + i] = digest[i]
    i = i + 1
  result.ok = true

proc emsaPkcs1v15Sha256(digest: Sha256Digest, emLen: int): tuple[
    ok: bool, em: seq[byte]] {.role: {math}.} =
  ## digest/emLen: message hash and the target encoded-message width.
  result = emsaPkcs1v15(rhSha256, digest, emLen)

proc rsaVerifyPkcs1v15*(k: RsaPublicKey, h: RsaHash,
    msg, sig: openArray[byte]): bool {.role: {math}.} =
  ## k/h/msg/sig: public key, hash selector, message, and signature.
  ## Re-encodes the expected block rather than parsing the recovered one,
  ## so no permissive padding parser is exposed to attacker input.
  var
    kLen: int = rsaModulusBytes(k)
    op: tuple[ok: bool, value: BigInt]
    s: BigInt
    expected: tuple[ok: bool, em: seq[byte]]
  if sig.len != kLen:
    return false
  s = bigFromBytesBe(sig)
  if bigCmp(s, k.n) >= 0:
    return false
  op = rsaPublicOp(k, s)
  if not op.ok:
    return false
  expected = emsaPkcs1v15(h, rsaDigest(h, msg), kLen)
  if not expected.ok:
    return false
  result = ctEqualBytes(bigToBytesBe(op.value, kLen), expected.em)

proc rsaVerifyPkcs1v15Sha256*(k: RsaPublicKey, msg, sig: openArray[byte]): bool {.
    role: {math}.} =
  ## k/msg/sig: public key, signed message, and candidate signature.
  ## Re-encodes the expected block and compares it to the recovered one,
  ## so no permissive padding parser is exposed to attacker input.
  var
    kLen: int = rsaModulusBytes(k)
    s, recovered: BigInt
    op: tuple[ok: bool, value: BigInt]
    expected: tuple[ok: bool, em: seq[byte]]
  if sig.len != kLen:
    return false
  s = bigFromBytesBe(sig)
  if bigCmp(s, k.n) >= 0:
    return false
  op = rsaPublicOp(k, s)
  if not op.ok:
    return false
  recovered = op.value
  expected = emsaPkcs1v15Sha256(sha256Hash(msg), kLen)
  if not expected.ok:
    return false
  result = ctEqualBytes(bigToBytesBe(recovered, kLen), expected.em)

proc rsaSignPkcs1v15Sha256*(k: RsaPrivateKey, msg: openArray[byte]): RsaSignResult {.
    role: {math}.} =
  ## k/msg: private key and the message to sign.
  var
    kLen: int = rsaPrivateModulusBytes(k)
    encoded: tuple[ok: bool, em: seq[byte]]
    op: tuple[ok: bool, value: BigInt]
  encoded = emsaPkcs1v15Sha256(sha256Hash(msg), kLen)
  if not encoded.ok:
    result.err = "RSA modulus is too small for a PKCS#1 v1.5 SHA-256 signature"
    return
  op = rsaPrivateOp(k, bigFromBytesBe(encoded.em))
  if not op.ok:
    result.err = "RSA private operation failed"
    return
  result.signature = bigToBytesBe(op.value, kLen)
  result.ok = true

proc mgf1Sha256*(seed: openArray[byte], outLen: int): seq[byte] {.role: {math}.} =
  ## seed/outLen: MGF1 seed and requested mask length.
  var
    counter: uint32 = 0
    block4: array[4, byte]
    buf: seq[byte] = @[]
    digest: Sha256Digest
    take: int = 0
  if outLen < 0 or uint64(outLen) > (uint64(high(uint32)) + 1'u64) *
      uint64(sha256DigestBytes):
    raise newException(ValueError, "MGF1 output length is out of range")
  while result.len < outLen:
    block4[0] = byte((counter shr 24) and 0xff'u32)
    block4[1] = byte((counter shr 16) and 0xff'u32)
    block4[2] = byte((counter shr 8) and 0xff'u32)
    block4[3] = byte(counter and 0xff'u32)
    buf = @seed
    buf.add(block4)
    digest = sha256Hash(buf)
    take = min(sha256DigestBytes, outLen - result.len)
    result.add(digest[0 ..< take])
    counter = counter + 1'u32

proc pssMHash(mHash: Sha256Digest, salt: openArray[byte]): Sha256Digest {.
    role: {math}.} =
  ## mHash/salt: message hash and PSS salt for the M' construction.
  var buf: seq[byte] = newSeq[byte](8)
  buf.add(mHash)
  buf.add(salt)
  result = sha256Hash(buf)

proc rsaVerifyPssSha256*(k: RsaPublicKey, msg, sig: openArray[byte];
    saltLen: int = sha256DigestBytes): bool {.role: {math}.} =
  ## k/msg/sig: public key, signed message, and candidate signature.
  ## saltLen: expected salt length; TLS 1.3 fixes this at the digest size.
  var
    kLen: int = rsaModulusBytes(k)
    emBits: int = bigBitLen(k.n) - 1
    emLen: int = (emBits + 7) div 8
    s: BigInt
    op: tuple[ok: bool, value: BigInt]
    em, db, mask, salt: seq[byte] = @[]
    mHash, expected: Sha256Digest
    i, dbLen, padLen: int = 0
    topBits: int = 0
    allowed: byte = 0
  if sig.len != kLen or saltLen < 0:
    return false
  if emLen < sha256DigestBytes + 2 or
      saltLen > emLen - sha256DigestBytes - 2:
    return false
  s = bigFromBytesBe(sig)
  if bigCmp(s, k.n) >= 0:
    return false
  op = rsaPublicOp(k, s)
  if not op.ok:
    return false
  if bigByteLen(op.value) > emLen:
    return false
  em = bigToBytesBe(op.value, emLen)
  if em[emLen - 1] != 0xbc'u8:
    return false
  dbLen = emLen - sha256DigestBytes - 1
  db = em[0 ..< dbLen]
  topBits = 8 * emLen - emBits
  allowed = byte(0xff'u32 shr uint32(topBits))
  if topBits > 0 and (db[0] and not allowed) != 0'u8:
    return false
  mask = mgf1Sha256(em[dbLen ..< dbLen + sha256DigestBytes], dbLen)
  i = 0
  while i < dbLen:
    db[i] = db[i] xor mask[i]
    i = i + 1
  # Clear the leftmost bits that the encoding requires to be zero.
  if topBits > 0:
    db[0] = db[0] and allowed
  padLen = dbLen - saltLen - 1
  i = 0
  while i < padLen:
    if db[i] != 0x00'u8:
      return false
    i = i + 1
  if db[padLen] != 0x01'u8:
    return false
  salt = db[padLen + 1 ..< dbLen]
  mHash = sha256Hash(msg)
  expected = pssMHash(mHash, salt)
  result = ctEqualBytes(em[dbLen ..< dbLen + sha256DigestBytes], expected)

proc rsaSignPssSha256*(k: RsaPrivateKey, msg: openArray[byte];
    saltLen: int = sha256DigestBytes): RsaSignResult {.role: {math}.} =
  ## k/msg: private key and the message to sign.
  ## saltLen: salt length; TLS 1.3 fixes this at the digest size.
  var
    kLen: int = rsaPrivateModulusBytes(k)
    emBits: int = bigBitLen(k.n) - 1
    emLen: int = (emBits + 7) div 8
    salt, em, db, mask: seq[byte] = @[]
    mHash, h: Sha256Digest
    i, dbLen, topBits: int = 0
    op: tuple[ok: bool, value: BigInt]
  if saltLen < 0:
    result.err = "PSS salt length cannot be negative"
    return
  if emLen < sha256DigestBytes + 2 or
      saltLen > emLen - sha256DigestBytes - 2:
    result.err = "RSA modulus is too small for the requested PSS salt"
    return
  salt = cryptoRandomBytes(saltLen)
  mHash = sha256Hash(msg)
  h = pssMHash(mHash, salt)
  dbLen = emLen - sha256DigestBytes - 1
  db = newSeq[byte](dbLen)
  db[dbLen - saltLen - 1] = 0x01'u8
  i = 0
  while i < saltLen:
    db[dbLen - saltLen + i] = salt[i]
    i = i + 1
  mask = mgf1Sha256(h, dbLen)
  i = 0
  while i < dbLen:
    db[i] = db[i] xor mask[i]
    i = i + 1
  topBits = 8 * emLen - emBits
  if topBits > 0:
    db[0] = db[0] and byte(0xff'u32 shr uint32(topBits))
  em = db
  em.add(h)
  em.add(0xbc'u8)
  op = rsaPrivateOp(k, bigFromBytesBe(em))
  if not op.ok:
    result.err = "RSA private operation failed"
    return
  result.signature = bigToBytesBe(op.value, kLen)
  result.ok = true
