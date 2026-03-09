import ../common
import ../bindings/nimcrypto
import ../custom_crypto/xchacha20
import ../custom_crypto/gimli_sponge
import ../custom_crypto/aes_ctr
import ../custom_crypto/blake3 as blake3Impl
when defined(hasLibsodium):
  import ../bindings/libsodium

type
  AlgoType* = enum
    chacha20,
    xchacha20Gimli,
    aesGimli,
    xchacha20AesGimli,
    xchacha20AesGimliPoly1305,
    aes256
  KeyType* = enum
    isSym, isPriv, isPub
  HmacType* = enum
    sha256,
    blake3,
    gimli,
    gimliPoly1305,
    aeadTag
  Key* = object
    key*: seq[uint8]
    keyType*: KeyType
  Hmac* = object
    hmac*: seq[uint8]
    hashType*: HmacType
  EncryptionState* = object
    algoType*: AlgoType
    keys*: seq[Key]
    nonce*: seq[uint8]
    tagLen*: uint16
  Message* = seq[uint8]
  CipherText* = object
    ciphertext*: seq[uint8]
    hmac*: seq[uint8]
    hmacType*: HmacType

const
  xchacha20GimliTagLenDefault = 32
  aesGimliTagLenDefault = 64
  xchacha20AesGimliTagLenDefault = 64
  xchacha20AesGimliPoly1305TagLenDefault = 64
  chacha20TagContext = "wrapper-chacha20-tag-v1"
  poly1305TagLenDefault = 16

when defined(hasLibsodium):
  const
    poly1305KeyContext = "wrapper-poly1305-key-v1"
    poly1305TagContext = "wrapper-poly1305-tag-v1"

proc constantTimeEqual(a, b: openArray[uint8]): bool =
  if a.len != b.len:
    return false
  var diff: uint8 = 0
  for i in 0 ..< a.len:
    diff = diff or (a[i] xor b[i])
  diff == 0

proc requireSymmetricKey(s: EncryptionState, algo: string): seq[uint8] =
  if s.keys.len == 0:
    raise newException(ValueError, "missing symmetric key for " & algo)
  s.keys[0].key

proc requireSymmetricKeyAt(s: EncryptionState, algo: string, idx: int): seq[uint8] =
  if s.keys.len <= idx:
    raise newException(ValueError, "missing symmetric key for " & algo)
  s.keys[idx].key

proc resolveTagLen(s: EncryptionState, d: int): int =
  if s.tagLen == 0'u16:
    result = d
  else:
    result = int(s.tagLen)

proc deriveAesCtrNonce(n: seq[uint8]): seq[uint8] =
  var
    ns: seq[uint8] = @[]
    i: int = 0
  ns.setLen(aesCtrNonceLen)
  i = 0
  while i < ns.len:
    ns[i] = n[i]
    i = i + 1
  result = ns

proc blake3Tag(key, nonce, ciphertext: openArray[uint8]): seq[uint8] =
  var buf = newSeq[uint8](chacha20TagContext.len + nonce.len + ciphertext.len)
  var offset = 0
  for ch in chacha20TagContext:
    buf[offset] = uint8(ord(ch))
    inc offset
  for b in nonce:
    buf[offset] = b
    inc offset
  for b in ciphertext:
    buf[offset] = b
    inc offset
  blake3Impl.blake3KeyedHash(key, buf)

when defined(hasLibsodium):
  proc poly1305Key(masterKey, nonce: openArray[uint8]): seq[uint8] =
    var buf = newSeq[uint8](poly1305KeyContext.len + nonce.len)
    var offset = 0
    for ch in poly1305KeyContext:
      buf[offset] = uint8(ord(ch))
      inc offset
    for b in nonce:
      buf[offset] = b
      inc offset
    result = blake3Impl.blake3KeyedHash(masterKey, buf, poly1305TagLenDefault * 2)

proc poly1305Tag(masterKey, nonce, ciphertext: openArray[uint8]): seq[uint8] =
  when not defined(hasLibsodium):
    discard masterKey
    discard nonce
    discard ciphertext
    raiseUnavailable("libsodium", "hasLibsodium")
    result = @[]
  else:
    ensureSodiumInitialised()
    var buf = newSeq[uint8](poly1305TagContext.len + nonce.len + ciphertext.len)
    var offset = 0
    for ch in poly1305TagContext:
      buf[offset] = uint8(ord(ch))
      inc offset
    for b in nonce:
      buf[offset] = b
      inc offset
    for b in ciphertext:
      buf[offset] = b
      inc offset
    let macKey = poly1305Key(masterKey, nonce)
    result = newSeq[uint8](poly1305TagLenDefault)
    let status = crypto_onetimeauth_poly1305(
      addr result[0],
      if buf.len > 0: unsafeAddr buf[0] else: nil,
      culonglong(buf.len),
      unsafeAddr macKey[0]
    )
    if status != 0:
      raiseOperation("libsodium", "poly1305 authentication failed")

proc combinedTag(gimliTagValue, polyTagValue: openArray[uint8]): seq[uint8] =
  result = newSeq[uint8](gimliTagValue.len + polyTagValue.len)
  var offset = 0
  for b in gimliTagValue:
    result[offset] = b
    inc offset
  for b in polyTagValue:
    result[offset] = b
    inc offset

proc encrypt*(m: Message, s: EncryptionState): CipherText =
  case s.algoType
  of chacha20:
    let key = requireSymmetricKey(s, "chacha20")
    if key.len != 32:
      raise newException(ValueError, "invalid chacha20 key length")
    if s.nonce.len != xchacha20NonceSize:
      raise newException(ValueError, "invalid chacha20 nonce length")
    let cipher = xchacha20Xor(key, s.nonce, m)
    let tag = blake3Tag(key, s.nonce, cipher)
    CipherText(ciphertext: cipher, hmac: tag, hmacType: blake3)
  of xchacha20Gimli:
    let keyX = requireSymmetricKeyAt(s, "xchacha20gimli", 0)
    let keyG = requireSymmetricKeyAt(s, "xchacha20gimli", 1)
    let tagLen = resolveTagLen(s, xchacha20GimliTagLenDefault)
    if keyX.len != 32:
      raise newException(ValueError, "invalid xchacha20gimli xchacha20 key length")
    if keyG.len != 32:
      raise newException(ValueError, "invalid xchacha20gimli gimli key length")
    if s.nonce.len != xchacha20NonceSize:
      raise newException(ValueError, "invalid xchacha20gimli nonce length")
    if tagLen <= 0:
      raise newException(ValueError, "invalid xchacha20gimli tag length")
    let c1 = xchacha20Xor(keyX, s.nonce, m)
    let c2 = gimliStreamXor(keyG, s.nonce, c1)
    let tag = gimliTag(keyG, s.nonce, c2, tagLen)
    CipherText(ciphertext: c2, hmac: tag, hmacType: gimli)
  of aesGimli:
    let keyA = requireSymmetricKeyAt(s, "aesgimli", 0)
    let keyG = requireSymmetricKeyAt(s, "aesgimli", 1)
    let tagLen = resolveTagLen(s, aesGimliTagLenDefault)
    if keyA.len != 32:
      raise newException(ValueError, "invalid aesgimli aes key length")
    if keyG.len != 32:
      raise newException(ValueError, "invalid aesgimli gimli key length")
    if s.nonce.len != xchacha20NonceSize:
      raise newException(ValueError, "invalid aesgimli nonce length")
    if tagLen <= 0:
      raise newException(ValueError, "invalid aesgimli tag length")
    let aesNonce = deriveAesCtrNonce(s.nonce)
    let c1 = aesCtrXor(keyA, aesNonce, m, acbAuto)
    let c2 = gimliStreamXor(keyG, s.nonce, c1)
    let tag = gimliTag(keyG, s.nonce, c2, tagLen)
    CipherText(ciphertext: c2, hmac: tag, hmacType: gimli)
  of xchacha20AesGimli:
    let keyX = requireSymmetricKeyAt(s, "xchacha20aesgimli", 0)
    let keyA = requireSymmetricKeyAt(s, "xchacha20aesgimli", 1)
    let keyG = requireSymmetricKeyAt(s, "xchacha20aesgimli", 2)
    let tagLen = resolveTagLen(s, xchacha20AesGimliTagLenDefault)
    if keyX.len != 32:
      raise newException(ValueError, "invalid xchacha20aesgimli xchacha20 key length")
    if keyA.len != 32:
      raise newException(ValueError, "invalid xchacha20aesgimli aes key length")
    if keyG.len != 32:
      raise newException(ValueError, "invalid xchacha20aesgimli gimli key length")
    if s.nonce.len != xchacha20NonceSize:
      raise newException(ValueError, "invalid xchacha20aesgimli nonce length")
    if tagLen <= 0:
      raise newException(ValueError, "invalid xchacha20aesgimli tag length")
    let c1 = xchacha20Xor(keyX, s.nonce, m)
    let aesNonce = deriveAesCtrNonce(s.nonce)
    let c2 = aesCtrXor(keyA, aesNonce, c1, acbAuto)
    let c3 = gimliStreamXor(keyG, s.nonce, c2)
    let tag = gimliTag(keyG, s.nonce, c3, tagLen)
    CipherText(ciphertext: c3, hmac: tag, hmacType: gimli)
  of xchacha20AesGimliPoly1305:
    let keyX = requireSymmetricKeyAt(s, "xchacha20aesgimlipoly1305", 0)
    let keyA = requireSymmetricKeyAt(s, "xchacha20aesgimlipoly1305", 1)
    let keyG = requireSymmetricKeyAt(s, "xchacha20aesgimlipoly1305", 2)
    let keyP = requireSymmetricKeyAt(s, "xchacha20aesgimlipoly1305", 3)
    let tagLen = resolveTagLen(s, xchacha20AesGimliPoly1305TagLenDefault)
    if keyX.len != 32:
      raise newException(ValueError, "invalid xchacha20aesgimlipoly1305 xchacha20 key length")
    if keyA.len != 32:
      raise newException(ValueError, "invalid xchacha20aesgimlipoly1305 aes key length")
    if keyG.len != 32:
      raise newException(ValueError, "invalid xchacha20aesgimlipoly1305 gimli key length")
    if keyP.len != 32:
      raise newException(ValueError, "invalid xchacha20aesgimlipoly1305 poly1305 key length")
    if s.nonce.len != xchacha20NonceSize:
      raise newException(ValueError, "invalid xchacha20aesgimlipoly1305 nonce length")
    if tagLen <= 0:
      raise newException(ValueError, "invalid xchacha20aesgimlipoly1305 gimli tag length")
    let c1 = xchacha20Xor(keyX, s.nonce, m)
    let aesNonce = deriveAesCtrNonce(s.nonce)
    let c2 = aesCtrXor(keyA, aesNonce, c1, acbAuto)
    let c3 = gimliStreamXor(keyG, s.nonce, c2)
    let gimliMac = gimliTag(keyG, s.nonce, c3, tagLen)
    let polyMac = poly1305Tag(keyP, s.nonce, c3)
    CipherText(ciphertext: c3, hmac: combinedTag(gimliMac, polyMac),
      hmacType: gimliPoly1305)
  of aes256:
    when not defined(hasNimcrypto):
      raiseUnavailable("nimcrypto", "hasNimcrypto")
    let key = requireSymmetricKey(s, "aes256")
    var ctx: Aes256GcmContext
    ctx.init(key, s.nonce)
    let cipher = ctx.encrypt(m)
    let tagArr = ctx.tag()
    var tag = newSeq[uint8](tagArr.len)
    for i, b in tagArr:
      tag[i] = b
    CipherText(ciphertext: cipher, hmac: tag, hmacType: aeadTag)

proc decrypt*(c: CipherText, s: EncryptionState): Message =
  case s.algoType
  of chacha20:
    let key = requireSymmetricKey(s, "chacha20")
    if key.len != 32:
      raise newException(ValueError, "invalid chacha20 key length")
    if s.nonce.len != xchacha20NonceSize:
      raise newException(ValueError, "invalid chacha20 nonce length")
    let expected = blake3Tag(key, s.nonce, c.ciphertext)
    if not constantTimeEqual(expected, c.hmac):
      raise newException(ValueError, "chacha20 authentication tag mismatch")
    xchacha20Xor(key, s.nonce, c.ciphertext)
  of xchacha20Gimli:
    let keyX = requireSymmetricKeyAt(s, "xchacha20gimli", 0)
    let keyG = requireSymmetricKeyAt(s, "xchacha20gimli", 1)
    let tagLen = resolveTagLen(s, xchacha20GimliTagLenDefault)
    if keyX.len != 32:
      raise newException(ValueError, "invalid xchacha20gimli xchacha20 key length")
    if keyG.len != 32:
      raise newException(ValueError, "invalid xchacha20gimli gimli key length")
    if s.nonce.len != xchacha20NonceSize:
      raise newException(ValueError, "invalid xchacha20gimli nonce length")
    if tagLen <= 0:
      raise newException(ValueError, "invalid xchacha20gimli tag length")
    let expected = gimliTag(keyG, s.nonce, c.ciphertext, tagLen)
    if not constantTimeEqual(expected, c.hmac):
      raise newException(ValueError, "xchacha20gimli authentication tag mismatch")
    let c1 = gimliStreamXor(keyG, s.nonce, c.ciphertext)
    xchacha20Xor(keyX, s.nonce, c1)
  of aesGimli:
    let keyA = requireSymmetricKeyAt(s, "aesgimli", 0)
    let keyG = requireSymmetricKeyAt(s, "aesgimli", 1)
    let tagLen = resolveTagLen(s, aesGimliTagLenDefault)
    if keyA.len != 32:
      raise newException(ValueError, "invalid aesgimli aes key length")
    if keyG.len != 32:
      raise newException(ValueError, "invalid aesgimli gimli key length")
    if s.nonce.len != xchacha20NonceSize:
      raise newException(ValueError, "invalid aesgimli nonce length")
    if tagLen <= 0:
      raise newException(ValueError, "invalid aesgimli tag length")
    let expected = gimliTag(keyG, s.nonce, c.ciphertext, tagLen)
    if not constantTimeEqual(expected, c.hmac):
      raise newException(ValueError, "aesgimli authentication tag mismatch")
    let aesNonce = deriveAesCtrNonce(s.nonce)
    let c1 = gimliStreamXor(keyG, s.nonce, c.ciphertext)
    aesCtrXor(keyA, aesNonce, c1, acbAuto)
  of xchacha20AesGimli:
    let keyX = requireSymmetricKeyAt(s, "xchacha20aesgimli", 0)
    let keyA = requireSymmetricKeyAt(s, "xchacha20aesgimli", 1)
    let keyG = requireSymmetricKeyAt(s, "xchacha20aesgimli", 2)
    let tagLen = resolveTagLen(s, xchacha20AesGimliTagLenDefault)
    if keyX.len != 32:
      raise newException(ValueError, "invalid xchacha20aesgimli xchacha20 key length")
    if keyA.len != 32:
      raise newException(ValueError, "invalid xchacha20aesgimli aes key length")
    if keyG.len != 32:
      raise newException(ValueError, "invalid xchacha20aesgimli gimli key length")
    if s.nonce.len != xchacha20NonceSize:
      raise newException(ValueError, "invalid xchacha20aesgimli nonce length")
    if tagLen <= 0:
      raise newException(ValueError, "invalid xchacha20aesgimli tag length")
    let expected = gimliTag(keyG, s.nonce, c.ciphertext, tagLen)
    if not constantTimeEqual(expected, c.hmac):
      raise newException(ValueError, "xchacha20aesgimli authentication tag mismatch")
    let aesNonce = deriveAesCtrNonce(s.nonce)
    let c2 = gimliStreamXor(keyG, s.nonce, c.ciphertext)
    let c1 = aesCtrXor(keyA, aesNonce, c2, acbAuto)
    xchacha20Xor(keyX, s.nonce, c1)
  of xchacha20AesGimliPoly1305:
    let keyX = requireSymmetricKeyAt(s, "xchacha20aesgimlipoly1305", 0)
    let keyA = requireSymmetricKeyAt(s, "xchacha20aesgimlipoly1305", 1)
    let keyG = requireSymmetricKeyAt(s, "xchacha20aesgimlipoly1305", 2)
    let keyP = requireSymmetricKeyAt(s, "xchacha20aesgimlipoly1305", 3)
    let tagLen = resolveTagLen(s, xchacha20AesGimliPoly1305TagLenDefault)
    if keyX.len != 32:
      raise newException(ValueError, "invalid xchacha20aesgimlipoly1305 xchacha20 key length")
    if keyA.len != 32:
      raise newException(ValueError, "invalid xchacha20aesgimlipoly1305 aes key length")
    if keyG.len != 32:
      raise newException(ValueError, "invalid xchacha20aesgimlipoly1305 gimli key length")
    if keyP.len != 32:
      raise newException(ValueError, "invalid xchacha20aesgimlipoly1305 poly1305 key length")
    if s.nonce.len != xchacha20NonceSize:
      raise newException(ValueError, "invalid xchacha20aesgimlipoly1305 nonce length")
    if tagLen <= 0:
      raise newException(ValueError, "invalid xchacha20aesgimlipoly1305 gimli tag length")
    if c.hmac.len != tagLen + poly1305TagLenDefault:
      raise newException(ValueError, "invalid xchacha20aesgimlipoly1305 tag length")
    let expectedGimli = gimliTag(keyG, s.nonce, c.ciphertext, tagLen)
    let expectedPoly = poly1305Tag(keyP, s.nonce, c.ciphertext)
    let actualGimli = c.hmac[0 ..< tagLen]
    let actualPoly = c.hmac[tagLen ..< c.hmac.len]
    if not constantTimeEqual(expectedGimli, actualGimli) or
        not constantTimeEqual(expectedPoly, actualPoly):
      raise newException(ValueError, "xchacha20aesgimlipoly1305 authentication tag mismatch")
    let aesNonce = deriveAesCtrNonce(s.nonce)
    let c2 = gimliStreamXor(keyG, s.nonce, c.ciphertext)
    let c1 = aesCtrXor(keyA, aesNonce, c2, acbAuto)
    xchacha20Xor(keyX, s.nonce, c1)
  of aes256:
    when not defined(hasNimcrypto):
      raiseUnavailable("nimcrypto", "hasNimcrypto")
    let key = requireSymmetricKey(s, "aes256")
    if c.hmac.len != 16:
      raise newException(ValueError, "invalid aes256 authentication tag length")
    var ctx: Aes256GcmContext
    ctx.init(key, s.nonce)
    ctx.decrypt(c.ciphertext, c.hmac)
