## ---------------------------------------------------------
## Custom HMAC <- generic two-pass HMAC over hash callbacks
## ---------------------------------------------------------

import ./blake3
import ./gimli_sponge
import ./sha3 as customSha3
import ./poly1305 as customPoly1305

type
  ## HashProc: unkeyed hash callback used by the generic HMAC helper.
  HashProc* = proc(input: openArray[byte], outLen: int): seq[byte] {.nimcall.}

  ## KeyedHashProc: keyed hash callback used by the keyed HMAC helper.
  KeyedHashProc* = proc(key, input: openArray[byte], outLen: int): seq[byte] {.nimcall.}

const
  hmacConstA* = 0x36'u8
  hmacConstB* = 0x5c'u8
  blake3HmacBlockLen* = 64
  gimliHmacBlockLen* = 48
  poly1305HmacBlockLen* = 64
  poly1305HmacOutLen* = 16

proc appendBytes(dst: var seq[byte], src: openArray[byte]) =
  ## dst: destination byte sequence.
  ## src: source bytes to append.
  var
    i: int = 0
    base: int = 0
  base = dst.len
  dst.setLen(base + src.len)
  i = 0
  while i < src.len:
    dst[base + i] = src[i]
    i = i + 1

proc copyBytes(src: openArray[byte]): seq[byte] =
  ## src: source bytes to copy into a new sequence.
  var
    i: int = 0
  result = newSeq[byte](src.len)
  i = 0
  while i < src.len:
    result[i] = src[i]
    i = i + 1

proc resolvedHmacKeyHashLen(blockLen, outLen: int): int =
  ## blockLen: HMAC block length.
  ## outLen: requested HMAC output length.
  if blockLen <= 0:
    raise newException(ValueError, "hmac block length must be positive")
  if outLen <= 0:
    raise newException(ValueError, "hmac output length must be positive")
  result = blockLen
  if outLen < result:
    result = outLen

proc padHmacKey(keyMaterial: openArray[byte], blockLen: int): seq[byte] =
  ## keyMaterial: normalized key bytes to pad.
  ## blockLen: HMAC block length.
  var
    i: int = 0
    take: int = 0
  if blockLen <= 0:
    raise newException(ValueError, "hmac block length must be positive")
  result = newSeq[byte](blockLen)
  take = keyMaterial.len
  if take > blockLen:
    take = blockLen
  i = 0
  while i < take:
    result[i] = keyMaterial[i]
    i = i + 1

proc applyHmacConst*(keyMaterial: openArray[byte], c: uint8): seq[byte] =
  ## keyMaterial: normalized HMAC key bytes.
  ## c: byte constant to xor into the key material.
  var
    i: int = 0
  result = newSeq[byte](keyMaterial.len)
  i = 0
  while i < keyMaterial.len:
    result[i] = keyMaterial[i] xor c
    i = i + 1

proc normalizeHmacKeyWithHash*(key: openArray[byte], blockLen, outLen: int,
    hashFn: HashProc): seq[byte] =
  ## key: caller key bytes.
  ## blockLen: HMAC block length.
  ## outLen: requested output length.
  ## hashFn: unkeyed hash callback used for long-key reduction.
  var
    keyMaterial: seq[byte] = @[]
    i: int = 0
    hashLen: int = 0
  if blockLen <= 0:
    raise newException(ValueError, "hmac block length must be positive")
  if outLen <= 0:
    raise newException(ValueError, "hmac output length must be positive")
  if key.len > blockLen:
    hashLen = resolvedHmacKeyHashLen(blockLen, outLen)
    keyMaterial = hashFn(key, hashLen)
  else:
    keyMaterial = newSeq[byte](key.len)
    i = 0
    while i < key.len:
      keyMaterial[i] = key[i]
      i = i + 1
  result = padHmacKey(keyMaterial, blockLen)

proc prepareKeyedHmacKey*(keyMaterial: openArray[byte], keyedKeyLen: int,
    hashFn: HashProc = nil): seq[byte] =
  ## keyMaterial: modified HMAC key bytes for the inner or outer pass.
  ## keyedKeyLen: required keyed-hash key length; `<= 0` keeps keyMaterial as-is.
  ## hashFn: reducer used when the keyed hash requires a fixed-length key.
  var
    reduced: seq[byte] = @[]
  if keyedKeyLen <= 0:
    return copyBytes(keyMaterial)
  if hashFn == nil:
    raise newException(ValueError,
      "fixed-length keyed hmac requires a reducer hash function")
  reduced = hashFn(keyMaterial, keyedKeyLen)
  result = padHmacKey(reduced, keyedKeyLen)

proc customHmacFromHash*(key, msg: openArray[byte], blockLen, outLen: int,
    hashFn: HashProc, constA: uint8 = hmacConstA,
    constB: uint8 = hmacConstB): seq[byte] =
  ## key: HMAC key bytes.
  ## msg: message bytes.
  ## blockLen: HMAC block length.
  ## outLen: requested output length.
  ## hashFn: unkeyed hash callback.
  ## constA: inner xor constant.
  ## constB: outer xor constant.
  var
    normalizedKey: seq[byte] = @[]
    innerKey: seq[byte] = @[]
    outerKey: seq[byte] = @[]
    mac: seq[byte] = @[]
    innerInput: seq[byte] = @[]
    outerInput: seq[byte] = @[]
  normalizedKey = normalizeHmacKeyWithHash(key, blockLen, outLen, hashFn)
  innerKey = applyHmacConst(normalizedKey, constA)
  outerKey = applyHmacConst(normalizedKey, constB)
  innerInput = @[]
  appendBytes(innerInput, innerKey)
  appendBytes(innerInput, msg)
  mac = hashFn(innerInput, outLen)
  outerInput = @[]
  appendBytes(outerInput, outerKey)
  appendBytes(outerInput, mac)
  result = hashFn(outerInput, outLen)

proc customHmacFromKeyedHash*(key, msg: openArray[byte], blockLen, outLen: int,
    keyedHashFn: KeyedHashProc, keyHashFn: HashProc = nil,
    keyedKeyLen: int = 0, constA: uint8 = hmacConstA,
    constB: uint8 = hmacConstB): seq[byte] =
  ## key: HMAC key bytes.
  ## msg: message bytes.
  ## blockLen: HMAC block length.
  ## outLen: requested output length.
  ## keyedHashFn: keyed hash callback.
  ## keyHashFn: reducer for long keys and fixed-length keyed-hash keys.
  ## keyedKeyLen: required keyed-hash key length; `<= 0` keeps modified keys as-is.
  ## constA: inner xor constant.
  ## constB: outer xor constant.
  var
    normalizedKey: seq[byte] = @[]
    innerKeyMaterial: seq[byte] = @[]
    outerKeyMaterial: seq[byte] = @[]
    innerKey: seq[byte] = @[]
    outerKey: seq[byte] = @[]
    mac: seq[byte] = @[]
  if key.len > blockLen and keyHashFn == nil:
    raise newException(ValueError,
      "keyed hmac long-key reduction requires a reducer hash function")
  normalizedKey = normalizeHmacKeyWithHash(key, blockLen, outLen, keyHashFn)
  innerKeyMaterial = applyHmacConst(normalizedKey, constA)
  outerKeyMaterial = applyHmacConst(normalizedKey, constB)
  innerKey = prepareKeyedHmacKey(innerKeyMaterial, keyedKeyLen, keyHashFn)
  outerKey = prepareKeyedHmacKey(outerKeyMaterial, keyedKeyLen, keyHashFn)
  mac = keyedHashFn(innerKey, msg, outLen)
  result = keyedHashFn(outerKey, mac, outLen)

proc blake3HashAdapter(input: openArray[byte], outLen: int): seq[byte] =
  ## input: message bytes.
  ## outLen: requested output length.
  result = blake3Hash(input, outLen)

proc blake3KeyedHashAdapter(key, input: openArray[byte], outLen: int): seq[byte] =
  ## key: keyed BLAKE3 key bytes.
  ## input: message bytes.
  ## outLen: requested output length.
  result = blake3KeyedHash(key, input, outLen)

proc gimliKeyedHashAdapter(key, input: openArray[byte], outLen: int): seq[byte] =
  ## key: keyed Gimli bytes.
  ## input: message bytes.
  ## outLen: requested output length.
  var
    nonce: seq[byte] = @[]
  result = gimliTag(key, nonce, input, outLen)

proc sha3HashAdapter(input: openArray[byte], outLen: int): seq[byte] =
  ## input: message bytes.
  ## outLen: requested output length.
  result = customSha3.sha3Hash(input, outLen)

proc sha3Hash*(input: openArray[byte], outLen: int = 32): seq[byte] =
  ## input: message bytes.
  ## outLen: output length. Must be one of 28, 32, 48, or 64.
  result = customSha3.sha3Hash(input, outLen)

proc poly1305KeyedHashAdapter(key, input: openArray[byte], outLen: int): seq[byte] =
  ## key: Poly1305 one-time key bytes.
  ## input: message bytes.
  ## outLen: requested output length.
  if key.len != customPoly1305.poly1305KeyBytes:
    raise newException(ValueError, "poly1305 keyed hash requires a 32-byte key")
  if outLen != poly1305HmacOutLen:
    raise newException(ValueError, "poly1305 keyed hash requires a 16-byte output length")
  result = customPoly1305.poly1305Tag(key, input)

proc blake3CustomHmac*(key, msg: openArray[byte], outLen: int = outLenDefault,
    blockLen: int = blake3HmacBlockLen, constA: uint8 = hmacConstA,
    constB: uint8 = hmacConstB): seq[byte] =
  ## key: keyed BLAKE3 HMAC key bytes.
  ## msg: message bytes.
  ## outLen: requested output length.
  ## blockLen: BLAKE3 HMAC block length.
  ## constA: inner xor constant.
  ## constB: outer xor constant.
  result = customHmacFromKeyedHash(key, msg, blockLen, outLen,
    blake3KeyedHashAdapter, blake3HashAdapter, 32, constA, constB)

proc blake3CustomHmacFromHash*(key, msg: openArray[byte],
    outLen: int = outLenDefault, blockLen: int = blake3HmacBlockLen,
    constA: uint8 = hmacConstA, constB: uint8 = hmacConstB): seq[byte] =
  ## key: BLAKE3 HMAC key bytes.
  ## msg: message bytes.
  ## outLen: requested output length.
  ## blockLen: BLAKE3 HMAC block length.
  ## constA: inner xor constant.
  ## constB: outer xor constant.
  result = customHmacFromHash(key, msg, blockLen, outLen,
    blake3HashAdapter, constA, constB)

proc gimliCustomHmac*(key, msg: openArray[byte],
    outLen: int = gimliTagLenDefault, blockLen: int = gimliHmacBlockLen,
    constA: uint8 = hmacConstA, constB: uint8 = hmacConstB): seq[byte] =
  ## key: keyed Gimli HMAC key bytes.
  ## msg: message bytes.
  ## outLen: requested output length.
  ## blockLen: Gimli HMAC block length.
  ## constA: inner xor constant.
  ## constB: outer xor constant.
  result = customHmacFromKeyedHash(key, msg, blockLen, outLen,
    gimliKeyedHashAdapter, nil, 0, constA, constB)

proc poly1305CustomHmac*(key, msg: openArray[byte],
    outLen: int = poly1305HmacOutLen, blockLen: int = poly1305HmacBlockLen,
    constA: uint8 = hmacConstA, constB: uint8 = hmacConstB): seq[byte] =
  ## key: Poly1305 HMAC key bytes.
  ## msg: message bytes.
  ## outLen: requested output length. Must be `16`.
  ## blockLen: HMAC block length for key normalization.
  ## constA: inner xor constant.
  ## constB: outer xor constant.
  result = customHmacFromKeyedHash(key, msg, blockLen, outLen,
    poly1305KeyedHashAdapter, blake3HashAdapter, 32, constA, constB)

proc sha3CustomHmac*(key, msg: openArray[byte], outLen: int = 32,
    blockLen: int = blake3HmacBlockLen, constA: uint8 = hmacConstA,
    constB: uint8 = hmacConstB): seq[byte] =
  ## key: SHA3 HMAC key bytes.
  ## msg: message bytes.
  ## outLen: requested output length. Supported: `28`, `32`, `48`, `64`.
  ## blockLen: HMAC block length for key normalization.
  ## constA: inner xor constant.
  ## constB: outer xor constant.
  result = customHmacFromHash(key, msg, blockLen, outLen,
    sha3HashAdapter, constA, constB)
