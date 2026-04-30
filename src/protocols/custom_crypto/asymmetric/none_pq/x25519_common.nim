## -------------------------------------------------------------
## X25519 Common <- shared helpers for the custom Curve25519 port
## -------------------------------------------------------------

import std/[typetraits, volatile]

import ../../[blake3, random]
when defined(hasLibsodium):
  import ../../../bindings/libsodium

const
  x25519KeyBytes* = 32

type
  X25519Bytes32* = array[x25519KeyBytes, byte]
  X25519Field* = array[5, uint64]
  X25519ScalarMultProc* =
    proc(outShared: var X25519Bytes32, secretKey, publicKey: X25519Bytes32): bool {.nimcall.}
  X25519ScalarBaseProc* =
    proc(publicKey: var X25519Bytes32, secretKey: X25519Bytes32): bool {.nimcall.}
  X25519TyrKeypair* = object
    publicKey*: seq[byte]
    secretKey*: seq[byte]

const
  smallOrderBlocklist*: array[7, X25519Bytes32] = [
    [
      0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
      0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
      0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
      0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
    ],
    [
      0x01'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
      0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
      0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
      0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
    ],
    [
      0xe0'u8, 0xeb'u8, 0x7a'u8, 0x7c'u8, 0x3b'u8, 0x41'u8, 0xb8'u8, 0xae'u8,
      0x16'u8, 0x56'u8, 0xe3'u8, 0xfa'u8, 0xf1'u8, 0x9f'u8, 0xc4'u8, 0x6a'u8,
      0xda'u8, 0x09'u8, 0x8d'u8, 0xeb'u8, 0x9c'u8, 0x32'u8, 0xb1'u8, 0xfd'u8,
      0x86'u8, 0x62'u8, 0x05'u8, 0x16'u8, 0x5f'u8, 0x49'u8, 0xb8'u8, 0x00'u8
    ],
    [
      0x5f'u8, 0x9c'u8, 0x95'u8, 0xbc'u8, 0xa3'u8, 0x50'u8, 0x8c'u8, 0x24'u8,
      0xb1'u8, 0xd0'u8, 0xb1'u8, 0x55'u8, 0x9c'u8, 0x83'u8, 0xef'u8, 0x5b'u8,
      0x04'u8, 0x44'u8, 0x5c'u8, 0xc4'u8, 0x58'u8, 0x1c'u8, 0x8e'u8, 0x86'u8,
      0xd8'u8, 0x22'u8, 0x4e'u8, 0xdd'u8, 0xd0'u8, 0x9f'u8, 0x11'u8, 0x57'u8
    ],
    [
      0xec'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8,
      0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8,
      0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8,
      0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0x7f'u8
    ],
    [
      0xed'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8,
      0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8,
      0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8,
      0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0x7f'u8
    ],
    [
      0xee'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8,
      0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8,
      0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8,
      0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0xff'u8, 0x7f'u8
    ]
  ]

proc load3*(input: openArray[byte], offset: int): int64 {.inline.} =
  result = int64(input[offset])
  result = result or (int64(input[offset + 1]) shl 8)
  result = result or (int64(input[offset + 2]) shl 16)

proc load4*(input: openArray[byte], offset: int): int64 {.inline.} =
  result = int64(input[offset])
  result = result or (int64(input[offset + 1]) shl 8)
  result = result or (int64(input[offset + 2]) shl 16)
  result = result or (int64(input[offset + 3]) shl 24)

proc secureZeroMem*(p: pointer, len: int) =
  var
    bytes: ptr UncheckedArray[byte]
    i: int = 0
  if p.isNil or len <= 0:
    return
  bytes = cast[ptr UncheckedArray[byte]](p)
  while i < len:
    volatileStore(addr bytes[i], 0'u8)
    inc i

proc secureClearPod*[T](value: var T) =
  static:
    doAssert supportsCopyMem(T), "secureClearPod requires a POD-style type"
  when sizeof(T) > 0:
    secureZeroMem(addr value, sizeof(T))

proc secureClearBytes*(value: var seq[byte]) =
  if value.len > 0:
    secureZeroMem(addr value[0], value.len)

proc toFixed32*(input: openArray[byte]): X25519Bytes32 =
  var i: int = 0
  if input.len != x25519KeyBytes:
    raise newException(ValueError, "invalid X25519 key length")
  while i < x25519KeyBytes:
    result[i] = input[i]
    inc i

proc toSeqBytes*(input: X25519Bytes32): seq[byte] =
  var i: int = 0
  result = newSeq[byte](x25519KeyBytes)
  while i < x25519KeyBytes:
    result[i] = input[i]
    inc i

proc clampScalar*(dst: var X25519Bytes32, src: X25519Bytes32) {.inline.} =
  var i: int = 0
  while i < x25519KeyBytes:
    dst[i] = src[i]
    inc i
  dst[0] = dst[0] and 248'u8
  dst[31] = (dst[31] and 127'u8) or 64'u8

proc isAllZero*(input: openArray[byte]): bool =
  var folded: byte = 0
  for b in input:
    folded = folded or b
  result = folded == 0

proc hasSmallOrder*(input: X25519Bytes32): bool {.inline.} =
  var
    compare: array[7, byte]
    j: int = 0
    i: int = 0
    folded: uint32 = 0
  while j < 31:
    i = 0
    while i < smallOrderBlocklist.len:
      compare[i] = compare[i] or (input[j] xor smallOrderBlocklist[i][j])
      inc i
    inc j
  i = 0
  while i < smallOrderBlocklist.len:
    compare[i] = compare[i] or ((input[31] and 0x7f'u8) xor smallOrderBlocklist[i][31])
    folded = folded or uint32(compare[i] - 1'u8)
    inc i
  result = ((folded shr 8) and 1'u32) == 1'u32

proc fillFromSeq(dst: var X25519Bytes32, src: openArray[byte]) =
  var i: int = 0
  while i < x25519KeyBytes:
    dst[i] = src[i]
    inc i

proc randomSecret32*(): X25519Bytes32 =
  let buf = cryptoRandomBytes(x25519KeyBytes)
  fillFromSeq(result, buf)

proc deriveSeedSecretCompat*(seed: openArray[byte]): X25519Bytes32 =
  if seed.len != x25519KeyBytes:
    raise newException(ValueError, "invalid X25519 seed length")
  when defined(hasLibsodium):
    if ensureLibSodiumLoaded():
      ensureSodiumInitialised()
      if crypto_generichash_blake2b(
          addr result[0],
          csize_t(x25519KeyBytes),
          unsafeAddr seed[0],
          culonglong(seed.len),
          nil,
          0) != 0:
        raise newException(ValueError, "crypto_generichash_blake2b failed for X25519 seed derivation")
    else:
      let digest = blake3Hash(seed, x25519KeyBytes)
      fillFromSeq(result, digest)
  else:
    let digest = blake3Hash(seed, x25519KeyBytes)
    fillFromSeq(result, digest)

proc buildShared*(raw: X25519ScalarMultProc, secretKey, publicKey: openArray[byte]): seq[byte] =
  let
    sk = toFixed32(secretKey)
    pk = toFixed32(publicKey)
  var shared: X25519Bytes32
  if not raw(shared, sk, pk):
    raise newException(ValueError, "X25519 shared secret derivation failed")
  result = toSeqBytes(shared)

proc buildPublicKey*(raw: X25519ScalarBaseProc, secretKey: openArray[byte]): seq[byte] =
  let sk = toFixed32(secretKey)
  var pk: X25519Bytes32
  if not raw(pk, sk):
    raise newException(ValueError, "X25519 public key derivation failed")
  result = toSeqBytes(pk)

proc buildRandomKeypair*(raw: X25519ScalarBaseProc): X25519TyrKeypair =
  var
    sk = randomSecret32()
    pk: X25519Bytes32
  if not raw(pk, sk):
    raise newException(ValueError, "X25519 public key derivation failed")
  result.publicKey = toSeqBytes(pk)
  result.secretKey = toSeqBytes(sk)

proc buildSeededKeypair*(raw: X25519ScalarBaseProc, seed: openArray[byte]): X25519TyrKeypair =
  var
    sk = deriveSeedSecretCompat(seed)
    pk: X25519Bytes32
  if not raw(pk, sk):
    raise newException(ValueError, "X25519 public key derivation failed")
  result.publicKey = toSeqBytes(pk)
  result.secretKey = toSeqBytes(sk)
