## ------------------------------------------------------
## AES-256 Core <- Pure Nim AES block implementation
## Default: constant-time S-box and branchless xtime.
## Define -d:unsafeFastAes to use table lookups (unsafe).
## ------------------------------------------------------

import std/[dynlib, os, strutils]

when defined(aesni):
  import nimsimd/sse2

const
  aesBlockLen* = 16
  aesKeyLen128* = 16
  aesKeyLen256* = 32
  aesNr128 = 10
  aesNr256 = 14
  aesRoundKeysLen128 = aesBlockLen * (aesNr128 + 1)
  aesRoundKeysLen256 = aesBlockLen * (aesNr256 + 1)

type
  AesBlock* = array[aesBlockLen, uint8]

  Aes128Ctx* = object
    roundKeys: array[aesRoundKeysLen128, uint8]

  Aes256Ctx* = object
    roundKeys: array[aesRoundKeysLen256, uint8]

  EVP_CIPHER = object
  EVP_CIPHER_CTX = object

  Aes128OpenSslCtx* = object
    ctx: ptr EVP_CIPHER_CTX

when defined(aesni):
  type
    Aes128NiCtx* = object
      roundKeys*: array[aesNr128 + 1, M128i]

type
  EvpAes128EcbProc = proc (): ptr EVP_CIPHER {.cdecl.}
  EvpCipherCtxNewProc = proc (): ptr EVP_CIPHER_CTX {.cdecl.}
  EvpCipherCtxFreeProc = proc (ctx: ptr EVP_CIPHER_CTX) {.cdecl.}
  EvpEncryptInitExProc = proc (ctx: ptr EVP_CIPHER_CTX, cipher: ptr EVP_CIPHER,
    impl: pointer, key: ptr uint8, iv: ptr uint8): cint {.cdecl.}
  EvpEncryptUpdateProc = proc (ctx: ptr EVP_CIPHER_CTX, outBuf: ptr uint8,
    outLen: ptr cint, inBuf: ptr uint8, inLen: cint): cint {.cdecl.}
  EvpEncryptFinalExProc = proc (ctx: ptr EVP_CIPHER_CTX, outBuf: ptr uint8,
    outLen: ptr cint): cint {.cdecl.}
  EvpCipherCtxSetPaddingProc = proc (ctx: ptr EVP_CIPHER_CTX, pad: cint): cint {.cdecl.}

const
  opensslAesLibNames = when defined(windows):
                         @["libcrypto-3-x64.dll"]
                       elif defined(macosx):
                         @["libcrypto.3.dylib", "libcrypto.dylib"]
                       else:
                         @["libcrypto.so.3", "libcrypto.so"]

var
  opensslAesHandle: LibHandle
  opensslAesChecked: bool = false
  opensslAesReady: bool = false
  osslAes128Ecb: EvpAes128EcbProc
  osslCipherCtxNew: EvpCipherCtxNewProc
  osslCipherCtxFree: EvpCipherCtxFreeProc
  osslEncryptInitEx: EvpEncryptInitExProc
  osslEncryptUpdate: EvpEncryptUpdateProc
  osslEncryptFinalEx: EvpEncryptFinalExProc
  osslCipherCtxSetPadding: EvpCipherCtxSetPaddingProc

proc appendOpenSslAesCandidates(candidates: var seq[string], dirPath: string) =
  let trimmed = dirPath.strip()
  if trimmed.len == 0:
    return
  for name in opensslAesLibNames:
    candidates.add(joinPath(trimmed, name))

proc collectOpenSslAesCandidates(): seq[string] =
  let envDirs = getEnv("OPENSSL_LIB_DIRS").strip()
  let pathDirs = getEnv("PATH").split(PathSep)
  let moduleDir = splitFile(currentSourcePath()).dir
  let repoRoot = absolutePath(joinPath(moduleDir, "..", "..", "..", ".."))
  when defined(windows):
    let commonWindowsDirs = [
      r"C:\Program Files\Git\mingw64\bin",
      r"C:\msys64\mingw64\bin",
      r"C:\msys64\clang64\bin"
    ]
  for name in opensslAesLibNames:
    result.add(name)
  if envDirs.len > 0:
    for dirPath in envDirs.split({';', ':'}):
      appendOpenSslAesCandidates(result, dirPath)
  appendOpenSslAesCandidates(result, joinPath(repoRoot, "build", "openssl", "lib"))
  appendOpenSslAesCandidates(result, joinPath(repoRoot, "build", "openssl", "install", "lib"))
  for dirPath in pathDirs:
    appendOpenSslAesCandidates(result, dirPath)
  when defined(windows):
    for dirPath in commonWindowsDirs:
      appendOpenSslAesCandidates(result, dirPath)

proc unloadOpenSslAes() =
  if opensslAesHandle != nil:
    unloadLib(opensslAesHandle)
    opensslAesHandle = nil
  opensslAesReady = false

proc loadOpenSslAesSymbol[T](symName: string, target: var T): bool =
  let addrSym = symAddr(opensslAesHandle, symName)
  if addrSym.isNil:
    unloadOpenSslAes()
    return false
  target = cast[T](addrSym)
  true

proc ensureOpenSslAesLoaded*(): bool =
  if opensslAesChecked:
    return opensslAesReady
  opensslAesChecked = true
  for candidate in collectOpenSslAesCandidates():
    opensslAesHandle = loadLib(candidate)
    if opensslAesHandle != nil:
      break
  if opensslAesHandle == nil:
    return false
  if not loadOpenSslAesSymbol("EVP_aes_128_ecb", osslAes128Ecb):
    return false
  if not loadOpenSslAesSymbol("EVP_CIPHER_CTX_new", osslCipherCtxNew):
    return false
  if not loadOpenSslAesSymbol("EVP_CIPHER_CTX_free", osslCipherCtxFree):
    return false
  if not loadOpenSslAesSymbol("EVP_EncryptInit_ex", osslEncryptInitEx):
    return false
  if not loadOpenSslAesSymbol("EVP_EncryptUpdate", osslEncryptUpdate):
    return false
  if not loadOpenSslAesSymbol("EVP_EncryptFinal_ex", osslEncryptFinalEx):
    return false
  if not loadOpenSslAesSymbol("EVP_CIPHER_CTX_set_padding", osslCipherCtxSetPadding):
    return false
  opensslAesReady = true
  true

proc clear*(ctx: var Aes128OpenSslCtx) =
  if ctx.ctx != nil:
    osslCipherCtxFree(ctx.ctx)
    ctx.ctx = nil

proc initOpenSslPublicFast*(ctx: var Aes128OpenSslCtx, key: openArray[uint8]): bool =
  if key.len != aesKeyLen128:
    raise newException(ValueError, "AES-128 requires 16-byte key")
  clear(ctx)
  if not ensureOpenSslAesLoaded():
    return false
  ctx.ctx = osslCipherCtxNew()
  if ctx.ctx == nil:
    return false
  if osslEncryptInitEx(ctx.ctx, osslAes128Ecb(), nil, unsafeAddr key[0], nil) != 1:
    clear(ctx)
    return false
  if osslCipherCtxSetPadding(ctx.ctx, 0) != 1:
    clear(ctx)
    return false
  true

proc encryptBlocksPublicFast*(ctx: Aes128OpenSslCtx, input: openArray[AesBlock],
    output: var openArray[AesBlock])

proc encryptBlock*(ctx: Aes128OpenSslCtx, input: AesBlock): AesBlock =
  var
    inBlock: array[1, AesBlock]
    outBlock: array[1, AesBlock]
  inBlock[0] = input
  encryptBlocksPublicFast(ctx, inBlock, outBlock)
  result = outBlock[0]

proc encryptBlocksPublicFast*(ctx: Aes128OpenSslCtx, input: openArray[AesBlock],
    output: var openArray[AesBlock]) =
  var
    outLen: cint = 0
    finalLen: cint = 0
    tail: AesBlock
  if ctx.ctx == nil:
    raise newException(ValueError, "OpenSSL AES context is not initialized")
  if output.len != input.len:
    raise newException(ValueError, "AES public bulk encrypt length mismatch")
  if input.len > 0:
    if osslEncryptUpdate(ctx.ctx, addr output[0][0], addr outLen,
        cast[ptr uint8](unsafeAddr input[0][0]), cint(input.len * aesBlockLen)) != 1:
      raise newException(ValueError, "OpenSSL AES bulk encrypt failed")
    if outLen != cint(input.len * aesBlockLen):
      raise newException(ValueError, "OpenSSL AES bulk encrypt length mismatch")
  if osslEncryptFinalEx(ctx.ctx, addr tail[0], addr finalLen) != 1:
    raise newException(ValueError, "OpenSSL AES bulk finalize failed")
  if finalLen != 0:
    raise newException(ValueError, "OpenSSL AES ECB finalize emitted trailing bytes")

when defined(aesni):
  {.push header: "wmmintrin.h".}
  proc mm_aesenc_si128(a, rk: M128i): M128i {.importc: "_mm_aesenc_si128".}
  proc mm_aesenclast_si128(a, rk: M128i): M128i {.importc: "_mm_aesenclast_si128".}
  {.pop.}

const
  sbox: array[256, uint8] = [
    0x63'u8, 0x7c'u8, 0x77'u8, 0x7b'u8, 0xf2'u8, 0x6b'u8, 0x6f'u8, 0xc5'u8,
    0x30'u8, 0x01'u8, 0x67'u8, 0x2b'u8, 0xfe'u8, 0xd7'u8, 0xab'u8, 0x76'u8,
    0xca'u8, 0x82'u8, 0xc9'u8, 0x7d'u8, 0xfa'u8, 0x59'u8, 0x47'u8, 0xf0'u8,
    0xad'u8, 0xd4'u8, 0xa2'u8, 0xaf'u8, 0x9c'u8, 0xa4'u8, 0x72'u8, 0xc0'u8,
    0xb7'u8, 0xfd'u8, 0x93'u8, 0x26'u8, 0x36'u8, 0x3f'u8, 0xf7'u8, 0xcc'u8,
    0x34'u8, 0xa5'u8, 0xe5'u8, 0xf1'u8, 0x71'u8, 0xd8'u8, 0x31'u8, 0x15'u8,
    0x04'u8, 0xc7'u8, 0x23'u8, 0xc3'u8, 0x18'u8, 0x96'u8, 0x05'u8, 0x9a'u8,
    0x07'u8, 0x12'u8, 0x80'u8, 0xe2'u8, 0xeb'u8, 0x27'u8, 0xb2'u8, 0x75'u8,
    0x09'u8, 0x83'u8, 0x2c'u8, 0x1a'u8, 0x1b'u8, 0x6e'u8, 0x5a'u8, 0xa0'u8,
    0x52'u8, 0x3b'u8, 0xd6'u8, 0xb3'u8, 0x29'u8, 0xe3'u8, 0x2f'u8, 0x84'u8,
    0x53'u8, 0xd1'u8, 0x00'u8, 0xed'u8, 0x20'u8, 0xfc'u8, 0xb1'u8, 0x5b'u8,
    0x6a'u8, 0xcb'u8, 0xbe'u8, 0x39'u8, 0x4a'u8, 0x4c'u8, 0x58'u8, 0xcf'u8,
    0xd0'u8, 0xef'u8, 0xaa'u8, 0xfb'u8, 0x43'u8, 0x4d'u8, 0x33'u8, 0x85'u8,
    0x45'u8, 0xf9'u8, 0x02'u8, 0x7f'u8, 0x50'u8, 0x3c'u8, 0x9f'u8, 0xa8'u8,
    0x51'u8, 0xa3'u8, 0x40'u8, 0x8f'u8, 0x92'u8, 0x9d'u8, 0x38'u8, 0xf5'u8,
    0xbc'u8, 0xb6'u8, 0xda'u8, 0x21'u8, 0x10'u8, 0xff'u8, 0xf3'u8, 0xd2'u8,
    0xcd'u8, 0x0c'u8, 0x13'u8, 0xec'u8, 0x5f'u8, 0x97'u8, 0x44'u8, 0x17'u8,
    0xc4'u8, 0xa7'u8, 0x7e'u8, 0x3d'u8, 0x64'u8, 0x5d'u8, 0x19'u8, 0x73'u8,
    0x60'u8, 0x81'u8, 0x4f'u8, 0xdc'u8, 0x22'u8, 0x2a'u8, 0x90'u8, 0x88'u8,
    0x46'u8, 0xee'u8, 0xb8'u8, 0x14'u8, 0xde'u8, 0x5e'u8, 0x0b'u8, 0xdb'u8,
    0xe0'u8, 0x32'u8, 0x3a'u8, 0x0a'u8, 0x49'u8, 0x06'u8, 0x24'u8, 0x5c'u8,
    0xc2'u8, 0xd3'u8, 0xac'u8, 0x62'u8, 0x91'u8, 0x95'u8, 0xe4'u8, 0x79'u8,
    0xe7'u8, 0xc8'u8, 0x37'u8, 0x6d'u8, 0x8d'u8, 0xd5'u8, 0x4e'u8, 0xa9'u8,
    0x6c'u8, 0x56'u8, 0xf4'u8, 0xea'u8, 0x65'u8, 0x7a'u8, 0xae'u8, 0x08'u8,
    0xba'u8, 0x78'u8, 0x25'u8, 0x2e'u8, 0x1c'u8, 0xa6'u8, 0xb4'u8, 0xc6'u8,
    0xe8'u8, 0xdd'u8, 0x74'u8, 0x1f'u8, 0x4b'u8, 0xbd'u8, 0x8b'u8, 0x8a'u8,
    0x70'u8, 0x3e'u8, 0xb5'u8, 0x66'u8, 0x48'u8, 0x03'u8, 0xf6'u8, 0x0e'u8,
    0x61'u8, 0x35'u8, 0x57'u8, 0xb9'u8, 0x86'u8, 0xc1'u8, 0x1d'u8, 0x9e'u8,
    0xe1'u8, 0xf8'u8, 0x98'u8, 0x11'u8, 0x69'u8, 0xd9'u8, 0x8e'u8, 0x94'u8,
    0x9b'u8, 0x1e'u8, 0x87'u8, 0xe9'u8, 0xce'u8, 0x55'u8, 0x28'u8, 0xdf'u8,
    0x8c'u8, 0xa1'u8, 0x89'u8, 0x0d'u8, 0xbf'u8, 0xe6'u8, 0x42'u8, 0x68'u8,
    0x41'u8, 0x99'u8, 0x2d'u8, 0x0f'u8, 0xb0'u8, 0x54'u8, 0xbb'u8, 0x16'u8
  ]

  rcon: array[11, uint8] = [
    0x00'u8, 0x01'u8, 0x02'u8, 0x04'u8, 0x08'u8, 0x10'u8,
    0x20'u8, 0x40'u8, 0x80'u8, 0x1b'u8, 0x36'u8
  ]

func xtimeConst(x: uint8): uint8 =
  let shifted = uint8(x shl 1)
  let carry = (x shr 7) and 0x1'u8
  shifted xor (0x1b'u8 * carry)

func mul2Const(x: uint8): uint8 =
  xtimeConst(x)

func mul3Const(x: uint8): uint8 =
  xtimeConst(x) xor x

func buildTe0(): array[256, uint32] =
  var
    i: int = 0
    s: uint8 = 0
  i = 0
  while i < 256:
    s = sbox[i]
    result[i] =
      (uint32(mul2Const(s)) shl 24) or
      (uint32(s) shl 16) or
      (uint32(s) shl 8) or
      uint32(mul3Const(s))
    i = i + 1

func buildTe1(): array[256, uint32] =
  var
    i: int = 0
    s: uint8 = 0
  i = 0
  while i < 256:
    s = sbox[i]
    result[i] =
      (uint32(mul3Const(s)) shl 24) or
      (uint32(mul2Const(s)) shl 16) or
      (uint32(s) shl 8) or
      uint32(s)
    i = i + 1

func buildTe2(): array[256, uint32] =
  var
    i: int = 0
    s: uint8 = 0
  i = 0
  while i < 256:
    s = sbox[i]
    result[i] =
      (uint32(s) shl 24) or
      (uint32(mul3Const(s)) shl 16) or
      (uint32(mul2Const(s)) shl 8) or
      uint32(s)
    i = i + 1

func buildTe3(): array[256, uint32] =
  var
    i: int = 0
    s: uint8 = 0
  i = 0
  while i < 256:
    s = sbox[i]
    result[i] =
      (uint32(s) shl 24) or
      (uint32(s) shl 16) or
      (uint32(mul3Const(s)) shl 8) or
      uint32(mul2Const(s))
    i = i + 1

const
  te0: array[256, uint32] = buildTe0()
  te1: array[256, uint32] = buildTe1()
  te2: array[256, uint32] = buildTe2()
  te3: array[256, uint32] = buildTe3()

{.push overflowChecks: off.}
proc ctEq(a, b: uint8): uint8 {.inline.} =
  ## Returns 0xFF when equal, 0x00 otherwise (constant-time).
  let x = a xor b
  result = uint8((uint16(x) - 1'u16) shr 8)

proc sboxCt(x: uint8): uint8 {.inline.} =
  ## Constant-time S-box lookup by scanning all entries.
  var acc: uint8 = 0
  var i = 0
  while i < 256:
    let mask = ctEq(x, uint8(i))
    acc = acc or (sbox[i] and mask)
    i = i + 1
  result = acc
{.pop.}

proc subByte(x: uint8): uint8 {.inline.} =
  when defined(unsafeFastAes):
    result = sbox[x]
  else:
    result = sboxCt(x)

proc subByteFast(x: uint8): uint8 {.inline.} =
  ## Fast table lookup for public-data-only AES paths.
  result = sbox[x]

proc xtime(x: uint8): uint8 {.inline.} =
  let shifted = uint8(x shl 1)
  let carry = (x shr 7) and 0x1'u8
  result = shifted xor (0x1b'u8 * carry)

proc mul2(x: uint8): uint8 {.inline.} =
  xtime(x)

proc mul3(x: uint8): uint8 {.inline.} =
  xtime(x) xor x

proc subBytes(state: var AesBlock) =
  var i: int = 0
  i = 0
  while i < state.len:
    state[i] = subByte(state[i])
    i = i + 1

proc subBytesFast(state: var AesBlock) =
  var i: int = 0
  i = 0
  while i < state.len:
    state[i] = subByteFast(state[i])
    i = i + 1

proc shiftRows(state: var AesBlock) =
  var t: uint8
  # Row 1: shift left by 1
  t = state[1]
  state[1] = state[5]
  state[5] = state[9]
  state[9] = state[13]
  state[13] = t
  # Row 2: shift left by 2
  t = state[2]
  state[2] = state[10]
  state[10] = t
  t = state[6]
  state[6] = state[14]
  state[14] = t
  # Row 3: shift left by 3
  t = state[3]
  state[3] = state[15]
  state[15] = state[11]
  state[11] = state[7]
  state[7] = t

proc mixColumns(state: var AesBlock) =
  var c: int = 0
  var a0, a1, a2, a3: uint8
  c = 0
  while c < 4:
    let o = c * 4
    a0 = state[o]
    a1 = state[o + 1]
    a2 = state[o + 2]
    a3 = state[o + 3]
    state[o] = mul2(a0) xor mul3(a1) xor a2 xor a3
    state[o + 1] = a0 xor mul2(a1) xor mul3(a2) xor a3
    state[o + 2] = a0 xor a1 xor mul2(a2) xor mul3(a3)
    state[o + 3] = mul3(a0) xor a1 xor a2 xor mul2(a3)
    c = c + 1

proc addRoundKey(state: var AesBlock, roundKeys: array[aesRoundKeysLen256, uint8],
    round: int) =
  let base = round * aesBlockLen
  var i: int = 0
  i = 0
  while i < aesBlockLen:
    state[i] = state[i] xor roundKeys[base + i]
    i = i + 1

proc addRoundKey(state: var AesBlock, roundKeys: array[aesRoundKeysLen128, uint8],
    round: int) =
  let base = round * aesBlockLen
  var i: int = 0
  i = 0
  while i < aesBlockLen:
    state[i] = state[i] xor roundKeys[base + i]
    i = i + 1

proc load32Be(A: openArray[uint8], o: int): uint32 {.inline.} =
  result =
    (uint32(A[o]) shl 24) or
    (uint32(A[o + 1]) shl 16) or
    (uint32(A[o + 2]) shl 8) or
    uint32(A[o + 3])

proc store32Be(A: var openArray[uint8], o: int, v: uint32) {.inline.} =
  A[o] = uint8((v shr 24) and 0xff'u32)
  A[o + 1] = uint8((v shr 16) and 0xff'u32)
  A[o + 2] = uint8((v shr 8) and 0xff'u32)
  A[o + 3] = uint8(v and 0xff'u32)

proc expandKey128(key: openArray[uint8]): array[aesRoundKeysLen128, uint8] =
  if key.len != aesKeyLen128:
    raise newException(ValueError, "AES-128 requires 16-byte key")
  var
    bytesGenerated: int = 0
    rconIter: int = 1
    temp: array[4, uint8]
    j: int = 0
  while bytesGenerated < aesKeyLen128:
    result[bytesGenerated] = key[bytesGenerated]
    bytesGenerated = bytesGenerated + 1
  while bytesGenerated < aesRoundKeysLen128:
    temp[0] = result[bytesGenerated - 4]
    temp[1] = result[bytesGenerated - 3]
    temp[2] = result[bytesGenerated - 2]
    temp[3] = result[bytesGenerated - 1]
    if (bytesGenerated mod aesKeyLen128) == 0:
      let t0 = temp[0]
      temp[0] = temp[1]
      temp[1] = temp[2]
      temp[2] = temp[3]
      temp[3] = t0
      temp[0] = subByte(temp[0])
      temp[1] = subByte(temp[1])
      temp[2] = subByte(temp[2])
      temp[3] = subByte(temp[3])
      temp[0] = temp[0] xor rcon[rconIter]
      rconIter = rconIter + 1
    j = 0
    while j < 4:
      result[bytesGenerated] = result[bytesGenerated - aesKeyLen128] xor temp[j]
      bytesGenerated = bytesGenerated + 1
      j = j + 1

proc expandKey128Fast(key: openArray[uint8]): array[aesRoundKeysLen128, uint8] =
  if key.len != aesKeyLen128:
    raise newException(ValueError, "AES-128 requires 16-byte key")
  var
    bytesGenerated: int = 0
    rconIter: int = 1
    temp: array[4, uint8]
    j: int = 0
  while bytesGenerated < aesKeyLen128:
    result[bytesGenerated] = key[bytesGenerated]
    bytesGenerated = bytesGenerated + 1
  while bytesGenerated < aesRoundKeysLen128:
    temp[0] = result[bytesGenerated - 4]
    temp[1] = result[bytesGenerated - 3]
    temp[2] = result[bytesGenerated - 2]
    temp[3] = result[bytesGenerated - 1]
    if (bytesGenerated mod aesKeyLen128) == 0:
      let t0 = temp[0]
      temp[0] = temp[1]
      temp[1] = temp[2]
      temp[2] = temp[3]
      temp[3] = t0
      temp[0] = subByteFast(temp[0])
      temp[1] = subByteFast(temp[1])
      temp[2] = subByteFast(temp[2])
      temp[3] = subByteFast(temp[3])
      temp[0] = temp[0] xor rcon[rconIter]
      rconIter = rconIter + 1
    j = 0
    while j < 4:
      result[bytesGenerated] = result[bytesGenerated - aesKeyLen128] xor temp[j]
      bytesGenerated = bytesGenerated + 1
      j = j + 1

proc init*(ctx: var Aes128Ctx, key: openArray[uint8]) =
  ctx.roundKeys = expandKey128(key)

proc initPublicFast*(ctx: var Aes128Ctx, key: openArray[uint8]) =
  ## Fast AES-128 key schedule for public-data-only use.
  ctx.roundKeys = expandKey128Fast(key)

when defined(aesni):
  proc init*(ctx: var Aes128NiCtx, key: openArray[uint8]) =
    var
      scalarCtx: Aes128Ctx
      i: int = 0
      o: int = 0
    scalarCtx.init(key)
    i = 0
    while i <= aesNr128:
      o = i * aesBlockLen
      ctx.roundKeys[i] = mm_loadu_si128(cast[pointer](unsafeAddr scalarCtx.roundKeys[o]))
      i = i + 1

  proc initPublicFast*(ctx: var Aes128NiCtx, key: openArray[uint8]) =
    ctx.init(key)

proc expandKey256(key: openArray[uint8]): array[aesRoundKeysLen256, uint8] =
  if key.len != aesKeyLen256:
    raise newException(ValueError, "AES-256 requires 32-byte key")
  var bytesGenerated = 0
  var rconIter = 1
  var temp: array[4, uint8]
  while bytesGenerated < aesKeyLen256:
    result[bytesGenerated] = key[bytesGenerated]
    bytesGenerated = bytesGenerated + 1
  while bytesGenerated < aesRoundKeysLen256:
    temp[0] = result[bytesGenerated - 4]
    temp[1] = result[bytesGenerated - 3]
    temp[2] = result[bytesGenerated - 2]
    temp[3] = result[bytesGenerated - 1]
    if (bytesGenerated mod aesKeyLen256) == 0:
      let t0 = temp[0]
      temp[0] = temp[1]
      temp[1] = temp[2]
      temp[2] = temp[3]
      temp[3] = t0
      temp[0] = subByte(temp[0])
      temp[1] = subByte(temp[1])
      temp[2] = subByte(temp[2])
      temp[3] = subByte(temp[3])
      temp[0] = temp[0] xor rcon[rconIter]
      rconIter = rconIter + 1
    elif (bytesGenerated mod aesKeyLen256) == 16:
      temp[0] = subByte(temp[0])
      temp[1] = subByte(temp[1])
      temp[2] = subByte(temp[2])
      temp[3] = subByte(temp[3])
    var j: int = 0
    j = 0
    while j < 4:
      result[bytesGenerated] = result[bytesGenerated - aesKeyLen256] xor temp[j]
      bytesGenerated = bytesGenerated + 1
      j = j + 1

proc init*(ctx: var Aes256Ctx, key: openArray[uint8]) =
  ctx.roundKeys = expandKey256(key)

proc encryptBlock*(ctx: Aes128Ctx, input: AesBlock): AesBlock =
  var
    state = input
    round: int = 1
  addRoundKey(state, ctx.roundKeys, 0)
  round = 1
  while round < aesNr128:
    subBytes(state)
    shiftRows(state)
    mixColumns(state)
    addRoundKey(state, ctx.roundKeys, round)
    round = round + 1
  subBytes(state)
  shiftRows(state)
  addRoundKey(state, ctx.roundKeys, aesNr128)
  result = state

proc encryptBlockPublicFast*(ctx: Aes128Ctx, input: AesBlock): AesBlock =
  ## Fast AES-128 encryption for public-data-only use.
  var
    s0: uint32 = load32Be(input, 0) xor load32Be(ctx.roundKeys, 0)
    s1: uint32 = load32Be(input, 4) xor load32Be(ctx.roundKeys, 4)
    s2: uint32 = load32Be(input, 8) xor load32Be(ctx.roundKeys, 8)
    s3: uint32 = load32Be(input, 12) xor load32Be(ctx.roundKeys, 12)
    t0: uint32 = 0
    t1: uint32 = 0
    t2: uint32 = 0
    t3: uint32 = 0
    round: int = 1
    rkOff: int = 16
  round = 1
  while round < aesNr128:
    t0 = te0[(s0 shr 24) and 0xff'u32] xor
      te1[(s1 shr 16) and 0xff'u32] xor
      te2[(s2 shr 8) and 0xff'u32] xor
      te3[s3 and 0xff'u32] xor
      load32Be(ctx.roundKeys, rkOff + 0)
    t1 = te0[(s1 shr 24) and 0xff'u32] xor
      te1[(s2 shr 16) and 0xff'u32] xor
      te2[(s3 shr 8) and 0xff'u32] xor
      te3[s0 and 0xff'u32] xor
      load32Be(ctx.roundKeys, rkOff + 4)
    t2 = te0[(s2 shr 24) and 0xff'u32] xor
      te1[(s3 shr 16) and 0xff'u32] xor
      te2[(s0 shr 8) and 0xff'u32] xor
      te3[s1 and 0xff'u32] xor
      load32Be(ctx.roundKeys, rkOff + 8)
    t3 = te0[(s3 shr 24) and 0xff'u32] xor
      te1[(s0 shr 16) and 0xff'u32] xor
      te2[(s1 shr 8) and 0xff'u32] xor
      te3[s2 and 0xff'u32] xor
      load32Be(ctx.roundKeys, rkOff + 12)
    s0 = t0
    s1 = t1
    s2 = t2
    s3 = t3
    rkOff = rkOff + 16
    round = round + 1
  t0 =
    (uint32(sbox[(s0 shr 24) and 0xff'u32]) shl 24) or
    (uint32(sbox[(s1 shr 16) and 0xff'u32]) shl 16) or
    (uint32(sbox[(s2 shr 8) and 0xff'u32]) shl 8) or
    uint32(sbox[s3 and 0xff'u32])
  t1 =
    (uint32(sbox[(s1 shr 24) and 0xff'u32]) shl 24) or
    (uint32(sbox[(s2 shr 16) and 0xff'u32]) shl 16) or
    (uint32(sbox[(s3 shr 8) and 0xff'u32]) shl 8) or
    uint32(sbox[s0 and 0xff'u32])
  t2 =
    (uint32(sbox[(s2 shr 24) and 0xff'u32]) shl 24) or
    (uint32(sbox[(s3 shr 16) and 0xff'u32]) shl 16) or
    (uint32(sbox[(s0 shr 8) and 0xff'u32]) shl 8) or
    uint32(sbox[s1 and 0xff'u32])
  t3 =
    (uint32(sbox[(s3 shr 24) and 0xff'u32]) shl 24) or
    (uint32(sbox[(s0 shr 16) and 0xff'u32]) shl 16) or
    (uint32(sbox[(s1 shr 8) and 0xff'u32]) shl 8) or
    uint32(sbox[s2 and 0xff'u32])
  t0 = t0 xor load32Be(ctx.roundKeys, rkOff + 0)
  t1 = t1 xor load32Be(ctx.roundKeys, rkOff + 4)
  t2 = t2 xor load32Be(ctx.roundKeys, rkOff + 8)
  t3 = t3 xor load32Be(ctx.roundKeys, rkOff + 12)
  store32Be(result, 0, t0)
  store32Be(result, 4, t1)
  store32Be(result, 8, t2)
  store32Be(result, 12, t3)

proc encryptBlocksPublicFast*(ctx: Aes128Ctx, input: openArray[AesBlock],
    output: var openArray[AesBlock]) =
  ## Fast AES-128 bulk encryption for public-data-only use.
  var
    i: int = 0
  if output.len != input.len:
    raise newException(ValueError, "AES public bulk encrypt length mismatch")
  i = 0
  while i < input.len:
    output[i] = encryptBlockPublicFast(ctx, input[i])
    i = i + 1

when defined(aesni):
  proc encryptBlock*(ctx: Aes128NiCtx, input: AesBlock): AesBlock =
    var
      state: M128i
      round: int = 1
    state = mm_loadu_si128(cast[pointer](unsafeAddr input[0]))
    state = mm_xor_si128(state, ctx.roundKeys[0])
    round = 1
    while round < aesNr128:
      state = mm_aesenc_si128(state, ctx.roundKeys[round])
      round = round + 1
    state = mm_aesenclast_si128(state, ctx.roundKeys[aesNr128])
    mm_storeu_si128(cast[pointer](unsafeAddr result[0]), state)

  proc encryptBlock4*(ctx: Aes128NiCtx, input: array[4, AesBlock]): array[4, AesBlock] =
    var
      s0, s1, s2, s3: M128i
      round: int = 1
    s0 = mm_loadu_si128(cast[pointer](unsafeAddr input[0][0]))
    s1 = mm_loadu_si128(cast[pointer](unsafeAddr input[1][0]))
    s2 = mm_loadu_si128(cast[pointer](unsafeAddr input[2][0]))
    s3 = mm_loadu_si128(cast[pointer](unsafeAddr input[3][0]))
    s0 = mm_xor_si128(s0, ctx.roundKeys[0])
    s1 = mm_xor_si128(s1, ctx.roundKeys[0])
    s2 = mm_xor_si128(s2, ctx.roundKeys[0])
    s3 = mm_xor_si128(s3, ctx.roundKeys[0])
    round = 1
    while round < aesNr128:
      s0 = mm_aesenc_si128(s0, ctx.roundKeys[round])
      s1 = mm_aesenc_si128(s1, ctx.roundKeys[round])
      s2 = mm_aesenc_si128(s2, ctx.roundKeys[round])
      s3 = mm_aesenc_si128(s3, ctx.roundKeys[round])
      round = round + 1
    s0 = mm_aesenclast_si128(s0, ctx.roundKeys[aesNr128])
    s1 = mm_aesenclast_si128(s1, ctx.roundKeys[aesNr128])
    s2 = mm_aesenclast_si128(s2, ctx.roundKeys[aesNr128])
    s3 = mm_aesenclast_si128(s3, ctx.roundKeys[aesNr128])
    mm_storeu_si128(cast[pointer](unsafeAddr result[0][0]), s0)
    mm_storeu_si128(cast[pointer](unsafeAddr result[1][0]), s1)
    mm_storeu_si128(cast[pointer](unsafeAddr result[2][0]), s2)
    mm_storeu_si128(cast[pointer](unsafeAddr result[3][0]), s3)

  proc encryptBlock8*(ctx: Aes128NiCtx, input: array[8, AesBlock]): array[8, AesBlock] =
    var
      s0, s1, s2, s3: M128i
      s4, s5, s6, s7: M128i
      round: int = 1
    s0 = mm_loadu_si128(cast[pointer](unsafeAddr input[0][0]))
    s1 = mm_loadu_si128(cast[pointer](unsafeAddr input[1][0]))
    s2 = mm_loadu_si128(cast[pointer](unsafeAddr input[2][0]))
    s3 = mm_loadu_si128(cast[pointer](unsafeAddr input[3][0]))
    s4 = mm_loadu_si128(cast[pointer](unsafeAddr input[4][0]))
    s5 = mm_loadu_si128(cast[pointer](unsafeAddr input[5][0]))
    s6 = mm_loadu_si128(cast[pointer](unsafeAddr input[6][0]))
    s7 = mm_loadu_si128(cast[pointer](unsafeAddr input[7][0]))
    s0 = mm_xor_si128(s0, ctx.roundKeys[0])
    s1 = mm_xor_si128(s1, ctx.roundKeys[0])
    s2 = mm_xor_si128(s2, ctx.roundKeys[0])
    s3 = mm_xor_si128(s3, ctx.roundKeys[0])
    s4 = mm_xor_si128(s4, ctx.roundKeys[0])
    s5 = mm_xor_si128(s5, ctx.roundKeys[0])
    s6 = mm_xor_si128(s6, ctx.roundKeys[0])
    s7 = mm_xor_si128(s7, ctx.roundKeys[0])
    round = 1
    while round < aesNr128:
      s0 = mm_aesenc_si128(s0, ctx.roundKeys[round])
      s1 = mm_aesenc_si128(s1, ctx.roundKeys[round])
      s2 = mm_aesenc_si128(s2, ctx.roundKeys[round])
      s3 = mm_aesenc_si128(s3, ctx.roundKeys[round])
      s4 = mm_aesenc_si128(s4, ctx.roundKeys[round])
      s5 = mm_aesenc_si128(s5, ctx.roundKeys[round])
      s6 = mm_aesenc_si128(s6, ctx.roundKeys[round])
      s7 = mm_aesenc_si128(s7, ctx.roundKeys[round])
      round = round + 1
    s0 = mm_aesenclast_si128(s0, ctx.roundKeys[aesNr128])
    s1 = mm_aesenclast_si128(s1, ctx.roundKeys[aesNr128])
    s2 = mm_aesenclast_si128(s2, ctx.roundKeys[aesNr128])
    s3 = mm_aesenclast_si128(s3, ctx.roundKeys[aesNr128])
    s4 = mm_aesenclast_si128(s4, ctx.roundKeys[aesNr128])
    s5 = mm_aesenclast_si128(s5, ctx.roundKeys[aesNr128])
    s6 = mm_aesenclast_si128(s6, ctx.roundKeys[aesNr128])
    s7 = mm_aesenclast_si128(s7, ctx.roundKeys[aesNr128])
    mm_storeu_si128(cast[pointer](unsafeAddr result[0][0]), s0)
    mm_storeu_si128(cast[pointer](unsafeAddr result[1][0]), s1)
    mm_storeu_si128(cast[pointer](unsafeAddr result[2][0]), s2)
    mm_storeu_si128(cast[pointer](unsafeAddr result[3][0]), s3)
    mm_storeu_si128(cast[pointer](unsafeAddr result[4][0]), s4)
    mm_storeu_si128(cast[pointer](unsafeAddr result[5][0]), s5)
    mm_storeu_si128(cast[pointer](unsafeAddr result[6][0]), s6)
    mm_storeu_si128(cast[pointer](unsafeAddr result[7][0]), s7)

  proc encryptBlocks*(ctx: Aes128NiCtx, input: openArray[AesBlock],
      output: var openArray[AesBlock]) =
    var
      i: int = 0
      s0, s1, s2, s3: M128i
      s4, s5, s6, s7: M128i
      round: int = 1
    if output.len != input.len:
      raise newException(ValueError, "AES block bulk encrypt length mismatch")
    i = 0
    while i + 8 <= input.len:
      s0 = mm_loadu_si128(cast[pointer](unsafeAddr input[i + 0][0]))
      s1 = mm_loadu_si128(cast[pointer](unsafeAddr input[i + 1][0]))
      s2 = mm_loadu_si128(cast[pointer](unsafeAddr input[i + 2][0]))
      s3 = mm_loadu_si128(cast[pointer](unsafeAddr input[i + 3][0]))
      s4 = mm_loadu_si128(cast[pointer](unsafeAddr input[i + 4][0]))
      s5 = mm_loadu_si128(cast[pointer](unsafeAddr input[i + 5][0]))
      s6 = mm_loadu_si128(cast[pointer](unsafeAddr input[i + 6][0]))
      s7 = mm_loadu_si128(cast[pointer](unsafeAddr input[i + 7][0]))
      s0 = mm_xor_si128(s0, ctx.roundKeys[0])
      s1 = mm_xor_si128(s1, ctx.roundKeys[0])
      s2 = mm_xor_si128(s2, ctx.roundKeys[0])
      s3 = mm_xor_si128(s3, ctx.roundKeys[0])
      s4 = mm_xor_si128(s4, ctx.roundKeys[0])
      s5 = mm_xor_si128(s5, ctx.roundKeys[0])
      s6 = mm_xor_si128(s6, ctx.roundKeys[0])
      s7 = mm_xor_si128(s7, ctx.roundKeys[0])
      round = 1
      while round < aesNr128:
        s0 = mm_aesenc_si128(s0, ctx.roundKeys[round])
        s1 = mm_aesenc_si128(s1, ctx.roundKeys[round])
        s2 = mm_aesenc_si128(s2, ctx.roundKeys[round])
        s3 = mm_aesenc_si128(s3, ctx.roundKeys[round])
        s4 = mm_aesenc_si128(s4, ctx.roundKeys[round])
        s5 = mm_aesenc_si128(s5, ctx.roundKeys[round])
        s6 = mm_aesenc_si128(s6, ctx.roundKeys[round])
        s7 = mm_aesenc_si128(s7, ctx.roundKeys[round])
        round = round + 1
      s0 = mm_aesenclast_si128(s0, ctx.roundKeys[aesNr128])
      s1 = mm_aesenclast_si128(s1, ctx.roundKeys[aesNr128])
      s2 = mm_aesenclast_si128(s2, ctx.roundKeys[aesNr128])
      s3 = mm_aesenclast_si128(s3, ctx.roundKeys[aesNr128])
      s4 = mm_aesenclast_si128(s4, ctx.roundKeys[aesNr128])
      s5 = mm_aesenclast_si128(s5, ctx.roundKeys[aesNr128])
      s6 = mm_aesenclast_si128(s6, ctx.roundKeys[aesNr128])
      s7 = mm_aesenclast_si128(s7, ctx.roundKeys[aesNr128])
      mm_storeu_si128(cast[pointer](unsafeAddr output[i + 0][0]), s0)
      mm_storeu_si128(cast[pointer](unsafeAddr output[i + 1][0]), s1)
      mm_storeu_si128(cast[pointer](unsafeAddr output[i + 2][0]), s2)
      mm_storeu_si128(cast[pointer](unsafeAddr output[i + 3][0]), s3)
      mm_storeu_si128(cast[pointer](unsafeAddr output[i + 4][0]), s4)
      mm_storeu_si128(cast[pointer](unsafeAddr output[i + 5][0]), s5)
      mm_storeu_si128(cast[pointer](unsafeAddr output[i + 6][0]), s6)
      mm_storeu_si128(cast[pointer](unsafeAddr output[i + 7][0]), s7)
      i = i + 8
    while i + 4 <= input.len:
      s0 = mm_loadu_si128(cast[pointer](unsafeAddr input[i + 0][0]))
      s1 = mm_loadu_si128(cast[pointer](unsafeAddr input[i + 1][0]))
      s2 = mm_loadu_si128(cast[pointer](unsafeAddr input[i + 2][0]))
      s3 = mm_loadu_si128(cast[pointer](unsafeAddr input[i + 3][0]))
      s0 = mm_xor_si128(s0, ctx.roundKeys[0])
      s1 = mm_xor_si128(s1, ctx.roundKeys[0])
      s2 = mm_xor_si128(s2, ctx.roundKeys[0])
      s3 = mm_xor_si128(s3, ctx.roundKeys[0])
      round = 1
      while round < aesNr128:
        s0 = mm_aesenc_si128(s0, ctx.roundKeys[round])
        s1 = mm_aesenc_si128(s1, ctx.roundKeys[round])
        s2 = mm_aesenc_si128(s2, ctx.roundKeys[round])
        s3 = mm_aesenc_si128(s3, ctx.roundKeys[round])
        round = round + 1
      s0 = mm_aesenclast_si128(s0, ctx.roundKeys[aesNr128])
      s1 = mm_aesenclast_si128(s1, ctx.roundKeys[aesNr128])
      s2 = mm_aesenclast_si128(s2, ctx.roundKeys[aesNr128])
      s3 = mm_aesenclast_si128(s3, ctx.roundKeys[aesNr128])
      mm_storeu_si128(cast[pointer](unsafeAddr output[i + 0][0]), s0)
      mm_storeu_si128(cast[pointer](unsafeAddr output[i + 1][0]), s1)
      mm_storeu_si128(cast[pointer](unsafeAddr output[i + 2][0]), s2)
      mm_storeu_si128(cast[pointer](unsafeAddr output[i + 3][0]), s3)
      i = i + 4
    while i < input.len:
      output[i] = encryptBlock(ctx, input[i])
      i = i + 1

proc encryptBlock*(ctx: Aes256Ctx, input: AesBlock): AesBlock =
  var state = input
  addRoundKey(state, ctx.roundKeys, 0)
  var round: int = 1
  round = 1
  while round < aesNr256:
    subBytes(state)
    shiftRows(state)
    mixColumns(state)
    addRoundKey(state, ctx.roundKeys, round)
    round = round + 1
  subBytes(state)
  shiftRows(state)
  addRoundKey(state, ctx.roundKeys, aesNr256)
  result = state
