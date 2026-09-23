## ------------------------------------------------------
## AES-256 Core <- Pure Nim AES block implementation
## Default: constant-time S-box and branchless xtime.
## Define -d:unsafeFastAes to use table lookups (unsafe).
## ------------------------------------------------------

import std/[dynlib, os, strutils]
import ../../helpers/secure_memory

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
    initialized: bool

  Aes256Ctx* = object
    roundKeys: array[aesRoundKeysLen256, uint8]
    initialized: bool

  EVP_CIPHER = object
  EVP_CIPHER_CTX = object

  Aes128OpenSslCtx* = object
    ctx: ptr EVP_CIPHER_CTX

when defined(aesni):
  type
    Aes128NiCtx* = object
      roundKeys*: array[aesNr128 + 1, M128i]
      initialized: bool

type
  EvpAes128EcbProc = proc (): ptr EVP_CIPHER {.cdecl, gcsafe.}
  EvpCipherCtxNewProc = proc (): ptr EVP_CIPHER_CTX {.cdecl, gcsafe.}
  EvpCipherCtxFreeProc = proc (ctx: ptr EVP_CIPHER_CTX) {.cdecl, gcsafe.}
  EvpEncryptInitExProc = proc (ctx: ptr EVP_CIPHER_CTX, cipher: ptr EVP_CIPHER,
    impl: pointer, key: ptr uint8, iv: ptr uint8): cint {.cdecl, gcsafe.}
  EvpEncryptUpdateProc = proc (ctx: ptr EVP_CIPHER_CTX, outBuf: ptr uint8,
    outLen: ptr cint, inBuf: ptr uint8, inLen: cint): cint {.cdecl, gcsafe.}
  EvpEncryptFinalExProc = proc (ctx: ptr EVP_CIPHER_CTX, outBuf: ptr uint8,
    outLen: ptr cint): cint {.cdecl, gcsafe.}
  EvpCipherCtxSetPaddingProc = proc (ctx: ptr EVP_CIPHER_CTX, pad: cint): cint {.cdecl, gcsafe.}

proc clear*(ctx: var Aes128Ctx) {.inline, raises: [].} =
  ## Overwrite the expanded AES-128 key schedule.
  secureClearPod(ctx)

proc clear*(ctx: var Aes256Ctx) {.inline, raises: [].} =
  ## Overwrite the expanded AES-256 key schedule.
  secureClearPod(ctx)

when defined(aesni):
  proc clear*(ctx: var Aes128NiCtx) {.inline, raises: [].} =
    ## Overwrite the AES-NI expanded key schedule.
    secureClearPod(ctx)

proc requireInitialized(ctx: Aes128Ctx) {.inline.} =
  if not ctx.initialized:
    raise newException(ValueError, "AES-128 context is not initialized")

proc requireInitialized(ctx: Aes256Ctx) {.inline.} =
  if not ctx.initialized:
    raise newException(ValueError, "AES-256 context is not initialized")

when defined(aesni):
  proc requireInitialized(ctx: Aes128NiCtx) {.inline.} =
    if not ctx.initialized:
      raise newException(ValueError, "AES-NI context is not initialized")

const
  opensslAesLibNames = when defined(windows):
                         @["libcrypto-3-x64.dll"]
                       elif defined(macosx):
                         @["libcrypto.3.dylib", "libcrypto.dylib"]
                       else:
                         @["libcrypto.so.3", "libcrypto.so"]

var
  opensslAesHandle: LibHandle = default(LibHandle)
  opensslAesChecked: bool = false
  opensslAesReady: bool = false
  osslAes128Ecb: EvpAes128EcbProc = default(EvpAes128EcbProc)
  osslCipherCtxNew: EvpCipherCtxNewProc = default(EvpCipherCtxNewProc)
  osslCipherCtxFree: EvpCipherCtxFreeProc = default(EvpCipherCtxFreeProc)
  osslEncryptInitEx: EvpEncryptInitExProc = default(EvpEncryptInitExProc)
  osslEncryptUpdate: EvpEncryptUpdateProc = default(EvpEncryptUpdateProc)
  osslEncryptFinalEx: EvpEncryptFinalExProc = default(EvpEncryptFinalExProc)
  osslCipherCtxSetPadding: EvpCipherCtxSetPaddingProc = default(EvpCipherCtxSetPaddingProc)

proc appendOpenSslAesCandidates(candidates: var seq[string], dirPath: string) =
  var trimmed: string = dirPath.strip()
  if trimmed.len == 0:
    return
  for name in opensslAesLibNames:
    candidates.add(joinPath(trimmed, name))

proc collectOpenSslAesCandidates(): seq[string] =
  var
    envDirs: string = getEnv("OPENSSL_LIB_DIRS").strip()
    pathDirs: seq[string] = getEnv("PATH").split(PathSep)
    moduleDir: string = splitFile(currentSourcePath()).dir
    repoRoot: string = absolutePath(joinPath(moduleDir, "..", "..", "..", ".."))
  when defined(windows):
    var commonWindowsDirs = [
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
  var addrSym = symAddr(opensslAesHandle, symName)
  if addrSym.isNil:
    unloadOpenSslAes()
    return false
  target = cast[T](addrSym)
  true

proc ensureOpenSslAesLoaded*(): bool =
  ## Dynamic libcrypto use is opt-in; normal builds remain Tyr/Nim native.
  when not defined(hasOpenSSL3):
    result = false
  else:
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
    result = true

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
    output: var openArray[AesBlock]) {.gcsafe.}

proc encryptBlock*(ctx: Aes128OpenSslCtx, input: AesBlock): AesBlock =
  var
    inBlock: array[1, AesBlock] = default(array[1, AesBlock])
    outBlock: array[1, AesBlock] = default(array[1, AesBlock])
  inBlock[0] = input
  encryptBlocksPublicFast(ctx, inBlock, outBlock)
  result = outBlock[0]

proc encryptBlocksPublicFast*(ctx: Aes128OpenSslCtx, input: openArray[AesBlock],
    output: var openArray[AesBlock]) {.gcsafe.} =
  var
    outLen: cint = 0
    finalLen: cint = 0
    tail: AesBlock = default(AesBlock)
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
  var
    shifted: uint8 = uint8(x shl 1)
    carry: uint8 = (x shr 7) and 0x1'u8
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

include ./aes_blocks
