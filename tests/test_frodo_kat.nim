import std/[json, os, osproc, strutils, unittest]

import ../src/protocols/custom_crypto/aes_core
import ../src/protocols/custom_crypto/frodo as custom_frodo

when defined(hasLibOqs):
  import ../src/protocols/bindings/liboqs

const
  frodoKatEntropyLen = 48
  frodoKatSeedLen = 48

type
  FrodoNistDrbgState = object
    key: array[32, byte]
    v: array[16, byte]
    reseedCounter: int

when defined(hasLibOqs):
  var
    oqsFrodoKatDrbgState: FrodoNistDrbgState
    oqsFrodoKatDrbgReady: bool = false

proc incrementFrodoV(S: var FrodoNistDrbgState) =
  var
    i: int = 15
  while i >= 0:
    if S.v[i] == 0xff'u8:
      S.v[i] = 0'u8
      i = i - 1
    else:
      S.v[i] = S.v[i] + 1'u8
      break

proc frodoAes256EcbBlock(k: openArray[byte], input: array[16, byte]): array[16, byte] =
  var
    ctx: Aes256Ctx
  ctx.init(k)
  result = encryptBlock(ctx, input)

proc frodoDrbgUpdate(S: var FrodoNistDrbgState,
    provided: ptr array[frodoKatEntropyLen, byte] = nil) =
  var
    temp: array[frodoKatEntropyLen, byte]
    blk: array[16, byte]
    i: int = 0
  i = 0
  while i < 3:
    incrementFrodoV(S)
    blk = frodoAes256EcbBlock(S.key, S.v)
    copyMem(addr temp[i * 16], addr blk[0], 16)
    i = i + 1
  if provided != nil:
    i = 0
    while i < frodoKatEntropyLen:
      temp[i] = temp[i] xor provided[][i]
      i = i + 1
  i = 0
  while i < 32:
    S.key[i] = temp[i]
    i = i + 1
  i = 0
  while i < 16:
    S.v[i] = temp[32 + i]
    i = i + 1

proc initFrodoNistDrbg(entropy: openArray[byte],
    personalization: openArray[byte] = @[]): FrodoNistDrbgState =
  var
    seedMaterial: array[frodoKatEntropyLen, byte]
    i: int = 0
  if entropy.len != frodoKatEntropyLen:
    raise newException(ValueError, "NIST DRBG entropy must be 48 bytes")
  if personalization.len != 0 and personalization.len != frodoKatEntropyLen:
    raise newException(ValueError, "NIST DRBG personalization must be 48 bytes")
  i = 0
  while i < frodoKatEntropyLen:
    seedMaterial[i] = entropy[i]
    if personalization.len == frodoKatEntropyLen:
      seedMaterial[i] = seedMaterial[i] xor personalization[i]
    i = i + 1
  frodoDrbgUpdate(result, addr seedMaterial)
  result.reseedCounter = 1

proc frodoDrbgRandomBytes(S: var FrodoNistDrbgState, n: int): seq[byte] =
  var
    blk: array[16, byte]
    offset: int = 0
    take: int = 0
    i: int = 0
  result = newSeq[byte](n)
  while offset < n:
    incrementFrodoV(S)
    blk = frodoAes256EcbBlock(S.key, S.v)
    take = min(16, n - offset)
    i = 0
    while i < take:
      result[offset + i] = blk[i]
      i = i + 1
    offset = offset + take
  frodoDrbgUpdate(S)
  S.reseedCounter = S.reseedCounter + 1

when defined(hasLibOqs):
  proc oqsFrodoKatCallback(random_array: ptr uint8, bytes_to_read: csize_t) {.cdecl.} =
    var
      outBytes = cast[ptr UncheckedArray[uint8]](random_array)
      bytesBuf = frodoDrbgRandomBytes(oqsFrodoKatDrbgState, int(bytes_to_read))
      i: int = 0
    if not oqsFrodoKatDrbgReady:
      return
    i = 0
    while i < bytesBuf.len:
      outBytes[i] = bytesBuf[i]
      i = i + 1

proc appendFrodoHexUpper(dst: var string, A: openArray[byte]) =
  const
    lut = "0123456789ABCDEF"
  var
    i: int = 0
    b: byte = 0
  if A.len == 0:
    dst.add("00")
    return
  i = 0
  while i < A.len:
    b = A[i]
    dst.add(lut[int(b shr 4)])
    dst.add(lut[int(b and 0x0f'u8)])
    i = i + 1

proc appendFrodoBstr(dst: var string, label: string, A: openArray[byte]) =
  dst.add(label)
  appendFrodoHexUpper(dst, A)
  dst.add("\n")

proc frodoTranscriptForPureKat(): string =
  var
    entropy: array[frodoKatEntropyLen, byte]
    rootDrbg: FrodoNistDrbgState
    katDrbg: FrodoNistDrbgState
    seed48: seq[byte] = @[]
    keypairRandom: seq[byte] = @[]
    encapsRandom: seq[byte] = @[]
    kp: custom_frodo.FrodoTyrKeypair
    env: custom_frodo.FrodoTyrCipher
    shared: seq[byte] = @[]
    i: int = 0
  i = 0
  while i < frodoKatEntropyLen:
    entropy[i] = byte(i)
    i = i + 1
  rootDrbg = initFrodoNistDrbg(entropy)
  result.add("count = 0\n")
  seed48 = frodoDrbgRandomBytes(rootDrbg, frodoKatSeedLen)
  appendFrodoBstr(result, "seed = ", seed48)
  katDrbg = initFrodoNistDrbg(seed48)
  keypairRandom = frodoDrbgRandomBytes(katDrbg, 64)
  kp = custom_frodo.frodoTyrKeypairDerand(custom_frodo.frodo976aes, keypairRandom)
  appendFrodoBstr(result, "pk = ", kp.publicKey)
  appendFrodoBstr(result, "sk = ", kp.secretKey)
  encapsRandom = frodoDrbgRandomBytes(katDrbg, 24)
  env = custom_frodo.frodoTyrEncapsDerand(custom_frodo.frodo976aes, kp.publicKey, encapsRandom)
  appendFrodoBstr(result, "ct = ", env.ciphertext)
  appendFrodoBstr(result, "ss = ", env.sharedSecret)
  shared = custom_frodo.frodoTyrDecaps(custom_frodo.frodo976aes, kp.secretKey, env.ciphertext)
  check shared == env.sharedSecret

when defined(hasLibOqs):
  proc frodoTranscriptForLiboqsKat(): string =
    var
      entropy: array[frodoKatEntropyLen, byte]
      rootDrbg: FrodoNistDrbgState
      seed48: seq[byte] = @[]
      kem: ptr OqsKem = nil
      pk: seq[uint8] = @[]
      sk: seq[uint8] = @[]
      ct: seq[uint8] = @[]
      ssE: seq[uint8] = @[]
      ssD: seq[uint8] = @[]
      i: int = 0
    kem = OQS_KEM_new(oqsAlgFrodoKEM976)
    if kem == nil:
      raise newException(ValueError, "liboqs FrodoKEM-976-AES unavailable")
    defer:
      OQS_KEM_free(kem)
      discard OQS_randombytes_switch_algorithm(oqsRandAlgSystem.cstring)
      oqsFrodoKatDrbgReady = false
    i = 0
    while i < frodoKatEntropyLen:
      entropy[i] = byte(i)
      i = i + 1
    rootDrbg = initFrodoNistDrbg(entropy)
    result.add("count = 0\n")
    seed48 = frodoDrbgRandomBytes(rootDrbg, frodoKatSeedLen)
    appendFrodoBstr(result, "seed = ", seed48)
    oqsFrodoKatDrbgState = initFrodoNistDrbg(seed48)
    oqsFrodoKatDrbgReady = true
    OQS_randombytes_custom_algorithm(oqsFrodoKatCallback)
    pk = newSeq[uint8](int kem[].length_public_key)
    sk = newSeq[uint8](int kem[].length_secret_key)
    ct = newSeq[uint8](int kem[].length_ciphertext)
    ssE = newSeq[uint8](int kem[].length_shared_secret)
    ssD = newSeq[uint8](int kem[].length_shared_secret)
    requireSuccess(OQS_KEM_keypair(kem, addr pk[0], addr sk[0]), "frodo kat keypair")
    appendFrodoBstr(result, "pk = ", pk)
    appendFrodoBstr(result, "sk = ", sk)
    requireSuccess(OQS_KEM_encaps(kem, addr ct[0], addr ssE[0], addr pk[0]), "frodo kat encaps")
    appendFrodoBstr(result, "ct = ", ct)
    appendFrodoBstr(result, "ss = ", ssE)
    requireSuccess(OQS_KEM_decaps(kem, addr ssD[0], addr ct[0], addr sk[0]), "frodo kat decaps")
    check ssD == ssE

proc frodoKatRepoRoot(): string =
  result = parentDir(parentDir(currentSourcePath()))

proc frodoKatJsonPath(): string =
  result = joinPath(frodoKatRepoRoot(), "..", "liboqs", "tests", "KATs", "kem", "kats.json")

proc loadExpectedFrodoKatHash(name: string): string =
  let node = parseJson(readFile(frodoKatJsonPath()))
  result = node[name]["single"].getStr().toLowerAscii()

proc writeTempFrodoKatFile(name, data: string): string =
  result = joinPath(getTempDir(), "tyr_" & name & "_kat.txt")
  writeFile(result, data)

proc sha256HexForFrodoFile(path: string): string =
  when defined(windows):
    let escaped = path.replace("'", "''")
    let output = execProcess(
      "powershell -NoProfile -Command \"(Get-FileHash -Algorithm SHA256 -LiteralPath '" &
      escaped & "').Hash.ToLowerInvariant()\"")
    result = output.strip().toLowerAscii()
  else:
    result = execProcess("sha256sum " & quoteShell(path)).splitWhitespace()[0].toLowerAscii()

suite "frodo kat":
  when defined(hasLibOqs) and defined(release):
    test "liboqs Frodo single KAT hash matches local corpus and pure transcript":
      let liboqsTranscript = frodoTranscriptForLiboqsKat()
      let pureTranscript = frodoTranscriptForPureKat()
      let katPath = writeTempFrodoKatFile("frodo976aes", liboqsTranscript)
      defer:
        if fileExists(katPath):
          removeFile(katPath)
      check sha256HexForFrodoFile(katPath) == loadExpectedFrodoKatHash("FrodoKEM-976-AES")
      check pureTranscript == liboqsTranscript
  else:
    test "frodo KAT corpus check requires release plus liboqs runtime":
      checkpoint("Frodo KAT corpus comparison is enabled only for release builds with liboqs")
