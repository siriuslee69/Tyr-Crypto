import std/[json, os, osproc, strutils, unittest]

import ../src/protocols/custom_crypto/aes_core
import ../src/protocols/custom_crypto/kyber as custom_kyber

when defined(hasLibOqs):
  import ../src/protocols/bindings/liboqs

const
  katEntropyLen = 48
  katSeedLen = 48

type
  NistDrbgState = object
    key: array[32, byte]
    v: array[16, byte]
    reseedCounter: int

when defined(hasLibOqs):
  var
    oqsKatDrbgState: NistDrbgState
    oqsKatDrbgReady: bool = false

proc incrementV(S: var NistDrbgState) =
  var
    i: int = 15
  while i >= 0:
    if S.v[i] == 0xff'u8:
      S.v[i] = 0'u8
      i = i - 1
    else:
      S.v[i] = S.v[i] + 1'u8
      break

proc aes256EcbBlock(k: openArray[byte], input: array[16, byte]): array[16, byte] =
  var
    ctx: Aes256Ctx
  ctx.init(k)
  result = encryptBlock(ctx, input)

proc drbgUpdate(S: var NistDrbgState, provided: ptr array[katEntropyLen, byte] = nil) =
  var
    temp: array[katEntropyLen, byte]
    blk: array[16, byte]
    i: int = 0
  i = 0
  while i < 3:
    incrementV(S)
    blk = aes256EcbBlock(S.key, S.v)
    copyMem(addr temp[i * 16], addr blk[0], 16)
    i = i + 1
  if provided != nil:
    i = 0
    while i < katEntropyLen:
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

proc initNistDrbg(entropy: openArray[byte], personalization: openArray[byte] = @[]): NistDrbgState =
  var
    seedMaterial: array[katEntropyLen, byte]
    i: int = 0
  if entropy.len != katEntropyLen:
    raise newException(ValueError, "NIST DRBG entropy must be 48 bytes")
  if personalization.len != 0 and personalization.len != katEntropyLen:
    raise newException(ValueError, "NIST DRBG personalization must be 48 bytes")
  i = 0
  while i < katEntropyLen:
    seedMaterial[i] = entropy[i]
    if personalization.len == katEntropyLen:
      seedMaterial[i] = seedMaterial[i] xor personalization[i]
    i = i + 1
  drbgUpdate(result, addr seedMaterial)
  result.reseedCounter = 1

proc drbgRandomBytes(S: var NistDrbgState, n: int): seq[byte] =
  var
    blk: array[16, byte]
    offset: int = 0
    take: int = 0
    i: int = 0
  result = newSeq[byte](n)
  while offset < n:
    incrementV(S)
    blk = aes256EcbBlock(S.key, S.v)
    take = min(16, n - offset)
    i = 0
    while i < take:
      result[offset + i] = blk[i]
      i = i + 1
    offset = offset + take
  drbgUpdate(S)
  S.reseedCounter = S.reseedCounter + 1

when defined(hasLibOqs):
  proc oqsKatCallback(random_array: ptr uint8, bytes_to_read: csize_t) {.cdecl.} =
    var
      outBytes = cast[ptr UncheckedArray[uint8]](random_array)
      bytesBuf = drbgRandomBytes(oqsKatDrbgState, int(bytes_to_read))
      i: int = 0
    if not oqsKatDrbgReady:
      return
    i = 0
    while i < bytesBuf.len:
      outBytes[i] = bytesBuf[i]
      i = i + 1

proc appendHexUpper(dst: var string, A: openArray[byte]) =
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

proc appendBstr(dst: var string, label: string, A: openArray[byte]) =
  dst.add(label)
  appendHexUpper(dst, A)
  dst.add("\n")

proc transcriptForPureKyberKat(v: custom_kyber.KyberVariant): string =
  var
    entropy: array[katEntropyLen, byte]
    rootDrbg: NistDrbgState
    katDrbg: NistDrbgState
    seed48: seq[byte] = @[]
    keypairMaterial: seq[byte] = @[]
    encapsSeed: seq[byte] = @[]
    kp: custom_kyber.KyberTyrKeypair
    env: custom_kyber.KyberTyrCipher
    shared: seq[byte] = @[]
    i: int = 0
  i = 0
  while i < katEntropyLen:
    entropy[i] = byte(i)
    i = i + 1
  rootDrbg = initNistDrbg(entropy)
  result.add("count = 0\n")
  seed48 = drbgRandomBytes(rootDrbg, katSeedLen)
  appendBstr(result, "seed = ", seed48)
  katDrbg = initNistDrbg(seed48)
  keypairMaterial = drbgRandomBytes(katDrbg, 32)
  let zSeed = drbgRandomBytes(katDrbg, 32)
  kp = custom_kyber.kyberTyrKeypairFromParts(v, keypairMaterial, zSeed)
  appendBstr(result, "pk = ", kp.publicKey)
  appendBstr(result, "sk = ", kp.secretKey)
  encapsSeed = drbgRandomBytes(katDrbg, 32)
  env = custom_kyber.kyberTyrEncaps(v, kp.publicKey, encapsSeed)
  appendBstr(result, "ct = ", env.ciphertext)
  appendBstr(result, "ss = ", env.sharedSecret)
  shared = custom_kyber.kyberTyrDecaps(v, kp.secretKey, env.ciphertext)
  check shared == env.sharedSecret

when defined(hasLibOqs):
  proc transcriptForLiboqsKat(algId: string): string =
    var
      entropy: array[katEntropyLen, byte]
      rootDrbg: NistDrbgState
      seed48: seq[byte] = @[]
      kem: ptr OqsKem = nil
      pk: seq[uint8] = @[]
      sk: seq[uint8] = @[]
      ct: seq[uint8] = @[]
      ssE: seq[uint8] = @[]
      ssD: seq[uint8] = @[]
      i: int = 0
    kem = OQS_KEM_new(algId)
    if kem == nil:
      raise newException(ValueError, "liboqs KEM unavailable: " & algId)
    defer:
      OQS_KEM_free(kem)
      discard OQS_randombytes_switch_algorithm(oqsRandAlgSystem.cstring)
      oqsKatDrbgReady = false
    i = 0
    while i < katEntropyLen:
      entropy[i] = byte(i)
      i = i + 1
    rootDrbg = initNistDrbg(entropy)
    result.add("count = 0\n")
    seed48 = drbgRandomBytes(rootDrbg, katSeedLen)
    appendBstr(result, "seed = ", seed48)
    oqsKatDrbgState = initNistDrbg(seed48)
    oqsKatDrbgReady = true
    OQS_randombytes_custom_algorithm(oqsKatCallback)
    pk = newSeq[uint8](int kem[].length_public_key)
    sk = newSeq[uint8](int kem[].length_secret_key)
    ct = newSeq[uint8](int kem[].length_ciphertext)
    ssE = newSeq[uint8](int kem[].length_shared_secret)
    ssD = newSeq[uint8](int kem[].length_shared_secret)
    requireSuccess(OQS_KEM_keypair(kem, addr pk[0], addr sk[0]), "kat keypair")
    appendBstr(result, "pk = ", pk)
    appendBstr(result, "sk = ", sk)
    requireSuccess(OQS_KEM_encaps(kem, addr ct[0], addr ssE[0], addr pk[0]), "kat encaps")
    appendBstr(result, "ct = ", ct)
    appendBstr(result, "ss = ", ssE)
    requireSuccess(OQS_KEM_decaps(kem, addr ssD[0], addr ct[0], addr sk[0]), "kat decaps")
    check ssD == ssE

proc repoRoot(): string =
  result = parentDir(parentDir(currentSourcePath()))

proc katJsonPath(): string =
  ## Resolve the liboqs KAT corpus from env first because sandboxed test runs may
  ## mirror Tyr-Crypto into a temp tree without mirroring the sibling liboqs clone.
  var
    envSource: string = getEnv("LIBOQS_SOURCE").strip()
    candidates: seq[string] = @[]
    p: string = ""
  if envSource.len > 0:
    candidates.add(joinPath(envSource, "tests", "KATs", "kem", "kats.json"))
  candidates.add(joinPath(repoRoot(), "..", "liboqs", "tests", "KATs", "kem", "kats.json"))
  candidates.add(joinPath(getCurrentDir(), "..", "liboqs", "tests", "KATs", "kem", "kats.json"))
  candidates.add(joinPath(getCurrentDir(), "submodules", "liboqs", "tests", "KATs", "kem", "kats.json"))
  for c in candidates:
    p = absolutePath(c)
    if fileExists(p):
      return p
  raise newException(IOError, "cannot find liboqs Kyber KAT corpus: " & candidates.join(" | "))

proc loadExpectedKatHash(name: string): string =
  let node = parseJson(readFile(katJsonPath()))
  result = node[name]["single"].getStr().toLowerAscii()

proc writeTempKatFile(name, data: string): string =
  result = joinPath(getTempDir(), "tyr_" & name & "_kat.txt")
  writeFile(result, data)

proc sha256HexForFile(path: string): string =
  when defined(windows):
    let escaped = path.replace("'", "''")
    let output = execProcess(
      "powershell -NoProfile -Command \"(Get-FileHash -Algorithm SHA256 -LiteralPath '" &
      escaped & "').Hash.ToLowerInvariant()\"")
    result = output.strip().toLowerAscii()
  else:
    var
      output: string = ""
    try:
      output = execProcess("sha256sum " & quoteShell(path))
      result = output.splitWhitespace()[0].toLowerAscii()
    except CatchableError:
      output = execProcess("shasum -a 256 " & quoteShell(path))
      result = output.splitWhitespace()[0].toLowerAscii()

suite "kyber kat":
  when defined(hasLibOqs):
    test "liboqs Kyber768 single KAT hash matches local corpus and pure transcript":
      let liboqsTranscript = transcriptForLiboqsKat("Kyber768")
      let pureTranscript = transcriptForPureKyberKat(custom_kyber.kyber768)
      let katPath = writeTempKatFile("kyber768", liboqsTranscript)
      defer:
        if fileExists(katPath):
          removeFile(katPath)
      check sha256HexForFile(katPath) == loadExpectedKatHash("Kyber768")
      check pureTranscript == liboqsTranscript

    test "liboqs Kyber1024 single KAT hash matches local corpus and pure transcript":
      let liboqsTranscript = transcriptForLiboqsKat("Kyber1024")
      let pureTranscript = transcriptForPureKyberKat(custom_kyber.kyber1024)
      let katPath = writeTempKatFile("kyber1024", liboqsTranscript)
      defer:
        if fileExists(katPath):
          removeFile(katPath)
      check sha256HexForFile(katPath) == loadExpectedKatHash("Kyber1024")
      check pureTranscript == liboqsTranscript
  else:
    test "kyber KAT corpus check requires liboqs runtime":
      checkpoint("liboqs runtime not available; skipping local KAT corpus comparison")
