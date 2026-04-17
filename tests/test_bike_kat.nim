import std/[json, os, osproc, strutils, unittest]

import ../src/protocols/custom_crypto/aes_core
import ../src/protocols/custom_crypto/bike as custom_bike

when defined(hasLibOqs):
  import ../src/protocols/bindings/liboqs

const
  bikeKatEntropyLen = 48
  bikeKatSeedLen = 48

type
  BikeNistDrbgState = object
    key: array[32, byte]
    v: array[16, byte]
    reseedCounter: int

when defined(hasLibOqs):
  var
    oqsBikeKatDrbgState: BikeNistDrbgState
    oqsBikeKatDrbgReady: bool = false

proc incrementBikeV(S: var BikeNistDrbgState) =
  var
    i: int = 15
  while i >= 0:
    if S.v[i] == 0xff'u8:
      S.v[i] = 0'u8
      i = i - 1
    else:
      S.v[i] = S.v[i] + 1'u8
      break

proc bikeAes256EcbBlock(k: openArray[byte], input: array[16, byte]): array[16, byte] =
  var
    ctx: Aes256Ctx
  ctx.init(k)
  result = encryptBlock(ctx, input)

proc bikeDrbgUpdate(S: var BikeNistDrbgState,
    provided: ptr array[bikeKatEntropyLen, byte] = nil) =
  var
    temp: array[bikeKatEntropyLen, byte]
    blk: array[16, byte]
    i: int = 0
  i = 0
  while i < 3:
    incrementBikeV(S)
    blk = bikeAes256EcbBlock(S.key, S.v)
    copyMem(addr temp[i * 16], addr blk[0], 16)
    i = i + 1
  if provided != nil:
    i = 0
    while i < bikeKatEntropyLen:
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

proc initBikeNistDrbg(entropy: openArray[byte],
    personalization: openArray[byte] = @[]): BikeNistDrbgState =
  var
    seedMaterial: array[bikeKatEntropyLen, byte]
    i: int = 0
  if entropy.len != bikeKatEntropyLen:
    raise newException(ValueError, "NIST DRBG entropy must be 48 bytes")
  if personalization.len != 0 and personalization.len != bikeKatEntropyLen:
    raise newException(ValueError, "NIST DRBG personalization must be 48 bytes")
  i = 0
  while i < bikeKatEntropyLen:
    seedMaterial[i] = entropy[i]
    if personalization.len == bikeKatEntropyLen:
      seedMaterial[i] = seedMaterial[i] xor personalization[i]
    i = i + 1
  bikeDrbgUpdate(result, addr seedMaterial)
  result.reseedCounter = 1

proc bikeDrbgRandomBytes(S: var BikeNistDrbgState, n: int): seq[byte] =
  var
    blk: array[16, byte]
    offset: int = 0
    take: int = 0
    i: int = 0
  result = newSeq[byte](n)
  while offset < n:
    incrementBikeV(S)
    blk = bikeAes256EcbBlock(S.key, S.v)
    take = min(16, n - offset)
    i = 0
    while i < take:
      result[offset + i] = blk[i]
      i = i + 1
    offset = offset + take
  bikeDrbgUpdate(S)
  S.reseedCounter = S.reseedCounter + 1

when defined(hasLibOqs):
  proc bikeOqsKatCallback(random_array: ptr uint8, bytes_to_read: csize_t) {.cdecl.} =
    var
      outBytes = cast[ptr UncheckedArray[uint8]](random_array)
      bytesBuf = bikeDrbgRandomBytes(oqsBikeKatDrbgState, int(bytes_to_read))
      i: int = 0
    if not oqsBikeKatDrbgReady:
      return
    i = 0
    while i < bytesBuf.len:
      outBytes[i] = bytesBuf[i]
      i = i + 1

proc appendBikeHexUpper(dst: var string, A: openArray[byte]) =
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

proc appendBikeBstr(dst: var string, label: string, A: openArray[byte]) =
  dst.add(label)
  appendBikeHexUpper(dst, A)
  dst.add("\n")

proc bikeTranscriptForPureKat(v: custom_bike.BikeVariant): string =
  var
    entropy: array[bikeKatEntropyLen, byte]
    rootDrbg: BikeNistDrbgState
    katDrbg: BikeNistDrbgState
    seed48: seq[byte] = @[]
    keypairMaterial: seq[byte] = @[]
    encapsMaterial: seq[byte] = @[]
    kp: custom_bike.BikeTyrKeypair
    env: custom_bike.BikeTyrCipher
    shared: seq[byte] = @[]
    i: int = 0
  i = 0
  while i < bikeKatEntropyLen:
    entropy[i] = byte(i)
    i = i + 1
  rootDrbg = initBikeNistDrbg(entropy)
  result.add("count = 0\n")
  seed48 = bikeDrbgRandomBytes(rootDrbg, bikeKatSeedLen)
  appendBikeBstr(result, "seed = ", seed48)
  katDrbg = initBikeNistDrbg(seed48)
  keypairMaterial = bikeDrbgRandomBytes(katDrbg, 64)
  kp = custom_bike.bikeTyrKeypairDerand(v, keypairMaterial)
  appendBikeBstr(result, "pk = ", kp.publicKey)
  appendBikeBstr(result, "sk = ", kp.secretKey)
  encapsMaterial = bikeDrbgRandomBytes(katDrbg, 64)
  env = custom_bike.bikeTyrEncapsDerand(v, kp.publicKey, encapsMaterial)
  appendBikeBstr(result, "ct = ", env.ciphertext)
  appendBikeBstr(result, "ss = ", env.sharedSecret)
  shared = custom_bike.bikeTyrDecaps(v, kp.secretKey, env.ciphertext)
  check shared == env.sharedSecret

when defined(hasLibOqs):
  proc bikeTranscriptForLiboqsKat(algId: string): string =
    var
      entropy: array[bikeKatEntropyLen, byte]
      rootDrbg: BikeNistDrbgState
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
      oqsBikeKatDrbgReady = false
    i = 0
    while i < bikeKatEntropyLen:
      entropy[i] = byte(i)
      i = i + 1
    rootDrbg = initBikeNistDrbg(entropy)
    result.add("count = 0\n")
    seed48 = bikeDrbgRandomBytes(rootDrbg, bikeKatSeedLen)
    appendBikeBstr(result, "seed = ", seed48)
    oqsBikeKatDrbgState = initBikeNistDrbg(seed48)
    oqsBikeKatDrbgReady = true
    OQS_randombytes_custom_algorithm(bikeOqsKatCallback)
    pk = newSeq[uint8](int kem[].length_public_key)
    sk = newSeq[uint8](int kem[].length_secret_key)
    ct = newSeq[uint8](int kem[].length_ciphertext)
    ssE = newSeq[uint8](int kem[].length_shared_secret)
    ssD = newSeq[uint8](int kem[].length_shared_secret)
    requireSuccess(OQS_KEM_keypair(kem, addr pk[0], addr sk[0]), "kat keypair")
    appendBikeBstr(result, "pk = ", pk)
    appendBikeBstr(result, "sk = ", sk)
    requireSuccess(OQS_KEM_encaps(kem, addr ct[0], addr ssE[0], addr pk[0]), "kat encaps")
    appendBikeBstr(result, "ct = ", ct)
    appendBikeBstr(result, "ss = ", ssE)
    requireSuccess(OQS_KEM_decaps(kem, addr ssD[0], addr ct[0], addr sk[0]), "kat decaps")
    check ssD == ssE

proc bikeRepoRoot(): string =
  result = parentDir(parentDir(currentSourcePath()))

proc bikeKatJsonPath(): string =
  result = joinPath(bikeRepoRoot(), "..", "liboqs", "tests", "KATs", "kem", "kats.json")

proc loadBikeExpectedKatHash(name: string): string =
  let node = parseJson(readFile(bikeKatJsonPath()))
  result = node[name]["single"].getStr().toLowerAscii()

proc writeBikeTempKatFile(name, data: string): string =
  result = joinPath(getTempDir(), "tyr_" & name & "_kat.txt")
  writeFile(result, data)

proc bikeSha256HexForFile(path: string): string =
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

suite "bike kat":
  when defined(hasLibOqs):
    test "liboqs BIKE-L1 single KAT hash matches local corpus and pure transcript":
      var
        liboqsTranscript: string = ""
        pureTranscript: string = ""
        katPath: string = ""
      try:
        liboqsTranscript = bikeTranscriptForLiboqsKat("BIKE-L1")
      except ValueError:
        checkpoint("liboqs BIKE-L1 unavailable; skipping local KAT corpus comparison")
      if liboqsTranscript.len > 0:
        pureTranscript = bikeTranscriptForPureKat(custom_bike.bikeL1)
        katPath = writeBikeTempKatFile("bike_l1", liboqsTranscript)
        defer:
          if fileExists(katPath):
            removeFile(katPath)
        check bikeSha256HexForFile(katPath) == loadBikeExpectedKatHash("BIKE-L1")
        check pureTranscript == liboqsTranscript
  else:
    test "bike KAT corpus check requires liboqs runtime":
      checkpoint("liboqs runtime not available; skipping local KAT corpus comparison")
