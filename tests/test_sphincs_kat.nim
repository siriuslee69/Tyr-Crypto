import std/[json, os, osproc, strutils, unittest]

import ../src/protocols/custom_crypto/aes_core
import ../src/protocols/custom_crypto/sphincs as custom_sphincs

when defined(hasLibOqs):
  import ../src/protocols/bindings/liboqs

const
  sphincsKatEntropyLen = 48
  sphincsKatSeedLen = 48

type
  SphincsNistDrbgState = object
    key: array[32, byte]
    v: array[16, byte]
    reseedCounter: int

when defined(hasLibOqs):
  var
    oqsSphincsKatDrbgState: SphincsNistDrbgState
    oqsSphincsKatDrbgReady: bool = false

proc incrementSphincsV(S: var SphincsNistDrbgState) =
  var i: int = 15
  while i >= 0:
    if S.v[i] == 0xff'u8:
      S.v[i] = 0'u8
      i = i - 1
    else:
      S.v[i] = S.v[i] + 1'u8
      break

proc sphincsAes256EcbBlock(k: openArray[byte], input: array[16, byte]): array[16, byte] =
  var ctx: Aes256Ctx
  ctx.init(k)
  result = encryptBlock(ctx, input)

proc sphincsDrbgUpdate(S: var SphincsNistDrbgState,
    provided: ptr array[sphincsKatEntropyLen, byte] = nil) =
  var
    temp: array[sphincsKatEntropyLen, byte]
    blk: array[16, byte]
  for i in 0 ..< 3:
    incrementSphincsV(S)
    blk = sphincsAes256EcbBlock(S.key, S.v)
    copyMem(addr temp[i * 16], addr blk[0], 16)
  if provided != nil:
    for i in 0 ..< sphincsKatEntropyLen:
      temp[i] = temp[i] xor provided[][i]
  for i in 0 ..< 32:
    S.key[i] = temp[i]
  for i in 0 ..< 16:
    S.v[i] = temp[32 + i]

proc initSphincsNistDrbg(entropy: openArray[byte],
    personalization: openArray[byte] = @[]): SphincsNistDrbgState =
  var seedMaterial: array[sphincsKatEntropyLen, byte]
  for i in 0 ..< sphincsKatEntropyLen:
    seedMaterial[i] = entropy[i]
    if personalization.len == sphincsKatEntropyLen:
      seedMaterial[i] = seedMaterial[i] xor personalization[i]
  sphincsDrbgUpdate(result, addr seedMaterial)
  result.reseedCounter = 1

proc sphincsDrbgRandomBytes(S: var SphincsNistDrbgState, n: int): seq[byte] =
  var
    blk: array[16, byte]
    offset: int = 0
    take: int = 0
  result = newSeq[byte](n)
  while offset < n:
    incrementSphincsV(S)
    blk = sphincsAes256EcbBlock(S.key, S.v)
    take = min(16, n - offset)
    for i in 0 ..< take:
      result[offset + i] = blk[i]
    offset = offset + take
  sphincsDrbgUpdate(S)
  S.reseedCounter = S.reseedCounter + 1

when defined(hasLibOqs):
  proc oqsSphincsKatCallback(random_array: ptr uint8, bytes_to_read: csize_t) {.cdecl.} =
    let outBytes = cast[ptr UncheckedArray[uint8]](random_array)
    let bytesBuf = sphincsDrbgRandomBytes(oqsSphincsKatDrbgState, int(bytes_to_read))
    if not oqsSphincsKatDrbgReady:
      return
    for i in 0 ..< bytesBuf.len:
      outBytes[i] = bytesBuf[i]

proc appendSphincsHexUpper(dst: var string, A: openArray[byte]) =
  const lut = "0123456789ABCDEF"
  if A.len == 0:
    dst.add("00")
    return
  for b in A:
    dst.add(lut[int(b shr 4)])
    dst.add(lut[int(b and 0x0f'u8)])

proc appendSphincsBstr(dst: var string, label: string, A: openArray[byte]) =
  dst.add(label)
  appendSphincsHexUpper(dst, A)
  dst.add("\n")

proc combineSphincsSignedMessage(sig, msg: openArray[byte]): seq[byte] =
  result = newSeq[byte](sig.len + msg.len)
  if sig.len > 0:
    copyMem(addr result[0], unsafeAddr sig[0], sig.len)
  if msg.len > 0:
    copyMem(addr result[sig.len], unsafeAddr msg[0], msg.len)

proc sphincsTranscriptForPureKat(): string =
  var
    entropy: array[sphincsKatEntropyLen, byte]
    rootDrbg: SphincsNistDrbgState
    katDrbg: SphincsNistDrbgState
    seed48: seq[byte] = @[]
    keypairSeed: seq[byte] = @[]
    msg: seq[byte] = @[]
    optrand: seq[byte] = @[]
    kp: custom_sphincs.SphincsTyrKeypair
    sig: seq[byte] = @[]
    sm: seq[byte] = @[]
  for i in 0 ..< sphincsKatEntropyLen:
    entropy[i] = byte(i)
  rootDrbg = initSphincsNistDrbg(entropy)
  result.add("count = 0\n")
  seed48 = sphincsDrbgRandomBytes(rootDrbg, sphincsKatSeedLen)
  appendSphincsBstr(result, "seed = ", seed48)
  msg = sphincsDrbgRandomBytes(rootDrbg, 33)
  result.add("mlen = 33\n")
  appendSphincsBstr(result, "msg = ", msg)
  katDrbg = initSphincsNistDrbg(seed48)
  keypairSeed = sphincsDrbgRandomBytes(katDrbg, 48)
  kp = custom_sphincs.sphincsTyrSeedKeypair(custom_sphincs.sphincsShake128fSimple, keypairSeed)
  appendSphincsBstr(result, "pk = ", kp.publicKey)
  appendSphincsBstr(result, "sk = ", kp.secretKey)
  optrand = sphincsDrbgRandomBytes(katDrbg, 16)
  sig = custom_sphincs.sphincsTyrSignDerand(custom_sphincs.sphincsShake128fSimple, msg, kp.secretKey, optrand)
  sm = combineSphincsSignedMessage(sig, msg)
  result.add("smlen = " & $sm.len & "\n")
  appendSphincsBstr(result, "sm = ", sm)

when defined(hasLibOqs):
  proc sphincsTranscriptForLiboqsKat(): string =
    var
      entropy: array[sphincsKatEntropyLen, byte]
      rootDrbg: SphincsNistDrbgState
      seed48: seq[byte] = @[]
      msg: seq[byte] = @[]
      sigObj: ptr OqsSig = nil
      pk: seq[uint8] = @[]
      sk: seq[uint8] = @[]
      sig: seq[uint8] = @[]
      sm: seq[byte] = @[]
      sigLen: csize_t
    sigObj = OQS_SIG_new("SPHINCS+-SHAKE-128f-simple")
    if sigObj == nil:
      raise newException(ValueError, "liboqs SPHINCS unavailable")
    defer:
      OQS_SIG_free(sigObj)
      discard OQS_randombytes_switch_algorithm(oqsRandAlgSystem.cstring)
      oqsSphincsKatDrbgReady = false
    for i in 0 ..< sphincsKatEntropyLen:
      entropy[i] = byte(i)
    rootDrbg = initSphincsNistDrbg(entropy)
    result.add("count = 0\n")
    seed48 = sphincsDrbgRandomBytes(rootDrbg, sphincsKatSeedLen)
    appendSphincsBstr(result, "seed = ", seed48)
    msg = sphincsDrbgRandomBytes(rootDrbg, 33)
    result.add("mlen = 33\n")
    appendSphincsBstr(result, "msg = ", msg)
    oqsSphincsKatDrbgState = initSphincsNistDrbg(seed48)
    oqsSphincsKatDrbgReady = true
    OQS_randombytes_custom_algorithm(oqsSphincsKatCallback)
    pk = newSeq[uint8](int sigObj[].length_public_key)
    sk = newSeq[uint8](int sigObj[].length_secret_key)
    requireSuccess(OQS_SIG_keypair(sigObj, addr pk[0], addr sk[0]), "OQS_SIG_keypair(SPHINCS)")
    appendSphincsBstr(result, "pk = ", pk)
    appendSphincsBstr(result, "sk = ", sk)
    sig = newSeq[uint8](int sigObj[].length_signature)
    requireSuccess(OQS_SIG_sign(sigObj, addr sig[0], addr sigLen, addr msg[0], csize_t(msg.len), addr sk[0]),
      "OQS_SIG_sign(SPHINCS)")
    sig.setLen(int(sigLen))
    sm = combineSphincsSignedMessage(sig, msg)
    result.add("smlen = " & $sm.len & "\n")
    appendSphincsBstr(result, "sm = ", sm)

proc sphincsKatRepoRoot(): string =
  result = parentDir(parentDir(currentSourcePath()))

proc sphincsKatJsonPath(): string =
  result = joinPath(sphincsKatRepoRoot(), "..", "liboqs", "tests", "KATs", "sig", "kats.json")

proc loadExpectedSphincsKatHash(name: string): string =
  let node = parseJson(readFile(sphincsKatJsonPath()))
  result = node[name]["single"].getStr().toLowerAscii()

proc writeTempSphincsKatFile(name, data: string): string =
  result = joinPath(getTempDir(), "tyr_" & name & "_kat.txt")
  writeFile(result, data)

proc sha256HexForSphincsFile(path: string): string =
  let escaped = path.replace("'", "''")
  let output = execProcess(
    "powershell -NoProfile -Command \"(Get-FileHash -Algorithm SHA256 -LiteralPath '" &
    escaped & "').Hash.ToLowerInvariant()\"")
  result = output.strip().toLowerAscii()

suite "sphincs kat":
  when defined(hasLibOqs) and defined(release):
    test "liboqs SPHINCS KAT hash matches local corpus and pure transcript":
      let liboqsTranscript = sphincsTranscriptForLiboqsKat()
      let pureTranscript = sphincsTranscriptForPureKat()
      let katPath = writeTempSphincsKatFile("SPHINCS+-SHAKE-128f-simple", liboqsTranscript)
      defer:
        if fileExists(katPath):
          removeFile(katPath)
      check sha256HexForSphincsFile(katPath) == loadExpectedSphincsKatHash("SPHINCS+-SHAKE-128f-simple")
      check pureTranscript == liboqsTranscript
  else:
    test "sphincs KAT corpus check requires release plus liboqs runtime":
      checkpoint("SPHINCS KAT corpus comparison is enabled only for release builds with liboqs")
