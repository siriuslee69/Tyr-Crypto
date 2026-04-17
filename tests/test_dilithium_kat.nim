import std/[json, os, osproc, strutils, unittest]

import ../src/protocols/custom_crypto/aes_core
import ../src/protocols/custom_crypto/dilithium as custom_dilithium

when defined(hasLibOqs):
  import ../src/protocols/bindings/liboqs

const
  diliKatEntropyLen = 48
  diliKatSeedLen = 48

type
  DiliNistDrbgState = object
    key: array[32, byte]
    v: array[16, byte]
    reseedCounter: int

when defined(hasLibOqs):
  var
    oqsDiliKatDrbgState: DiliNistDrbgState
    oqsDiliKatDrbgReady: bool = false

proc incrementDiliV(S: var DiliNistDrbgState) =
  var i: int = 15
  while i >= 0:
    if S.v[i] == 0xff'u8:
      S.v[i] = 0'u8
      i = i - 1
    else:
      S.v[i] = S.v[i] + 1'u8
      break

proc diliAes256EcbBlock(k: openArray[byte], input: array[16, byte]): array[16, byte] =
  var ctx: Aes256Ctx
  ctx.init(k)
  result = encryptBlock(ctx, input)

proc diliDrbgUpdate(S: var DiliNistDrbgState, provided: ptr array[diliKatEntropyLen, byte] = nil) =
  var
    temp: array[diliKatEntropyLen, byte]
    blk: array[16, byte]
    i: int = 0
  i = 0
  while i < 3:
    incrementDiliV(S)
    blk = diliAes256EcbBlock(S.key, S.v)
    copyMem(addr temp[i * 16], addr blk[0], 16)
    i = i + 1
  if provided != nil:
    i = 0
    while i < diliKatEntropyLen:
      temp[i] = temp[i] xor provided[][i]
      i = i + 1
  for i in 0 ..< 32:
    S.key[i] = temp[i]
  for i in 0 ..< 16:
    S.v[i] = temp[32 + i]

proc initDiliNistDrbg(entropy: openArray[byte], personalization: openArray[byte] = @[]): DiliNistDrbgState =
  var
    seedMaterial: array[diliKatEntropyLen, byte]
    i: int = 0
  i = 0
  while i < diliKatEntropyLen:
    seedMaterial[i] = entropy[i]
    if personalization.len == diliKatEntropyLen:
      seedMaterial[i] = seedMaterial[i] xor personalization[i]
    i = i + 1
  diliDrbgUpdate(result, addr seedMaterial)
  result.reseedCounter = 1

proc diliDrbgRandomBytes(S: var DiliNistDrbgState, n: int): seq[byte] =
  var
    blk: array[16, byte]
    offset: int = 0
    take: int = 0
  result = newSeq[byte](n)
  while offset < n:
    incrementDiliV(S)
    blk = diliAes256EcbBlock(S.key, S.v)
    take = min(16, n - offset)
    for i in 0 ..< take:
      result[offset + i] = blk[i]
    offset = offset + take
  diliDrbgUpdate(S)
  S.reseedCounter = S.reseedCounter + 1

when defined(hasLibOqs):
  proc oqsDiliKatCallback(random_array: ptr uint8, bytes_to_read: csize_t) {.cdecl.} =
    let outBytes = cast[ptr UncheckedArray[uint8]](random_array)
    let bytesBuf = diliDrbgRandomBytes(oqsDiliKatDrbgState, int(bytes_to_read))
    if not oqsDiliKatDrbgReady:
      return
    for i in 0 ..< bytesBuf.len:
      outBytes[i] = bytesBuf[i]

proc appendDiliHexUpper(dst: var string, A: openArray[byte]) =
  const lut = "0123456789ABCDEF"
  if A.len == 0:
    dst.add("00")
    return
  for b in A:
    dst.add(lut[int(b shr 4)])
    dst.add(lut[int(b and 0x0f'u8)])

proc appendDiliBstr(dst: var string, label: string, A: openArray[byte]) =
  dst.add(label)
  appendDiliHexUpper(dst, A)
  dst.add("\n")

proc combineSignedMessage(sig, msg: openArray[byte]): seq[byte] =
  result = newSeq[byte](sig.len + msg.len)
  if sig.len > 0:
    copyMem(addr result[0], unsafeAddr sig[0], sig.len)
  if msg.len > 0:
    copyMem(addr result[sig.len], unsafeAddr msg[0], msg.len)

proc diliKatMethodName(v: custom_dilithium.DilithiumVariant): string =
  case v
  of custom_dilithium.dilithium44: result = "ML-DSA-44"
  of custom_dilithium.dilithium65: result = "ML-DSA-65"
  of custom_dilithium.dilithium87: result = "ML-DSA-87"

proc diliTranscriptForPureKat(v: custom_dilithium.DilithiumVariant): string =
  var
    entropy: array[diliKatEntropyLen, byte]
    rootDrbg: DiliNistDrbgState
    katDrbg: DiliNistDrbgState
    seed48: seq[byte] = @[]
    msg: seq[byte] = @[]
    keypairSeed: seq[byte] = @[]
    signRnd: seq[byte] = @[]
    kp: custom_dilithium.DilithiumTyrKeypair
    sig: seq[byte] = @[]
    sm: seq[byte] = @[]
  for i in 0 ..< diliKatEntropyLen:
    entropy[i] = byte(i)
  rootDrbg = initDiliNistDrbg(entropy)
  result.add("count = 0\n")
  seed48 = diliDrbgRandomBytes(rootDrbg, diliKatSeedLen)
  appendDiliBstr(result, "seed = ", seed48)
  msg = diliDrbgRandomBytes(rootDrbg, 33)
  result.add("mlen = 33\n")
  appendDiliBstr(result, "msg = ", msg)
  katDrbg = initDiliNistDrbg(seed48)
  keypairSeed = diliDrbgRandomBytes(katDrbg, 32)
  kp = custom_dilithium.dilithiumTyrKeypair(v, keypairSeed)
  appendDiliBstr(result, "pk = ", kp.publicKey)
  appendDiliBstr(result, "sk = ", kp.secretKey)
  signRnd = diliDrbgRandomBytes(katDrbg, 32)
  sig = custom_dilithium.dilithiumTyrSignDerand(v, msg, kp.secretKey, signRnd)
  sm = combineSignedMessage(sig, msg)
  result.add("smlen = " & $sm.len & "\n")
  appendDiliBstr(result, "sm = ", sm)

when defined(hasLibOqs):
  proc diliTranscriptForLiboqsKat(v: custom_dilithium.DilithiumVariant): string =
    var
      entropy: array[diliKatEntropyLen, byte]
      rootDrbg: DiliNistDrbgState
      seed48: seq[byte] = @[]
      msg: seq[byte] = @[]
      sigObj: ptr OqsSig = nil
      pk: seq[uint8] = @[]
      sk: seq[uint8] = @[]
      sig: seq[uint8] = @[]
      sm: seq[byte] = @[]
      sigLen: csize_t
    sigObj = OQS_SIG_new(diliKatMethodName(v).cstring)
    if sigObj == nil:
      raise newException(ValueError, "liboqs signature unavailable")
    defer:
      OQS_SIG_free(sigObj)
      discard OQS_randombytes_switch_algorithm(oqsRandAlgSystem.cstring)
      oqsDiliKatDrbgReady = false
    for i in 0 ..< diliKatEntropyLen:
      entropy[i] = byte(i)
    rootDrbg = initDiliNistDrbg(entropy)
    result.add("count = 0\n")
    seed48 = diliDrbgRandomBytes(rootDrbg, diliKatSeedLen)
    appendDiliBstr(result, "seed = ", seed48)
    msg = diliDrbgRandomBytes(rootDrbg, 33)
    result.add("mlen = 33\n")
    appendDiliBstr(result, "msg = ", msg)
    oqsDiliKatDrbgState = initDiliNistDrbg(seed48)
    oqsDiliKatDrbgReady = true
    OQS_randombytes_custom_algorithm(oqsDiliKatCallback)
    pk = newSeq[uint8](int sigObj[].length_public_key)
    sk = newSeq[uint8](int sigObj[].length_secret_key)
    requireSuccess(OQS_SIG_keypair(sigObj, addr pk[0], addr sk[0]), "OQS_SIG_keypair(" & diliKatMethodName(v) & ")")
    appendDiliBstr(result, "pk = ", pk)
    appendDiliBstr(result, "sk = ", sk)
    sig = newSeq[uint8](int sigObj[].length_signature)
    requireSuccess(OQS_SIG_sign(sigObj, addr sig[0], addr sigLen, addr msg[0], csize_t(msg.len), addr sk[0]),
      "OQS_SIG_sign(" & diliKatMethodName(v) & ")")
    sig.setLen(int(sigLen))
    sm = combineSignedMessage(sig, msg)
    result.add("smlen = " & $sm.len & "\n")
    appendDiliBstr(result, "sm = ", sm)

proc diliKatRepoRoot(): string =
  result = parentDir(parentDir(currentSourcePath()))

proc diliKatJsonPath(): string =
  result = joinPath(diliKatRepoRoot(), "..", "liboqs", "tests", "KATs", "sig", "kats.json")

proc loadExpectedDiliKatHash(name: string): string =
  let node = parseJson(readFile(diliKatJsonPath()))
  result = node[name]["single"].getStr().toLowerAscii()

proc writeTempDiliKatFile(name, data: string): string =
  result = joinPath(getTempDir(), "tyr_" & name & "_kat.txt")
  writeFile(result, data)

proc sha256HexForDiliFile(path: string): string =
  let escaped = path.replace("'", "''")
  let output = execProcess(
    "powershell -NoProfile -Command \"(Get-FileHash -Algorithm SHA256 -LiteralPath '" &
    escaped & "').Hash.ToLowerInvariant()\"")
  result = output.strip().toLowerAscii()

suite "dilithium kat":
  when defined(hasLibOqs) and defined(release):
    test "liboqs ML-DSA KAT hashes match local corpus and pure transcript":
      for v in [custom_dilithium.dilithium44, custom_dilithium.dilithium65, custom_dilithium.dilithium87]:
        let liboqsTranscript = diliTranscriptForLiboqsKat(v)
        let pureTranscript = diliTranscriptForPureKat(v)
        let katPath = writeTempDiliKatFile(diliKatMethodName(v), liboqsTranscript)
        defer:
          if fileExists(katPath):
            removeFile(katPath)
        check sha256HexForDiliFile(katPath) == loadExpectedDiliKatHash(diliKatMethodName(v))
        check pureTranscript == liboqsTranscript
  else:
    test "dilithium KAT corpus check requires release plus liboqs runtime":
      checkpoint("Dilithium KAT corpus comparison is enabled only for release builds with liboqs")
