## -------------------------------------------------------------
## NTRU Tyr Tests <- roundtrip, KAT hash, and optional AVX2 parity
## -------------------------------------------------------------

import std/[json, os, osproc, strutils, unittest]

import ../src/protocols/custom_crypto/ntru as custom_ntru
import ../src/protocols/custom_crypto/asymmetric/pq/common/pq_rng as pqc

const
  ntruKatEntropyLen = 48
  ntruKatSeedLen = 48

proc fillNtruSeed(S: var seq[byte], base: int) =
  var
    i: int = 0
  i = 0
  while i < S.len:
    S[i] = byte((base + i) mod 256)
    i = i + 1

proc ntruRootKatSeed(): seq[byte] =
  var
    entropy: array[ntruKatEntropyLen, byte]
    root: pqc.PqNistDrbgState
    i: int = 0
  i = 0
  while i < ntruKatEntropyLen:
    entropy[i] = byte(i)
    i = i + 1
  root = pqc.initNistDrbg(entropy)
  result = pqc.nistDrbgRandomBytes(root, ntruKatSeedLen)
  pqc.secureClearBytes(root.key)
  pqc.secureClearBytes(root.v)
  pqc.secureClearBytes(entropy)

proc appendNtruHexUpper(dst: var string, A: openArray[byte]) =
  const
    lut = "0123456789ABCDEF"
  var
    i: int = 0
    b: byte = 0
  i = 0
  while i < A.len:
    b = A[i]
    dst.add(lut[int(b shr 4)])
    dst.add(lut[int(b and 0x0f'u8)])
    i = i + 1

proc appendNtruBstr(dst: var string, label: string, A: openArray[byte]) =
  dst.add(label)
  appendNtruHexUpper(dst, A)
  dst.add("\n")

proc ntruTranscriptForKat(v: custom_ntru.NtruVariant,
    backend: custom_ntru.NtruBackend): string =
  var
    seed48: seq[byte] = @[]
    kat: tuple[keypair: custom_ntru.NtruTyrKeypair, cipher: custom_ntru.NtruTyrCipher]
    shared: seq[byte] = @[]
  seed48 = ntruRootKatSeed()
  result.add("count = 0\n")
  appendNtruBstr(result, "seed = ", seed48)
  kat = custom_ntru.ntruTyrKatKemFromSeed(v, seed48, backend)
  appendNtruBstr(result, "pk = ", kat.keypair.publicKey)
  appendNtruBstr(result, "sk = ", kat.keypair.secretKey)
  appendNtruBstr(result, "ct = ", kat.cipher.ciphertext)
  appendNtruBstr(result, "ss = ", kat.cipher.sharedSecret)
  shared = custom_ntru.ntruTyrDecaps(v, kat.keypair.secretKey,
    kat.cipher.ciphertext, backend)
  check shared == kat.cipher.sharedSecret
  pqc.secureClearBytes(seed48)
  pqc.secureClearBytes(shared)

proc ntruRepoRoot(): string =
  result = parentDir(parentDir(currentSourcePath()))

proc ntruKatJsonPath(): string =
  var
    envSource: string = getEnv("LIBOQS_SOURCE").strip()
    candidates: seq[string] = @[]
    p: string = ""
    i: int = 0
  if envSource.len > 0:
    candidates.add(joinPath(envSource, "tests", "KATs", "kem", "kats.json"))
  candidates.add(joinPath(ntruRepoRoot(), "submodules", "liboqs", "tests", "KATs",
    "kem", "kats.json"))
  candidates.add(joinPath(ntruRepoRoot(), "..", "liboqs", "tests", "KATs", "kem",
    "kats.json"))
  candidates.add(joinPath(getCurrentDir(), "submodules", "liboqs", "tests", "KATs",
    "kem", "kats.json"))
  candidates.add(joinPath(getCurrentDir(), "..", "liboqs", "tests", "KATs", "kem",
    "kats.json"))
  i = 0
  while i < candidates.len:
    p = absolutePath(candidates[i])
    if fileExists(p):
      return p
    i = i + 1
  raise newException(IOError, "cannot find liboqs NTRU KAT corpus")

proc loadExpectedNtruKatHash(name: string): string =
  var
    node: JsonNode
  node = parseJson(readFile(ntruKatJsonPath()))
  result = node[name]["single"].getStr().toLowerAscii()

proc writeNtruTempKatFile(name, data: string): string =
  result = joinPath(getTempDir(), "tyr_" & name & "_kat.txt")
  writeFile(result, data)

proc ntruSha256HexForFile(path: string): string =
  when defined(windows):
    var
      escaped: string = ""
      output: string = ""
    escaped = path.replace("'", "''")
    output = execProcess(
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

template runNtruRoundtripCase(variant: untyped, keyBase, encBase: int) =
  block:
    var
      p: custom_ntru.NtruParams = custom_ntru.ntruParamsTable[variant]
      keySeed: seq[byte] = newSeq[byte](pqc.pqKatSeedBytes)
      encSeed: seq[byte] = newSeq[byte](pqc.pqKatSeedBytes)
      kp: custom_ntru.NtruTyrKeypair
      env: custom_ntru.NtruTyrCipher
      shared: seq[byte] = @[]
    checkpoint("NTRU roundtrip " & p.name)
    fillNtruSeed(keySeed, keyBase)
    fillNtruSeed(encSeed, encBase)
    kp = custom_ntru.ntruTyrKeypairDerand(variant, keySeed, custom_ntru.ntruClean)
    env = custom_ntru.ntruTyrEncapsDerand(variant, kp.publicKey, encSeed,
      custom_ntru.ntruClean)
    shared = custom_ntru.ntruTyrDecaps(variant, kp.secretKey, env.ciphertext,
      custom_ntru.ntruClean)
    check shared == env.sharedSecret
    check kp.publicKey.len == p.publicKeyBytes
    check kp.secretKey.len == p.secretKeyBytes
    check env.ciphertext.len == p.ciphertextBytes
    check env.sharedSecret.len == p.sharedSecretBytes
    pqc.secureClearBytes(keySeed)
    pqc.secureClearBytes(encSeed)
    pqc.secureClearBytes(shared)

template runNtruKatCase(variant: untyped) =
  block:
    var
      p: custom_ntru.NtruParams = custom_ntru.ntruParamsTable[variant]
      transcript: string = ""
      katPath: string = ""
    checkpoint("NTRU KAT " & p.katName)
    transcript = ntruTranscriptForKat(variant, custom_ntru.ntruClean)
    katPath = writeNtruTempKatFile(p.name, transcript)
    defer:
      if fileExists(katPath):
        removeFile(katPath)
    check ntruSha256HexForFile(katPath) == loadExpectedNtruKatHash(p.katName)

template runNtruAvx2ParityCase(variant: untyped) =
  block:
    var
      p: custom_ntru.NtruParams = custom_ntru.ntruParamsTable[variant]
      cleanTranscript: string = ""
      avx2Transcript: string = ""
    checkpoint("NTRU AVX2 parity " & p.name)
    cleanTranscript = ntruTranscriptForKat(variant, custom_ntru.ntruClean)
    avx2Transcript = ntruTranscriptForKat(variant, custom_ntru.ntruAvx2)
    check avx2Transcript == cleanTranscript

suite "ntru tyr":
  test "clean NTRU roundtrips for all variants":
    runNtruRoundtripCase(custom_ntru.ntruHps2048509, 11, 61)
    runNtruRoundtripCase(custom_ntru.ntruHps2048677, 13, 63)
    runNtruRoundtripCase(custom_ntru.ntruHps4096821, 17, 67)
    runNtruRoundtripCase(custom_ntru.ntruHrss701, 19, 69)

  when defined(ntruIsoSample):
    test "NTRU KAT hashes are skipped for the experimental shuffling sampler":
      checkpoint("ntruIsoSample changes HPS deterministic KAT transcripts")
  else:
    test "clean NTRU single KAT hashes match the liboqs corpus":
      runNtruKatCase(custom_ntru.ntruHps2048509)
      runNtruKatCase(custom_ntru.ntruHps2048677)
      runNtruKatCase(custom_ntru.ntruHps4096821)
      runNtruKatCase(custom_ntru.ntruHrss701)

  when custom_ntru.ntruAvx2Build:
    test "AVX2 NTRU transcripts match clean transcripts":
      runNtruAvx2ParityCase(custom_ntru.ntruHps2048509)
      runNtruAvx2ParityCase(custom_ntru.ntruHps2048677)
      runNtruAvx2ParityCase(custom_ntru.ntruHps4096821)
      runNtruAvx2ParityCase(custom_ntru.ntruHrss701)
  elif defined(avx2):
    test "AVX2 NTRU backend is disabled on this platform":
      checkpoint("PQClean NTRU AVX2 assembly is enabled only on x86_64 Linux/Darwin")
