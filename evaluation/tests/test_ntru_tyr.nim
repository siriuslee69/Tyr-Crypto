## -------------------------------------------------------------
## NTRU Tyr Tests <- roundtrip, KAT hash, and optional AVX2 parity
## -------------------------------------------------------------

import std/[json, os, strutils, unittest]
import ../paths

import ../../src/tyr/kems/ntru as custom_ntru
import ../../src/tyr/hashes/sha256
import ../../src/tyr/helpers/common/pq_rng as pqc
import ../../src/tyr/hashes/sha3 as tyr_sha3

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
  result = repoRootFrom(currentSourcePath())

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
  const lut = "0123456789abcdef"
  var
    data: string = readFile(path)
    bytes: seq[byte] = newSeq[byte](data.len)
    digest: Sha256Digest
    i: int = 0
  while i < data.len:
    bytes[i] = byte(ord(data[i]))
    i = i + 1
  digest = sha256Hash(bytes)
  result = newStringOfCap(digest.len * 2)
  i = 0
  while i < digest.len:
    result.add(lut[int(digest[i] shr 4)])
    result.add(lut[int(digest[i] and 0x0f'u8)])
    i = i + 1

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

  test "invalid NTRU ciphertext uses deterministic implicit rejection":
    var
      v = custom_ntru.ntruHps2048509
      p: custom_ntru.NtruParams = custom_ntru.ntruParamsTable[v]
      keySeed: seq[byte] = newSeq[byte](pqc.pqKatSeedBytes)
      encSeed: seq[byte] = newSeq[byte](pqc.pqKatSeedBytes)
      kp: custom_ntru.NtruTyrKeypair
      env: custom_ntru.NtruTyrCipher
      tampered: seq[byte] = @[]
      allZero: seq[byte] = @[]
      allFf: seq[byte] = @[]
      fallbackInput: seq[byte] = @[]
      expectedZero: seq[byte] = @[]
      bad0: seq[byte] = @[]
      bad1: seq[byte] = @[]
      zero0: seq[byte] = @[]
      zero1: seq[byte] = @[]
      ff0: seq[byte] = @[]
      ff1: seq[byte] = @[]
      i: int = 0
    fillNtruSeed(keySeed, 101)
    fillNtruSeed(encSeed, 151)
    kp = custom_ntru.ntruTyrKeypairDerand(v, keySeed,
      custom_ntru.ntruClean)
    env = custom_ntru.ntruTyrEncapsDerand(v, kp.publicKey, encSeed,
      custom_ntru.ntruClean)
    expect ValueError:
      discard custom_ntru.ntruTyrDecaps(v, kp.secretKey, @[],
        custom_ntru.ntruClean)
    expect ValueError:
      discard custom_ntru.ntruTyrDecaps(v, kp.secretKey,
        newSeq[byte](p.ciphertextBytes - 1), custom_ntru.ntruClean)
    expect ValueError:
      discard custom_ntru.ntruTyrDecaps(v, kp.secretKey,
        newSeq[byte](p.ciphertextBytes + 1), custom_ntru.ntruClean)
    tampered = env.ciphertext
    tampered[0] = tampered[0] xor 1'u8
    bad0 = custom_ntru.ntruTyrDecaps(v, kp.secretKey, tampered,
      custom_ntru.ntruClean)
    bad1 = custom_ntru.ntruTyrDecaps(v, kp.secretKey, tampered,
      custom_ntru.ntruClean)
    check bad0.len == p.sharedSecretBytes
    check bad0 == bad1
    check bad0 != env.sharedSecret
    allZero = newSeq[byte](p.ciphertextBytes)
    allFf = newSeq[byte](p.ciphertextBytes)
    i = 0
    while i < allFf.len:
      allFf[i] = 0xff'u8
      i = i + 1
    fallbackInput = newSeq[byte](custom_ntru.ntruPrfKeyBytes +
      p.ciphertextBytes)
    i = 0
    while i < custom_ntru.ntruPrfKeyBytes:
      fallbackInput[i] = kp.secretKey[p.owcpaSecretKeyBytes + i]
      i = i + 1
    i = 0
    while i < p.ciphertextBytes:
      fallbackInput[custom_ntru.ntruPrfKeyBytes + i] = allZero[i]
      i = i + 1
    expectedZero = tyr_sha3.sha3_256(fallbackInput)
    zero0 = custom_ntru.ntruTyrDecaps(v, kp.secretKey, allZero,
      custom_ntru.ntruClean)
    zero1 = custom_ntru.ntruTyrDecaps(v, kp.secretKey, allZero,
      custom_ntru.ntruClean)
    ff0 = custom_ntru.ntruTyrDecaps(v, kp.secretKey, allFf,
      custom_ntru.ntruClean)
    ff1 = custom_ntru.ntruTyrDecaps(v, kp.secretKey, allFf,
      custom_ntru.ntruClean)
    check zero0 == zero1
    check zero0 == expectedZero
    check zero0 != env.sharedSecret
    check ff0 == ff1
    check ff0 != env.sharedSecret
    pqc.secureClearBytes(keySeed)
    pqc.secureClearBytes(encSeed)
    pqc.secureClearBytes(bad0)
    pqc.secureClearBytes(bad1)
    pqc.secureClearBytes(zero0)
    pqc.secureClearBytes(zero1)
    pqc.secureClearBytes(ff0)
    pqc.secureClearBytes(ff1)

  when defined(tyrAndroidHarness):
    test "file-backed NTRU KAT hashes remain host-only":
      checkpoint("Android harness runs NTRU roundtrip and rejection regressions")
  elif defined(ntruIsoSample):
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
