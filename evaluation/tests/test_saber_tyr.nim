## ----------------------------------------------------------------
## SABER Tyr Tests <- official KAT vectors and AVX2-core parity
## ----------------------------------------------------------------

import std/[os, strutils, unittest]

import ./helpers
import ../../src/tyr/kems/saber as custom_saber
import ../../src/tyr/helpers/common/pq_rng as pqc
import ../../src/tyr/hashes/sha3 as tyr_sha3

type
  SaberKatCase = object
    seed: seq[byte]
    publicKey: seq[byte]
    secretKey: seq[byte]
    ciphertext: seq[byte]
    sharedSecret: seq[byte]

proc fillSaberSeed(S: var seq[byte], base: int) =
  var
    i: int = 0
  i = 0
  while i < S.len:
    S[i] = byte((base + i) mod 256)
    i = i + 1

proc saberVectorPath(v: custom_saber.SaberVariant): string =
  var
    dir: string = ""
  dir = joinPath(parentDir(currentSourcePath()), "vectors", "saber")
  case v
  of custom_saber.lightSaber:
    result = joinPath(dir, "lightsaber_PQCkemKAT_1568.rsp")
  of custom_saber.saber:
    result = joinPath(dir, "saber_PQCkemKAT_2304.rsp")
  of custom_saber.fireSaber:
    result = joinPath(dir, "firesaber_PQCkemKAT_3040.rsp")

proc assignSaberKatField(C: var SaberKatCase, key, value: string) =
  if key == "seed":
    C.seed = hexToBytes(value)
    return
  if key == "pk":
    C.publicKey = hexToBytes(value)
    return
  if key == "sk":
    C.secretKey = hexToBytes(value)
    return
  if key == "ct":
    C.ciphertext = hexToBytes(value)
    return
  if key == "ss":
    C.sharedSecret = hexToBytes(value)
    return

proc loadFirstSaberKat(v: custom_saber.SaberVariant): SaberKatCase =
  var
    line: string = ""
    eqPos: int = -1
    key: string = ""
    value: string = ""
  for rawLine in lines(saberVectorPath(v)):
    line = rawLine.strip()
    eqPos = line.find('=')
    if eqPos < 0:
      continue
    key = line[0 ..< eqPos].strip()
    value = line[eqPos + 1 .. ^1].strip()
    assignSaberKatField(result, key, value)
  if result.seed.len != pqc.pqKatSeedBytes:
    raise newException(ValueError, "invalid SABER KAT seed")

template runSaberRoundtripCase(variant: untyped, keyBase, encBase: int) =
  block:
    var
      p: custom_saber.SaberParams = custom_saber.saberParamsTable[variant]
      keySeed: seq[byte] = newSeq[byte](pqc.pqKatSeedBytes)
      encSeed: seq[byte] = newSeq[byte](pqc.pqKatSeedBytes)
      kp: custom_saber.SaberTyrKeypair
      env: custom_saber.SaberTyrCipher
      shared: seq[byte] = @[]
    checkpoint("SABER roundtrip " & p.name)
    fillSaberSeed(keySeed, keyBase)
    fillSaberSeed(encSeed, encBase)
    kp = custom_saber.saberTyrKeypairDerand(variant, keySeed, custom_saber.saberClean)
    env = custom_saber.saberTyrEncapsDerand(variant, kp.publicKey, encSeed,
      custom_saber.saberClean)
    shared = custom_saber.saberTyrDecaps(variant, kp.secretKey, env.ciphertext,
      custom_saber.saberClean)
    check shared == env.sharedSecret
    check kp.publicKey.len == p.publicKeyBytes
    check kp.secretKey.len == p.secretKeyBytes
    check env.ciphertext.len == p.ciphertextBytes
    check env.sharedSecret.len == p.sharedSecretBytes
    pqc.secureClearBytes(keySeed)
    pqc.secureClearBytes(encSeed)
    pqc.secureClearBytes(shared)

template runSaberKatCase(variant: untyped, backend: untyped) =
  block:
    var
      p: custom_saber.SaberParams = custom_saber.saberParamsTable[variant]
      expected: SaberKatCase
      kat: tuple[keypair: custom_saber.SaberTyrKeypair,
        cipher: custom_saber.SaberTyrCipher]
      shared: seq[byte] = @[]
    checkpoint("SABER KAT " & p.name)
    expected = loadFirstSaberKat(variant)
    kat = custom_saber.saberTyrKatKemFromSeed(variant, expected.seed, backend)
    check kat.keypair.publicKey == expected.publicKey
    check kat.keypair.secretKey == expected.secretKey
    check kat.cipher.ciphertext == expected.ciphertext
    check kat.cipher.sharedSecret == expected.sharedSecret
    shared = custom_saber.saberTyrDecaps(variant, kat.keypair.secretKey,
      kat.cipher.ciphertext, backend)
    check shared == expected.sharedSecret
    pqc.secureClearBytes(expected.seed)
    pqc.secureClearBytes(expected.secretKey)
    pqc.secureClearBytes(expected.sharedSecret)
    pqc.secureClearBytes(shared)

suite "saber tyr":
  test "clean SABER roundtrips for all variants":
    runSaberRoundtripCase(custom_saber.lightSaber, 23, 73)
    runSaberRoundtripCase(custom_saber.saber, 29, 79)
    runSaberRoundtripCase(custom_saber.fireSaber, 31, 83)

  test "invalid SABER ciphertext uses deterministic implicit rejection":
    var
      v = custom_saber.lightSaber
      p: custom_saber.SaberParams = custom_saber.saberParamsTable[v]
      keySeed: seq[byte] = newSeq[byte](pqc.pqKatSeedBytes)
      encSeed: seq[byte] = newSeq[byte](pqc.pqKatSeedBytes)
      kp: custom_saber.SaberTyrKeypair
      env: custom_saber.SaberTyrCipher
      tampered: seq[byte] = @[]
      allZero: seq[byte] = @[]
      allFf: seq[byte] = @[]
      fallbackInput: seq[byte] = @[]
      ctHash: seq[byte] = @[]
      expectedZero: seq[byte] = @[]
      bad0: seq[byte] = @[]
      bad1: seq[byte] = @[]
      zero0: seq[byte] = @[]
      zero1: seq[byte] = @[]
      ff0: seq[byte] = @[]
      ff1: seq[byte] = @[]
      i: int = 0
    fillSaberSeed(keySeed, 107)
    fillSaberSeed(encSeed, 157)
    kp = custom_saber.saberTyrKeypairDerand(v, keySeed,
      custom_saber.saberClean)
    env = custom_saber.saberTyrEncapsDerand(v, kp.publicKey, encSeed,
      custom_saber.saberClean)
    expect ValueError:
      discard custom_saber.saberTyrDecaps(v, kp.secretKey, @[],
        custom_saber.saberClean)
    expect ValueError:
      discard custom_saber.saberTyrDecaps(v, kp.secretKey,
        newSeq[byte](p.ciphertextBytes - 1), custom_saber.saberClean)
    expect ValueError:
      discard custom_saber.saberTyrDecaps(v, kp.secretKey,
        newSeq[byte](p.ciphertextBytes + 1), custom_saber.saberClean)
    tampered = env.ciphertext
    tampered[0] = tampered[0] xor 1'u8
    bad0 = custom_saber.saberTyrDecaps(v, kp.secretKey, tampered,
      custom_saber.saberClean)
    bad1 = custom_saber.saberTyrDecaps(v, kp.secretKey, tampered,
      custom_saber.saberClean)
    check bad0.len == p.sharedSecretBytes
    check bad0 == bad1
    check bad0 != env.sharedSecret
    allZero = newSeq[byte](p.ciphertextBytes)
    allFf = newSeq[byte](p.ciphertextBytes)
    i = 0
    while i < allFf.len:
      allFf[i] = 0xff'u8
      i = i + 1
    ctHash = tyr_sha3.sha3_256(allZero)
    fallbackInput = newSeq[byte](2 * custom_saber.saberKeyBytes)
    i = 0
    while i < custom_saber.saberKeyBytes:
      fallbackInput[i] = kp.secretKey[
        p.secretKeyBytes - custom_saber.saberKeyBytes + i]
      fallbackInput[custom_saber.saberKeyBytes + i] = ctHash[i]
      i = i + 1
    expectedZero = tyr_sha3.sha3_256(fallbackInput)
    zero0 = custom_saber.saberTyrDecaps(v, kp.secretKey, allZero,
      custom_saber.saberClean)
    zero1 = custom_saber.saberTyrDecaps(v, kp.secretKey, allZero,
      custom_saber.saberClean)
    ff0 = custom_saber.saberTyrDecaps(v, kp.secretKey, allFf,
      custom_saber.saberClean)
    ff1 = custom_saber.saberTyrDecaps(v, kp.secretKey, allFf,
      custom_saber.saberClean)
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
    test "file-backed SABER KAT vectors remain host-only":
      checkpoint("Android harness runs SABER roundtrip and rejection regressions")
  else:
    test "clean SABER matches official reference KAT vectors":
      runSaberKatCase(custom_saber.lightSaber, custom_saber.saberClean)
      runSaberKatCase(custom_saber.saber, custom_saber.saberClean)
      runSaberKatCase(custom_saber.fireSaber, custom_saber.saberClean)

  when defined(avx2):
    test "AVX2 multiplication core matches official reference KAT vectors":
      runSaberKatCase(custom_saber.lightSaber, custom_saber.saberAvx2)
      runSaberKatCase(custom_saber.saber, custom_saber.saberAvx2)
      runSaberKatCase(custom_saber.fireSaber, custom_saber.saberAvx2)
