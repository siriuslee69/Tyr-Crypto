## ----------------------------------------------------------------
## SABER Tyr Tests <- official KAT vectors and AVX2-core parity
## ----------------------------------------------------------------

import std/[os, strutils, unittest]

import ./helpers
import ../src/protocols/custom_crypto/saber as custom_saber
import ../src/protocols/custom_crypto/asymmetric/pq/common/pq_rng as pqc

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

  test "clean SABER matches official reference KAT vectors":
    runSaberKatCase(custom_saber.lightSaber, custom_saber.saberClean)
    runSaberKatCase(custom_saber.saber, custom_saber.saberClean)
    runSaberKatCase(custom_saber.fireSaber, custom_saber.saberClean)

  when defined(avx2):
    test "AVX2 multiplication core matches official reference KAT vectors":
      runSaberKatCase(custom_saber.lightSaber, custom_saber.saberAvx2)
      runSaberKatCase(custom_saber.saber, custom_saber.saberAvx2)
      runSaberKatCase(custom_saber.fireSaber, custom_saber.saberAvx2)
