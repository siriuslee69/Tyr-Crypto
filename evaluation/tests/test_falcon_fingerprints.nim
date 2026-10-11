## ============================================================
## | Falcon Fingerprints <- frozen outputs of keygen and sign |
## ============================================================
##
## Falcon has no official answer file in this repo, so a rewrite of
## keygen or signing could change every output and the round-trip tests
## would still pass (a new key still verifies its own signature).
## This file pins the exact bytes instead:
##
##   fixed seed / fixed "random" bytes
##     -> keygen  -> public key, secret key  --\
##     -> sign    -> signature                ---> one 64-bit fingerprint
##     -> prepare -> prepared signature      --/
##
## The fingerprint is FNV-1a over all of those bytes, in that order.
## If a value below changes, an output of Falcon changed. That is only
## correct when the change is a deliberate fix; otherwise it is a bug.

import std/[os, strutils, unittest]

import ../../src/tyr/signatures/falcon as falcon
import ../../src/tyr/signatures/falcon/randomness

import runePragmas

const
  falconFingerprints: array[FalconVariant, uint64] = [
    falcon512: 12972442233676967479'u64,
    falcon1024: 459760415271008815'u64
  ]
  falconSizeNames: array[FalconVariant, string] = ["512", "1024"]

var
  fakeRandomBase: int = 0
  fakeRandomOffset: int = 0

proc fakeRandomBytes(R: ptr uint8, n: csize_t) {.cdecl, role: {dataFetcher}.} =
  ## R/n: buffer to fill with a predictable counting pattern.
  var
    O: ptr UncheckedArray[uint8] = cast[ptr UncheckedArray[uint8]](R)
    i: int = 0
  while i < int(n):
    O[i] = byte((fakeRandomBase + fakeRandomOffset + i) and 0xff)
    i = i + 1
  fakeRandomOffset = fakeRandomOffset + int(n)

proc resetFakeRandom(b: int) {.role: {helper}.} =
  ## b: first byte of the next counting pattern.
  fakeRandomBase = b
  fakeRandomOffset = 0

proc foldBytes(h: var uint64, A: openArray[byte]) {.role: {helper}.} =
  ## h: running FNV-1a fingerprint. A: bytes folded into it.
  var
    i: int = 0
  while i < A.len:
    h = (h xor uint64(A[i])) * 0x100000001b3'u64
    i = i + 1

proc countingBytes(n, s: int): seq[byte] {.role: {helper}.} =
  ## n: length. s: first value of the counting pattern.
  var
    i: int = 0
  result = newSeq[byte](n)
  while i < n:
    result[i] = byte((s + i) and 0xff)
    i = i + 1

proc falconFingerprint(v: FalconVariant, b: FalconBackend): uint64
    {.role: {orchestrator}.} =
  ## v/b: variant and backend run through seeded keygen, random keygen,
  ## signing and prepared signing.
  var
    seed: seq[byte] = countingBytes(48, 0x31)
    msg: seq[byte] = countingBytes(77, 0x07)
    kpSeed, kpRandom: FalconTyrKeypair = FalconTyrKeypair()
    prepared: FalconPreparedSecret = FalconPreparedSecret()
    sig: seq[byte] = @[]
  result = 0xcbf29ce484222325'u64
  falconSetRandombytesCallback(fakeRandomBytes)
  defer:
    falconClearRandombytesCallback()
    falconTyrClearKeypair(kpSeed)
    falconTyrClearKeypair(kpRandom)
    falconTyrClearPreparedSecret(prepared)
  kpSeed = falconTyrKeypair(v, seed, b)
  foldBytes(result, kpSeed.publicKey)
  foldBytes(result, kpSeed.secretKey)
  resetFakeRandom(0x10)
  kpRandom = falconTyrKeypair(v, b)
  foldBytes(result, kpRandom.publicKey)
  foldBytes(result, kpRandom.secretKey)
  resetFakeRandom(0x40)
  sig = falconTyrSign(v, msg, kpSeed.secretKey, b)
  check falconTyrVerify(v, msg, sig, kpSeed.publicKey, b)
  foldBytes(result, sig)
  prepared = falconTyrPrepareSecret(v, kpRandom.secretKey, b)
  resetFakeRandom(0x60)
  sig = falconTyrSignPrepared(prepared, msg)
  check falconTyrVerify(v, msg, sig, kpRandom.publicKey, b)
  foldBytes(result, sig)

proc backendsToCheck(): seq[FalconBackend] {.role: {parser}.} =
  ## Every backend this build can run.
  result = @[falconScalar]
  if backendAvailable(falconSimd):
    result.add(falconSimd)

proc variantMatches(v: FalconVariant): bool {.role: {orchestrator}.} =
  ## v: variant checked on every backend against its frozen fingerprint.
  var
    B: seq[FalconBackend] = backendsToCheck()
    h: uint64 = 0
    i: int = 0
  result = true
  while i < B.len:
    h = falconFingerprint(v, B[i])
    echo "falcon ", v, " ", B[i], " fingerprint ", h
    result = result and h == falconFingerprints[v]
    i = i + 1

proc variantWanted(v: FalconVariant): bool {.role: {parser}.} =
  ## v: variant; TYR_FALCON_TEST_VARIANT=512|1024 picks one (the test runner
  ## splits Falcon into two groups), empty or "all" picks both.
  var
    t: string = getEnv("TYR_FALCON_TEST_VARIANT").strip().toLowerAscii()
  result = t.len == 0 or t == "all" or t == falconSizeNames[v]

suite "falcon fingerprints":
  # {.testKind: tkRegression.}
  test "falcon512 keygen and signing outputs stay byte-identical":
    check not variantWanted(falcon512) or variantMatches(falcon512)

  # {.testKind: tkRegression.}
  test "falcon1024 keygen and signing outputs stay byte-identical":
    check not variantWanted(falcon1024) or variantMatches(falcon1024)
