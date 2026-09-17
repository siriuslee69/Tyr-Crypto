## ---------------------------------------------------------------------
## | HQC KAT <- checking against the published known-answer vectors     |
## ---------------------------------------------------------------------
##
## What a known-answer test proves
## -------------------------------
## A round-trip test only proves the code agrees with itself. A
## known-answer test proves it agrees with everyone else: same seed in,
## byte-for-byte the same public key, secret key, ciphertext and shared
## secret out as the reference implementation.
##
## How the seed becomes a transcript
## ---------------------------------
## HQC does not use the AES generator the other families use. Its vectors
## are produced from a SHAKE-256 stream, so this file rebuilds that:
##
##   entropy 00 01 02 ... 2F
##        |
##        |  SHAKE-256( entropy || 00 )
##        v
##   outer stream ---- 48 bytes per record ----> seed
##                                                 |
##                                SHAKE-256( seed || 00 )
##                                                 v
##                                       inner stream
##                                       [0 .. 31]  keypair
##                                       [32 ..  ]  message, then salt
##
## Each record is then printed in the NIST response-file layout and the
## whole transcript is hashed:
##
##   count = 0
##   seed = <96 hex digits>
##   pk = ...
##   sk = ...
##   ct = ...
##   ss = ...
##
## The expected hashes live in the pinned liboqs checkout under
## `submodules/`, which carries the same HQC version this port follows.
##
## Reference: [HQC-20250822] published known-answer values; transcript
## layout from liboqs `tests/kat_kem.c` and its SHAKE-256 KAT generator
## in `tests/test_helpers.c`.

import std/[json, os, strutils, unittest]

import runePragmas
import ../paths
import ../../src/tyr/hashes/sha256/sha256
import ../../src/tyr/hashes/sha3 as tyr_sha3
import ../../src/tyr/kems/hqc as custom_hqc

const
  hqcKatPrngDomain = 0'u8
    ## The tag byte the HQC vector generator appends to its seed.
  hqcKatSeedBytes = 48
    ## Every record starts from 48 bytes of the outer stream.
  hqcKatFullCounts = 100
    ## How many records the published "all" hash covers.

## Reference: [HQC-20250822] known-answer vector generation; seeded stream for `hqcKatStream`; pitfall: the tag byte goes after the seed, and the stream must be one continuous squeeze.
proc hqcKatStream(seed: openArray[byte], outLen: int): seq[byte] {.role: {dataFetcher}.} =
  ## seed/outLen: what to stretch, and how many bytes are wanted.
  ## The SHAKE-256 stream the HQC vector generator uses.
  var
    input: seq[byte] = @[]
    i: int = 0
  input = newSeq[byte](seed.len + 1)
  while i < seed.len:
    input[i] = seed[i]
    i = i + 1
  input[seed.len] = hqcKatPrngDomain
  result = shake256(input, outLen)

## Reference: [HQC-20250822] known-answer vector layout; hexadecimal rendering for `appendHqcHexUpper`; pitfall: the layout uses upper case, and an empty field prints as `00`.
proc appendHqcHexUpper(dst: var string, A: openArray[byte]) {.role: {dataWriter}.} =
  ## dst/A: the transcript being built, and the bytes to render.
  const
    lut = "0123456789ABCDEF"
  var
    i: int = 0
  if A.len == 0:
    dst.add("00")
    return
  while i < A.len:
    dst.add(lut[int(A[i] shr 4)])
    dst.add(lut[int(A[i] and 0x0f'u8)])
    i = i + 1

## Reference: [HQC-20250822] known-answer vector layout; one labelled line for `appendHqcBstr`; pitfall: every line ends with a newline, including the last one of a record.
proc appendHqcBstr(dst: var string, label: string, A: openArray[byte])
    {.role: {dataWriter}.} =
  ## dst/label/A: the transcript, the field name, and its bytes.
  dst.add(label)
  appendHqcHexUpper(dst, A)
  dst.add("\n")

## Reference: [HQC-20250822] known-answer vector generation; transcript construction for `hqcTranscript`; pitfall: a blank line separates records but must not follow the last one.
proc hqcTranscript(v: custom_hqc.HqcVariant, counts: int): string
    {.role: {orchestrator}.} =
  ## v/counts: the parameter set, and how many records to produce.
  ## Rebuild the published response file and check every shared secret
  ## survives its own round trip on the way.
  var
    p: custom_hqc.HqcParams = params(v)
    entropy: seq[byte] = @[]
    outer: seq[byte] = @[]
    seed48: seq[byte] = @[]
    inner: seq[byte] = @[]
    kp = default(custom_hqc.HqcTyrKeypair)
    env = default(custom_hqc.HqcTyrCipher)
    shared: seq[byte] = @[]
    count: int = 0
    i: int = 0
  entropy = newSeq[byte](hqcKatSeedBytes)
  i = 0
  while i < hqcKatSeedBytes:
    entropy[i] = byte(i)
    i = i + 1
  outer = hqcKatStream(entropy, hqcKatSeedBytes * counts)
  count = 0
  while count < counts:
    seed48 = outer[hqcKatSeedBytes * count ..< hqcKatSeedBytes * (count + 1)]
    inner = hqcKatStream(seed48, p.keypairRandomBytes + p.encapsRandomBytes)
    kp = custom_hqc.hqcTyrKeypairDerand(v, inner[0 ..< p.keypairRandomBytes])
    env = custom_hqc.hqcTyrEncapsDerand(v, kp.publicKey,
      inner[p.keypairRandomBytes ..< p.keypairRandomBytes + p.encapsRandomBytes])
    shared = custom_hqc.hqcTyrDecaps(v, kp.secretKey, env.ciphertext)
    check shared == env.sharedSecret
    result.add("count = " & $count & "\n")
    appendHqcBstr(result, "seed = ", seed48)
    appendHqcBstr(result, "pk = ", kp.publicKey)
    appendHqcBstr(result, "sk = ", kp.secretKey)
    appendHqcBstr(result, "ct = ", env.ciphertext)
    appendHqcBstr(result, "ss = ", env.sharedSecret)
    if count != counts - 1:
      result.add("\n")
    count = count + 1

## Reference: [HQC-20250822] known-answer vector corpus; corpus lookup for `hqcKatJsonPath`; pitfall: the workspace also holds an older liboqs whose HQC predates this specification, so the pinned submodule is the only correct source.
proc hqcKatJsonPath(): string {.role: {parser}.} =
  ## Where the pinned expected hashes live.
  result = joinPath(repoRootFrom(currentSourcePath()), "submodules",
    "cNimWrapper", "submodules", "liboqs", "tests", "KATs", "kem", "kats.json")

## Reference: [HQC-20250822] known-answer vector corpus; expected-hash lookup for `hqcExpectedKatHash`; pitfall: the corpus keys are the liboqs algorithm names, not the Tyr variant names.
proc hqcExpectedKatHash(name, field: string): string {.role: {parser}.} =
  ## name/field: the liboqs algorithm name, and "single" or "all".
  result = parseJson(readFile(hqcKatJsonPath()))[name][field].getStr().toLowerAscii()

## Reference: [HQC-20250822] known-answer vector comparison; transcript fingerprint for `hqcTranscriptHash`; pitfall: the transcript is hashed as raw bytes, exactly as written to a file.
proc hqcTranscriptHash(t: string): string {.role: {math}.} =
  ## t: the rendered transcript.
  var
    digest = default(Sha256Digest)
    i: int = 0
  digest = sha256Hash(cast[seq[byte]](t))
  while i < digest.len:
    result.add(toHex(int(digest[i]), 2).toLowerAscii())
    i = i + 1

suite "hqc kat":
  # {.testKind: tkRegression.}
  test "HQC-1 single KAT hash matches the published corpus":
    check hqcTranscriptHash(hqcTranscript(custom_hqc.hqc1, 1)) ==
      hqcExpectedKatHash("HQC-1", "single")

  # {.testKind: tkRegression.}
  test "HQC-3 single KAT hash matches the published corpus":
    check hqcTranscriptHash(hqcTranscript(custom_hqc.hqc3, 1)) ==
      hqcExpectedKatHash("HQC-3", "single")

  # {.testKind: tkRegression.}
  test "HQC-5 single KAT hash matches the published corpus":
    check hqcTranscriptHash(hqcTranscript(custom_hqc.hqc5, 1)) ==
      hqcExpectedKatHash("HQC-5", "single")

  when defined(tyrHqcFullKat):
    ## All hundred records per parameter set. Slow enough to want a
    ## release build, which is what the `test_hqc_kat_full` task does.
    # {.testKind: tkRegression.}
    test "HQC-1 all-100 KAT hash matches the published corpus":
      check hqcTranscriptHash(hqcTranscript(custom_hqc.hqc1, hqcKatFullCounts)) ==
        hqcExpectedKatHash("HQC-1", "all")

    # {.testKind: tkRegression.}
    test "HQC-3 all-100 KAT hash matches the published corpus":
      check hqcTranscriptHash(hqcTranscript(custom_hqc.hqc3, hqcKatFullCounts)) ==
        hqcExpectedKatHash("HQC-3", "all")

    # {.testKind: tkRegression.}
    test "HQC-5 all-100 KAT hash matches the published corpus":
      check hqcTranscriptHash(hqcTranscript(custom_hqc.hqc5, hqcKatFullCounts)) ==
        hqcExpectedKatHash("HQC-5", "all")

