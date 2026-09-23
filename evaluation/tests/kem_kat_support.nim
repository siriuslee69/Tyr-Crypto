## ---------------------------------------------------------------------
## | KEM KAT support <- shared scaffolding for the known-answer tests    |
## | NIST seed -> transcript text -> SHA-256 -> compare with liboqs list |
## ---------------------------------------------------------------------
##
## What a known-answer test proves
## -------------------------------
## A round-trip test only proves the code agrees with itself. A
## known-answer test proves it agrees with everyone else: the same seed
## in gives byte-for-byte the same keys, ciphertext and shared secret out
## as the reference implementation.
##
## How one record is built
## -----------------------
##
##   entropy 00 01 02 ... 2F
##        |  NIST AES-256-CTR generator ("root")
##        v
##   seed (48 bytes) ------------------------> printed as "seed = ..."
##        |  NIST generator again ("record")
##        v
##   keypair bytes, then encapsulation bytes, in the order the KEM asks
##
## The record is printed in the NIST response-file layout:
##
##   count = 0
##   seed = <96 hex digits>
##   pk = ...
##   sk = ...
##   ct = ...
##   ss = ...
##
## and the SHA-256 of that text is compared with the "single" value
## liboqs publishes in `tests/KATs/kem/kats.json`. No liboqs library is
## needed, only that file, so these tests always run.
##
## Which list
## ----------
## The pinned checkout under `submodules/cNimWrapper/submodules/liboqs`
## is the one source. It is liboqs 0.16, where the unsalted FrodoKEM that
## Tyr implements is listed as `eFrodoKEM-*`; plain `FrodoKEM-*` there is
## the newer salted ISO version.

import std/[json, os, strutils]

import runePragmas
import ../paths
import ../../src/tyr/hashes/sha256/sha256
import ../../src/tyr/helpers/common/pq_rng

export pq_rng.PqNistDrbgState, pq_rng.initNistDrbg, pq_rng.nistDrbgRandomBytes

const
  kemKatSeedBytes* = 48
    ## Every record starts from 48 bytes of the root generator.

proc kemKatRootSeed*(): seq[byte] {.role: {dataFetcher}.} =
  ## The 48-byte seed of record 0: entropy 00..2F through the NIST generator.
  var
    entropy = default(array[kemKatSeedBytes, byte])
    root = default(PqNistDrbgState)
    i: int = 0
  while i < kemKatSeedBytes:
    entropy[i] = byte(i)
    i = i + 1
  root = initNistDrbg(entropy)
  result = nistDrbgRandomBytes(root, kemKatSeedBytes)

proc appendKatField*(dst: var string, label: string, A: openArray[byte])
    {.role: {dataWriter}.} =
  ## dst/label/A: the transcript, the "pk = " style label, the bytes.
  ## Append one line as upper-case hex. An empty field prints "00", as the
  ## reference generator does.
  const
    lut = "0123456789ABCDEF"
  var
    i: int = 0
  dst.add(label)
  if A.len == 0:
    dst.add("00")
  while i < A.len:
    dst.add(lut[int(A[i] shr 4)])
    dst.add(lut[int(A[i] and 0x0f'u8)])
    i = i + 1
  dst.add("\n")

proc kemKatJsonPath*(): string {.role: {parser}.} =
  ## Where the pinned expected hashes live.
  result = joinPath(repoRootFrom(currentSourcePath()), "submodules",
    "cNimWrapper", "submodules", "liboqs", "tests", "KATs", "kem", "kats.json")

proc kemKatExpectedHash*(name: string, field: string = "single"): string
    {.role: {parser}.} =
  ## name/field: the liboqs algorithm name, and "single" or "all".
  var
    node = parseJson(readFile(kemKatJsonPath()))
  if not node.hasKey(name):
    raise newException(KeyError, "no known-answer entry for " & name)
  result = node[name][field].getStr().toLowerAscii()

proc kemKatTranscriptHash*(t: string): string {.role: {math}.} =
  ## t: the rendered transcript, hashed as the raw bytes of the text.
  var
    digest = default(Sha256Digest)
    i: int = 0
  digest = sha256Hash(cast[seq[byte]](t))
  while i < digest.len:
    result.add(toHex(int(digest[i]), 2).toLowerAscii())
    i = i + 1
