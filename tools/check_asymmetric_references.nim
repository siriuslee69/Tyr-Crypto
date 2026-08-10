## -------------------------------------------------------------------------
## Asymmetric Reference Check <- citation insertion and verification gate
## -------------------------------------------------------------------------

import std/[algorithm, json, os, sets, strutils]
import metaPragmas
import ./research_paper_downloader

const
  declarationKinds = ["proc ", "func ", "template ", "iterator ",
    "converter ", "method ", "macro "]
  referenceMarker = "## Reference: ["

type
  ReferenceRule = object
    id: string
    part: string

proc normalizedPath(p: string): string {.role: {helper}.} =
  ## Convert platform separators so path rules work on Linux and Windows.
  result = p.replace('\\', '/')

proc isDeclarationLine(s: string): bool {.role: {parser}.} =
  ## Detect one physical line that starts a Nim function-like declaration.
  var
    t: string = s.strip(leading = true, trailing = false)
  for k in declarationKinds:
    if t.startsWith(k):
      return true
  result = false

proc declarationName(s: string): string {.role: {parser}.} =
  ## Extract the declaration name for a human-readable implementation note.
  var
    t: string = s.strip()
    start: int = 0
    i: int = 0
  for k in declarationKinds:
    if t.startsWith(k):
      start = k.len
      break
  i = start
  while i < t.len and (t[i].isAlphaNumeric or t[i] == '_' or t[i] == '`'):
    i = i + 1
  result = t[start ..< i].replace("`", "")

proc modulePart(path: string): string {.role: {parser}.} =
  ## Identify the exact specification area implemented by one source module.
  var
    p: string = normalizedPath(path)
    name: string = splitFile(p).name
  case name
  of "params": result = "parameter-set tables"
  of "operations": result = "key generation, encapsulation/signing, and decapsulation/verification algorithms"
  of "codec", "format", "util": result = "canonical byte and polynomial encoding rules"
  of "sampling", "noise", "cbd": result = "noise, error, and secret sampling rules"
  of "ntt", "reduce", "arith", "fft", "fpr", "gf", "gf2x": result = "finite-field, ring, and transform arithmetic"
  of "poly", "polyvec", "core": result = "polynomial arithmetic and internal algorithm steps"
  of "indcpa": result = "public-key encryption key generation, encryption, and decryption algorithms"
  of "verify", "ct_compare": result = "constant-time comparison and conditional-selection requirements"
  of "hash", "symmetric", "shake": result = "hash, XOF, and domain-separation rules"
  of "rng", "randomness", "pq_rng": result = "random-source and deterministic KAT generation rules"
  of "decode", "decrypt", "vrfy", "pure_verify": result = "decoding, malformed-input rejection, and verification rules"
  of "address", "context": result = "address layout and hash-domain separation"
  of "wots": result = "WOTS+ algorithms"
  of "fors": result = "FORS algorithms"
  of "merkle", "merkle_utils": result = "hypertree and authentication-path algorithms"
  of "keygen", "sk_gen", "pk_gen": result = "key-generation algorithms"
  of "sign": result = "signature generation algorithms"
  of "encrypt": result = "encapsulation error generation and syndrome computation"
  of "benes", "controlbits": result = "Benes network and permutation-control-bit algorithms"
  of "bm", "root", "synd": result = "Goppa decoding and syndrome algorithms"
  of "sort": result = "fixed-schedule sorting used by key generation and sampling"
  of "transpose", "support", "common": result = "portable representation and constant-schedule support"
  else: result = "implementation support for the family algorithms"

proc ruleFor(path: string): ReferenceRule {.role: {parser}.} =
  ## Map each asymmetric family to the exact pinned normative baseline.
  var
    p: string = normalizedPath(path)
  if p.contains("/none_pq/x25519"):
    result = ReferenceRule(id: "RFC-7748", part: "sections 5-6, X25519 and Diffie-Hellman")
    return
  if p.contains("/none_pq/ed25519"):
    result = ReferenceRule(id: "RFC-8032", part: "sections 5.1.1-5.1.7, Ed25519 arithmetic, encoding, signing, and verification")
    return
  if p.contains("/pq/kyber/"):
    result = ReferenceRule(id: "KYBER-R3-20210804", part: "version 3.02 sections 1.3 and 4, algorithms 1-9")
    return
  if p.contains("/pq/dilithium/"):
    result = ReferenceRule(id: "FIPS-204", part: "sections 6-7 and algorithms 1-33")
    return
  if p.contains("/pq/sphincs/"):
    result = ReferenceRule(id: "SPHINCS-R3.1", part: "version 3.1 sections 3-4 and algorithms 1-23")
    return
  if p.contains("/pq/falcon/"):
    result = ReferenceRule(id: "FALCON-SPEC", part: "sections 2-3 and the keygen, signing, verification, and encoding algorithms")
    return
  if p.contains("/pq/frodo/"):
    result = ReferenceRule(id: "FRODOKEM-20250929", part: "parameter tables and the FrodoKEM keygen, encapsulation, and decapsulation algorithms")
    return
  if p.contains("/pq/bike/"):
    result = ReferenceRule(id: "BIKE-5.2", part: "sections 2-4, BIKE KEM and BGF decoder algorithms")
    return
  if p.contains("/pq/mceliece/"):
    result = ReferenceRule(id: "MCELIECE-20221023", part: "sections 2-5 and the implementation-guide keygen, encapsulation, and decapsulation algorithms")
    return
  if p.contains("/pq/ntru/"):
    result = ReferenceRule(id: "NTRU-20190330", part: "sections 1.8 and 2, DPKE and KEM algorithms")
    return
  if p.contains("/pq/saber/"):
    result = ReferenceRule(id: "SABER-R3", part: "sections 4-6, algorithms 1-9")
    return
  result = ReferenceRule(id: "PQ-SUPPORT", part: "FIPS 202 XOF use and SP 800-90A deterministic KAT support")

proc pitfallFor(name, path: string): string {.role: {parser}.} =
  ## State the invariant most likely to be broken in this declaration.
  var
    n: string = name.toLowerAscii()
    p: string = normalizedPath(path).toLowerAscii()
  if n.contains("decode") or n.contains("unpack") or n.contains("parse"):
    result = "reject malformed or non-canonical input before indexed access"
    return
  if n.contains("verify") or n.contains("check") or n.contains("cmp") or n.contains("equal"):
    result = "fail closed and preserve canonical, constant-time comparison where secrets are involved"
    return
  if n.contains("decap") or n.contains("decrypt"):
    result = "preserve implicit rejection and never expose a secret-dependent validity oracle"
    return
  if n.contains("sample") or n.contains("noise") or n.contains("secret") or n.contains("sign"):
    result = "avoid secret-dependent branches, indices, and unbounded secret lifetimes"
    return
  if n.contains("random") or n.contains("rng") or p.contains("pq_rng"):
    result = "use deterministic generation only for KAT replay and system entropy in production"
    return
  if n.contains("simd") or n.contains("avx") or n.contains("sse") or n.contains("neon"):
    result = "match scalar ranges, reductions, lane order, and fixed public loop bounds"
    return
  if n.contains("pack") or n.contains("encode") or n.contains("serialize"):
    result = "emit the unique canonical wire representation and enforce exact bounds"
    return
  if n.contains("keypair") or n.contains("keygen") or n.contains("encaps"):
    result = "keep transcript order, domain separation, sizes, and secret wiping exact"
    return
  result = "preserve the cited equations, fixed bounds, and representation invariants"

proc referenceComment(path, declaration: string): string {.role: {dataWriter}.} =
  ## Build one concise citation line for a declaration.
  var
    rule: ReferenceRule = ruleFor(path)
    name: string = declarationName(declaration)
    indent: string = declaration[0 ..< declaration.len - declaration.strip(leading = true, trailing = false).len]
  result = indent & "## Reference: [" & rule.id & "] " & rule.part & "; " &
    modulePart(path) & " for `" & name & "`; pitfall: " & pitfallFor(name, path) & "."

proc asymmetricFiles(root: string): seq[string] {.role: {dataFetcher}.} =
  ## Return all asymmetric Nim modules in stable order.
  for p in walkDirRec(root):
    if p.endsWith(".nim"):
      result.add(p)
  result.sort()

proc annotateFile(path: string): int {.role: {dataWriter}.} =
  ## Insert missing immediate citations and return the insertion count.
  var
    lines: seq[string] = readFile(path).splitLines()
    output: seq[string] = @[]
    previous: string = ""
  for line in lines:
    if isDeclarationLine(line) and not previous.contains(referenceMarker):
      output.add(referenceComment(path, line))
      result = result + 1
    output.add(line)
    previous = line
  while output.len > 0 and output[^1].len == 0:
    output.setLen(output.len - 1)
  writeFile(path, output.join("\n") & "\n")

proc referenceIds(lockPath: string): HashSet[string] {.role: {truthBuilder}.} =
  ## Parse every valid citation ID from the source lock.
  var
    manifest: JsonNode = parseFile(lockPath)
  for document in manifest["documents"]:
    result.incl(document["id"].getStr())

proc citedId(s: string): string {.role: {parser}.} =
  ## Extract the bracketed source ID from one reference comment.
  var
    start: int = s.find(referenceMarker)
    finish: int = -1
  if start < 0:
    return ""
  start = start + referenceMarker.len
  finish = s.find(']', start)
  if finish < 0:
    return ""
  result = s[start ..< finish]

proc checkFile(path: string, ids: HashSet[string]): seq[string] {.role: {actor}.} =
  ## Report declarations without immediate, known source citations.
  var
    lines: seq[string] = readFile(path).splitLines()
    id: string = ""
    previous: string = ""
    i: int = 0
  while i < lines.len:
    if isDeclarationLine(lines[i]):
      if not previous.contains(referenceMarker):
        result.add(path & ":" & $(i + 1) & ": missing immediate Reference comment")
      else:
        id = citedId(previous)
        if id notin ids:
          result.add(path & ":" & $i & ": unknown reference ID " & id)
    previous = lines[i]
    i = i + 1

proc checkLockedFiles(repoRoot, lockPath: string): seq[string] {.role: {actor}.} =
  ## Verify size and SHA-256 metadata for every tracked source.
  var
    manifest: JsonNode = parseFile(lockPath)
    localPath: string = ""
    fullPath: string = ""
    expectedBytes: int64 = 0
  for document in manifest["documents"]:
    if not document.hasKey("localPath"):
      continue
    if document["gitPolicy"].getStr() != "tracked":
      continue
    localPath = document["localPath"].getStr()
    fullPath = joinPath(repoRoot, localPath)
    expectedBytes = document["bytes"].getBiggestInt()
    if not fileExists(fullPath):
      result.add(localPath & ": locked reference is missing")
    elif getFileSize(fullPath) != expectedBytes:
      result.add(localPath & ": byte size differs from references.lock.json")
    elif not fileMatchesSha256(fullPath, document["sha256"].getStr()):
      result.add(localPath & ": SHA-256 differs from references.lock.json")

proc run(writeMode: bool) {.role: {orchestrator}.} =
  ## Coordinate annotation or strict verification for the asymmetric tree.
  var
    repoRoot: string = parentDir(parentDir(currentSourcePath()))
    sourceRoot: string = joinPath(repoRoot, "src", "protocols", "custom_crypto", "asymmetric")
    lockPath: string = joinPath(repoRoot, "docs", "research", "asymmetric_verification", "references.lock.json")
    files: seq[string] = asymmetricFiles(sourceRoot)
    ids: HashSet[string] = referenceIds(lockPath)
    errors: seq[string] = @[]
    inserted: int = 0
  if writeMode:
    for path in files:
      inserted = inserted + annotateFile(path)
    echo "inserted asymmetric reference comments: " & $inserted
    return
  errors.add(checkLockedFiles(repoRoot, lockPath))
  for path in files:
    errors.add(checkFile(path, ids))
  if errors.len > 0:
    for error in errors:
      stderr.writeLine(error)
    quit("asymmetric reference check failed: " & $errors.len & " error(s)", 1)
  echo "asymmetric reference check passed: " & $files.len & " modules"

when isMainModule:
  var
    writeMode: bool = paramCount() > 0 and paramStr(1) == "--write"
  run(writeMode)
