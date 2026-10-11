## -----------------------------------------------------------------------
## NuGimli Domain <- tagged SHAKE256 derivation for independent key/state
## -----------------------------------------------------------------------
##
## Moving material from one width to another, or from any secret into a
## Cascade key, always goes through SHAKE256 with a full description of
## the use in front:
##
##   prefix = "Tyr-NuGimli-Cascade-KDF" | version 1 | purpose (1 = state, 2 = key)
##          | source bits (u32 LE) | target bits (u32 LE) | output bytes (u32 LE)
##          | tag length (u32 LE) | context length (u64 LE) | tag | context
##   output = SHAKE256(prefix | source), target bits long, read as u32 LE words
##
## State and key come from two runs that differ only in the purpose byte.
##
##   var m = deriveCascade(NuGimli2048, output1024, tag, context)  # CascadeMaterial2048
##   ciphertext = cascadeEncrypt(m.state, m.key)
##   clearCascadeMaterial(m)

import runePragmas
import ../../hashes/sha3
import ../../helpers/secure_memory
import ./types

const
  cascadeDomainMagic = "Tyr-NuGimli-Cascade-KDF"
  cascadeDomainVersion = 1'u8
  cascadeDomainMaxTagBytes* = 255
  cascadeDomainMaxContextBytes* = 65_535

type
  CascadeDomainPurpose = enum
    cdpState = 1
    cdpKey = 2

  CascadeDomainTag* = object
    value*: string

  CascadeMaterial*[N: static[int]] = object
    ## A derived Cascade state and key of N 32-bit words each.
    state*: array[N, uint32]
    key*: array[N, uint32]

  CascadeMaterial512* = CascadeMaterial[16]
  CascadeMaterial1024* = CascadeMaterial[32]
  CascadeMaterial2048* = CascadeMaterial[64]

proc cascadeDomainTag*(label: string): CascadeDomainTag {.role: {parser}.} =
  ## label: non-empty public protocol/use-case label of at most 255 bytes.
  if label.len == 0 or label.len > cascadeDomainMaxTagBytes:
    raise newException(ValueError, "Cascade domain tag must contain 1..255 bytes")
  result.value = label

proc appendU32Le(B: var seq[byte], x: uint32) {.inline, role: {helper}.} =
  ## B: destination bytes. x: little-endian public integer.
  B.add(byte(x))
  B.add(byte(x shr 8))
  B.add(byte(x shr 16))
  B.add(byte(x shr 24))

proc appendU64Le(B: var seq[byte], x: uint64) {.inline, role: {helper}.} =
  ## B: destination bytes. x: little-endian public integer.
  appendU32Le(B, uint32(x and 0xffff_ffff'u64))
  appendU32Le(B, uint32(x shr 32))

proc validateSource(sourceLen, sourceBits, contextLen: int) {.role: {parser}.} =
  ## sourceLen/sourceBits/contextLen: public derivation dimensions.
  if sourceBits mod 32 != 0 or cascadeRounds(sourceBits div 32) == 0:
    raise newException(ValueError, "Cascade source width must be 512, 1024, or 2048 bits")
  if sourceLen * 8 != sourceBits:
    raise newException(ValueError, "Cascade source byte length does not match source width")
  if contextLen > cascadeDomainMaxContextBytes:
    raise newException(ValueError, "Cascade domain context is too long")

proc buildPrefix(sourceBits, targetBits: int, purpose: CascadeDomainPurpose,
    tag: CascadeDomainTag, context: openArray[byte]): seq[byte] {.role: {truthBuilder}.} =
  ## Widths/purpose/tag/context: the injectively encoded public domain.
  result = newSeqOfCap[byte](cascadeDomainMagic.len + tag.value.len +
    context.len + 32)
  result.add(cascadeDomainMagic.toOpenArrayByte(0, cascadeDomainMagic.high))
  result.add(cascadeDomainVersion)
  result.add(byte(ord(purpose)))
  appendU32Le(result, uint32(sourceBits))
  appendU32Le(result, uint32(targetBits))
  appendU32Le(result, uint32(targetBits div 8))
  appendU32Le(result, uint32(tag.value.len))
  appendU64Le(result, uint64(context.len))
  result.add(tag.value.toOpenArrayByte(0, tag.value.high))
  result.add(context)

proc deriveWords[N: static[int]](source: openArray[byte], sourceBits: int,
    purpose: CascadeDomainPurpose, tag: CascadeDomainTag,
    context: openArray[byte]): array[N, uint32] {.role: {math}.} =
  ## source: source-width secret. Returns N words of SHAKE256 output.
  var
    prefix: seq[byte] = buildPrefix(sourceBits, N * 32, purpose, tag, context)
    output: seq[byte] = newSeq[byte](N * 4)
    i: int = 0
  defer:
    secureClearBytes(prefix)
    secureClearBytes(output)
  shake256Into(output, prefix, source)
  while i < N:
    result[i] = uint32(output[i * 4]) or (uint32(output[i * 4 + 1]) shl 8) or
      (uint32(output[i * 4 + 2]) shl 16) or (uint32(output[i * 4 + 3]) shl 24)
    i = i + 1

proc stateBytes(S: openArray[uint32]): seq[byte] {.inline, role: {helper}.} =
  ## S: source state serialized little-endian for domain derivation.
  var
    i: int = 0
  result = newSeq[byte](S.len * 4)
  while i < S.len:
    result[i * 4] = byte(S[i])
    result[i * 4 + 1] = byte(S[i] shr 8)
    result[i * 4 + 2] = byte(S[i] shr 16)
    result[i * 4 + 3] = byte(S[i] shr 24)
    i = i + 1

proc deriveMaterial[N: static[int]](source: openArray[byte], sourceBits: int,
    tag: CascadeDomainTag, context: openArray[byte]): CascadeMaterial[N] {.role: {truthBuilder}.} =
  ## N: target width in words. State and key differ only in the purpose byte.
  requireCascadeWidth(N)
  validateSource(source.len, sourceBits, context.len)
  result.state = deriveWords[N](source, sourceBits, cdpState, tag, context)
  result.key = deriveWords[N](source, sourceBits, cdpKey, tag, context)

proc deriveCascade*[N: static[int]](target: typedesc[array[N, uint32]],
    source: openArray[byte], sourceBits: int, tag: CascadeDomainTag,
    context: openArray[byte] = []): CascadeMaterial[N] {.role: {truthBuilder}.} =
  ## target: NuGimli512, NuGimli1024 or NuGimli2048. source/sourceBits: source secret of
  ## 512, 1024 or 2048 bits. tag/context: public derivation domain.
  result = deriveMaterial[N](source, sourceBits, tag, context)

proc deriveCascade*[N: static[int]](target: typedesc[array[N, uint32]],
    source: openArray[uint32], tag: CascadeDomainTag,
    context: openArray[byte] = []): CascadeMaterial[N] {.role: {truthBuilder}.} =
  ## source: a Cascade state of any width, taken as little-endian bytes.
  var
    B: seq[byte] = stateBytes(source)
  defer:
    secureClearBytes(B)
  result = deriveMaterial[N](B, source.len * 32, tag, context)

proc clearCascadeMaterial*[N: static[int]](M: var CascadeMaterial[N]) {.role: {helper}.} =
  ## M: derived state and key overwritten with volatile zero stores.
  secureClearPod(M)
