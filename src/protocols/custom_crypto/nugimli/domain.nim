## -----------------------------------------------------------------------
## NuGimli Domain <- tagged SHAKE256 derivation for independent key/state
## -----------------------------------------------------------------------

import metaPragmas
import ../symmetric/sha3/sha3
import ../symmetric/secure_memory
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

  CascadeMaterial512* = object
    state*: NuGimli512
    key*: NuGimli512

  CascadeMaterial1024* = object
    state*: NuGimli1024
    key*: NuGimli1024

  CascadeMaterial2048* = object
    state*: NuGimli2048
    key*: NuGimli2048

proc cascadeDomainTag*(label: string): CascadeDomainTag {.role: {parser}.} =
  ## label: non-empty public protocol/use-case label of at most 255 bytes.
  if label.len == 0 or label.len > cascadeDomainMaxTagBytes:
    raise newException(ValueError, "Cascade domain tag must contain 1..255 bytes")
  result.value = label

proc appendString(B: var seq[byte], s: string) {.inline, role: {helper}.} =
  ## B: destination bytes. s: public ASCII/UTF-8 domain text.
  var
    i: int = 0
  i = 0
  while i < s.len:
    B.add(byte(ord(s[i])))
    i = i + 1

proc appendU32Le(B: var seq[byte], x: uint32) {.inline, role: {helper}.} =
  ## B: destination bytes. x: little-endian public integer.
  B.add(byte(x))
  B.add(byte(x shr 8))
  B.add(byte(x shr 16))
  B.add(byte(x shr 24))

proc appendU64Le(B: var seq[byte], x: uint64) {.inline, role: {helper}.} =
  ## B: destination bytes. x: little-endian public integer.
  var
    i: int = 0
  i = 0
  while i < 8:
    B.add(byte(x shr (i * 8)))
    i = i + 1

proc appendBytes(B: var seq[byte], A: openArray[byte])
    {.inline, role: {helper}.} =
  ## B: destination. A: bytes appended without reinterpretation.
  var
    i: int = 0
  i = 0
  while i < A.len:
    B.add(A[i])
    i = i + 1

proc validateDerivation(sourceLen, sourceBits, targetBits,
    contextLen: int) {.role: {parser}.} =
  ## sourceLen/sourceBits/targetBits/contextLen: public derivation dimensions.
  if sourceBits != nugimli512Bits and sourceBits != nugimli1024Bits and
      sourceBits != nugimli2048Bits:
    raise newException(ValueError, "Cascade source width must be 512, 1024, or 2048 bits")
  if targetBits != nugimli512Bits and targetBits != nugimli1024Bits and
      targetBits != nugimli2048Bits:
    raise newException(ValueError, "Cascade target width must be 512, 1024, or 2048 bits")
  if sourceLen * 8 != sourceBits:
    raise newException(ValueError, "Cascade source byte length does not match source width")
  if contextLen > cascadeDomainMaxContextBytes:
    raise newException(ValueError, "Cascade domain context is too long")

proc buildPrefix(sourceBits, targetBits, outputBytes: int,
    purpose: CascadeDomainPurpose, tag: CascadeDomainTag,
    context: openArray[byte]): seq[byte] {.role: {truthBuilder}.} =
  ## Widths/output/purpose/tag/context: injectively encoded public domain.
  result = newSeqOfCap[byte](cascadeDomainMagic.len + tag.value.len +
    context.len + 32)
  appendString(result, cascadeDomainMagic)
  result.add(cascadeDomainVersion)
  result.add(byte(ord(purpose)))
  appendU32Le(result, uint32(sourceBits))
  appendU32Le(result, uint32(targetBits))
  appendU32Le(result, uint32(outputBytes))
  appendU32Le(result, uint32(tag.value.len))
  appendU64Le(result, uint64(context.len))
  appendString(result, tag.value)
  appendBytes(result, context)

proc deriveBytes(source: openArray[byte], sourceBits, targetBits: int,
    purpose: CascadeDomainPurpose, tag: CascadeDomainTag,
    context: openArray[byte]): seq[byte] {.role: {math}.} =
  ## source: source-width secret. Other parameters: public derivation domain.
  var
    prefix: seq[byte] = @[]
  defer:
    secureClearBytes(prefix)
  validateDerivation(source.len, sourceBits, targetBits, context.len)
  prefix = buildPrefix(sourceBits, targetBits, targetBits div 8, purpose,
    tag, context)
  result.setLen(targetBits div 8)
  shake256Into(result, prefix, source)

proc loadWords[N: static[int]](B: openArray[byte]): array[N, uint32]
    {.inline, role: {parser}.} =
  ## B: exact-width SHAKE output loaded as little-endian words.
  var
    i, o: int = 0
  if B.len != N * 4:
    raise newException(ValueError, "Cascade derived byte length is invalid")
  i = 0
  while i < N:
    o = i * 4
    result[i] = uint32(B[o]) or (uint32(B[o + 1]) shl 8) or
      (uint32(B[o + 2]) shl 16) or (uint32(B[o + 3]) shl 24)
    i = i + 1

proc stateBytes[N: static[int]](S: array[N, uint32]): seq[byte]
    {.inline, role: {helper}.} =
  ## S: source state serialized little-endian for domain derivation.
  var
    i, o: int = 0
  result.setLen(N * 4)
  i = 0
  while i < N:
    o = i * 4
    result[o] = byte(S[i])
    result[o + 1] = byte(S[i] shr 8)
    result[o + 2] = byte(S[i] shr 16)
    result[o + 3] = byte(S[i] shr 24)
    i = i + 1

proc deriveCascade512*(source: openArray[byte], sourceBits: int,
    tag: CascadeDomainTag, context: openArray[byte] = []): CascadeMaterial512
    {.role: {truthBuilder}.} =
  ## source/sourceBits: source secret. tag/context: public derivation domain.
  var
    stateOutput, keyOutput: seq[byte] = @[]
  defer:
    secureClearBytes(stateOutput)
    secureClearBytes(keyOutput)
  stateOutput = deriveBytes(source, sourceBits, nugimli512Bits, cdpState,
    tag, context)
  keyOutput = deriveBytes(source, sourceBits, nugimli512Bits, cdpKey,
    tag, context)
  result.state = loadWords[nugimli512Bits div 32](stateOutput)
  result.key = loadWords[nugimli512Bits div 32](keyOutput)

proc deriveCascade1024*(source: openArray[byte], sourceBits: int,
    tag: CascadeDomainTag, context: openArray[byte] = []): CascadeMaterial1024
    {.role: {truthBuilder}.} =
  ## source/sourceBits: source secret. tag/context: public derivation domain.
  var
    stateOutput, keyOutput: seq[byte] = @[]
  defer:
    secureClearBytes(stateOutput)
    secureClearBytes(keyOutput)
  stateOutput = deriveBytes(source, sourceBits, nugimli1024Bits, cdpState,
    tag, context)
  keyOutput = deriveBytes(source, sourceBits, nugimli1024Bits, cdpKey,
    tag, context)
  result.state = loadWords[nugimli1024Bits div 32](stateOutput)
  result.key = loadWords[nugimli1024Bits div 32](keyOutput)

proc deriveCascade2048*(source: openArray[byte], sourceBits: int,
    tag: CascadeDomainTag, context: openArray[byte] = []): CascadeMaterial2048
    {.role: {truthBuilder}.} =
  ## source/sourceBits: source secret. tag/context: public derivation domain.
  var
    stateOutput, keyOutput: seq[byte] = @[]
  defer:
    secureClearBytes(stateOutput)
    secureClearBytes(keyOutput)
  stateOutput = deriveBytes(source, sourceBits, nugimli2048Bits, cdpState,
    tag, context)
  keyOutput = deriveBytes(source, sourceBits, nugimli2048Bits, cdpKey,
    tag, context)
  result.state = loadWords[nugimli2048Bits div 32](stateOutput)
  result.key = loadWords[nugimli2048Bits div 32](keyOutput)

template defineStateDerivation(targetProc, MaterialType: untyped) =
  proc targetProc*(source: NuGimli512, tag: CascadeDomainTag,
      context: openArray[byte] = []): MaterialType {.role: {truthBuilder}.} =
    var B: seq[byte] = stateBytes(source)
    defer: secureClearBytes(B)
    result = targetProc(B, nugimli512Bits, tag, context)

  proc targetProc*(source: NuGimli1024, tag: CascadeDomainTag,
      context: openArray[byte] = []): MaterialType {.role: {truthBuilder}.} =
    var B: seq[byte] = stateBytes(source)
    defer: secureClearBytes(B)
    result = targetProc(B, nugimli1024Bits, tag, context)

  proc targetProc*(source: NuGimli2048, tag: CascadeDomainTag,
      context: openArray[byte] = []): MaterialType {.role: {truthBuilder}.} =
    var B: seq[byte] = stateBytes(source)
    defer: secureClearBytes(B)
    result = targetProc(B, nugimli2048Bits, tag, context)

defineStateDerivation(deriveCascade512, CascadeMaterial512)
defineStateDerivation(deriveCascade1024, CascadeMaterial1024)
defineStateDerivation(deriveCascade2048, CascadeMaterial2048)

proc clearCascadeMaterial*(M: var CascadeMaterial512) {.role: {helper}.} =
  ## M: derived 512-bit state and key overwritten with volatile zero stores.
  secureClearPod(M)

proc clearCascadeMaterial*(M: var CascadeMaterial1024) {.role: {helper}.} =
  ## M: derived 1024-bit state and key overwritten with volatile zero stores.
  secureClearPod(M)

proc clearCascadeMaterial*(M: var CascadeMaterial2048) {.role: {helper}.} =
  ## M: derived 2048-bit state and key overwritten with volatile zero stores.
  secureClearPod(M)
