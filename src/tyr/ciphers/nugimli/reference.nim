## ----------------------------------------------------------------------
## NuGimli Cascade Reference <- direct scalar round loops for comparison
## ----------------------------------------------------------------------

import std/bitops
import tyrPragmas
import ./types
import ./scalar_box

proc referenceDistance(chunks: static[int], r: uint32): int
    {.inline, role: {parser}.} =
  ## chunks/r: public state width and round selecting butterfly distance.
  case chunks
  of 4: result = 1 shl int((r - 1'u32) mod 2'u32)
  of 8: result = 1 shl int((r - 1'u32) mod 3'u32)
  of 16: result = 1 shl int((r - 1'u32) mod 4'u32)
  else: raise newException(ValueError, "Cascade supports 4, 8, or 16 chunks")

proc cascadePermuteReference*[N: static[int]](S: var array[N, uint32],
    rounds: static[int]) {.role: {math}.} =
  ## S/rounds: fixed-width state and direct descending scalar round count.
  const chunks = N div nugimliChunkWords
  var
    r: uint32 = uint32(rounds)
    c, d, target, o, blockIndex, i: int = 0
    domain: uint32 = cascadeRoundDomain xor uint32(N * 32)
  while r > 0'u32:
    c = 0
    while c + 2 < chunks:
      gimliBoxAtScalar(S, c, c + 1, c + 2)
      c = c + 1

    target = (int(r) * 5) and (chunks - 1)
    o = target * nugimliChunkWords
    case r and 3'u32
    of 0'u32:
      swap(S[o], S[o + 1])
      swap(S[o + 2], S[o + 3])
    of 2'u32:
      swap(S[o], S[o + 2])
      swap(S[o + 1], S[o + 3])
    else:
      discard

    i = 0
    while i < N:
      S[i] = rotateLeftBits(S[i], 1)
      i = i + 1

    S[0] = S[0] xor domain xor r
    S[N - 1] = S[N - 1] xor rotateLeftBits(domain xor uint32(N),
      int(r and 31'u32))

    d = referenceDistance(chunks, r)
    blockIndex = 0
    while blockIndex < chunks:
      i = 0
      while i < d * nugimliChunkWords:
        swap(S[blockIndex * nugimliChunkWords + i],
          S[(blockIndex + d) * nugimliChunkWords + i])
        i = i + 1
      blockIndex = blockIndex + d * 2
    r = r - 1'u32

proc cascadeInvertReference*[N: static[int]](S: var array[N, uint32],
    rounds: static[int]) {.role: {math}.} =
  ## S/rounds: fixed-width state and direct ascending scalar inverse count.
  const chunks = N div nugimliChunkWords
  var
    r: uint32 = 1'u32
    c, d, target, o, blockIndex, i: int = 0
    domain: uint32 = cascadeRoundDomain xor uint32(N * 32)
  while r <= uint32(rounds):
    d = referenceDistance(chunks, r)
    blockIndex = 0
    while blockIndex < chunks:
      i = 0
      while i < d * nugimliChunkWords:
        swap(S[blockIndex * nugimliChunkWords + i],
          S[(blockIndex + d) * nugimliChunkWords + i])
        i = i + 1
      blockIndex = blockIndex + d * 2

    S[0] = S[0] xor domain xor r
    S[N - 1] = S[N - 1] xor rotateLeftBits(domain xor uint32(N),
      int(r and 31'u32))

    i = 0
    while i < N:
      S[i] = rotateRightBits(S[i], 1)
      i = i + 1

    target = (int(r) * 5) and (chunks - 1)
    o = target * nugimliChunkWords
    case r and 3'u32
    of 0'u32:
      swap(S[o], S[o + 1])
      swap(S[o + 2], S[o + 3])
    of 2'u32:
      swap(S[o], S[o + 2])
      swap(S[o + 1], S[o + 3])
    else:
      discard

    c = chunks - 3
    while c >= 0:
      gimliBoxInverseAtScalar(S, c, c + 1, c + 2)
      c = c - 1
    r = r + 1'u32

proc cascadeReferencePermute512*(S: var NuGimli512) {.role: {math}.} =
  ## S: 512-bit state transformed by the direct scalar reference.
  cascadePermuteReference(S, nugimli512Rounds)

proc cascadeReferencePermute1024*(S: var NuGimli1024) {.role: {math}.} =
  ## S: 1024-bit state transformed by the direct scalar reference.
  cascadePermuteReference(S, nugimli1024Rounds)

proc cascadeReferencePermute2048*(S: var NuGimli2048) {.role: {math}.} =
  ## S: 2048-bit state transformed by the direct scalar reference.
  cascadePermuteReference(S, nugimli2048Rounds)

proc cascadeReferenceInvert512*(S: var NuGimli512) {.role: {math}.} =
  ## S: 512-bit reference state inverted directly.
  cascadeInvertReference(S, nugimli512Rounds)

proc cascadeReferenceInvert1024*(S: var NuGimli1024) {.role: {math}.} =
  ## S: 1024-bit reference state inverted directly.
  cascadeInvertReference(S, nugimli1024Rounds)

proc cascadeReferenceInvert2048*(S: var NuGimli2048) {.role: {math}.} =
  ## S: 2048-bit reference state inverted directly.
  cascadeInvertReference(S, nugimli2048Rounds)
