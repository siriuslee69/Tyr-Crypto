## ------------------------------------------------------
## Blake3 SIMD <- SSE/AVX compression helpers
## ------------------------------------------------------

import simd_nexus/simd/base_operations

const
  blake3BlockLen* = 64
  blake3Iv: array[8, uint32] = [
    0x6a09e667'u32, 0xbb67ae85'u32, 0x3c6ef372'u32, 0xa54ff53a'u32,
    0x510e527f'u32, 0x9b05688c'u32, 0x1f83d9ab'u32, 0x5be0cd19'u32
  ]
  blake3MsgPerm: array[16, int] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]

type
  Blake3Cv* = array[8, uint32]
  Blake3Block* = array[16, uint32]
  Blake3Out* = array[16, uint32]


proc permute(schedule: var array[16, int]) {.inline.} =
  var next: array[16, int]
  for i in 0 ..< 16:
    next[i] = schedule[blake3MsgPerm[i]]
  schedule = next


template gVec(v: var array[16, M128i], a, b, c, d: int, x, y: M128i) =
  v[a] = v[a] + v[b] + x
  v[d] = rot_left(v[d] xor v[a], 16)
  v[c] = v[c] + v[d]
  v[b] = rot_left(v[b] xor v[c], 20)
  v[a] = v[a] + v[b] + y
  v[d] = rot_left(v[d] xor v[a], 24)
  v[c] = v[c] + v[d]
  v[b] = rot_left(v[b] xor v[c], 25)


when defined(avx2):
  template gVec(v: var array[16, M256i], a, b, c, d: int, x, y: M256i) =
    v[a] = v[a] + v[b] + x
    v[d] = rotLeft32(v[d] xor v[a], 16)
    v[c] = v[c] + v[d]
    v[b] = rotLeft32(v[b] xor v[c], 20)
    v[a] = v[a] + v[b] + y
    v[d] = rotLeft32(v[d] xor v[a], 24)
    v[c] = v[c] + v[d]
    v[b] = rotLeft32(v[b] xor v[c], 25)


proc loadVec4(ss: array[4, Blake3Block], i: int): M128i {.inline.} =
  result = mm_setr_epi32(int32(ss[0][i]), int32(ss[1][i]), int32(ss[2][i]), int32(ss[3][i]))


proc loadCv4(cs: array[4, Blake3Cv], i: int): M128i {.inline.} =
  result = mm_setr_epi32(int32(cs[0][i]), int32(cs[1][i]), int32(cs[2][i]), int32(cs[3][i]))


proc storeVec4(v: M128i, outs: var array[4, Blake3Out], i: int) {.inline.} =
  var
    tmp: array[4, int32]
  mm_storeu_si128(addr tmp[0], v)
  outs[0][i] = uint32(tmp[0])
  outs[1][i] = uint32(tmp[1])
  outs[2][i] = uint32(tmp[2])
  outs[3][i] = uint32(tmp[3])


when defined(avx2):
  proc loadVec8(ss: array[8, Blake3Block], i: int): M256i {.inline.} =
    result = mm256_setr_epi32(
      cast[int32](ss[0][i]), cast[int32](ss[1][i]), cast[int32](ss[2][i]), cast[int32](ss[3][i]),
      cast[int32](ss[4][i]), cast[int32](ss[5][i]), cast[int32](ss[6][i]), cast[int32](ss[7][i])
    )

  proc loadCv8(cs: array[8, Blake3Cv], i: int): M256i {.inline.} =
    result = mm256_setr_epi32(
      cast[int32](cs[0][i]), cast[int32](cs[1][i]), cast[int32](cs[2][i]), cast[int32](cs[3][i]),
      cast[int32](cs[4][i]), cast[int32](cs[5][i]), cast[int32](cs[6][i]), cast[int32](cs[7][i])
    )

  proc storeVec8(v: M256i, outs: var array[8, Blake3Out], i: int) {.inline.} =
    var
      tmp: array[8, int32]
    mm256_storeu_si256(addr tmp[0], v)
    outs[0][i] = uint32(tmp[0])
    outs[1][i] = uint32(tmp[1])
    outs[2][i] = uint32(tmp[2])
    outs[3][i] = uint32(tmp[3])
    outs[4][i] = uint32(tmp[4])
    outs[5][i] = uint32(tmp[5])
    outs[6][i] = uint32(tmp[6])
    outs[7][i] = uint32(tmp[7])


proc blake3CompressSse4*(cvs: array[4, Blake3Cv], blocks: array[4, Blake3Block],
    counter: uint64, blkLen, flags: uint32): array[4, Blake3Out] =
  var
    state: array[16, M128i]
    words: array[16, M128i]
    schedule: array[16, int]
    cvVec: array[8, M128i]
    i: int = 0
    outVec: array[16, M128i]
    lo: uint32 = 0
    hi: uint32 = 0
  i = 0
  while i < 8:
    cvVec[i] = loadCv4(cvs, i)
    state[i] = cvVec[i]
    i = i + 1
  state[8] = mm_set1_epi32(cast[int32](blake3Iv[0]))
  state[9] = mm_set1_epi32(cast[int32](blake3Iv[1]))
  state[10] = mm_set1_epi32(cast[int32](blake3Iv[2]))
  state[11] = mm_set1_epi32(cast[int32](blake3Iv[3]))
  lo = uint32(counter and 0xffffffff'u64)
  hi = uint32((counter shr 32) and 0xffffffff'u64)
  state[12] = mm_set1_epi32(cast[int32](lo))
  state[13] = mm_set1_epi32(cast[int32](hi))
  state[14] = mm_set1_epi32(cast[int32](blkLen))
  state[15] = mm_set1_epi32(cast[int32](flags))
  i = 0
  while i < 16:
    words[i] = loadVec4(blocks, i)
    schedule[i] = i
    i = i + 1
  i = 0
  while i < 7:
    gVec(state, 0, 4, 8, 12, words[schedule[0]], words[schedule[1]])
    gVec(state, 1, 5, 9, 13, words[schedule[2]], words[schedule[3]])
    gVec(state, 2, 6, 10, 14, words[schedule[4]], words[schedule[5]])
    gVec(state, 3, 7, 11, 15, words[schedule[6]], words[schedule[7]])

    gVec(state, 0, 5, 10, 15, words[schedule[8]], words[schedule[9]])
    gVec(state, 1, 6, 11, 12, words[schedule[10]], words[schedule[11]])
    gVec(state, 2, 7, 8, 13, words[schedule[12]], words[schedule[13]])
    gVec(state, 3, 4, 9, 14, words[schedule[14]], words[schedule[15]])

    permute(schedule)
    i = i + 1
  i = 0
  while i < 8:
    outVec[i] = state[i] xor state[i + 8]
    outVec[i + 8] = outVec[i] xor cvVec[i]
    i = i + 1
  i = 0
  while i < 16:
    storeVec4(outVec[i], result, i)
    i = i + 1


when defined(avx2):
  proc blake3CompressAvx8*(cvs: array[8, Blake3Cv], blocks: array[8, Blake3Block],
      counter: uint64, blkLen, flags: uint32): array[8, Blake3Out] =
    var
      state: array[16, M256i]
      words: array[16, M256i]
      schedule: array[16, int]
      cvVec: array[8, M256i]
      i: int = 0
      outVec: array[16, M256i]
      lo: uint32 = 0
      hi: uint32 = 0
    i = 0
    while i < 8:
      cvVec[i] = loadCv8(cvs, i)
      state[i] = cvVec[i]
      i = i + 1
    state[8] = mm256_set1_epi32(cast[int32](blake3Iv[0]))
    state[9] = mm256_set1_epi32(cast[int32](blake3Iv[1]))
    state[10] = mm256_set1_epi32(cast[int32](blake3Iv[2]))
    state[11] = mm256_set1_epi32(cast[int32](blake3Iv[3]))
    lo = uint32(counter and 0xffffffff'u64)
    hi = uint32((counter shr 32) and 0xffffffff'u64)
    state[12] = mm256_set1_epi32(cast[int32](lo))
    state[13] = mm256_set1_epi32(cast[int32](hi))
    state[14] = mm256_set1_epi32(cast[int32](blkLen))
    state[15] = mm256_set1_epi32(cast[int32](flags))
    i = 0
    while i < 16:
      words[i] = loadVec8(blocks, i)
      schedule[i] = i
      i = i + 1
    i = 0
    while i < 7:
      gVec(state, 0, 4, 8, 12, words[schedule[0]], words[schedule[1]])
      gVec(state, 1, 5, 9, 13, words[schedule[2]], words[schedule[3]])
      gVec(state, 2, 6, 10, 14, words[schedule[4]], words[schedule[5]])
      gVec(state, 3, 7, 11, 15, words[schedule[6]], words[schedule[7]])

      gVec(state, 0, 5, 10, 15, words[schedule[8]], words[schedule[9]])
      gVec(state, 1, 6, 11, 12, words[schedule[10]], words[schedule[11]])
      gVec(state, 2, 7, 8, 13, words[schedule[12]], words[schedule[13]])
      gVec(state, 3, 4, 9, 14, words[schedule[14]], words[schedule[15]])

      permute(schedule)
      i = i + 1
    i = 0
    while i < 8:
      outVec[i] = state[i] xor state[i + 8]
      outVec[i + 8] = outVec[i] xor cvVec[i]
      i = i + 1
    i = 0
    while i < 16:
      storeVec8(outVec[i], result, i)
      i = i + 1
