import std/unittest

import ../src/tyr_crypto/custom_crypto/blake3

proc buildBlock(seed: uint32): array[16, uint32] =
  var
    b: array[16, uint32]
    i: int = 0
  i = 0
  while i < b.len:
    b[i] = seed + uint32(i) * 0x01010101'u32
    i = i + 1
  result = b

suite "blake3 simd":
  test "SSE4x compression matches reference":
    var
      cvs: array[4, Blake3Cv]
      blocks: array[4, Blake3Block]
      outs: array[4, Blake3Out]
      refs: array[4, Blake3Out]
      i: int = 0
      j: int = 0
    i = 0
    while i < cvs.len:
      j = 0
      while j < 8:
        cvs[i][j] = 0x01020304'u32 + uint32(i) * 0x11111111'u32 + uint32(j)
        j = j + 1
      blocks[i] = buildBlock(uint32(0x05060708'u32 + uint32(i) * 0x01010101'u32))
      i = i + 1
    i = 0
    while i < refs.len:
      refs[i] = blake3Compress(cvs[i], blocks[i], 0'u64, 64'u32, 0'u32)
      i = i + 1
    outs = blake3CompressSse4(cvs, blocks, 0'u64, 64'u32, 0'u32)
    check outs == refs

  test "auto batch matches scalar":
    var
      cvs: seq[Blake3Cv] = @[]
      blocks: seq[Blake3Block] = @[]
      outs: seq[Blake3Out]
      i: int = 0
      j: int = 0
    i = 0
    while i < 9:
      var cv: Blake3Cv
      j = 0
      while j < 8:
        cv[j] = 0x11111111'u32 + uint32(i) * 0x01010101'u32 + uint32(j)
        j = j + 1
      cvs.add(cv)
      blocks.add(buildBlock(uint32(0x22222222'u32 + uint32(i) * 3'u32)))
      i = i + 1
    outs = blake3CompressBatch(cvs, blocks, 3'u64, 64'u32, 5'u32, bcbAuto)
    i = 0
    while i < cvs.len:
      check outs[i] == blake3Compress(cvs[i], blocks[i], 3'u64, 64'u32, 5'u32)
      i = i + 1

  when defined(avx2):
    test "AVX8 compression matches reference":
      var
        cvs: array[8, Blake3Cv]
        blocks: array[8, Blake3Block]
        outs: array[8, Blake3Out]
        refs: array[8, Blake3Out]
        i: int = 0
        j: int = 0
      i = 0
      while i < cvs.len:
        j = 0
        while j < 8:
          cvs[i][j] = 0x0a0b0c0d'u32 + uint32(i) * 0x11111111'u32 + uint32(j)
          j = j + 1
        blocks[i] = buildBlock(uint32(0x0e0f1011'u32 + uint32(i) * 0x01010101'u32))
        i = i + 1
      i = 0
      while i < refs.len:
        refs[i] = blake3Compress(cvs[i], blocks[i], 1'u64, 64'u32, 0'u32)
        i = i + 1
      outs = blake3CompressAvx8(cvs, blocks, 1'u64, 64'u32, 0'u32)
      check outs == refs
