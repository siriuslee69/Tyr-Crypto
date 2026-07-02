import std/unittest
import ../src/protocols/custom_crypto/argon2
import ./helpers

proc patternedBlock(seed: uint64): array[128, uint64] =
  var
    i: int = 0
  i = 0
  while i < result.len:
    result[i] = seed + uint64(i * 0x0101) + (uint64(i and 7) shl 32)
    i = i + 1

suite "argon2 simd":
  test "auto backend matches scalar hash":
    var
      password: seq[byte] = toBytes("Correct Horse Battery Staple")
      salt: seq[byte] = toBytes(">A 16-bytes salt")
      p: Argon2Params
      scalarHash: seq[byte] = @[]
      autoHash: seq[byte] = @[]
    p = initArgon2Params(3, 4096, 1, 32)
    scalarHash = argon2idHash(password, salt, p, a2bScalar)
    autoHash = argon2idHash(password, salt, p, a2bAuto)
    check autoHash == scalarHash

  test "auto backend matches scalar for custom BLAKE3 and Gimli Argon variants":
    var
      password: seq[byte] = toBytes("Correct Horse Battery Staple")
      salt: seq[byte] = toBytes(">A 16-bytes salt")
      p: Argon2Params
    p = initArgon2Params(3, 4096, 1, 32)
    check argon2idHash(password, salt, p, a2hBlake3, a2bAuto) ==
      argon2idHash(password, salt, p, a2hBlake3, a2bScalar)
    check argon2idHash(password, salt, p, a2hGimli, a2bAuto) ==
      argon2idHash(password, salt, p, a2hGimli, a2bScalar)

  test "scalar round helper is stable":
    var
      b0 = patternedBlock(0x1020'u64)
      b1 = patternedBlock(0x1020'u64)
    applyArgon2RoundsScalar(b0)
    applyArgon2RoundsScalar(b1)
    check b0 == b1

  when defined(sse2):
    test "sse2 round core matches scalar":
      var
        scalarBlock = patternedBlock(0x2000'u64)
        simdBlock = scalarBlock
      applyArgon2RoundsScalar(scalarBlock)
      applyArgon2RoundsSse2x(simdBlock)
      check simdBlock == scalarBlock

    test "sse2 fill helpers match scalar":
      var
        prevBlock = patternedBlock(0x3000'u64)
        refBlock = patternedBlock(0x4000'u64)
        nextBlock = patternedBlock(0x5000'u64)
        scalarFill: array[128, uint64]
        simdFill: array[128, uint64]
        scalarFillXor: array[128, uint64]
        simdFillXor: array[128, uint64]
      fillBlockScalar(prevBlock, refBlock, scalarFill)
      fillArgon2BlockSse2x(prevBlock, refBlock, simdFill)
      fillBlockWithXorScalar(prevBlock, refBlock, nextBlock, scalarFillXor)
      fillArgon2BlockWithXorSse2x(prevBlock, refBlock, nextBlock, simdFillXor)
      check simdFill == scalarFill
      check simdFillXor == scalarFillXor

    test "sse2 backend matches scalar hash":
      var
        password: seq[byte] = toBytes("Correct Horse Battery Staple")
        salt: seq[byte] = toBytes(">A 16-bytes salt")
        p: Argon2Params
      p = initArgon2Params(2, 4096, 1, 32)
      check argon2iHash(password, salt, p, a2bSse2) == argon2iHash(password, salt, p, a2bScalar)
      check argon2idHash(password, salt, p, a2bSse2) == argon2idHash(password, salt, p, a2bScalar)

  when defined(neon) or defined(arm64) or defined(aarch64):
    test "neon round core matches scalar":
      var
        scalarBlock = patternedBlock(0x6000'u64)
        simdBlock = scalarBlock
      applyArgon2RoundsScalar(scalarBlock)
      applyArgon2RoundsNeon2x(simdBlock)
      check simdBlock == scalarBlock

    test "neon fill helpers match scalar":
      var
        prevBlock = patternedBlock(0x7000'u64)
        refBlock = patternedBlock(0x8000'u64)
        nextBlock = patternedBlock(0x9000'u64)
        scalarFill: array[128, uint64]
        simdFill: array[128, uint64]
        scalarFillXor: array[128, uint64]
        simdFillXor: array[128, uint64]
      fillBlockScalar(prevBlock, refBlock, scalarFill)
      fillArgon2BlockNeon2x(prevBlock, refBlock, simdFill)
      fillBlockWithXorScalar(prevBlock, refBlock, nextBlock, scalarFillXor)
      fillArgon2BlockWithXorNeon2x(prevBlock, refBlock, nextBlock, simdFillXor)
      check simdFill == scalarFill
      check simdFillXor == scalarFillXor

    test "neon backend matches scalar hash":
      var
        password: seq[byte] = toBytes("Correct Horse Battery Staple")
        salt: seq[byte] = toBytes(">A 16-bytes salt")
        p: Argon2Params
      p = initArgon2Params(2, 4096, 1, 32)
      check argon2iHash(password, salt, p, a2bNeon) == argon2iHash(password, salt, p, a2bScalar)
      check argon2idHash(password, salt, p, a2bNeon) == argon2idHash(password, salt, p, a2bScalar)

  when defined(avx2):
    test "avx2 round core matches scalar":
      var
        scalarBlock = patternedBlock(0xa000'u64)
        simdBlock = scalarBlock
      applyArgon2RoundsScalar(scalarBlock)
      applyArgon2RoundsAvx4x(simdBlock)
      check simdBlock == scalarBlock

    test "avx2 fill helpers match scalar":
      var
        prevBlock = patternedBlock(0xb000'u64)
        refBlock = patternedBlock(0xc000'u64)
        nextBlock = patternedBlock(0xd000'u64)
        scalarFill: array[128, uint64]
        simdFill: array[128, uint64]
        scalarFillXor: array[128, uint64]
        simdFillXor: array[128, uint64]
      fillBlockScalar(prevBlock, refBlock, scalarFill)
      fillArgon2BlockAvx4x(prevBlock, refBlock, simdFill)
      fillBlockWithXorScalar(prevBlock, refBlock, nextBlock, scalarFillXor)
      fillArgon2BlockWithXorAvx4x(prevBlock, refBlock, nextBlock, simdFillXor)
      check simdFill == scalarFill
      check simdFillXor == scalarFillXor

    test "avx2 backend matches scalar hash":
      var
        password: seq[byte] = toBytes("Correct Horse Battery Staple")
        salt: seq[byte] = toBytes(">A 16-bytes salt")
        p: Argon2Params
      p = initArgon2Params(2, 4096, 1, 32)
      check argon2iHash(password, salt, p, a2bAvx2) == argon2iHash(password, salt, p, a2bScalar)
      check argon2idHash(password, salt, p, a2bAvx2) == argon2idHash(password, salt, p, a2bScalar)
