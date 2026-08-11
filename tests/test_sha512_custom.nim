## -------------------------------------------------------------------
## SHA-512 Test <- vectors, block boundaries, streaming, length limits
## -------------------------------------------------------------------

import std/unittest

import ../src/tyr/hashes/sha512 as custom_sha512
import ../src/tyr/signatures/ed25519 as reference_sha512
import ./helpers

proc patternedBytes(n: int): seq[byte] =
  var i: int = 0
  result = newSeq[byte](n)
  while i < result.len:
    result[i] = byte((i * 37 + 11) and 0xff)
    i = i + 1

proc incrementalSha512(A: openArray[byte], split: int): custom_sha512.Sha512Digest =
  var S: custom_sha512.Sha512Context = custom_sha512.initSha512()
  if split > 0:
    S.updateSha512(A.toOpenArray(0, split - 1))
  if split < A.len:
    S.updateSha512(A.toOpenArray(split, A.len - 1))
  result = S.finishSha512()

proc incrementalSha384(A: openArray[byte], split: int): custom_sha512.Sha384Digest =
  var S: custom_sha512.Sha512Context = custom_sha512.initSha384()
  if split > 0:
    S.updateSha512(A.toOpenArray(0, split - 1))
  if split < A.len:
    S.updateSha512(A.toOpenArray(split, A.len - 1))
  result = S.finishSha384()

suite "custom SHA-512 and SHA-384":
  test "FIPS empty and abc vectors match":
    var
      empty: seq[byte] = @[]
      abc: seq[byte] = toBytes("abc")
    check @(custom_sha512.sha512Hash(empty)) == hexToBytes(
      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce4" &
      "7d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")
    check @(custom_sha512.sha512Hash(abc)) == hexToBytes(
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" &
      "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")
    check @(custom_sha512.sha384Hash(empty)) == hexToBytes(
      "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da" &
      "274edebfe76f65fbd51ad2f14898b95b")
    check @(custom_sha512.sha384Hash(abc)) == hexToBytes(
      "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed" &
      "8086072ba1e7cc2358baeca134c825a7")

  test "padding boundaries match the independent Ed25519 SHA-512 core":
    var
      lengths: array[8, int] = [0, 3, 111, 112, 113, 127, 128, 129]
      A: seq[byte] = @[]
      expected: reference_sha512.Ed25519Bytes64
      split: int = 0
    for n in lengths:
      A = patternedBytes(n)
      expected = reference_sha512.ed25519Sha512Hash(A)
      check custom_sha512.sha512Hash(A) == expected
      split = n div 2
      check incrementalSha512(A, 0) == expected
      check incrementalSha512(A, min(1, n)) == expected
      check incrementalSha512(A, split) == expected
      check incrementalSha512(A, n) == expected

  test "SHA-384 streaming matches one-shot at padding boundaries":
    var
      lengths: array[8, int] = [0, 3, 111, 112, 113, 127, 128, 129]
      A: seq[byte] = @[]
      expected: custom_sha512.Sha384Digest
    for n in lengths:
      A = patternedBytes(n)
      expected = custom_sha512.sha384Hash(A)
      check incrementalSha384(A, 0) == expected
      check incrementalSha384(A, min(1, n)) == expected
      check incrementalSha384(A, n div 2) == expected
      check incrementalSha384(A, n) == expected

  test "128-bit message length overflow rejects before state mutation":
    var S: custom_sha512.Sha512Context = custom_sha512.initSha512()
    S.lengthHigh = high(uint64)
    S.lengthLow = high(uint64) - 7'u64
    expect ValueError:
      S.updateSha512(@[0'u8])
    check S.lengthHigh == high(uint64)
    check S.lengthLow == high(uint64) - 7'u64
    check S.bufferLen == 0
