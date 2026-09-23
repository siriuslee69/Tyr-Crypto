## ---------------------------------------------------------
## Poly1305 <- scalar one-time authenticator over LE message
## ---------------------------------------------------------

import ../../helpers/secure_memory

const
  poly1305KeyBytes* = 32
  poly1305TagBytes* = 16
  poly1305BlockBytes = 16
  poly1305Mask26 = 0x3ffffff'u64
  poly1305Hibit = 1'u64 shl 24

type
  ## Fixed detached Poly1305 tag.
  Poly1305Tag* = array[poly1305TagBytes, byte]

proc load32Le(A: openArray[byte], o: int): uint32 {.inline.} =
  result =
    uint32(A[o]) or
    (uint32(A[o + 1]) shl 8) or
    (uint32(A[o + 2]) shl 16) or
    (uint32(A[o + 3]) shl 24)

proc store32Le(A: var openArray[byte], o: int, v: uint32) {.inline.} =
  A[o] = byte(v and 0xff'u32)
  A[o + 1] = byte((v shr 8) and 0xff'u32)
  A[o + 2] = byte((v shr 16) and 0xff'u32)
  A[o + 3] = byte((v shr 24) and 0xff'u32)

proc constantTimeEqual(A, B: openArray[byte]): bool =
  var
    diff: uint = if A.len == B.len: 0'u else: 1'u
    i: int = 0
    b: byte = 0
  while i < A.len:
    b = if i < B.len: B[i] else: 0'u8
    diff = diff or uint(A[i] xor b)
    i = i + 1
  result = diff == 0'u

include "poly1305_finalize.nim"

when defined(amd64) or defined(i386) or defined(neon) or defined(arm64) or defined(aarch64):
  import ./poly1305_simd
  export poly1305_simd

include "poly1305_api.nim"
