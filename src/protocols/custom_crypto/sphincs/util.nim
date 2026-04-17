## ---------------------------------------------------------------
## SPHINCS Util <- byte helpers, tree hashing, and Merkle helpers
## ---------------------------------------------------------------

import std/volatile
import std/typetraits

proc ullToBytes*(outBytes: var openArray[byte], value: uint64) =
  var
    i: int = 0
  i = outBytes.len - 1
  while i >= 0:
    outBytes[i] = byte(value shr (8 * (outBytes.len - 1 - i)))
    i = i - 1

proc u32ToBytes*(outBytes: var openArray[byte], value: uint32) =
  outBytes[0] = byte((value shr 24) and 0xff'u32)
  outBytes[1] = byte((value shr 16) and 0xff'u32)
  outBytes[2] = byte((value shr 8) and 0xff'u32)
  outBytes[3] = byte(value and 0xff'u32)

proc bytesToUll*(A: openArray[byte]): uint64 =
  for i in 0 ..< A.len:
    result = result or (uint64(A[i]) shl (8 * (A.len - 1 - i)))

proc appendBytes*(S: var seq[byte], A: openArray[byte]) =
  let start = S.len
  S.setLen(start + A.len)
  if A.len > 0:
    copyMem(addr S[start], unsafeAddr A[0], A.len)

proc clearBytes*(A: var openArray[byte]) {.raises: [].} =
  if A.len > 0:
    zeroMem(addr A[0], A.len)

proc clearPlainData*[T](S: var T) {.raises: [].} =
  ## Use this only for POD-style local state that supports raw byte copies.
  when supportsCopyMem(T):
    zeroMem(addr S, sizeof(T))
  else:
    {.error: "clearPlainData requires supportsCopyMem(T)".}

proc clearSensitiveBytes*(A: var openArray[byte]) {.raises: [].} =
  var
    i: int = 0
  while i < A.len:
    volatileStore(addr A[i], 0'u8)
    i = i + 1

proc clearSensitivePlainData*[T](S: var T) {.raises: [].} =
  ## Reserve volatile wipes for direct secret-bearing POD state.
  when supportsCopyMem(T):
    var
      p: ptr UncheckedArray[byte] = cast[ptr UncheckedArray[byte]](addr S)
      i: int = 0
    while i < sizeof(T):
      volatileStore(addr p[i], 0'u8)
      i = i + 1
  else:
    {.error: "clearSensitivePlainData requires supportsCopyMem(T)".}

proc ctMaskEqU32*(a, b: uint32): uint32 {.inline, raises: [].} =
  var
    x: uint32 = a xor b
    neq: uint32 = (x or (0'u32 - x)) shr 31
  result = 0'u32 - (neq xor 1'u32)

proc ctCopyBytesMasked*(dst: var openArray[byte], src: openArray[byte],
    mask: uint32) {.inline, raises: [].} =
  var
    m: byte = byte(mask and 0xff'u32)
    keep: byte = not m
    i: int = 0
  while i < dst.len:
    dst[i] = (dst[i] and keep) or (src[i] and m)
    i = i + 1
