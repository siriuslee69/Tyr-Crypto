## ---------------------------------------------------------------
## SPHINCS Util <- byte helpers, tree hashing, and Merkle helpers
## ---------------------------------------------------------------

import std/volatile
import std/typetraits

## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; canonical byte and polynomial encoding rules for `ullToBytes`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc ullToBytes*(outBytes: var openArray[byte], value: uint64) =
  var
    i: int = 0
  i = outBytes.len - 1
  while i >= 0:
    outBytes[i] = byte(value shr (8 * (outBytes.len - 1 - i)))
    i = i - 1

## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; canonical byte and polynomial encoding rules for `u32ToBytes`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc u32ToBytes*(outBytes: var openArray[byte], value: uint32) =
  outBytes[0] = byte((value shr 24) and 0xff'u32)
  outBytes[1] = byte((value shr 16) and 0xff'u32)
  outBytes[2] = byte((value shr 8) and 0xff'u32)
  outBytes[3] = byte(value and 0xff'u32)

## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; canonical byte and polynomial encoding rules for `bytesToUll`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc bytesToUll*(A: openArray[byte]): uint64 =
  for i in 0 ..< A.len:
    result = result or (uint64(A[i]) shl (8 * (A.len - 1 - i)))

## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; canonical byte and polynomial encoding rules for `appendBytes`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc appendBytes*(S: var seq[byte], A: openArray[byte]) =
  var start = S.len
  S.setLen(start + A.len)
  if A.len > 0:
    copyMem(addr S[start], unsafeAddr A[0], A.len)

## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; canonical byte and polynomial encoding rules for `clearBytes`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc clearBytes*(A: var openArray[byte]) {.raises: [].} =
  if A.len > 0:
    zeroMem(addr A[0], A.len)

## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; canonical byte and polynomial encoding rules for `clearPlainData`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc clearPlainData*[T](S: var T) {.raises: [].} =
  ## Use this only for POD-style local state that supports raw byte copies.
  when supportsCopyMem(T):
    zeroMem(addr S, sizeof(T))
  else:
    {.error: "clearPlainData requires supportsCopyMem(T)".}

## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; canonical byte and polynomial encoding rules for `clearSensitiveBytes`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc clearSensitiveBytes*(A: var openArray[byte]) {.raises: [].} =
  var
    i: int = 0
  while i < A.len:
    volatileStore(addr A[i], 0'u8)
    i = i + 1

## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; canonical byte and polynomial encoding rules for `clearSensitivePlainData`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
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

## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; canonical byte and polynomial encoding rules for `ctMaskEqU32`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc ctMaskEqU32*(a, b: uint32): uint32 {.inline, raises: [].} =
  var
    x: uint32 = a xor b
    neq: uint32 = (x or (0'u32 - x)) shr 31
  result = 0'u32 - (neq xor 1'u32)

## Reference: [SPHINCS-R3.1] version 3.1 sections 3-4 and algorithms 1-23; canonical byte and polynomial encoding rules for `ctCopyBytesMasked`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc ctCopyBytesMasked*(dst: var openArray[byte], src: openArray[byte],
    mask: uint32) {.inline, raises: [].} =
  var
    m: byte = byte(mask and 0xff'u32)
    keep: byte = not m
    i: int = 0
  while i < dst.len:
    dst[i] = (dst[i] and keep) or (src[i] and m)
    i = i + 1
