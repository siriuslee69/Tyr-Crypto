## ----------------------------------------------------------------
## X25519 Ref10 Nim <- local scalar reference facade for benchmarks
## ----------------------------------------------------------------

import ./x25519_common
import ./x25519_pass1

proc copyFromPtr(dst: var X25519Bytes32, src: ptr uint8) =
  var
    bytes: ptr UncheckedArray[uint8]
    i: int = 0
  if src.isNil:
    return
  bytes = cast[ptr UncheckedArray[uint8]](src)
  i = 0
  while i < x25519KeyBytes:
    dst[i] = byte(bytes[i])
    i = i + 1

proc copyToPtr(dst: ptr uint8, src: X25519Bytes32) =
  var
    bytes: ptr UncheckedArray[uint8]
    i: int = 0
  if dst.isNil:
    return
  bytes = cast[ptr UncheckedArray[uint8]](dst)
  i = 0
  while i < x25519KeyBytes:
    bytes[i] = uint8(src[i])
    i = i + 1

proc tyr_x25519_ref10_scalarmult*(q: ptr uint8, n: ptr uint8, p: ptr uint8): cint {.cdecl.} =
  var
    shared: X25519Bytes32
    secretKey: X25519Bytes32
    publicKey: X25519Bytes32
    ok: bool = false
  if q.isNil or n.isNil or p.isNil:
    return -1
  copyFromPtr(secretKey, n)
  copyFromPtr(publicKey, p)
  ok = x25519_pass1.x25519ScalarmultRaw(shared, secretKey, publicKey)
  if not ok:
    copyToPtr(q, shared)
    return -1
  copyToPtr(q, shared)
  result = 0

proc tyr_x25519_ref10_scalarmult_base*(q: ptr uint8, n: ptr uint8): cint {.cdecl.} =
  var
    publicKey: X25519Bytes32
    secretKey: X25519Bytes32
    ok: bool = false
  if q.isNil or n.isNil:
    return -1
  copyFromPtr(secretKey, n)
  ok = x25519_pass1.x25519ScalarmultBaseRaw(publicKey, secretKey)
  if not ok:
    copyToPtr(q, publicKey)
    return -1
  copyToPtr(q, publicKey)
  result = 0
