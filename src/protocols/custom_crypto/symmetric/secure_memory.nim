## -----------------------------------------------------------------
## | Secure Memory <- compiler-resistant wiping for symmetric data |
## | secret bytes/words -> volatile zero writes -> cleared storage |
## -----------------------------------------------------------------

import std/[typetraits, volatile]

proc secureClearBytes*(A: var openArray[byte]) {.raises: [].} =
  ## A: secret byte storage to overwrite in place.
  var
    i: int = 0
  while i < A.len:
    volatileStore(addr A[i], 0'u8)
    i = i + 1

proc secureClearPod*[T](v: var T) {.raises: [].} =
  ## v: plain value whose full storage must be overwritten.
  when supportsCopyMem(T):
    var
      p: ptr UncheckedArray[byte] = cast[ptr UncheckedArray[byte]](addr v)
      i: int = 0
    while i < sizeof(T):
      volatileStore(addr p[i], 0'u8)
      i = i + 1
  else:
    {.error: "secureClearPod requires a POD-style type".}
