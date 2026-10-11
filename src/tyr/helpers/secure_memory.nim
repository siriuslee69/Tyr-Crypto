## -----------------------------------------------------------------
## | Secure Memory <- the ONE place that wipes secrets in Tyr       |
## | secret bytes/words -> volatile zero writes -> cleared storage |
## -----------------------------------------------------------------
##
##   call                    for                        example
##   ──────────────────────  ─────────────────────────  ───────────────────
##   secureClearBytes(A)     bytes: seq, array, slice   a key, a seed
##   secureClearItems(A)     a list of plain items      seq[uint16] poly
##   secureClearPod(v)       one plain value            a state object
##
## Every algorithm uses these three. Do not write another copy: until
## 2026-10-11 eleven modules had their own, one of them without volatile
## writes (so the compiler could delete it).
##
## A "volatile" write is one the compiler must keep, even when it can see
## that nobody reads the memory afterwards. A plain `zeroMem` at the end of
## a routine is often deleted for exactly that reason.
##
##   storage:  [b b b][w w w w w w ... w][b b]
##              ^ bytes until the address is a multiple of 8
##                     ^ 8-byte words: one write clears 8 bytes
##                                        ^ the last 0..7 bytes
##
## The word part is what keeps wiping cheap. A 200-byte SHAKE state takes
## 25 writes instead of 200, so even the hot hashing paths can afford it.

import std/[typetraits, volatile]

proc secureClearRaw(p: pointer, n: int) {.inline, raises: [].} =
  ## p/n: start and byte length of the secret storage to overwrite.
  var
    B: ptr UncheckedArray[byte] = cast[ptr UncheckedArray[byte]](p)
    i: int = 0
  while i < n and (cast[uint](addr B[i]) and 7'u) != 0:
    volatileStore(addr B[i], 0'u8)
    i = i + 1
  while i + 8 <= n:
    volatileStore(cast[ptr uint64](addr B[i]), 0'u64)
    i = i + 8
  while i < n:
    volatileStore(addr B[i], 0'u8)
    i = i + 1

proc secureClearBytes*(A: var openArray[byte]) {.inline, raises: [].} =
  ## A: secret byte storage to overwrite in place.
  if A.len > 0:
    secureClearRaw(addr A[0], A.len)

proc secureClearPod*[T](v: var T) {.inline, raises: [].} =
  ## v: plain value whose full storage must be overwritten.
  when supportsCopyMem(T):
    secureClearRaw(addr v, sizeof(T))
  else:
    {.error: "secureClearPod requires a POD-style type".}

proc secureClearItems*[T](A: var openArray[T]) {.inline, raises: [].} =
  ## A: secret list of plain items (uint16, uint64, int32, objects ...),
  ## for example a seq or a polynomial buffer. Every item is overwritten.
  when supportsCopyMem(T):
    if A.len > 0:
      secureClearRaw(addr A[0], A.len * sizeof(T))
  else:
    {.error: "secureClearItems requires POD-style items".}
