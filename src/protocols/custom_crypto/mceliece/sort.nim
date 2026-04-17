## Constant-time bitonic sorts used by Classic McEliece controlbits logic.
## Pure-Nim port of PQClean int32_sort/uint64_sort (clean variants).

{.compile: "sort_fast.c".}

import ../../helpers/otter_support

proc cUint64Sort(x: ptr uint64, n: clonglong) {.
    importc: "tyr_mceliece_uint64_sort", cdecl.}

{.push checks: off.}
proc int32MinMax(a, b: var int32) {.inline.} =
  let ab = b xor a
  var c = b - a
  c = c xor (ab and (c xor b))
  c = c shr 31
  c = c and ab
  a = a xor c
  b = b xor c
{.pop.}

proc uint64MinMax(a, b: var uint64) {.inline.} =
  var c = b - a
  c = c shr 63          # 0 or 1
  let mask = (0'u64 - c) and (a xor b)
  a = a xor mask
  b = b xor mask

## In-place constant-time sort of int32 values (bitonic network).
{.push checks: off.}
proc int32SortTop(n: int): int {.inline.} =
  var top: int = 1
  while top < n - top:
    top = top + top
  result = top

proc int32SortLeadPass(x: ptr UncheckedArray[int32], n, p: int) {.inline.} =
  var i: int = 0
  while i < n - p:
    if (i and p) == 0:
      int32MinMax(x[i], x[i + p])
    i = i + 1

proc int32SortCascade(a: var int32, x: ptr UncheckedArray[int32], i, q, p: int) {.inline.} =
  var r: int = q
  while r > p:
    int32MinMax(a, x[i + r])
    r = r shr 1

proc int32SortTailPass(x: ptr UncheckedArray[int32], n, top, p: int) {.inline.} =
  var
    i: int = 0
    q: int = top
    a: int32 = 0
  while q > p:
    while i < n - q:
      if (i and p) == 0:
        a = x[i + p]
        int32SortCascade(a, x, i, q, p)
        x[i + p] = a
      i = i + 1
    q = q shr 1

proc int32SortRaw*(x: ptr UncheckedArray[int32], n: int) {.otterBench.} =
  if n < 2:
    return
  var
    top: int = 0
    p: int = 0
  top = int32SortTop(n)

  p = top
  while p > 0:
    int32SortLeadPass(x, n, p)
    int32SortTailPass(x, n, top, p)
    p = p shr 1

proc int32Sort*(x: var openArray[int32]) =
  int32SortRaw(cast[ptr UncheckedArray[int32]](unsafeAddr x[0]), x.len)

proc uint64SortRawC*(x: ptr UncheckedArray[uint64], n: int) =
  if n < 2:
    return
  cUint64Sort(cast[ptr uint64](x), clonglong(n))

proc uint64SortTop(n: int): int {.inline.} =
  var top: int = 1
  while top < n - top:
    top = top + top
  result = top

proc uint64SortLeadPass(x: ptr UncheckedArray[uint64], n, p: int) {.inline.} =
  var i: int = 0
  while i < n - p:
    if (i and p) == 0:
      uint64MinMax(x[i], x[i + p])
    i = i + 1

proc uint64SortCascade(a: var uint64, x: ptr UncheckedArray[uint64], i, q, p: int) {.inline.} =
  var r: int = q
  while r > p:
    uint64MinMax(a, x[i + r])
    r = r shr 1

proc uint64SortTailPass(x: ptr UncheckedArray[uint64], n, top, p: int) {.inline.} =
  var
    i: int = 0
    q: int = top
    a: uint64 = 0
  while q > p:
    while i < n - q:
      if (i and p) == 0:
        a = x[i + p]
        uint64SortCascade(a, x, i, q, p)
        x[i + p] = a
      i = i + 1
    q = q shr 1

proc uint64SortRawNim*(x: ptr UncheckedArray[uint64], n: int) =
  if n < 2:
    return
  var
    top: int = 0
    p: int = 0
  top = uint64SortTop(n)

  p = top
  while p > 0:
    uint64SortLeadPass(x, n, p)
    uint64SortTailPass(x, n, top, p)
    p = p shr 1

proc uint64SortC*(x: var openArray[uint64]) =
  if x.len < 2:
    return
  uint64SortRawC(cast[ptr UncheckedArray[uint64]](unsafeAddr x[0]), x.len)

proc uint64SortNim*(x: var openArray[uint64]) =
  if x.len < 2:
    return
  uint64SortRawNim(cast[ptr UncheckedArray[uint64]](unsafeAddr x[0]), x.len)

## In-place constant-time sort of uint64 values (bitonic network).
proc uint64Sort*(x: var openArray[uint64]) =
  when defined(mcelieceUseCSort) or defined(mcelieceUseCFast):
    uint64SortC(x)
  else:
    uint64SortNim(x)
{.pop.}
