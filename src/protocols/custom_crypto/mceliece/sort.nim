## Constant-time bitonic sorts used by Classic McEliece controlbits logic.
## Pure-Nim port of PQClean int32_sort/uint64_sort (clean variants).

proc int32MinMax(a, b: var int32) {.inline.} =
  let ab = b xor a
  let c = b - a
  var m = c xor ab
  m = m shr 31          # arithmetic: 0 or -1
  m = m and ab
  a = a xor m
  b = b xor m

proc uint64MinMax(a, b: var uint64) {.inline.} =
  var c = b - a
  c = c shr 63          # 0 or 1
  let mask = (0'u64 - c) and (a xor b)
  a = a xor mask
  b = b xor mask

## In-place constant-time sort of int32 values (bitonic network).
proc int32Sort*(x: var openArray[int32]) =
  let n = x.len
  if n < 2: return
  var top = 1
  while top < n - top:
    top = top shl 1

  var p = top
  while p > 0:
    for i in 0 ..< n - p:
      if (i and p) == 0:
        int32MinMax(x[i], x[i + p])
    var i = 0
    var q = top
    while q > p:
      while i < n - q:
        if (i and p) == 0:
          var a = x[i + p]
          var r = q
          while r > p:
            int32MinMax(a, x[i + r])
            r = r shr 1
          x[i + p] = a
        inc i
      q = q shr 1
    p = p shr 1

## In-place constant-time sort of uint64 values (bitonic network).
proc uint64Sort*(x: var openArray[uint64]) =
  let n = x.len
  if n < 2: return
  var top = 1
  while top < n - top:
    top = top shl 1

  var p = top
  while p > 0:
    for i in 0 ..< n - p:
      if (i and p) == 0:
        uint64MinMax(x[i], x[i + p])
    var i = 0
    var q = top
    while q > p:
      while i < n - q:
        if (i and p) == 0:
          var a = x[i + p]
          var r = q
          while r > p:
            uint64MinMax(a, x[i + r])
            r = r shr 1
          x[i + p] = a
        inc i
      q = q shr 1
    p = p shr 1

