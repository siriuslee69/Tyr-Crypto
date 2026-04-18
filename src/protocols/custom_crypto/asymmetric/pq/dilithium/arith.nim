## -----------------------------------------------------------------
## Dilithium Arithmetic <- reductions, NTT, rounding, and XOF helpers
## -----------------------------------------------------------------

import ./params
import ../../../sha3

const
  dilithiumMont = -4186625'i32
  dilithiumQInv = 58728449'i32

const zetas*: array[dilithiumN, int32] = [
    0'i32,    25847'i32, -2608894'i32,  -518909'i32,   237124'i32,  -777960'i32,  -876248'i32,   466468'i32,
  1826347'i32,  2353451'i32,  -359251'i32, -2091905'i32,  3119733'i32, -2884855'i32,  3111497'i32,  2680103'i32,
  2725464'i32,  1024112'i32, -1079900'i32,  3585928'i32,  -549488'i32, -1119584'i32,  2619752'i32, -2108549'i32,
 -2118186'i32, -3859737'i32, -1399561'i32, -3277672'i32,  1757237'i32,   -19422'i32,  4010497'i32,   280005'i32,
  2706023'i32,    95776'i32,  3077325'i32,  3530437'i32, -1661693'i32, -3592148'i32, -2537516'i32,  3915439'i32,
 -3861115'i32, -3043716'i32,  3574422'i32, -2867647'i32,  3539968'i32,  -300467'i32,  2348700'i32,  -539299'i32,
 -1699267'i32, -1643818'i32,  3505694'i32, -3821735'i32,  3507263'i32, -2140649'i32, -1600420'i32,  3699596'i32,
   811944'i32,   531354'i32,   954230'i32,  3881043'i32,  3900724'i32, -2556880'i32,  2071892'i32, -2797779'i32,
 -3930395'i32, -1528703'i32, -3677745'i32, -3041255'i32, -1452451'i32,  3475950'i32,  2176455'i32, -1585221'i32,
 -1257611'i32,  1939314'i32, -4083598'i32, -1000202'i32, -3190144'i32, -3157330'i32, -3632928'i32,   126922'i32,
  3412210'i32,  -983419'i32,  2147896'i32,  2715295'i32, -2967645'i32, -3693493'i32,  -411027'i32, -2477047'i32,
  -671102'i32, -1228525'i32,   -22981'i32, -1308169'i32,  -381987'i32,  1349076'i32,  1852771'i32, -1430430'i32,
 -3343383'i32,   264944'i32,   508951'i32,  3097992'i32,    44288'i32, -1100098'i32,   904516'i32,  3958618'i32,
 -3724342'i32,    -8578'i32,  1653064'i32, -3249728'i32,  2389356'i32,  -210977'i32,   759969'i32, -1316856'i32,
   189548'i32, -3553272'i32,  3159746'i32, -1851402'i32, -2409325'i32,  -177440'i32,  1315589'i32,  1341330'i32,
  1285669'i32, -1584928'i32,  -812732'i32, -1439742'i32, -3019102'i32, -3881060'i32, -3628969'i32,  3839961'i32,
  2091667'i32,  3407706'i32,  2316500'i32,  3817976'i32, -3342478'i32,  2244091'i32, -2446433'i32, -3562462'i32,
   266997'i32,  2434439'i32, -1235728'i32,  3513181'i32, -3520352'i32, -3759364'i32, -1197226'i32, -3193378'i32,
   900702'i32,  1859098'i32,   909542'i32,   819034'i32,   495491'i32, -1613174'i32,   -43260'i32,  -522500'i32,
  -655327'i32, -3122442'i32,  2031748'i32,  3207046'i32, -3556995'i32,  -525098'i32,  -768622'i32, -3595838'i32,
   342297'i32,   286988'i32, -2437823'i32,  4108315'i32,  3437287'i32, -3342277'i32,  1735879'i32,   203044'i32,
  2842341'i32,  2691481'i32, -2590150'i32,  1265009'i32,  4055324'i32,  1247620'i32,  2486353'i32,  1595974'i32,
 -3767016'i32,  1250494'i32,  2635921'i32, -3548272'i32, -2994039'i32,  1869119'i32,  1903435'i32, -1050970'i32,
 -1333058'i32,  1237275'i32, -3318210'i32, -1430225'i32,  -451100'i32,  1312455'i32,  3306115'i32, -1962642'i32,
 -1279661'i32,  1917081'i32, -2546312'i32, -1374803'i32,  1500165'i32,   777191'i32,  2235880'i32,  3406031'i32,
  -542412'i32, -2831860'i32, -1671176'i32, -1846953'i32, -2584293'i32, -3724270'i32,   594136'i32, -3776993'i32,
 -2013608'i32,  2432395'i32,  2454455'i32,  -164721'i32,  1957272'i32,  3369112'i32,   185531'i32, -1207385'i32,
 -3183426'i32,   162844'i32,  1616392'i32,  3014001'i32,   810149'i32,  1652634'i32, -3694233'i32, -1799107'i32,
 -3038916'i32,  3523897'i32,  3866901'i32,   269760'i32,  2213111'i32,  -975884'i32,  1717735'i32,   472078'i32,
  -426683'i32,  1723600'i32, -1803090'i32,  1910376'i32, -1667432'i32, -1104333'i32,  -260646'i32, -3833893'i32,
 -2939036'i32, -2235985'i32,  -420899'i32, -2286327'i32,   183443'i32,  -976891'i32,  1612842'i32, -3545687'i32,
  -554416'i32,  3919660'i32,   -48306'i32, -1362209'i32,  3937738'i32,  1400424'i32,  -846154'i32,  1976782'i32
]

proc concatNonce(seed: openArray[byte], nonce: uint16): seq[byte] =
  result = newSeq[byte](seed.len + 2)
  if seed.len > 0:
    copyMem(addr result[0], unsafeAddr seed[0], seed.len)
  result[seed.len] = byte(nonce and 0xff'u16)
  result[seed.len + 1] = byte((nonce shr 8) and 0xff'u16)

proc shake128Stream*(seed: openArray[byte], nonce: uint16, outLen: int): seq[byte] =
  ## SHAKE128(seed || nonce_le) stream used by ML-DSA.
  result = shake128(concatNonce(seed, nonce), outLen)

proc shake256Stream*(seed: openArray[byte], nonce: uint16, outLen: int): seq[byte] =
  ## SHAKE256(seed || nonce_le) stream used by ML-DSA.
  result = shake256(concatNonce(seed, nonce), outLen)

{.push boundChecks: off, overflowChecks: off.}
proc montgomeryReduce*(a: int64): int32 {.inline, raises: [].} =
  ## Compute `a * 2^-32 mod q` with the reference Dilithium bounds.
  var
    t: int32 = 0
    t64: int64 = 0
  t64 = int64(cast[int32](a)) * int64(dilithiumQInv)
  t = cast[int32](t64)
  ## The reference Dilithium bounds guarantee the post-shift value fits in int32.
  result = cast[int32]((a - int64(t) * int64(dilithiumQ)) shr 32)

proc reduce32*(a: int32): int32 {.inline, raises: [].} =
  ## Reduce to the centered Dilithium interval.
  var
    t: int32 = 0
  t = (a + (1 shl 22)) shr 23
  result = a - t * dilithiumQ

proc caddq*(a: int32): int32 {.inline, raises: [].} =
  ## Add `q` when the value is negative.
  result = a + ((a shr 31) and dilithiumQ)

proc freeze*(a: int32): int32 {.inline, raises: [].} =
  ## Canonical representative mod `q`.
  result = caddq(reduce32(a))

proc power2round*(a: int32): tuple[a1, a0: int32] {.inline, raises: [].} =
  ## Split into high and low bits around `2^D`.
  result.a1 = (a + (1 shl (dilithiumD - 1)) - 1) shr dilithiumD
  result.a0 = a - (result.a1 shl dilithiumD)

proc decomposeGamma32*(a: int32): tuple[a1, a0: int32] {.inline, raises: [].} =
  var
    a1: int32 = 0
    a0: int32 = 0
  a1 = (a + 127) shr 7
  a1 = (a1 * 1025 + (1 shl 21)) shr 22
  a1 = a1 and 15
  a0 = a - a1 * 2 * ((dilithiumQ - 1) div 32)
  a0 = a0 - (((((dilithiumQ - 1) div 2) - a0) shr 31) and dilithiumQ)
  result = (a1: a1, a0: a0)

proc decomposeGamma88*(a: int32): tuple[a1, a0: int32] {.inline, raises: [].} =
  var
    a1: int32 = 0
    a0: int32 = 0
  a1 = (a + 127) shr 7
  a1 = (a1 * 11275 + (1 shl 23)) shr 24
  a1 = a1 xor (((43 - a1) shr 31) and a1)
  a0 = a - a1 * 2 * ((dilithiumQ - 1) div 88)
  a0 = a0 - (((((dilithiumQ - 1) div 2) - a0) shr 31) and dilithiumQ)
  result = (a1: a1, a0: a0)

proc decompose*(p: DilithiumParams, a: int32): tuple[a1, a0: int32] {.inline, raises: [].} =
  ## Split into high and low bits around `alpha = 2*gamma2`.
  if p.gamma2 == (dilithiumQ - 1) div 32:
    result = decomposeGamma32(a)
    return
  result = decomposeGamma88(a)

proc useHintGamma32*(a: int32, hint: uint32): int32 {.inline, raises: [].} =
  var
    d: tuple[a1, a0: int32]
  d = decomposeGamma32(a)
  if hint == 0'u32:
    return d.a1
  if d.a0 > 0:
    return (d.a1 + 1) and 15
  result = (d.a1 - 1) and 15

proc useHintGamma88*(a: int32, hint: uint32): int32 {.inline, raises: [].} =
  var
    d: tuple[a1, a0: int32]
  d = decomposeGamma88(a)
  if hint == 0'u32:
    return d.a1
  if d.a0 > 0:
    if d.a1 == 43:
      return 0
    return d.a1 + 1
  if d.a1 == 0:
    return 43
  result = d.a1 - 1

proc useHint*(p: DilithiumParams, a: int32, hint: uint32): int32 {.inline, raises: [].} =
  ## Correct high bits using the hint bit.
  if p.gamma2 == (dilithiumQ - 1) div 32:
    result = useHintGamma32(a, hint)
    return
  result = useHintGamma88(a, hint)

proc makeHint*(p: DilithiumParams, a0, a1: int32): uint32 {.inline, raises: [].} =
  ## Hint whether low bits overflow into high bits.
  if a0 > p.gamma2 or a0 < -p.gamma2 or (a0 == -p.gamma2 and a1 != 0):
    return 1'u32
  result = 0'u32


template nttLayer(A, l, k: untyped) =
  block:
    var
      start: int = 0
      j: int = 0
      zeta: int32 = 0
      t: int32 = 0
    start = 0
    while start < dilithiumN:
      k = k + 1
      zeta = zetas[k]
      j = start
      while j < start + l:
        t = montgomeryReduce(int64(zeta) * int64(A[j + l]))
        A[j + l] = A[j] - t
        A[j] = A[j] + t
        j = j + 1
      start = j + l

template invnttLayer(A, l, k: untyped) =
  block:
    var
      start: int = 0
      j: int = 0
      t: int32 = 0
      zeta: int32 = 0
    start = 0
    while start < dilithiumN:
      k = k - 1
      zeta = -zetas[k]
      j = start
      while j < start + l:
        t = A[j]
        A[j] = t + A[j + l]
        A[j + l] = t - A[j + l]
        A[j + l] = montgomeryReduce(int64(zeta) * int64(A[j + l]))
        j = j + 1
      start = j + l

proc ntt*(A: var array[dilithiumN, int32]) {.raises: [].} =
  ## Forward in-place NTT.
  var
    k: int = 0
  k = 0
  nttLayer(A, 128, k)
  nttLayer(A, 64, k)
  nttLayer(A, 32, k)
  nttLayer(A, 16, k)
  nttLayer(A, 8, k)
  nttLayer(A, 4, k)
  nttLayer(A, 2, k)
  nttLayer(A, 1, k)

proc invnttTomont*(A: var array[dilithiumN, int32]) {.raises: [].} =
  ## Inverse in-place NTT with final Montgomery factor.
  var
    j: int = 0
    k: int = dilithiumN
  const f = 41978'i32
  invnttLayer(A, 1, k)
  invnttLayer(A, 2, k)
  invnttLayer(A, 4, k)
  invnttLayer(A, 8, k)
  invnttLayer(A, 16, k)
  invnttLayer(A, 32, k)
  invnttLayer(A, 64, k)
  invnttLayer(A, 128, k)
  j = 0
  while j < dilithiumN:
    A[j] = montgomeryReduce(int64(f) * int64(A[j]))
    j = j + 1
{.pop.}
