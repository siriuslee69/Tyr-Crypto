## -------------------------------------------------------
## Kyber NTT <- negacyclic NTT and base multiplication core
## -------------------------------------------------------

import ./params
import ./reduce

when defined(avx2):
  import nimsimd/avx as navx
  import nimsimd/avx2 as navx2

{.push boundChecks: off.}

const zetas*: array[128, int16] = [
  -1044'i16,  -758'i16,  -359'i16, -1517'i16,  1493'i16,  1422'i16,   287'i16,   202'i16,
   -171'i16,   622'i16,  1577'i16,   182'i16,   962'i16, -1202'i16, -1474'i16,  1468'i16,
    573'i16, -1325'i16,   264'i16,   383'i16,  -829'i16,  1458'i16, -1602'i16,  -130'i16,
   -681'i16,  1017'i16,   732'i16,   608'i16, -1542'i16,   411'i16,  -205'i16, -1571'i16,
   1223'i16,   652'i16,  -552'i16,  1015'i16, -1293'i16,  1491'i16,  -282'i16, -1544'i16,
    516'i16,    -8'i16,  -320'i16,  -666'i16, -1618'i16, -1162'i16,   126'i16,  1469'i16,
   -853'i16,   -90'i16,  -271'i16,   830'i16,   107'i16, -1421'i16,  -247'i16,  -951'i16,
   -398'i16,   961'i16, -1508'i16,  -725'i16,   448'i16, -1065'i16,   677'i16, -1275'i16,
  -1103'i16,   430'i16,   555'i16,   843'i16, -1251'i16,   871'i16,  1550'i16,   105'i16,
    422'i16,   587'i16,   177'i16,  -235'i16,  -291'i16,  -460'i16,  1574'i16,  1653'i16,
   -246'i16,   778'i16,  1159'i16,  -147'i16,  -777'i16,  1483'i16,  -602'i16,  1119'i16,
  -1590'i16,   644'i16,  -872'i16,   349'i16,   418'i16,   329'i16,  -156'i16,   -75'i16,
    817'i16,  1097'i16,   603'i16,   610'i16,  1322'i16, -1285'i16, -1465'i16,   384'i16,
  -1215'i16,  -136'i16,  1218'i16, -1335'i16,  -874'i16,   220'i16, -1187'i16, -1659'i16,
  -1185'i16, -1530'i16, -1278'i16,   794'i16, -1510'i16,  -854'i16,  -870'i16,   478'i16,
   -108'i16,  -308'i16,   996'i16,   991'i16,   958'i16, -1460'i16,  1522'i16,  1628'i16
]

proc fqMul(a, b: int16): int16 {.inline.} =
  result = montgomeryReduce(int32(a) * int32(b))

when defined(avx2):
  proc nttButterflyChunk8(aPtr, bPtr: ptr int16, zeta: int16) {.inline.} =
    var
      aVec: navx.M256i = loadI16x8AsI32x8(aPtr)
      bVec: navx.M256i = loadI16x8AsI32x8(bPtr)
      zetaVec: navx.M256i = navx.mm256_set1_epi32(int32(zeta))
      tVec: navx.M256i = montgomeryReduceVec8(navx2.mm256_mullo_epi32(bVec, zetaVec))
    packStoreI32x8ToI16x8(aPtr, navx2.mm256_add_epi32(aVec, tVec))
    packStoreI32x8ToI16x8(bPtr, navx2.mm256_sub_epi32(aVec, tVec))

  proc invNttButterflyChunk8(aPtr, bPtr: ptr int16, zeta: int16) {.inline.} =
    var
      aVec: navx.M256i = loadI16x8AsI32x8(aPtr)
      bVec: navx.M256i = loadI16x8AsI32x8(bPtr)
      zetaVec: navx.M256i = navx.mm256_set1_epi32(int32(zeta))
      sumVec: navx.M256i = barrettReduceVec8(navx2.mm256_add_epi32(aVec, bVec))
      diffVec: navx.M256i = navx2.mm256_sub_epi32(bVec, aVec)
    diffVec = montgomeryReduceVec8(navx2.mm256_mullo_epi32(diffVec, zetaVec))
    packStoreI32x8ToI16x8(aPtr, sumVec)
    packStoreI32x8ToI16x8(bPtr, diffVec)

proc ntt*(R: var array[kyberN, int16]) {.inline.} =
  ## Forward NTT from standard order to bit-reversed order.
  var
    len: int = 0
    start: int = 0
    j: int = 0
    k: int = 1
    t: int16 = 0
    zeta: int16 = 0
  len = 128
  when defined(avx2):
    while len >= 8:
      start = 0
      while start < kyberN:
        zeta = zetas[k]
        k = k + 1
        j = start
        while j + 8 <= start + len:
          nttButterflyChunk8(unsafeAddr R[j], unsafeAddr R[j + len], zeta)
          j = j + 8
        while j < start + len:
          t = fqMul(zeta, R[j + len])
          R[j + len] = R[j] - t
          R[j] = R[j] + t
          j = j + 1
        start = j + len
      len = len shr 1
  while len >= 2:
    start = 0
    while start < kyberN:
      zeta = zetas[k]
      k = k + 1
      j = start
      while j < start + len:
        t = fqMul(zeta, R[j + len])
        R[j + len] = R[j] - t
        R[j] = R[j] + t
        j = j + 1
      start = j + len
    len = len shr 1

proc invNtt*(R: var array[kyberN, int16]) {.inline.} =
  ## Inverse NTT back to standard order and Montgomery scale factor.
  var
    start: int = 0
    len: int = 2
    j: int = 0
    k: int = 127
    t: int16 = 0
    zeta: int16 = 0
  const f = 1441'i16 ## mont^2 / 128
  when defined(avx2):
    j = 0
    while j + 8 <= kyberN:
      montgomeryMulChunk8(unsafeAddr R[j], unsafeAddr R[j], f)
      j = j + 8
    while j < kyberN:
      R[j] = fqMul(R[j], f)
      j = j + 1
    len = 2
    while len <= 4:
      start = 0
      while start < kyberN:
        zeta = zetas[k]
        k = k - 1
        j = start
        while j < start + len:
          t = R[j]
          R[j] = barrettReduce(t + R[j + len])
          R[j + len] = R[j + len] - t
          R[j + len] = fqMul(zeta, R[j + len])
          j = j + 1
        start = j + len
      len = len shl 1
    while len <= 128:
      start = 0
      while start < kyberN:
        zeta = zetas[k]
        k = k - 1
        j = start
        while j + 8 <= start + len:
          invNttButterflyChunk8(unsafeAddr R[j], unsafeAddr R[j + len], zeta)
          j = j + 8
        while j < start + len:
          t = R[j]
          R[j] = barrettReduce(t + R[j + len])
          R[j + len] = R[j + len] - t
          R[j + len] = fqMul(zeta, R[j + len])
          j = j + 1
        start = j + len
      len = len shl 1
  else:
    j = 0
    while j < kyberN:
      R[j] = fqMul(R[j], f)
      j = j + 1
    len = 2
    while len <= 128:
      start = 0
      while start < kyberN:
        zeta = zetas[k]
        k = k - 1
        j = start
        while j < start + len:
          t = R[j]
          R[j] = barrettReduce(t + R[j + len])
          R[j + len] = R[j + len] - t
          R[j + len] = fqMul(zeta, R[j + len])
          j = j + 1
        start = j + len
      len = len shl 1

proc baseMul*(R: var array[2, int16], A, B: array[2, int16], zeta: int16) {.inline.} =
  ## Multiply two degree-1 polynomials in Z_q[X]/(X^2 - zeta).
  R[0] = fqMul(A[1], B[1])
  R[0] = fqMul(R[0], zeta)
  R[0] = R[0] + fqMul(A[0], B[0])
  R[1] = fqMul(A[0], B[1])
  R[1] = R[1] + fqMul(A[1], B[0])

{.pop.}
