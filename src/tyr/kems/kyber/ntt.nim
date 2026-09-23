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

## Reference: [KYBER-R3-20210804] version 3.02 sections 1.3 and 4, algorithms 1-9; finite-field, ring, and transform arithmetic for `fqMul`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.
proc fqMul(a, b: int16): int16 {.inline.} =
  result = montgomeryReduce(int32(a) * int32(b))

include "ntt_avx2.nim"
include "ntt_forward.nim"
## Reference: [KYBER-R3-20210804] version 3.02 sections 1.3 and 4, algorithms 1-9; finite-field, ring, and transform arithmetic for `invNtt`; pitfall: preserve the cited equations, fixed bounds, and representation invariants.

include "ntt_inverse.nim"
