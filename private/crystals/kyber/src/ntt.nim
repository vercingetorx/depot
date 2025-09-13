# ntt.nim

import reduce

## zetas table from the Kyber reference (ntt.c)
const zetas*: array[128, int16] = [
  -1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
   -171,   622,  1577,   182,   962, -1202, -1474,  1468,
    573, -1325,   264,   383,  -829,  1458, -1602,  -130,
   -681,  1017,   732,   608, -1542,   411,  -205, -1571,
   1223,   652,  -552,  1015, -1293,  1491,  -282, -1544,
    516,    -8,  -320,  -666, -1618, -1162,   126,  1469,
   -853,   -90,  -271,   830,   107, -1421,  -247,  -951,
   -398,   961, -1508,  -725,   448, -1065,   677, -1275,
  -1103,   430,   555,   843, -1251,   871,  1550,   105,
    422,   587,   177,  -235,  -291,  -460,  1574,  1653,
   -246,   778,  1159,  -147,  -777,  1483,  -602,  1119,
  -1590,   644,  -872,   349,   418,   329,  -156,   -75,
    817,  1097,   603,   610,  1322, -1285, -1465,   384,
  -1215,  -136,  1218, -1335,  -874,   220, -1187, -1659,
  -1185, -1530, -1278,   794, -1510,  -854,  -870,   478,
   -108,  -308,   996,   991,   958, -1460,  1522,  1628
]

## fqmul: (a * b) followed by Montgomery reduction
proc fqmul(a, b: int16): int16 {.inline.} =
  montgomery_reduce(a.int32 * b.int32)

## In-place forward NTT: input standard order -> output bit-reversed order
proc ntt*(r: var openArray[int16]) =
  when not defined(release):
    doAssert r.len >= 256
  var k = 1
  var len = 128
  while len >= 2:
    var start = 0
    while start < 256:
      let zeta = zetas[k]
      inc k
      for j in start ..< start + len:
        let t = fqmul(zeta, r[j + len])
        r[j + len] = r[j] - t
        r[j] = r[j] + t
      start += 2 * len   # matches C's: start = j + len (with j == start + len)
    len = len shr 1

## In-place inverse NTT, then multiply by mont factor 2^16 (via f = 1441)
## Input bit-reversed order -> output standard order
proc invntt*(r: var openArray[int16]) =
  when not defined(release):
    doAssert r.len >= 256
  var k = 127
  const f: int16 = 1441  # mont^2 / 128

  var len = 2
  while len <= 128:
    var start = 0
    while start < 256:
      let zeta = zetas[k]
      dec k
      for j in start ..< start + len:
        let t = r[j]
        r[j] = barrett_reduce(t + r[j + len])
        r[j + len] = r[j + len] - t
        r[j + len] = fqmul(zeta, r[j + len])
      start += 2 * len   # matches C's: start = j + len
    len = len shl 1

  for j in 0 ..< 256:
    r[j] = fqmul(r[j], f)

## Base multiplication in Z_q[X]/(X^2 - zeta)
proc basemul*(r: var array[2, int16]; a, b: array[2, int16]; zeta: int16) =
  r[0]  = fqmul(a[1], b[1])
  r[0]  = fqmul(r[0], zeta)
  r[0] += fqmul(a[0], b[0])
  r[1]  = fqmul(a[0], b[1])
  r[1] += fqmul(a[1], b[0])
