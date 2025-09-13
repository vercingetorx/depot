# polyvec.nim — Kyber polynomial vector ops

import params, poly, types

type
  PolyVec* = object
    vec*: array[KYBER_K, Poly]

# ---------------------------------------------------------------------------
# Compress / Decompress
# ---------------------------------------------------------------------------

proc polyvec_compress*(r: var openArray[byte]; a: PolyVec) =
  ## Compress and serialize vector of polynomials.
  ## Writes exactly KYBER_POLYVECCOMPRESSEDBYTES bytes starting at r[0].
  var roff = 0

  when KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 352):
    var t: array[8, uint16]
    for i in 0 ..< KYBER_K:
      for j in 0 ..< (KYBER_N div 8):
        for k in 0 ..< 8:
          let u = a.vec[i].coeffs[8*j + k]
          t[k] = u.uint16 + ((u shr 15).uint16 and KYBER_Q.uint16)
          var d0 = t[k].uint64
          d0 = (d0 shl 11) + 1664'u64
          d0 = d0 * 645084'u64
          d0 = d0 shr 31
          t[k] = (d0 and 0x7FF'u64).uint16

        r[roff + 0]  = (t[0] shr 0).uint8
        r[roff + 1]  = ((t[0] shr 8) or (t[1] shl 3)).uint8
        r[roff + 2]  = ((t[1] shr 5) or (t[2] shl 6)).uint8
        r[roff + 3]  = (t[2] shr 2).uint8
        r[roff + 4]  = ((t[2] shr 10) or (t[3] shl 1)).uint8
        r[roff + 5]  = ((t[3] shr 7) or (t[4] shl 4)).uint8
        r[roff + 6]  = ((t[4] shr 4) or (t[5] shl 7)).uint8
        r[roff + 7]  = (t[5] shr 1).uint8
        r[roff + 8]  = ((t[5] shr 9) or (t[6] shl 2)).uint8
        r[roff + 9]  = ((t[6] shr 6) or (t[7] shl 5)).uint8
        r[roff + 10] = (t[7] shr 3).uint8
        roff += 11

  elif KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 320):
    var t: array[4, uint16]
    for i in 0 ..< KYBER_K:
      for j in 0 ..< (KYBER_N div 4):
        for k in 0 ..< 4:
          let u = a.vec[i].coeffs[4*j + k]
          t[k] = u.uint16 + ((u shr 15).uint16 and KYBER_Q.uint16)
          var d0 = t[k].uint64
          d0 = (d0 shl 10) + 1665'u64
          d0 = d0 * 1290167'u64
          d0 = d0 shr 32
          t[k] = (d0 and 0x3FF'u64).uint16

        r[roff + 0] = (t[0] shr 0).uint8
        r[roff + 1] = ((t[0] shr 8) or (t[1] shl 2)).uint8
        r[roff + 2] = ((t[1] shr 6) or (t[2] shl 4)).uint8
        r[roff + 3] = ((t[2] shr 4) or (t[3] shl 6)).uint8
        r[roff + 4] = (t[3] shr 2).uint8
        roff += 5

  else:
    {.error: "KYBER_POLYVECCOMPRESSEDBYTES must be KYBER_K * 320 or KYBER_K * 352".}

proc polyvec_decompress*(r: var PolyVec; a: openArray[byte]) =
  ## Decompress vector of polynomials from a.
  ## Reads exactly KYBER_POLYVECCOMPRESSEDBYTES bytes from a[0].
  var aoff = 0

  when KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 352):
    var t: array[8, uint16]
    for i in 0 ..< KYBER_K:
      for j in 0 ..< (KYBER_N div 8):
        t[0] = (a[aoff + 0].uint16 shr 0) or (a[aoff + 1].uint16 shl 8)
        t[1] = (a[aoff + 1].uint16 shr 3) or (a[aoff + 2].uint16 shl 5)
        t[2] = (a[aoff + 2].uint16 shr 6) or (a[aoff + 3].uint16 shl 2) or (a[aoff + 4].uint16 shl 10)
        t[3] = (a[aoff + 4].uint16 shr 1) or (a[aoff + 5].uint16 shl 7)
        t[4] = (a[aoff + 5].uint16 shr 4) or (a[aoff + 6].uint16 shl 4)
        t[5] = (a[aoff + 6].uint16 shr 7) or (a[aoff + 7].uint16 shl 1) or (a[aoff + 8].uint16 shl 9)
        t[6] = (a[aoff + 8].uint16 shr 2) or (a[aoff + 9].uint16 shl 6)
        t[7] = (a[aoff + 9].uint16 shr 5) or (a[aoff + 10].uint16 shl 3)
        aoff += 11

        for k in 0 ..< 8:
          r.vec[i].coeffs[8*j + k] =
            (((t[k] and 0x7FF'u16).uint32 * KYBER_Q.uint32 + 1024'u32) shr 11).int16

  elif KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 320):
    var t: array[4, uint16]
    for i in 0 ..< KYBER_K:
      for j in 0 ..< (KYBER_N div 4):
        t[0] = (a[aoff + 0].uint16 shr 0) or (a[aoff + 1].uint16 shl 8)
        t[1] = (a[aoff + 1].uint16 shr 2) or (a[aoff + 2].uint16 shl 6)
        t[2] = (a[aoff + 2].uint16 shr 4) or (a[aoff + 3].uint16 shl 4)
        t[3] = (a[aoff + 3].uint16 shr 6) or (a[aoff + 4].uint16 shl 2)
        aoff += 5

        for k in 0 ..< 4:
          r.vec[i].coeffs[4*j + k] =
            (((t[k] and 0x3FF'u16).uint32 * KYBER_Q.uint32 + 512'u32) shr 10).int16

  else:
    {.error: "KYBER_POLYVECCOMPRESSEDBYTES must be KYBER_K * 320 or KYBER_K * 352".}

# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

proc polyvec_tobytes*(r: var openArray[byte]; a: PolyVec) =
  ## Serialize a vector of polynomials.
  ## Writes into the first KYBER_POLYVECBYTES of r.
  when not defined(release):
    doAssert r.len >= KYBER_POLYVECBYTES  # allow larger buffers (e.g., pk)
  for i in 0 ..< KYBER_K:
    poly_tobytes(
      r.toOpenArray(i*KYBER_POLYBYTES, (i+1)*KYBER_POLYBYTES - 1),
      a.vec[i]
    )

proc polyvec_frombytes*(r: var PolyVec; a: openArray[byte]) =
  ## De-serialize a vector of polynomials.
  ## Reads from the first KYBER_POLYVECBYTES of a.
  when not defined(release):
    doAssert a.len >= KYBER_POLYVECBYTES  # allow larger buffers (e.g., pk)
  for i in 0 ..< KYBER_K:
    poly_frombytes(
      r.vec[i],
      a.toOpenArray(i*KYBER_POLYBYTES, (i+1)*KYBER_POLYBYTES - 1)
    )

# ---------------------------------------------------------------------------
# NTT wrappers / arithmetic
# ---------------------------------------------------------------------------

proc polyvec_ntt*(r: var PolyVec) =
  for i in 0 ..< KYBER_K:
    poly_ntt(r.vec[i])

proc polyvec_invntt_tomont*(r: var PolyVec) =
  for i in 0 ..< KYBER_K:
    poly_invntt_tomont(r.vec[i])

proc polyvec_basemul_acc_montgomery*(r: var Poly; a, b: PolyVec) =
  var t: Poly
  poly_basemul_montgomery(r, a.vec[0], b.vec[0])
  for i in 1 ..< KYBER_K:
    poly_basemul_montgomery(t, a.vec[i], b.vec[i])
    poly_add(r, r, t)
  poly_reduce(r)

proc polyvec_reduce*(r: var PolyVec) =
  for i in 0 ..< KYBER_K:
    poly_reduce(r.vec[i])

proc polyvec_add*(r: var PolyVec; a, b: PolyVec) =
  ## r = a + b (no modular reduction)
  for i in 0 ..< KYBER_K:
    poly_add(r.vec[i], a.vec[i], b.vec[i])
