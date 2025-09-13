# poly.nim — Kyber polynomial ops

import params, ntt, reduce, symmetric, types, cbd

# --- Constant-time small helper ------------------------------------------------

proc cmov_int16(r: var int16; v: int16; b: uint8) {.inline.} =
  ## Conditional move: if b==1 then r=v else r=r, constant time.
  ## Only the LSB of b is used.
  let m = -int16(b and 1'u8)      # 0x0000 or 0xFFFF
  r = r xor (m and (r xor v))

# --- Message <-> Polynomial ----------------------------------------------------

proc poly_frommsg*(r: var Poly; msg: openArray[byte]) =
  ## Convert 32-byte msg to polynomial.
  when not defined(release):
    doAssert msg.len == KYBER_INDCPA_MSGBYTES
  for i in 0 ..< (KYBER_N div 8):
    for j in 0 ..< 8:
      r.coeffs[8*i + j] = 0
      cmov_int16(r.coeffs[8*i + j],
                 ((KYBER_Q + 1) div 2).int16,
                 ((msg[i] shr j) and 1'u8))

proc poly_tomsg*(msg: var openArray[byte]; a: Poly) =
  ## Convert polynomial to 32-byte msg.
  when not defined(release):
    doAssert msg.len == KYBER_INDCPA_MSGBYTES
  var t: uint32
  for i in 0 ..< (KYBER_N div 8):
    msg[i] = 0
    for j in 0 ..< 8:
      t  = a.coeffs[8*i + j].uint32
      t = (t shl 1) + 1665
      t = t * 80635'u32
      t = (t shr 28) and 1
      msg[i] = msg[i] or (t shl j).byte

# --- Noise sampling ------------------------------------------------------------

proc poly_getnoise_eta1*(r: var Poly; seed: openArray[byte]; nonce: byte) =
  ## Sample polynomial with CBD parameter ETA1
  var buf: array[KYBER_ETA1 * KYBER_N div 4, byte]
  prf(buf, buf.len, seed, nonce)
  poly_cbd_eta1(r, buf)

proc poly_getnoise_eta2*(r: var Poly; seed: openArray[byte]; nonce: byte) =
  ## Sample polynomial with CBD parameter ETA2
  var buf: array[KYBER_ETA2 * KYBER_N div 4, byte]
  prf(buf, buf.len, seed, nonce)
  poly_cbd_eta2(r, buf)

# --- Compression / Decompression ----------------------------------------------

proc poly_compress*(r: var openArray[byte]; a: Poly) =
  ## Compress+serialize polynomial.
  when not defined(release):
    doAssert r.len == KYBER_POLYCOMPRESSEDBYTES
  var d0: uint32
  var t: array[8, uint8]
  var off = 0

  when KYBER_POLYCOMPRESSEDBYTES == 128:
    for i in 0 ..< (KYBER_N div 8):
      for j in 0 ..< 8:
        # map to positive standard representative: u += (u>>15) & q
        let u = (a.coeffs[8*i + j].int32 + ((a.coeffs[8*i + j].int32 shr 15) and KYBER_Q)).uint32
        d0 = (u shl 4) + 1665'u32
        d0 = d0 * 80635'u32
        d0 = d0 shr 28
        t[j] = (d0 and 0x0F'u32).uint8

      r[off + 0] = t[0] or (t[1] shl 4)
      r[off + 1] = t[2] or (t[3] shl 4)
      r[off + 2] = t[4] or (t[5] shl 4)
      r[off + 3] = t[6] or (t[7] shl 4)
      off += 4

  elif KYBER_POLYCOMPRESSEDBYTES == 160:
    for i in 0 ..< (KYBER_N div 8):
      for j in 0 ..< 8:
        let u = (a.coeffs[8*i + j].int32 + ((a.coeffs[8*i + j].int32 shr 15) and KYBER_Q)).uint32
        d0 = (u shl 5) + 1664'u32
        d0 = d0 * 40318'u32
        d0 = d0 shr 27
        t[j] = (d0 and 0x1F'u32).uint8

      r[off + 0] = (t[0] shr 0) or (t[1] shl 5)
      r[off + 1] = (t[1] shr 3) or (t[2] shl 2) or (t[3] shl 7)
      r[off + 2] = (t[3] shr 1) or (t[4] shl 4)
      r[off + 3] = (t[4] shr 4) or (t[5] shl 1) or (t[6] shl 6)
      r[off + 4] = (t[6] shr 2) or (t[7] shl 3)
      off += 5

  else:
    {.error: "KYBER_POLYCOMPRESSEDBYTES must be 128 or 160".}

proc poly_decompress*(r: var Poly; a: openArray[byte]) =
  ## De-serialize+decompress polynomial.
  when not defined(release):
    doAssert a.len == KYBER_POLYCOMPRESSEDBYTES
  var off = 0

  when KYBER_POLYCOMPRESSEDBYTES == 128:
    for i in 0 ..< (KYBER_N div 2):
      r.coeffs[2*i + 0] = ((((a[off] and 15).uint16 * KYBER_Q.uint16) + 8'u16) shr 4).int16
      r.coeffs[2*i + 1] = ((((a[off] shr 4).uint16 * KYBER_Q.uint16) + 8'u16) shr 4).int16
      inc off

  elif KYBER_POLYCOMPRESSEDBYTES == 160:
    var t: array[8, uint8]
    for i in 0 ..< (KYBER_N div 8):
      t[0] = (a[off + 0] shr 0)
      t[1] = (a[off + 0] shr 5) or (a[off + 1] shl 3)
      t[2] = (a[off + 1] shr 2)
      t[3] = (a[off + 1] shr 7) or (a[off + 2] shl 1)
      t[4] = (a[off + 2] shr 4) or (a[off + 3] shl 4)
      t[5] = (a[off + 3] shr 1)
      t[6] = (a[off + 3] shr 6) or (a[off + 4] shl 2)
      t[7] = (a[off + 4] shr 3)
      off += 5
      for j in 0 ..< 8:
        r.coeffs[8*i + j] = (((t[j] and 31).uint32 * KYBER_Q.uint32 + 16'u32) shr 5).int16

  else:
    {.error: "KYBER_POLYCOMPRESSEDBYTES must be 128 or 160".}

# --- Serialization -------------------------------------------------------------

proc poly_tobytes*(r: var openArray[byte]; a: Poly) =
  ## Serialize polynomial to KYBER_POLYBYTES.
  when not defined(release):
    doAssert r.len == KYBER_POLYBYTES
  var t0, t1: uint16
  for i in 0 ..< (KYBER_N div 2):
    # map to positive representatives using constant-time trick
    t0 = (a.coeffs[2*i].uint16) + ((a.coeffs[2*i].int32 shr 15) and KYBER_Q).uint16
    t1 = (a.coeffs[2*i + 1].uint16) + ((a.coeffs[2*i + 1].int32 shr 15) and KYBER_Q).uint16
    r[3*i + 0] = (t0 shr 0).uint8
    r[3*i + 1] = ((t0 shr 8) or (t1 shl 4)).uint8
    r[3*i + 2] = (t1 shr 4).uint8

proc poly_frombytes*(r: var Poly; a: openArray[byte]) =
  ## De-serialize polynomial from KYBER_POLYBYTES.
  when not defined(release):
    doAssert a.len == KYBER_POLYBYTES
  for i in 0 ..< (KYBER_N div 2):
    r.coeffs[2*i]   = (((a[3*i + 0].uint16) or (a[3*i + 1].uint16 shl 8)) and 0x0FFF'u16).int16
    r.coeffs[2*i+1] = (((a[3*i + 1].uint16 shr 4) or (a[3*i + 2].uint16 shl 4)) and 0x0FFF'u16).int16

# --- Arithmetic on polynomials -----------------------------------------------

proc poly_add*(r: var Poly; a, b: Poly) =
  for i in 0 ..< KYBER_N:
    r.coeffs[i] = a.coeffs[i] + b.coeffs[i]

proc poly_sub*(r: var Poly; a, b: Poly) =
  for i in 0 ..< KYBER_N:
    r.coeffs[i] = a.coeffs[i] - b.coeffs[i]

proc poly_reduce*(r: var Poly) =
  for i in 0 ..< KYBER_N:
    r.coeffs[i] = barrett_reduce(r.coeffs[i])

# --- NTT wrappers -------------------------------------------------------------

proc poly_ntt*(r: var Poly) =
  ntt(r.coeffs)
  poly_reduce(r)

proc poly_invntt_tomont*(r: var Poly) =
  invntt(r.coeffs)

proc poly_basemul_montgomery*(r: var Poly; a, b: Poly) =
  ## Multiply two polys in NTT domain (basemul in Z_q[X]/(X^2 - zeta)).
  for i in 0 ..< (KYBER_N div 4):
    var ra, aa, ba: array[2, int16]
    aa[0] = a.coeffs[4*i]
    aa[1] = a.coeffs[4*i + 1]
    ba[0] = b.coeffs[4*i]
    ba[1] = b.coeffs[4*i + 1]
    basemul(ra, aa, ba, zetas[64 + i])
    r.coeffs[4*i]     = ra[0]
    r.coeffs[4*i + 1] = ra[1]

    aa[0] = a.coeffs[4*i + 2]
    aa[1] = a.coeffs[4*i + 3]
    ba[0] = b.coeffs[4*i + 2]
    ba[1] = b.coeffs[4*i + 3]
    basemul(ra, aa, ba, -zetas[64 + i])
    r.coeffs[4*i + 2] = ra[0]
    r.coeffs[4*i + 3] = ra[1]

proc poly_tomont*(r: var Poly) =
  ## In-place conversion from normal to Montgomery domain: x -> x * R mod q
  # f = (1ULL << 32) % KYBER_Q, computed in 64-bit to be explicit
  const f: int32 = ( (1'u64 shl 32) mod KYBER_Q.uint64 ).int32
  for i in 0 ..< KYBER_N:
    r.coeffs[i] = montgomery_reduce(r.coeffs[i].int32 * f)
