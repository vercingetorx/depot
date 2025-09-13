# poly.nim
# Port of Dilithium poly.c with Nim safety checks on.

import helpers, params, ntt, reduce, rounding, symmetric, types


proc polyz_unpack*(r: var Poly; a: openArray[byte])

# ---------------- Basic arith ----------------

proc poly_reduce*(a: var Poly) =
  for i in 0 ..< N:
    a.coeffs[i] = reduce32(a.coeffs[i])

proc poly_caddq*(a: var Poly) =
  for i in 0 ..< N:
    a.coeffs[i] = caddq(a.coeffs[i])

proc poly_add*(c: var Poly; a, b: Poly) =
  for i in 0 ..< N:
    c.coeffs[i] = a.coeffs[i] + b.coeffs[i]

proc poly_sub*(c: var Poly; a, b: Poly) =
  for i in 0 ..< N:
    c.coeffs[i] = a.coeffs[i] - b.coeffs[i]

proc poly_shiftl*(a: var Poly) =
  for i in 0 ..< N:
    a.coeffs[i] = a.coeffs[i] shl D

# ---------------- NTT ----------------

proc poly_ntt*(a: var Poly) =
  ntt(a.coeffs)

proc poly_invntt_tomont*(a: var Poly) =
  invntt_tomont(a.coeffs)

proc poly_pointwise_montgomery*(c: var Poly; a, b: Poly) =
  for i in 0 ..< N:
    c.coeffs[i] = montgomery_reduce(int64(a.coeffs[i]) * int64(b.coeffs[i]))

# ---------------- Rounding / Decompose / Hints ----------------

proc poly_power2round*(a1: var Poly; a0: var Poly; a: Poly) =
  for i in 0 ..< N:
    a1.coeffs[i] = power2round(a0.coeffs[i], a.coeffs[i])

proc poly_decompose*(a1: var Poly; a0: var Poly; a: Poly) =
  for i in 0 ..< N:
    a1.coeffs[i] = decompose(a0.coeffs[i], a.coeffs[i])

proc poly_make_hint*(h: var Poly; a0, a1: Poly): uint =
  var s: uint = 0
  for i in 0 ..< N:
    h.coeffs[i] = make_hint(a0.coeffs[i], a1.coeffs[i])
    s += uint(h.coeffs[i])
  s

proc poly_use_hint*(b: var Poly; a, h: Poly) =
  for i in 0 ..< N:
    b.coeffs[i] = use_hint(a.coeffs[i], h.coeffs[i])

# ---------------- Norm check ----------------

proc poly_chknorm*(a: Poly; B: int32): int =
  if B > (Q - 1) div 8: return 1
  for i in 0 ..< N:
    var t = a.coeffs[i] shr 31            # sign mask
    t = a.coeffs[i] - (t and 2 * a.coeffs[i])  # abs value without leaking sign
    if t >= B: return 1
  0

# ---------------- Rejection samplers ----------------

proc rej_uniform(dst: var openArray[int32], len: int,
                 buf: openArray[byte], buflen: int): int =
  var ctr = 0
  var pos = 0
  while ctr < len and pos + 3 <= buflen:
    var t = (uint32(buf[pos]) or (uint32(buf[pos+1]) shl 8) or (uint32(buf[pos+2]) shl 16)) and 0x7FFFFFu32
    pos += 3
    if int(t) < Q:
      dst[ctr] = int32(t)
      inc ctr
  ctr

proc rej_eta(dst: var openArray[int32], len: int,
             buf: openArray[byte], buflen: int): int =
  var ctr = 0
  var pos = 0
  while ctr < len and pos < buflen:
    var t0 = uint32(buf[pos]) and 0x0Fu32
    var t1 = uint32(buf[pos]) shr 4
    inc pos
    when ETA == 2:
      if t0 < 15'u32:
        t0 = t0 - (205'u32 * t0 shr 10) * 5'u32
        dst[ctr] = int32(2 - int(t0)); inc ctr
      if t1 < 15'u32 and ctr < len:
        t1 = t1 - (205'u32 * t1 shr 10) * 5'u32
        dst[ctr] = int32(2 - int(t1)); inc ctr
    elif ETA == 4:
      if t0 < 9'u32:
        dst[ctr] = int32(4 - int(t0)); inc ctr
      if t1 < 9'u32 and ctr < len:
        dst[ctr] = int32(4 - int(t1)); inc ctr
  ctr

# ---------------- Uniform sampling ----------------

const POLY_UNIFORM_NBLOCKS* = (768 + STREAM128_BLOCKBYTES - 1) div STREAM128_BLOCKBYTES

proc poly_uniform*(a: var Poly; seed: openArray[byte]; nonce: uint16) =
  doAssert seed.len == SEEDBYTES
  var buflen = POLY_UNIFORM_NBLOCKS * STREAM128_BLOCKBYTES
  var buf = newSeq[byte](buflen + 2) # +2 per ref impl
  var st: Stream128State
  stream128_init(st, seed, nonce)
  stream128_squeezeblocks(buf.oa(0, buflen), POLY_UNIFORM_NBLOCKS, st)

  var ctr = rej_uniform(a.coeffs.oa(0, N), N, buf.roa(0, buflen), buflen)
  while ctr < N:
    let off = buflen mod 3
    for i in 0 ..< off:
      buf[i] = buf[buflen - off + i]
    stream128_squeezeblocks(buf.oa(off, STREAM128_BLOCKBYTES), 1, st)
    buflen = STREAM128_BLOCKBYTES + off
    ctr += rej_uniform(a.coeffs.oa(ctr, N - ctr), N - ctr, buf.roa(0, buflen), buflen)

# ---------------- ETA sampling ----------------

when ETA == 2:
  const POLY_UNIFORM_ETA_NBLOCKS* = (136 + STREAM256_BLOCKBYTES - 1) div STREAM256_BLOCKBYTES
elif ETA == 4:
  const POLY_UNIFORM_ETA_NBLOCKS* = (227 + STREAM256_BLOCKBYTES - 1) div STREAM256_BLOCKBYTES

proc poly_uniform_eta*(a: var Poly; seed: openArray[byte]; nonce: uint16) =
  doAssert seed.len == CRHBYTES
  var buflen = POLY_UNIFORM_ETA_NBLOCKS * STREAM256_BLOCKBYTES
  var buf = newSeq[byte](buflen)
  var st: Stream256State
  stream256_init(st, seed, nonce)
  stream256_squeezeblocks(buf.oa(0, buflen), POLY_UNIFORM_ETA_NBLOCKS, st)

  var ctr = rej_eta(a.coeffs.oa(0, N), N, buf.roa(0, buflen), buflen)
  while ctr < N:
    stream256_squeezeblocks(buf.oa(0, STREAM256_BLOCKBYTES), 1, st)
    ctr += rej_eta(a.coeffs.oa(ctr, N - ctr), N - ctr, buf.roa(0, STREAM256_BLOCKBYTES), STREAM256_BLOCKBYTES)

# ---------------- GAMMA1 sampling ----------------

const POLY_UNIFORM_GAMMA1_NBLOCKS* =
  (POLYZ_PACKEDBYTES + STREAM256_BLOCKBYTES - 1) div STREAM256_BLOCKBYTES

proc poly_uniform_gamma1*(a: var Poly; seed: openArray[byte]; nonce: uint16) =
  doAssert seed.len == CRHBYTES
  var buf = newSeq[byte](POLY_UNIFORM_GAMMA1_NBLOCKS * STREAM256_BLOCKBYTES)
  var st: Stream256State
  stream256_init(st, seed, nonce)
  stream256_squeezeblocks(buf.oa(0, buf.len), POLY_UNIFORM_GAMMA1_NBLOCKS, st)
  polyz_unpack(a, oa(buf, 0, POLYZ_PACKEDBYTES))

# ---------------- Challenge (H) ----------------

proc poly_challenge*(c: var Poly; seed: openArray[byte]) =
  doAssert seed.len == CTILDEBYTES
  var st: KeccakState
  var buf = newSeq[byte](SHAKE256_RATE)
  shake256_init(st)
  shake256_absorb(st, seed)
  shake256_finalize(st)
  shake256_squeezeblocks(buf.oa(0, SHAKE256_RATE), 1, st)

  var signs: uint64 = 0
  for i in 0 ..< 8:
    signs = signs or (uint64(buf[i]) shl (8 * i))
  var pos = 8

  for i in 0 ..< N: c.coeffs[i] = 0
  for i in (N - TAU) ..< N:
    var b: int
    while true:
      if pos >= SHAKE256_RATE:
        shake256_squeezeblocks(buf.oa(0, SHAKE256_RATE), 1, st)
        pos = 0
      b = int(buf[pos]); inc pos
      if b <= i: break
    c.coeffs[i] = c.coeffs[b]
    let bit = int(signs and 1'u64)
    c.coeffs[b] = int32(1 - 2 * bit)
    signs = signs shr 1

# ---------------- Packing: eta ----------------

proc polyeta_pack*(r: var openArray[byte]; a: Poly) =
  doAssert r.len == POLYETA_PACKEDBYTES
  when ETA == 2:
    for i in 0 ..< N div 8:
      var t: array[8, uint32]
      for j in 0 .. 7: t[j] = uint32(ETA - a.coeffs[8*i + j])
      r[3*i + 0] = byte( (t[0]      ) or (t[1] shl 3) or (t[2] shl 6) )
      r[3*i + 1] = byte( (t[2] shr 2) or (t[3] shl 1) or (t[4] shl 4) or (t[5] shl 7) )
      r[3*i + 2] = byte( (t[5] shr 1) or (t[6] shl 2) or (t[7] shl 5) )
  elif ETA == 4:
    for i in 0 ..< N div 2:
      let t0 = uint32(ETA - a.coeffs[2*i])
      let t1 = uint32(ETA - a.coeffs[2*i+1])
      r[i] = byte( t0 or (t1 shl 4) )

proc polyeta_unpack*(r: var Poly; a: openArray[byte]) =
  doAssert a.len == POLYETA_PACKEDBYTES
  when ETA == 2:
    for i in 0 ..< N div 8:
      var v0 = (a[3*i+0]      ) and 7
      var v1 = (a[3*i+0] shr 3) and 7
      var v2 = ( (a[3*i+0] shr 6) or (a[3*i+1] shl 2) ) and 7
      var v3 = (a[3*i+1] shr 1) and 7
      var v4 = (a[3*i+1] shr 4) and 7
      var v5 = ( (a[3*i+1] shr 7) or (a[3*i+2] shl 1) ) and 7
      var v6 = (a[3*i+2] shr 2) and 7
      var v7 = (a[3*i+2] shr 5) and 7
      r.coeffs[8*i+0] = ETA - int32(v0)
      r.coeffs[8*i+1] = ETA - int32(v1)
      r.coeffs[8*i+2] = ETA - int32(v2)
      r.coeffs[8*i+3] = ETA - int32(v3)
      r.coeffs[8*i+4] = ETA - int32(v4)
      r.coeffs[8*i+5] = ETA - int32(v5)
      r.coeffs[8*i+6] = ETA - int32(v6)
      r.coeffs[8*i+7] = ETA - int32(v7)
  elif ETA == 4:
    for i in 0 ..< N div 2:
      let lo = int32(a[i] and 0x0F)
      let hi = int32(a[i] shr 4)
      r.coeffs[2*i]   = ETA - lo
      r.coeffs[2*i+1] = ETA - hi

# ---------------- Packing: t1 (10-bit) ----------------

proc polyt1_pack*(r: var openArray[byte]; a: Poly) =
  doAssert r.len == POLYT1_PACKEDBYTES
  for i in 0 ..< N div 4:
    let a0 = uint32(a.coeffs[4*i+0]) and 0x3FF
    let a1 = uint32(a.coeffs[4*i+1]) and 0x3FF
    let a2 = uint32(a.coeffs[4*i+2]) and 0x3FF
    let a3 = uint32(a.coeffs[4*i+3]) and 0x3FF
    r[5*i+0] = byte(a0 and 0xFF)
    r[5*i+1] = byte(((a0 shr 8) or (a1 shl 2)) and 0xFF)
    r[5*i+2] = byte(((a1 shr 6) or (a2 shl 4)) and 0xFF)
    r[5*i+3] = byte(((a2 shr 4) or (a3 shl 6)) and 0xFF)
    r[5*i+4] = byte( (a3 shr 2) and 0xFF )

proc polyt1_unpack*(r: var Poly; a: openArray[byte]) =
  doAssert a.len == POLYT1_PACKEDBYTES
  for i in 0 ..< N div 4:
    r.coeffs[4*i+0] = int32( (uint32(a[5*i+0]) or (uint32(a[5*i+1]) shl 8)) and 0x3FF )
    r.coeffs[4*i+1] = int32( ((uint32(a[5*i+1]) shr 2) or (uint32(a[5*i+2]) shl 6)) and 0x3FF )
    r.coeffs[4*i+2] = int32( ((uint32(a[5*i+2]) shr 4) or (uint32(a[5*i+3]) shl 4)) and 0x3FF )
    r.coeffs[4*i+3] = int32( ((uint32(a[5*i+3]) shr 6) or (uint32(a[5*i+4]) shl 2)) and 0x3FF )

# ---------------- Packing: t0 (13-bit signed window) ----------------

proc polyt0_pack*(r: var openArray[byte]; a: Poly) =
  doAssert r.len == POLYT0_PACKEDBYTES
  for i in 0 ..< N div 8:
    var t: array[8, uint32]
    for j in 0 .. 7:
      t[j] = uint32((1 shl (D-1)) - a.coeffs[8*i + j]) and 0x1FFF'u32
    r[13*i+0]  = byte( t[0]        and 0xFF )
    r[13*i+1]  = byte((t[0] shr 8) or (t[1] shl 5))
    r[13*i+2]  = byte( t[1] shr 3 )
    r[13*i+3]  = byte((t[1] shr 11) or (t[2] shl 2))
    r[13*i+4]  = byte((t[2] shr 6)  or (t[3] shl 7))
    r[13*i+5]  = byte( t[3] shr 1 )
    r[13*i+6]  = byte((t[3] shr 9)  or (t[4] shl 4))
    r[13*i+7]  = byte((t[4] shr 4))
    r[13*i+8]  = byte((t[4] shr 12) or (t[5] shl 1))
    r[13*i+9]  = byte((t[5] shr 7)  or (t[6] shl 6))
    r[13*i+10] = byte((t[6] shr 2))
    r[13*i+11] = byte((t[6] shr 10) or (t[7] shl 3))
    r[13*i+12] = byte((t[7] shr 5))

proc polyt0_unpack*(r: var Poly; a: openArray[byte]) =
  doAssert a.len == POLYT0_PACKEDBYTES
  for i in 0 ..< N div 8:
    let x0 = (uint32(a[13*i+0]) or (uint32(a[13*i+1]) shl 8)) and 0x1FFF
    let x1 = ((uint32(a[13*i+1]) shr 5) or (uint32(a[13*i+2]) shl 3) or (uint32(a[13*i+3]) shl 11)) and 0x1FFF
    let x2 = ((uint32(a[13*i+3]) shr 2) or (uint32(a[13*i+4]) shl 6)) and 0x1FFF
    let x3 = ((uint32(a[13*i+4]) shr 7) or (uint32(a[13*i+5]) shl 1) or (uint32(a[13*i+6]) shl 9)) and 0x1FFF
    let x4 = ((uint32(a[13*i+6]) shr 4) or (uint32(a[13*i+7]) shl 4) or (uint32(a[13*i+8]) shl 12)) and 0x1FFF
    let x5 = ((uint32(a[13*i+8]) shr 1) or (uint32(a[13*i+9]) shl 7)) and 0x1FFF
    let x6 = ((uint32(a[13*i+9]) shr 6) or (uint32(a[13*i+10]) shl 2) or (uint32(a[13*i+11]) shl 10)) and 0x1FFF
    let x7 = ((uint32(a[13*i+11]) shr 3) or (uint32(a[13*i+12]) shl 5)) and 0x1FFF
    r.coeffs[8*i+0] = (1 shl (D-1)) - int32(x0)
    r.coeffs[8*i+1] = (1 shl (D-1)) - int32(x1)
    r.coeffs[8*i+2] = (1 shl (D-1)) - int32(x2)
    r.coeffs[8*i+3] = (1 shl (D-1)) - int32(x3)
    r.coeffs[8*i+4] = (1 shl (D-1)) - int32(x4)
    r.coeffs[8*i+5] = (1 shl (D-1)) - int32(x5)
    r.coeffs[8*i+6] = (1 shl (D-1)) - int32(x6)
    r.coeffs[8*i+7] = (1 shl (D-1)) - int32(x7)

# ---------------- Packing: z (GAMMA1) ----------------

proc polyz_pack*(r: var openArray[byte]; a: Poly) =
  doAssert r.len == POLYZ_PACKEDBYTES
  when GAMMA1 == (1 shl 17):
    for i in 0 ..< N div 4:
      var t0 = uint32(GAMMA1 - a.coeffs[4*i+0])
      var t1 = uint32(GAMMA1 - a.coeffs[4*i+1])
      var t2 = uint32(GAMMA1 - a.coeffs[4*i+2])
      var t3 = uint32(GAMMA1 - a.coeffs[4*i+3])
      r[9*i+0] = byte(t0)
      r[9*i+1] = byte(t0 shr 8)
      r[9*i+2] = byte((t0 shr 16) or (t1 shl 2))
      r[9*i+3] = byte(t1 shr 6)
      r[9*i+4] = byte((t1 shr 14) or (t2 shl 4))
      r[9*i+5] = byte(t2 shr 4)
      r[9*i+6] = byte((t2 shr 12) or (t3 shl 6))
      r[9*i+7] = byte(t3 shr 2)
      r[9*i+8] = byte(t3 shr 10)
  elif GAMMA1 == (1 shl 19):
    for i in 0 ..< N div 2:
      var t0 = uint32(GAMMA1 - a.coeffs[2*i+0])
      var t1 = uint32(GAMMA1 - a.coeffs[2*i+1])
      r[5*i+0] = byte(t0)
      r[5*i+1] = byte(t0 shr 8)
      r[5*i+2] = byte((t0 shr 16) or (t1 shl 4))
      r[5*i+3] = byte(t1 shr 4)
      r[5*i+4] = byte(t1 shr 12)

proc polyz_unpack*(r: var Poly; a: openArray[byte]) =
  doAssert a.len == POLYZ_PACKEDBYTES
  when GAMMA1 == (1 shl 17):
    for i in 0 ..< N div 4:
      let x0 = (uint32(a[9*i+0]) or (uint32(a[9*i+1]) shl 8) or (uint32(a[9*i+2]) shl 16)) and 0x3FFFF
      let x1 = ((uint32(a[9*i+2]) shr 2) or (uint32(a[9*i+3]) shl 6) or (uint32(a[9*i+4]) shl 14)) and 0x3FFFF
      let x2 = ((uint32(a[9*i+4]) shr 4) or (uint32(a[9*i+5]) shl 4) or (uint32(a[9*i+6]) shl 12)) and 0x3FFFF
      let x3 = ((uint32(a[9*i+6]) shr 6) or (uint32(a[9*i+7]) shl 2) or (uint32(a[9*i+8]) shl 10)) and 0x3FFFF
      r.coeffs[4*i+0] = GAMMA1 - int32(x0)
      r.coeffs[4*i+1] = GAMMA1 - int32(x1)
      r.coeffs[4*i+2] = GAMMA1 - int32(x2)
      r.coeffs[4*i+3] = GAMMA1 - int32(x3)
  elif GAMMA1 == (1 shl 19):
    for i in 0 ..< N div 2:
      let x0 = (uint32(a[5*i+0]) or (uint32(a[5*i+1]) shl 8) or (uint32(a[5*i+2]) shl 16)) and 0xFFFFF
      let x1 = (((uint32(a[5*i+2]) shr 4) or (uint32(a[5*i+3]) shl 4) or (uint32(a[5*i+4]) shl 12))) and 0xFFFFF'u32 # up to 20 bits
      r.coeffs[2*i+0] = GAMMA1 - int32(x0)
      r.coeffs[2*i+1] = GAMMA1 - int32(x1)

# ---------------- Packing: w1 ----------------

proc polyw1_pack*(r: var openArray[byte]; a: Poly) =
  doAssert r.len == POLYW1_PACKEDBYTES
  when GAMMA2 == (Q - 1) div 88:
    for i in 0 ..< N div 4:
      let x0 = uint32(a.coeffs[4*i+0]) and 0x3F
      let x1 = uint32(a.coeffs[4*i+1]) and 0x3F
      let x2 = uint32(a.coeffs[4*i+2]) and 0x3F
      let x3 = uint32(a.coeffs[4*i+3]) and 0x3F
      r[3*i+0] = byte(x0 or (x1 shl 6))
      r[3*i+1] = byte((x1 shr 2) or (x2 shl 4))
      r[3*i+2] = byte((x2 shr 4) or (x3 shl 2))
  elif GAMMA2 == (Q - 1) div 32:
    for i in 0 ..< N div 2:
      let x0 = uint32(a.coeffs[2*i+0]) and 0x0F
      let x1 = uint32(a.coeffs[2*i+1]) and 0x0F
      r[i] = byte(x0 or (x1 shl 4))
