# reduce.nim — Kyber reductions (Montgomery & Barrett)

import params

# QINV = -q^{-1} mod 2^16 (conventionally 62209; -3327 ≡ 62209 (mod 2^16))
const
  QINV* = -3327

# ---- helper: truncate to 16 bits like C's (int16_t) cast (no range check)
template trunc16(x: int32): int16 =
  cast[int16](uint16(cast[uint32](x) and 0xFFFF'u32))

proc montgomery_reduce*(a: int32): int16 =
  ## Return t = (a * R^{-1}) mod q, with R = 2^16.
  ## C: t = (int16_t)a * QINV; t = (a - (int32)t * q) >> 16;
  let t16 = trunc16(trunc16(a).int32 * QINV.int32)
  let r = a - int32(t16) * KYBER_Q.int32
  result = int16(r shr 16)   # arithmetic right shift on signed int32

proc barrett_reduce*(a: int16): int16 =
  ## Centered representative of a mod q in [-(q-1)/2, ..., (q-1)/2].
  ## C: v = ((1<<26) + q/2)/q; t = ((v*a + (1<<25)) >> 26); return a - t*q;
  const v: int32 = ((1'i32 shl 26) + (KYBER_Q div 2)) div KYBER_Q
  let t = ((v * a.int32) + (1'i32 shl 25)) shr 26
  let r = a.int32 - t * KYBER_Q
  result = r.int16
