# reduce.nim
# Modular reduction helpers for Dilithium over Z_q.

import params

const
  MONT* = -4_186_625'i32     ## 2^32 % Q
  QINV* = 58_728_449'i32     ## q^(-1) mod 2^32


# Signed 32-bit multiply with 32-bit wrap (C int32_t * int32_t)
func mul32wrap(x, y: int32): int32 =
  let p = int64(x) * int64(y)                    # full 64-bit product
  let lo = uint64(p) and 0xFFFF_FFFF'u64         # take low 32 bits
  cast[int32](uint32(lo))                        # interpret as signed

proc montgomery_reduce*(a: int64): int32 =
  ## C:
  ##   t = (int32_t)a * QINV;
  ##   t = (a - (int64)t * Q) >> 32;
  ##   return t;
  let a32 = cast[int32](uint32(uint64(a) and 0xFFFF_FFFF'u64))  # (int32_t)a truncation
  let t   = mul32wrap(a32, QINV)                                # signed 32-bit wrap mul
  let r   = (a - int64(t) * int64(Q)) shr 32
  int32(r)


proc reduce32*(a: int32): int32 =
  ## For a <= 2^{31} - 2^{22} - 1, compute r ≡ a (mod Q)
  ## with -6283008 <= r <= 6283008.
  let t = (a + (1'i32 shl 22)) shr 23
  result = a - t * int32(Q)

proc caddq*(a: int32): int32 =
  ## Add Q if a is negative.
  result = a + ((a shr 31) and int32(Q))

proc freeze*(a: int32): int32 =
  ## Standard representative r = a mod^+ Q.
  result = caddq(reduce32(a))
