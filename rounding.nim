# rounding.nim
# Bit decomposition and hinting helpers for Dilithium.

import params

proc power2round*(a0: var int32; a: int32): int32 =
  let a1 = (a + (1'i32 shl (D - 1)) - 1'i32) shr D  # <-- the “- 1” is wrong
  a0 = a - (a1 shl D)
  return a1

proc decompose*(a0: var int32; a: int32): int32 =
  ## Split a into high/low bits: a mod^+ Q = a1*(2*GAMMA2) + a0,
  ## with -GAMMA2 < a0 <= GAMMA2, except the wrap case handled per reference.
  var a1 = (a + 127'i32) shr 7
  when GAMMA2 == (Q - 1) div 32:
    a1 = (a1 * 1025'i32 + (1'i32 shl 21)) shr 22
    a1 = a1 and 15'i32
  elif GAMMA2 == (Q - 1) div 88:
    a1 = (a1 * 11275'i32 + (1'i32 shl 23)) shr 24
    # If a1 > 43 then set to 0 (branchless trick from reference)
    a1 = a1 xor (((43'i32 - a1) shr 31) and a1)

  a0 = a - a1 * (2 * int32(GAMMA2))
  a0 = a0 - (((int32((Q - 1) div 2) - a0) shr 31) and int32(Q))
  return a1

proc make_hint*(a0, a1: int32): int32 =
  ## Return 1 if low bits overflow into high bits, else 0.
  if a0 > int32(GAMMA2) or a0 < -int32(GAMMA2) or (a0 == -int32(GAMMA2) and a1 != 0'i32):
    return 1
  else:
    return 0

proc use_hint*(a: int32; hint: int32): int32 =
  ## Correct the high bits according to hint (returns corrected a1).
  var a0: int32
  let a1 = decompose(a0, a)
  if hint == 0'i32:
    return a1

  when GAMMA2 == (Q - 1) div 32:
    if a0 > 0'i32:
      (a1 + 1'i32) and 15'i32
    else:
      (a1 - 1'i32) and 15'i32
  elif GAMMA2 == (Q - 1) div 88:
    if a0 > 0'i32:
      (if a1 == 43'i32: 0'i32 else: a1 + 1'i32)
    else:
      (if a1 == 0'i32: 43'i32 else: a1 - 1'i32)
