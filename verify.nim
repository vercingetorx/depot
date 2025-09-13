# verify.nim — constant-time equality and conditional moves (Kyber)

# 0 if equal, 1 otherwise (constant-time)
proc verify*(a, b: openArray[byte]; len: int): int {.inline.} =
  var r: uint8 = 0
  for i in 0 ..< len:
    r = r or (a[i] xor b[i])
  # (-(uint64)r) >> 63  — use unsigned to avoid arithmetic shift
  let ret = (0'u64 - r.uint64) shr 63
  result = int(ret)      # 0 or 1

# Copy len bytes from x to r iff b == 1 (constant-time)
proc cmov*(r: var openArray[byte]; x: openArray[byte]; len: int; b: byte) {.inline.} =
  let m = -int16(b and 1'u8)  # 0x0000 or 0xFFFF, from LSB of b
  for i in 0 ..< len:
    r[i] = r[i] xor (m.byte and (r[i] xor x[i]))

# Copy v into r iff b == 1 (constant-time)
proc cmov_int16*(r: var int16; v: int16; b: uint16) {.inline.} =
  let m = -int16((b and 1'u16).int16)  # 0x0000 or 0xFFFF
  r = r xor (m and (r xor v))
