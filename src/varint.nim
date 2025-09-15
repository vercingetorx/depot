## Unsigned varint (LEB128-like) encoding/decoding helpers.
type
  ## Raised when a varint is truncated or malformed.
  VarintError* = object of CatchableError

proc putUvar*(x: uint64): seq[byte] =
  ## Encode unsigned varint (LEB128-like, 7 bits per byte).
  var v = x
  while v >= 0x80'u64:
    result.add(byte((v and 0x7F'u64) or 0x80'u64))
    v = v shr 7
  result.add(byte(v))

proc getUvar*(data: openArray[byte], start: int = 0): tuple[value: uint64, next: int] =
  ## Decode unsigned varint and return (value, nextIndex).
  ## Accepts up to 10 bytes for uint64; raises VarintError on truncation.
  var shift: uint64
  var idx = start
  var val: uint64
  while true:
    if idx >= data.len: raise newException(VarintError, "truncated varint")
    let b = uint64(data[idx])
    if (b and 0x80'u64) == 0:
      val = val or ((b and 0x7F'u64) shl shift)
      return (val, idx + 1)
    val = val or ((b and 0x7F'u64) shl shift)
    shift += 7
    inc idx
