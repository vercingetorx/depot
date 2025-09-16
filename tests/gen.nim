import std/[os]

type XorShift64 = object
  s: uint64

proc initXorShift64(seed: uint64): XorShift64 =
  result.s = if seed == 0: 0x9E3779B97F4A7C15'u64 else: seed

proc next*(r: var XorShift64): uint64 =
  var x = r.s
  x = x xor (x shl 13)
  x = x xor (x shr 7)
  x = x xor (x shl 17)
  r.s = x
  x

proc writeDeterministicFile*(path: string, size: int, seed: uint64) =
  ## Write a file of 'size' bytes with deterministic pseudo-random content.
  let parent = splitFile(path).dir
  if parent.len > 0: createDir(parent)
  var f = open(path, fmWrite)
  defer: f.close()
  var r = initXorShift64(seed)
  var left = size
  var buf = newSeq[byte](min(1_048_576, max(1, left)))
  while left > 0:
    let n = min(buf.len, left)
    var i = 0
    while i < n:
      let v = r.next()
      # fill up to 8 bytes from v
      var k = 0
      while k < 8 and i < n:
        buf[i] = byte((v shr (8*k)) and 0xff'u64)
        inc i; inc k
    discard f.writeBytes(buf, 0, n)
    left -= n
