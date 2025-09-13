import params, types

# --- Helpers --------------------------------------------------------------

proc load32le(buf: openArray[byte], off: int): uint32 {.inline.} =
  # Little-endian 4-byte load
  (buf[off].uint32) or
  (buf[off+1].uint32 shl 8) or
  (buf[off+2].uint32 shl 16) or
  (buf[off+3].uint32 shl 24)

when KYBER_ETA1 == 3:
  proc load24le(buf: openArray[byte], off: int): uint32 {.inline.} =
    # Little-endian 3-byte load (MSB zero)
    (buf[off].uint32) or
    (buf[off+1].uint32 shl 8) or
    (buf[off+2].uint32 shl 16)

# --- CBD core -------------------------------------------------------------

proc cbd2(r: var Poly; buf: openArray[byte]) =
  when not defined(release):
    doAssert r.coeffs.len >= KYBER_N
    doAssert buf.len >= (KYBER_N div 2)  # 2*KYBER_N/4

  let mask = 0x55555555'u32
  for i in 0 ..< (KYBER_N div 8):
    let t = load32le(buf, 4*i)
    var d = (t and mask) + ((t shr 1) and mask)

    # 8 coefficients per 32-bit chunk
    let base = 8*i
    for j in 0 ..< 8:
      let a = int16((d shr (4*j))     and 0x3'u32)
      let b = int16((d shr (4*j + 2)) and 0x3'u32)
      r.coeffs[base + j] = a - b

when KYBER_ETA1 == 3:
  proc cbd3(r: var Poly; buf: openArray[byte]) =
    when not defined(release):
      doAssert r.coeffs.len >= KYBER_N
      doAssert buf.len >= (3*KYBER_N div 4)

    let mask = 0x00249249'u32
    for i in 0 ..< (KYBER_N div 4):
      let t = load24le(buf, 3*i)
      var d = (t and mask) + ((t shr 1) and mask) + ((t shr 2) and mask)

      let base = 4*i
      for j in 0 ..< 4:
        let a = int16((d shr (6*j))     and 0x7'u32)
        let b = int16((d shr (6*j + 3)) and 0x7'u32)
        r.coeffs[base + j] = a - b

# --- Public wrappers ------------------------------------------------------

proc poly_cbd_eta1*(r: var Poly; buf: openArray[byte]) =
  when KYBER_ETA1 == 2:
    cbd2(r, buf)
  elif KYBER_ETA1 == 3:
    cbd3(r, buf)
  else:
    {.error: "This implementation requires eta1 in {2,3}".}

proc poly_cbd_eta2*(r: var Poly; buf: openArray[byte]) =
  when KYBER_ETA2 == 2:
    cbd2(r, buf)
  else:
    {.error: "This implementation requires eta2 = 2".}
