# packing.nim
# Bit-packing for Dilithium keys & signatures.

import helpers, params, poly, polyvec, types

# --- Public key: pk = (rho, t1) ----------------------------------------------

proc pack_pk*(pk: var openArray[byte],
              rho: openArray[byte],
              t1: Polyveck) =
  doAssert pk.len == CRYPTO_PUBLICKEYBYTES
  doAssert rho.len == SEEDBYTES

  # rho
  for i in 0..<SEEDBYTES:
    pk[i] = rho[i]

  # t1
  var off = SEEDBYTES
  for i in 0..<K:
    var buf: array[POLYT1_PACKEDBYTES, byte]
    polyt1_pack(buf, t1.vec[i])
    for j in 0..<POLYT1_PACKEDBYTES:
      pk[off + j] = buf[j]
    off += POLYT1_PACKEDBYTES

proc unpack_pk*(rho: var openArray[byte],
                t1: var Polyveck,
                pk: openArray[byte]) =
  doAssert pk.len == CRYPTO_PUBLICKEYBYTES
  doAssert rho.len == SEEDBYTES

  # rho
  for i in 0..<SEEDBYTES:
    rho[i] = pk[i]

  # t1
  var off = SEEDBYTES
  for i in 0..<K:
    var buf: array[POLYT1_PACKEDBYTES, byte]
    for j in 0..<POLYT1_PACKEDBYTES:
      buf[j] = pk[off + j]
    polyt1_unpack(t1.vec[i], buf)
    off += POLYT1_PACKEDBYTES

# --- Secret key: sk = (rho, key, tr, s1, s2, t0) -----------------------------

proc pack_sk*(sk: var openArray[byte],
              rho: openArray[byte],
              tr: openArray[byte],
              key: openArray[byte],
              t0: Polyveck,
              s1: Polyvecl,
              s2: Polyveck) =
  doAssert sk.len == CRYPTO_SECRETKEYBYTES
  doAssert rho.len == SEEDBYTES
  doAssert key.len == SEEDBYTES
  doAssert tr.len == TRBYTES

  var off = 0

  # rho
  for i in 0..<SEEDBYTES:
    sk[off + i] = rho[i]
  off += SEEDBYTES

  # key
  for i in 0..<SEEDBYTES:
    sk[off + i] = key[i]
  off += SEEDBYTES

  # tr
  for i in 0..<TRBYTES:
    sk[off + i] = tr[i]
  off += TRBYTES

  # s1
  for i in 0..<L:
    var b: array[POLYETA_PACKEDBYTES, byte]
    polyeta_pack(b, s1.vec[i])
    for j in 0..<POLYETA_PACKEDBYTES:
      sk[off + j] = b[j]
    off += POLYETA_PACKEDBYTES

  # s2
  for i in 0..<K:
    var b: array[POLYETA_PACKEDBYTES, byte]
    polyeta_pack(b, s2.vec[i])
    for j in 0..<POLYETA_PACKEDBYTES:
      sk[off + j] = b[j]
    off += POLYETA_PACKEDBYTES

  # t0
  for i in 0..<K:
    var b: array[POLYT0_PACKEDBYTES, byte]
    polyt0_pack(b, t0.vec[i])
    for j in 0..<POLYT0_PACKEDBYTES:
      sk[off + j] = b[j]
    off += POLYT0_PACKEDBYTES

proc unpack_sk*(rho: var openArray[byte],
                tr: var openArray[byte],
                key: var openArray[byte],
                t0: var Polyveck,
                s1: var Polyvecl,
                s2: var Polyveck,
                sk: openArray[byte]) =
  doAssert sk.len == CRYPTO_SECRETKEYBYTES
  doAssert rho.len == SEEDBYTES
  doAssert key.len == SEEDBYTES
  doAssert tr.len == TRBYTES

  var off = 0

  # rho
  for i in 0..<SEEDBYTES:
    rho[i] = sk[off + i]
  off += SEEDBYTES

  # key
  for i in 0..<SEEDBYTES:
    key[i] = sk[off + i]
  off += SEEDBYTES

  # tr
  for i in 0..<TRBYTES:
    tr[i] = sk[off + i]
  off += TRBYTES

  # s1
  for i in 0..<L:
    var b: array[POLYETA_PACKEDBYTES, byte]
    for j in 0..<POLYETA_PACKEDBYTES:
      b[j] = sk[off + j]
    polyeta_unpack(s1.vec[i], b)
    off += POLYETA_PACKEDBYTES

  # s2
  for i in 0..<K:
    var b: array[POLYETA_PACKEDBYTES, byte]
    for j in 0..<POLYETA_PACKEDBYTES:
      b[j] = sk[off + j]
    polyeta_unpack(s2.vec[i], b)
    off += POLYETA_PACKEDBYTES

  # t0
  for i in 0..<K:
    var b: array[POLYT0_PACKEDBYTES, byte]
    for j in 0..<POLYT0_PACKEDBYTES:
      b[j] = sk[off + j]
    polyt0_unpack(t0.vec[i], b)
    off += POLYT0_PACKEDBYTES

# --- Signature: sig = (c, z, h) ---------------------------------------------

proc pack_sig*(sig: var openArray[byte],
               c: openArray[byte],
               z: Polyvecl,
               h: Polyveck) =
  doAssert sig.len == CRYPTO_BYTES
  doAssert c.len == CTILDEBYTES

  var off = 0

  # c
  for i in 0..<CTILDEBYTES:
    sig[off + i] = c[i]
  off += CTILDEBYTES

  # z
  for i in 0..<L:
    var b: array[POLYZ_PACKEDBYTES, byte]
    polyz_pack(b, z.vec[i])
    for j in 0..<POLYZ_PACKEDBYTES:
      sig[off + j] = b[j]
    off += POLYZ_PACKEDBYTES

  # h (sparse indices encoding)
  for i in 0..<(OMEGA + K):
    sig[off + i] = 0'u8

  var k = 0
  for i in 0..<K:
    for j in 0..<N:
      if h.vec[i].coeffs[j] != 0:
        sig[off + k] = byte(j)
        inc k
    sig[off + OMEGA + i] = byte(k)

proc unpack_sig*(c: var openArray[byte],
                 z: var Polyvecl,
                 h: var Polyveck,
                 sig: openArray[byte]): int =
  doAssert sig.len == CRYPTO_BYTES
  doAssert c.len == CTILDEBYTES

  var off = 0

  # c
  for i in 0..<CTILDEBYTES:
    c[i] = sig[off + i]
  off += CTILDEBYTES

  # z
  for i in 0..<L:
    var b: array[POLYZ_PACKEDBYTES, byte]
    for j in 0..<POLYZ_PACKEDBYTES:
      b[j] = sig[off + j]
    polyz_unpack(z.vec[i], b)
    off += POLYZ_PACKEDBYTES

  # h (sparse indices decoding)
  var k = 0
  for i in 0..<K:
    for j in 0..<N:
      h.vec[i].coeffs[j] = 0

    let delim = int(sig[off + OMEGA + i])
    if delim < k or delim > OMEGA:
      return 1

    var j = k
    while j < delim:
      # coefficients are ordered for strong unforgeability
      if j > k and sig[off + j] <= sig[off + j - 1]:
        return 1
      h.vec[i].coeffs[int(sig[off + j])] = 1
      inc j

    k = delim

  # Extra indices must be zero for strong unforgeability
  for j in k..<OMEGA:
    if sig[off + j] != 0'u8:
      return 1

  return 0
