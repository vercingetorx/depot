# polyvec.nim — port of polyvec.c with Nim safety checks on.
# Depends on: params, dilithium_types, dilithium_helpers, poly

import helpers, params, poly, types

proc polyvecl_pointwise_acc_montgomery*(w: var Poly, u, v: Polyvecl)

# -------------------- Matrix A --------------------

proc polyvec_matrix_expand*(mat: var MatrixA, rho: openArray[byte]) =
  ## ExpandA: mat[i].vec[j] <- uniform(rho, nonce=(i<<8)+j)
  doAssert rho.len == SEEDBYTES
  for i in 0..<K:
    for j in 0..<L:
      poly_uniform(mat[i].vec[j], rho, uint16((i shl 8) + j))

proc polyvec_matrix_pointwise_montgomery*(t: var Polyveck,
                                          mat: MatrixA,
                                          v: Polyvecl) =
  ## t[i] <- <mat[i], v> pointwise-acc in Montgomery domain
  for i in 0..<K:
    polyvecl_pointwise_acc_montgomery(t.vec[i], mat[i], v)

# --------------- polyvecl (length L) ----------------

proc polyvecl_uniform_eta*(v: var Polyvecl,
                           seed: openArray[byte],
                           nonce: uint16) =
  doAssert seed.len == CRHBYTES
  var n = nonce
  for i in 0..<L:
    poly_uniform_eta(v.vec[i], seed, n)
    inc n

proc polyvecl_uniform_gamma1*(v: var Polyvecl,
                              seed: openArray[byte],
                              nonce: uint16) =
  doAssert seed.len == CRHBYTES
  for i in 0..<L:
    let n = uint16(uint32(L) * uint32(nonce) + uint32(i))
    poly_uniform_gamma1(v.vec[i], seed, n)

proc polyvecl_reduce*(v: var Polyvecl) =
  for i in 0..<L:
    poly_reduce(v.vec[i])

proc polyvecl_add*(w: var Polyvecl, u, v: Polyvecl) =
  for i in 0..<L:
    poly_add(w.vec[i], u.vec[i], v.vec[i])

proc polyvecl_ntt*(v: var Polyvecl) =
  for i in 0..<L:
    poly_ntt(v.vec[i])

proc polyvecl_invntt_tomont*(v: var Polyvecl) =
  for i in 0..<L:
    poly_invntt_tomont(v.vec[i])

proc polyvecl_pointwise_poly_montgomery*(r: var Polyvecl,
                                         a: Poly,
                                         v: Polyvecl) =
  for i in 0..<L:
    poly_pointwise_montgomery(r.vec[i], a, v.vec[i])

proc polyvecl_pointwise_acc_montgomery*(w: var Poly,
                                        u, v: Polyvecl) =
  ## w <- sum_i u[i] * v[i] (pointwise, montgomery)
  var t: Poly
  poly_pointwise_montgomery(w, u.vec[0], v.vec[0])
  for i in 1..<L:
    poly_pointwise_montgomery(t, u.vec[i], v.vec[i])
    poly_add(w, w, t)

proc polyvecl_chknorm*(v: Polyvecl, bound: int32): int =
  for i in 0..<L:
    if poly_chknorm(v.vec[i], bound) != 0:
      return 1
  0

# --------------- polyveck (length K) ----------------

proc polyveck_uniform_eta*(v: var Polyveck,
                           seed: openArray[byte],
                           nonce: uint16) =
  doAssert seed.len == CRHBYTES
  var n = nonce
  for i in 0..<K:
    poly_uniform_eta(v.vec[i], seed, n)
    inc n

proc polyveck_reduce*(v: var Polyveck) =
  for i in 0..<K:
    poly_reduce(v.vec[i])

proc polyveck_caddq*(v: var Polyveck) =
  for i in 0..<K:
    poly_caddq(v.vec[i])

proc polyveck_add*(w: var Polyveck, u, v: Polyveck) =
  for i in 0..<K:
    poly_add(w.vec[i], u.vec[i], v.vec[i])

proc polyveck_sub*(w: var Polyveck, u, v: Polyveck) =
  for i in 0..<K:
    poly_sub(w.vec[i], u.vec[i], v.vec[i])

proc polyveck_shiftl*(v: var Polyveck) =
  for i in 0..<K:
    poly_shiftl(v.vec[i])

proc polyveck_ntt*(v: var Polyveck) =
  for i in 0..<K:
    poly_ntt(v.vec[i])

proc polyveck_invntt_tomont*(v: var Polyveck) =
  for i in 0..<K:
    poly_invntt_tomont(v.vec[i])

proc polyveck_pointwise_poly_montgomery*(r: var Polyveck,
                                         a: Poly,
                                         v: Polyveck) =
  for i in 0..<K:
    poly_pointwise_montgomery(r.vec[i], a, v.vec[i])

proc polyveck_chknorm*(v: Polyveck, bound: int32): int =
  for i in 0..<K:
    if poly_chknorm(v.vec[i], bound) != 0:
      return 1
  0

proc polyveck_power2round*(v1: var Polyveck, v0: var Polyveck, v: Polyveck) =
  for i in 0..<K:
    poly_power2round(v1.vec[i], v0.vec[i], v.vec[i])

proc polyveck_decompose*(v1: var Polyveck, v0: var Polyveck, v: Polyveck) =
  for i in 0..<K:
    poly_decompose(v1.vec[i], v0.vec[i], v.vec[i])

proc polyveck_make_hint*(h: var Polyveck,
                         v0, v1: Polyveck): uint =
  var s: uint = 0
  for i in 0..<K:
    s += poly_make_hint(h.vec[i], v0.vec[i], v1.vec[i])
  s

proc polyveck_use_hint*(w: var Polyveck, u, h: Polyveck) =
  for i in 0..<K:
    poly_use_hint(w.vec[i], u.vec[i], h.vec[i])

proc polyveck_pack_w1*(r: var openArray[byte], w1: Polyveck) =
  doAssert r.len == K * POLYW1_PACKEDBYTES
  for i in 0..<K:
    polyw1_pack(r.oa(i * POLYW1_PACKEDBYTES, POLYW1_PACKEDBYTES), w1.vec[i])
