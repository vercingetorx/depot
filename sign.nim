import helpers, params, poly, polyvec, packing, reduce, rounding, symmetric, types
import ../private/sha3/shake256

when defined(kat):
  import ../nistkat/rng
else:
  import randombytes


# ----------------------------- keypair ---------------------------------------

proc crypto_sign_keypair*(pk: var openArray[byte],
                          sk: var openArray[byte]): int =
  ## Generates public/secret key pair.
  ## pk.len == CRYPTO_PUBLICKEYBYTES, sk.len == CRYPTO_SECRETKEYBYTES
  doAssert pk.len == CRYPTO_PUBLICKEYBYTES
  doAssert sk.len == CRYPTO_SECRETKEYBYTES

  var rho:      array[SEEDBYTES, byte]
  var rhoprime: array[CRHBYTES,  byte]
  var key:      array[SEEDBYTES, byte]
  var tr:       array[TRBYTES,   byte]

  # seedbuf <- random(SEEDBYTES) ++ [K,L], expand via SHAKE256 → rho|rhoprime|key
  var seedInput: array[SEEDBYTES + 2, byte]
  randombytes(oa(seedInput, 0, SEEDBYTES))
  seedInput[SEEDBYTES + 0] = byte(K)
  seedInput[SEEDBYTES + 1] = byte(L)

  var kctx = newShake256Ctx(seedInput)
  kctx.read(rho)
  kctx.read(rhoprime)
  kctx.read(key)

  # Expand matrix A from rho
  var mat: array[K, Polyvecl]
  polyvec_matrix_expand(mat, rho)

  # Sample secrets s1, s2 from rhoprime
  var s1, s1hat: Polyvecl
  var s2: Polyveck
  polyvecl_uniform_eta(s1, rhoprime, 0)
  polyveck_uniform_eta(s2, rhoprime, L.uint16)

  # t1 = A * NTT(s1) + s2
  s1hat = s1
  polyvecl_ntt(s1hat)
  var t1, t0: Polyveck
  polyvec_matrix_pointwise_montgomery(t1, mat, s1hat)
  polyveck_reduce(t1)
  polyveck_invntt_tomont(t1)
  polyveck_add(t1, t1, s2)

  # Split (power2round), pack pk, derive tr = SHAKE256(pk), then pack sk
  polyveck_caddq(t1)
  polyveck_power2round(t1, t0, t1)       # t1=high, t0=low
  pack_pk(pk, rho, t1)

  var trctx = newShake256Ctx(pk)
  trctx.read(tr)

  pack_sk(sk, rho, tr, key, t0, s1, s2)
  result = 0

# ----------------------- detached signature (internal) -----------------------

proc crypto_sign_signature_internal*(sig: var openArray[byte],
                                     siglen: var uint,
                                     m: openArray[byte],
                                     pre: openArray[byte],
                                     rnd: openArray[byte],   # RNDBYTES
                                     sk: openArray[byte]): int =
  ## Computes signature (internal API). Returns 0 on success.
  doAssert sig.len == CRYPTO_BYTES
  doAssert rnd.len == RNDBYTES

  # Unpack sk -> rho, tr, key, t0, s1, s2
  var rho: array[SEEDBYTES, byte]
  var tr:  array[TRBYTES,   byte]
  var key: array[SEEDBYTES, byte]
  var t0:  Polyveck
  var s1:  Polyvecl
  var s2:  Polyveck
  unpack_sk(rho, tr, key, t0, s1, s2, sk)

  # mu = CRH(tr, pre, m) using SHAKE256
  var mu: array[CRHBYTES, byte]
  block:
    var ctx = newShake256Ctx()
    ctx.update(tr)
    ctx.update(pre)
    ctx.update(m)
    ctx.read(mu)

  # rhoprime = CRH(key, rnd, mu)
  var rhoprime: array[CRHBYTES, byte]
  block:
    var ctx = newShake256Ctx()
    ctx.update(key)
    ctx.update(rnd)
    ctx.update(mu)
    ctx.read(rhoprime)

  # Expand A, NTT s1/s2/t0
  var mat: array[K, Polyvecl]
  polyvec_matrix_expand(mat, rho)
  polyvecl_ntt(s1)
  polyveck_ntt(s2)
  polyveck_ntt(t0)

  var nonce: uint16 = 0
  var y, z: Polyvecl
  var w1, w0, h: Polyveck
  var cp: Poly

  # Rejection loop (same logic as reference)
  while true:
    # y ~ uniform_gamma1
    polyvecl_uniform_gamma1(y, rhoprime, nonce)
    inc nonce

    # w1 = A * NTT(y)
    z = y
    polyvecl_ntt(z)
    polyvec_matrix_pointwise_montgomery(w1, mat, z)
    polyveck_reduce(w1)
    polyveck_invntt_tomont(w1)

    # Decompose w → (w1 high, w0 low); pack w1 for hashing
    polyveck_caddq(w1)
    polyveck_decompose(w1, w0, w1)
    var w1packed: array[K*POLYW1_PACKEDBYTES, byte]
    polyveck_pack_w1(w1packed, w1)

    # c = H(mu || w1packed), then challenge polynomial cp
    var ctilde: array[CTILDEBYTES, byte]
    block:
      var ctx = newShake256Ctx()
      ctx.update(mu)
      ctx.update(w1packed)
      ctx.read(ctilde)
    poly_challenge(cp, ctilde)
    poly_ntt(cp)

    # z = y + s1*c ; reject if norm too large
    polyvecl_pointwise_poly_montgomery(z, cp, s1)
    polyvecl_invntt_tomont(z)
    polyvecl_add(z, z, y)
    polyvecl_reduce(z)
    if polyvecl_chknorm(z, GAMMA1 - BETA) != 0:
      continue

    # w0' = w0 - s2*c ; reject if norm too large
    polyveck_pointwise_poly_montgomery(h, cp, s2)
    polyveck_invntt_tomont(h)
    polyveck_sub(w0, w0, h)
    polyveck_reduce(w0)
    if polyveck_chknorm(w0, GAMMA2 - BETA) != 0:
      continue

    # h = t0*c ; reject if norm too large
    polyveck_pointwise_poly_montgomery(h, cp, t0)
    polyveck_invntt_tomont(h)
    polyveck_reduce(h)
    if polyveck_chknorm(h, GAMMA2) != 0:
      continue

    # Compute hints, must be ≤ OMEGA
    polyveck_add(w0, w0, h)
    let nHints = polyveck_make_hint(h, w0, w1)
    if nHints > OMEGA.uint:
      continue

    # Pack signature: (ctilde, z, h)
    pack_sig(sig, ctilde, z, h)
    siglen = CRYPTO_BYTES.uint
    return 0

# ----------------------- detached signature (wrapper) ------------------------

proc crypto_sign_signature*(sig: var openArray[byte],
                            siglen: var uint,
                            m: openArray[byte],
                            ctx: openArray[byte],
                            sk: openArray[byte]): int =
  ## Compute a detached signature for message `m` with optional context `ctx`.
  ## Returns 0 on success, or -1 if context too long (>255).
  if ctx.len > 255: return -1

  # pre = (0, ctxlen, ctx)
  var pre: array[2 + 255, byte]
  pre[0] = 0
  pre[1] = byte(ctx.len)
  for i in 0 ..< ctx.len:
    pre[2 + i] = ctx[i]
  let preLen = 2 + ctx.len

  # rnd: randomized signing on/off (compile-time)
  var rnd: array[RNDBYTES, byte]
  when DILITHIUM_RANDOMIZED_SIGNING:
    randombytes(rnd)
  else:
    for i in 0..<RNDBYTES: rnd[i] = 0

  result = crypto_sign_signature_internal(
    sig, siglen,
    m,
    pre.toOpenArray(0, preLen - 1),
    rnd,
    sk
  )

# ----------------------------- attached sign ---------------------------------

proc crypto_sign*(sm: var openArray[byte],
                  smlen: var uint,
                  m: openArray[byte],
                  ctx: openArray[byte],
                  sk: openArray[byte]): int =
  ## Produce sm = signature || message. Caller must provide sm big enough.
  if m.len + CRYPTO_BYTES > sm.len:
    smlen = 0
    return -2

  # Copy message after the signature area
  for i in 0..<m.len:
    sm[CRYPTO_BYTES + i] = m[i]

  var sigLen: uint = 0
  let ret = crypto_sign_signature(
    sm.toOpenArray(0, CRYPTO_BYTES - 1),  # write detached sig in place
    sigLen,
    m,                                    # sign the message directly
    ctx, sk
  )
  smlen = sigLen + uint(m.len)
  return ret

# ----------------------------- verify (internal) -----------------------------

proc crypto_sign_verify_internal*(sig: openArray[byte],
                                  m: openArray[byte],
                                  pre: openArray[byte],
                                  pk: openArray[byte]): int =
  ## 0 if valid, -1 otherwise
  if sig.len != CRYPTO_BYTES: return -1

  # Unpack pk and sig
  var rho: array[SEEDBYTES, byte]
  var t1:  Polyveck
  unpack_pk(rho, t1, pk)

  var ctilde: array[CTILDEBYTES, byte]
  var z: Polyvecl
  var h: Polyveck
  if unpack_sig(ctilde, z, h, sig) != 0: return -1
  if polyvecl_chknorm(z, GAMMA1 - BETA) != 0: return -1

  # mu = CRH(H(rho, t1), pre, m)
  var tr: array[TRBYTES, byte]
  block:
    var ctx = newShake256Ctx(pk)  # pk = (rho || t1) packed
    ctx.read(tr)
  var mu: array[CRHBYTES, byte]
  block:
    var ctx = newShake256Ctx()
    ctx.update(tr)
    ctx.update(pre)
    ctx.update(m)
    ctx.read(mu)

  # Compute w1' = A*z - c*t1
  var cp: Poly
  poly_challenge(cp, ctilde)

  var mat: array[K, Polyvecl]
  polyvec_matrix_expand(mat, rho)

  var w1, t1tmp: Polyveck
  var zhat = z
  polyvecl_ntt(zhat)
  polyvec_matrix_pointwise_montgomery(w1, mat, zhat)

  poly_ntt(cp)
  polyveck_shiftl(t1)
  polyveck_ntt(t1)
  polyveck_pointwise_poly_montgomery(t1tmp, cp, t1)

  polyveck_sub(w1, w1, t1tmp)
  polyveck_reduce(w1)
  polyveck_invntt_tomont(w1)

  # Reconstruct w1 using hints, then c2 = H(mu || w1pack)
  polyveck_caddq(w1)
  polyveck_use_hint(w1, w1, h)

  var w1packed: array[K*POLYW1_PACKEDBYTES, byte]
  polyveck_pack_w1(w1packed, w1)

  var c2: array[CTILDEBYTES, byte]
  block:
    var ctx = newShake256Ctx()
    ctx.update(mu)
    ctx.update(w1packed)
    ctx.read(c2)

  for i in 0..<CTILDEBYTES:
    if ctilde[i] != c2[i]:
      return -1
  return 0

# ----------------------------- verify (wrapper) ------------------------------

proc crypto_sign_verify*(sig: openArray[byte],
                         m: openArray[byte],
                         ctx: openArray[byte],
                         pk: openArray[byte]): int =
  ## Verify detached signature over message `m` with context `ctx`.
  if ctx.len > 255: return -1
  var pre: array[2 + 255, byte]
  pre[0] = 0
  pre[1] = byte(ctx.len)
  for i in 0 ..< ctx.len:
    pre[2 + i] = ctx[i]
  let preLen = 2 + ctx.len
  crypto_sign_verify_internal(sig, m, pre.toOpenArray(0, preLen - 1), pk)

# ----------------------------- open (attached) -------------------------------

proc crypto_sign_open*(m: var openArray[byte],
                       mlen: var uint,
                       sm: openArray[byte],
                       ctx: openArray[byte],
                       pk: openArray[byte]): int =
  ## Verify sm = signature || message; on success write the message to `m`.
  if sm.len < CRYPTO_BYTES:
    mlen = 0
    for i in 0..<m.len: m[i] = 0
    return -1

  mlen = uint(sm.len - CRYPTO_BYTES)
  let ok = crypto_sign_verify(
    sm.toOpenArray(0, CRYPTO_BYTES - 1),       # sig
    sm.toOpenArray(CRYPTO_BYTES, sm.len - 1),  # msg
    ctx, pk
  ) == 0

  if not ok:
    mlen = 0
    for i in 0..<m.len: m[i] = 0
    return -1

  # Copy out the message
  for i in 0..<int(mlen):
    m[i] = sm[CRYPTO_BYTES + i]
  return 0
