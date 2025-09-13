# indcpa.nim
# Port of CRYSTALS-Kyber IND-CPA layer from the C reference.

import params, poly, polyvec, symmetric, types

# ---------- Packing helpers ------------------------------------------------

proc pack_pk(r: var openArray[byte]; pk: PolyVec; seed: openArray[byte]) =
  ## Serialize public key: polyvec || seed
  when not defined(release):
    doAssert r.len >= KYBER_INDCPA_PUBLICKEYBYTES
    doAssert seed.len >= KYBER_SYMBYTES
  polyvec_tobytes(r, pk)
  copyMem(addr r[KYBER_POLYVECBYTES], unsafeAddr seed[0], KYBER_SYMBYTES)

proc unpack_pk(pk: var PolyVec; seed: var openArray[byte]; packedpk: openArray[byte]) =
  ## De-serialize public key
  when not defined(release):
    doAssert packedpk.len >= KYBER_INDCPA_PUBLICKEYBYTES
    doAssert seed.len >= KYBER_SYMBYTES
  polyvec_frombytes(pk, packedpk)
  copyMem(addr seed[0], unsafeAddr packedpk[KYBER_POLYVECBYTES], KYBER_SYMBYTES)

proc pack_sk(r: var openArray[byte]; sk: PolyVec) =
  ## Serialize secret key
  when not defined(release):
    doAssert r.len >= KYBER_INDCPA_SECRETKEYBYTES
  polyvec_tobytes(r, sk)

proc unpack_sk(sk: var PolyVec; packedsk: openArray[byte]) =
  ## De-serialize secret key
  when not defined(release):
    doAssert packedsk.len >= KYBER_INDCPA_SECRETKEYBYTES
  polyvec_frombytes(sk, packedsk)

proc pack_ciphertext(r: var openArray[byte]; b: PolyVec; v: Poly) =
  ## Serialize ciphertext: polyvec_compress(b) || poly_compress(v)
  when not defined(release):
    doAssert r.len >= KYBER_INDCPA_BYTES
  polyvec_compress(r, b)
  poly_compress(
    r.toOpenArray(
      KYBER_POLYVECCOMPRESSEDBYTES,
      KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES - 1
    ),
    v
  )

proc unpack_ciphertext(b: var PolyVec; v: var Poly; c: openArray[byte]) =
  ## De-serialize ciphertext
  when not defined(release):
    doAssert c.len >= KYBER_INDCPA_BYTES
  polyvec_decompress(b, c)
  poly_decompress(
    v,
    c.toOpenArray(
      KYBER_POLYVECCOMPRESSEDBYTES,
      KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES - 1
    )
  )

# ---------- Rejection sampling --------------------------------------------

proc rej_uniform(r: var openArray[int16]; len: int;
                 buf: openArray[byte]; buflen: int): int {.inline.} =
  ## Rejection-sample values mod q from uniform bytes.
  var ctr = 0
  var pos = 0
  const mask = 0x0FFF'u16
  while ctr < len and pos + 3 <= buflen:
    let v0 = (buf[pos].uint16 or (buf[pos+1].uint16 shl 8)) and mask
    let v1 = ((buf[pos+1].uint16 shr 4) or (buf[pos+2].uint16 shl 4)) and mask
    pos += 3
    if v0 < KYBER_Q.uint16:
      r[ctr] = v0.int16
      inc ctr
    if ctr < len and v1 < KYBER_Q.uint16:
      r[ctr] = v1.int16
      inc ctr
  ctr

# ---------- Matrix generation ---------------------------------------------

static:
  doAssert (XOF_BLOCKBYTES mod 3) == 0,
    "gen_matrix assumes XOF_BLOCKBYTES is a multiple of 3"

const GEN_MATRIX_NBLOCKS* =
  ((12*KYBER_N div 8 * (1 shl 12) div KYBER_Q) + XOF_BLOCKBYTES) div XOF_BLOCKBYTES

proc gen_matrix(a: var array[KYBER_K, PolyVec];
                seed: openArray[byte];
                transposed: bool) =
  ## Deterministically generate A (or A^T) from seed using XOF + rejection sampling.
  var state: XofState

  for i in 0 ..< KYBER_K:
    for j in 0 ..< KYBER_K:
      if transposed:
        xof_absorb(state, seed, i.byte, j.byte)
      else:
        xof_absorb(state, seed, j.byte, i.byte)

      # Squeeze initial blocks
      var buf: array[GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES, byte]
      xof_squeezeblocks(buf, GEN_MATRIX_NBLOCKS, state)
      var ctr = rej_uniform(a[i].vec[j].coeffs, KYBER_N, buf, buf.len)

      # Tail fill if needed
      while ctr < KYBER_N:
        var tmp: array[XOF_BLOCKBYTES, byte]
        xof_squeezeblocks(tmp, 1, state)
        let wrote = rej_uniform(
          a[i].vec[j].coeffs.toOpenArray(ctr, KYBER_N - 1),
          KYBER_N - ctr, tmp, tmp.len
        )
        ctr += wrote

# ---------- IND-CPA API ----------------------------------------------------

proc indcpa_keypair_derand*(pk: var openArray[byte];
                            sk: var openArray[byte];
                            coins: openArray[byte]) =
  ## Deterministic (derand) keypair from coins (len = KYBER_SYMBYTES).
  var
    buf: array[2*KYBER_SYMBYTES, byte]
    nonce: byte = 0
    a: array[KYBER_K, PolyVec]
    e, pkpv, skpv: PolyVec

  # buf = coins || KYBER_K ; hash_g(buf, buf[0..SYMBYTES])  (SYMBYTES+1 input)
  copyMem(addr buf[0], unsafeAddr coins[0], KYBER_SYMBYTES)
  buf[KYBER_SYMBYTES] = KYBER_K.byte
  hash_g(buf, buf.toOpenArray(0, KYBER_SYMBYTES))  # length = SYMBYTES+1

  # publicseed = buf[0 ..< SYMBYTES], noiseseed = buf[SYMBYTES ..< 2*SYMBYTES]
  gen_matrix(a, buf.toOpenArray(0, KYBER_SYMBYTES - 1), false)

  for i in 0 ..< KYBER_K:
    poly_getnoise_eta1(skpv.vec[i], buf.toOpenArray(KYBER_SYMBYTES, 2*KYBER_SYMBYTES - 1), nonce)
    inc nonce
  for i in 0 ..< KYBER_K:
    poly_getnoise_eta1(e.vec[i], buf.toOpenArray(KYBER_SYMBYTES, 2*KYBER_SYMBYTES - 1), nonce)
    inc nonce

  polyvec_ntt(skpv)
  polyvec_ntt(e)

  # Matrix-vector multiply
  for i in 0 ..< KYBER_K:
    polyvec_basemul_acc_montgomery(pkpv.vec[i], a[i], skpv)
    poly_tomont(pkpv.vec[i])

  polyvec_add(pkpv, pkpv, e)
  polyvec_reduce(pkpv)

  pack_sk(sk, skpv)
  pack_pk(pk, pkpv, buf.toOpenArray(0, KYBER_SYMBYTES - 1))

proc indcpa_enc*(c: var openArray[byte];
                 m: openArray[byte];
                 pk: openArray[byte];
                 coins: openArray[byte]) =
  ## Encrypt (CPA): c = Enc(pk, m; coins)
  var
    seed: array[KYBER_SYMBYTES, byte]
    nonce: byte = 0
    sp, pkpv, ep, b: PolyVec
    at: array[KYBER_K, PolyVec]
    v, k, epp: Poly

  unpack_pk(pkpv, seed, pk)
  poly_frommsg(k, m)
  gen_matrix(at, seed, true)  # A^T

  for i in 0 ..< KYBER_K:
    poly_getnoise_eta1(sp.vec[i], coins, nonce); inc nonce
  for i in 0 ..< KYBER_K:
    poly_getnoise_eta2(ep.vec[i], coins, nonce); inc nonce
  poly_getnoise_eta2(epp, coins, nonce); inc nonce

  polyvec_ntt(sp)

  # Matrix-vector products
  for i in 0 ..< KYBER_K:
    polyvec_basemul_acc_montgomery(b.vec[i], at[i], sp)
  polyvec_basemul_acc_montgomery(v, pkpv, sp)

  polyvec_invntt_tomont(b)
  poly_invntt_tomont(v)

  polyvec_add(b, b, ep)
  poly_add(v, v, epp)
  poly_add(v, v, k)
  polyvec_reduce(b)
  poly_reduce(v)

  pack_ciphertext(c, b, v)

proc indcpa_dec*(m: var openArray[byte];
                 c: openArray[byte];
                 sk: openArray[byte]) =
  ## Decrypt (CPA): m = Dec(sk, c)
  var
    b, skpv: PolyVec
    v, mp: Poly

  unpack_ciphertext(b, v, c)
  unpack_sk(skpv, sk)

  polyvec_ntt(b)
  polyvec_basemul_acc_montgomery(mp, skpv, b)
  poly_invntt_tomont(mp)

  poly_sub(mp, v, mp)
  poly_reduce(mp)

  poly_tomsg(m, mp)
