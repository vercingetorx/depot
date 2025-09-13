# kem.nim
# Port of CRYSTALS-Kyber KEM layer from the C reference.

import params, indcpa, symmetric, verify
when defined(kat):
  import ../nistkat/rng
else:
  import randombytes

export params

# ---------------------------------------------------------------------------
# Keypair (deterministic)
# ---------------------------------------------------------------------------

proc crypto_kem_keypair_derand*(
    pk: var openArray[byte],
    sk: var openArray[byte],
    coins: openArray[byte]
) =
  ## Generates Kyber public/secret key using provided randomness (coins).
  ## coins must contain 2*KYBER_SYMBYTES random bytes.
  indcpa_keypair_derand(pk, sk, coins)

  # sk ||= pk
  copyMem(addr sk[KYBER_INDCPA_SECRETKEYBYTES], unsafeAddr pk[0], KYBER_PUBLICKEYBYTES)

  # sk[SK_BYTES - 2*SYMBYTES ..< SK_BYTES - SYMBYTES] = H(pk)
  hash_h(
    sk.toOpenArray(KYBER_SECRETKEYBYTES - 2*KYBER_SYMBYTES,
                   KYBER_SECRETKEYBYTES - KYBER_SYMBYTES - 1),
    pk
  )

  # z for PRF on reject: sk[SK_BYTES - SYMBYTES ..< SK_BYTES] = coins[SYMBYTES ..< 2*SYMBYTES]
  copyMem(addr sk[KYBER_SECRETKEYBYTES - KYBER_SYMBYTES],
          unsafeAddr coins[KYBER_SYMBYTES],
          KYBER_SYMBYTES)

# ---------------------------------------------------------------------------
# Keypair (random)
# ---------------------------------------------------------------------------

proc crypto_kem_keypair*(pk: var openArray[byte], sk: var openArray[byte]) =
  var coins: array[2*KYBER_SYMBYTES, byte]
  randombytes(coins)  # fill all 2*SYMBYTES
  crypto_kem_keypair_derand(pk, sk, coins)

# ---------------------------------------------------------------------------
# Encapsulation (deterministic)
# ---------------------------------------------------------------------------

proc crypto_kem_enc_derand*(
    ct: var openArray[byte],
    ss: var openArray[byte],
    pk: openArray[byte],
    coins: openArray[byte]
) =
  ## Encapsulate using explicit coins (len = KYBER_SYMBYTES).
  var
    buf: array[2*KYBER_SYMBYTES, byte]   # will hold: m || H(pk)
    kr:  array[2*KYBER_SYMBYTES, byte]   # will hold: K || coins'

  # buf[0..SYMBYTES-1] = coins
  copyMem(addr buf[0], unsafeAddr coins[0], KYBER_SYMBYTES)

  # buf[SYMBYTES..2*SYMBYTES-1] = H(pk)
  hash_h(buf.toOpenArray(KYBER_SYMBYTES, 2*KYBER_SYMBYTES - 1), pk)

  # kr = G(buf)  (first half: key; second half: coins for IND-CPA)
  hash_g(kr, buf)

  # IND-CPA encrypt: m = buf[0..SYMBYTES-1], coins = kr[SYMBYTES..2*SYMBYTES-1]
  indcpa_enc(ct,
             buf.toOpenArray(0, KYBER_SYMBYTES - 1),
             pk,
             kr.toOpenArray(KYBER_SYMBYTES, 2*KYBER_SYMBYTES - 1))

  # ss = kr[0..SYMBYTES-1]
  copyMem(addr ss[0], addr kr[0], KYBER_SYMBYTES)

# ---------------------------------------------------------------------------
# Encapsulation (random)
# ---------------------------------------------------------------------------

proc crypto_kem_enc*(ct: var openArray[byte], ss: var openArray[byte], pk: openArray[byte]) =
  var coins: array[KYBER_SYMBYTES, byte]
  randombytes(coins)
  crypto_kem_enc_derand(ct, ss, pk, coins)

# ---------------------------------------------------------------------------
# Decapsulation
# ---------------------------------------------------------------------------

proc crypto_kem_dec*(ss: var openArray[byte], ct: openArray[byte], sk: openArray[byte]) =
  ## Decapsulate: ss = K if valid, else PRF(z, ct) with constant-time cmov.
  var
    buf: array[2*KYBER_SYMBYTES, byte]     # will hold: m' || H(pk) input for G
    kr:  array[2*KYBER_SYMBYTES, byte]     # G output: K || coins'
    cmp: array[KYBER_CIPHERTEXTBYTES, byte]

  # Recover message m' into buf[0..SYMBYTES-1]
  indcpa_dec(buf.toOpenArray(0, KYBER_SYMBYTES - 1), ct, sk)

  # Second half of buf: H(pk) input (pk is stored inside sk after IND-CPA sk)
  hash_h(
    buf.toOpenArray(KYBER_SYMBYTES, 2*KYBER_SYMBYTES - 1),
    sk.toOpenArray(KYBER_INDCPA_SECRETKEYBYTES,
                   KYBER_INDCPA_SECRETKEYBYTES + KYBER_PUBLICKEYBYTES - 1)
  )

  # kr = G(m' || H(pk))
  hash_g(kr, buf)

  # Re-encrypt with pk and coins' to check validity → cmp
  indcpa_enc(cmp,
             buf.toOpenArray(0, KYBER_SYMBYTES - 1),
             sk.toOpenArray(KYBER_INDCPA_SECRETKEYBYTES,
                            KYBER_INDCPA_SECRETKEYBYTES + KYBER_PUBLICKEYBYTES - 1),
             kr.toOpenArray(KYBER_SYMBYTES, 2*KYBER_SYMBYTES - 1))

  let fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES)  # 0 on success

  # Rejection key: ss = PRF(z, ct)
  rkprf(ss,
        sk.toOpenArray(KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, KYBER_SECRETKEYBYTES - 1),
        ct)

  # If valid (fail == 0) overwrite ss with true key in constant time
  cmov(ss, kr, KYBER_SYMBYTES, (if fail == 0: 1.byte else: 0.byte))
