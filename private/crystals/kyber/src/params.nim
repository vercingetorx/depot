# params.nim — Kyber parameter set

# ---- Security level selector --------------------------------------------------
const KYBER_K* = # 2=Kyber512, 3=Kyber768, 4=Kyber1024
  when defined(kyber512): 2
  elif defined(kyber1024): 4
  else: 3

static:
  doAssert KYBER_K in {2, 3, 4}, "KYBER_K must be one of {2,3,4}"

# ---- Base parameters ----------------------------------------------------------
const
  KYBER_N* = 256
  KYBER_Q* = 3329

  KYBER_SYMBYTES* = 32  # size in bytes of hashes and seeds
  KYBER_SSBYTES*  = 32  # size in bytes of shared key

  KYBER_POLYBYTES*    = 384
  KYBER_POLYVECBYTES* = KYBER_K * KYBER_POLYBYTES

# Variant-specific knobs (eta1, compression sizes)
when KYBER_K == 2:
  const
    KYBER_ETA1* = 3
    KYBER_POLYCOMPRESSEDBYTES*    = 128
    KYBER_POLYVECCOMPRESSEDBYTES* = KYBER_K * 320
elif KYBER_K == 3:
  const
    KYBER_ETA1* = 2
    KYBER_POLYCOMPRESSEDBYTES*    = 128
    KYBER_POLYVECCOMPRESSEDBYTES* = KYBER_K * 320
elif KYBER_K == 4:
  const
    KYBER_ETA1* = 2
    KYBER_POLYCOMPRESSEDBYTES*    = 160
    KYBER_POLYVECCOMPRESSEDBYTES* = KYBER_K * 352
else:
  {.error: "KYBER_K must be in {2,3,4}".}

const KYBER_ETA2* = 2

# ---- IND-CPA sizes ------------------------------------------------------------
const
  KYBER_INDCPA_MSGBYTES*       = KYBER_SYMBYTES
  KYBER_INDCPA_PUBLICKEYBYTES* = KYBER_POLYVECBYTES + KYBER_SYMBYTES
  KYBER_INDCPA_SECRETKEYBYTES* = KYBER_POLYVECBYTES
  KYBER_INDCPA_BYTES*          = KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES

# Public/secret key and ciphertext sizes (CCA-secure KEM wrapper)
const
  KYBER_PUBLICKEYBYTES*  = KYBER_INDCPA_PUBLICKEYBYTES
  # extra 32 bytes to store H(pk), plus z and a copy of pk (matches C)
  KYBER_SECRETKEYBYTES*  = KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES + 2*KYBER_SYMBYTES
  KYBER_CIPHERTEXTBYTES* = KYBER_INDCPA_BYTES

# ---- Handy derived constant (optional but often used in refs) -----------------
# Montgomery radix R = 2^16; MONT = R mod q = 65536 mod 3329 = 2285
const MONT* = ((1'u64 shl 16) mod KYBER_Q.uint64).int16

const CRYPTO_SECRETKEYBYTES*  = KYBER_SECRETKEYBYTES
const CRYPTO_PUBLICKEYBYTES*  = KYBER_PUBLICKEYBYTES
const CRYPTO_CIPHERTEXTBYTES* = KYBER_CIPHERTEXTBYTES
const CRYPTO_BYTES*           = KYBER_SSBYTES
