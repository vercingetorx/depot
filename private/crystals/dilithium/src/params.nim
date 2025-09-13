# params.nim

const mode {.intdefine.} = 2
const DILITHIUM_MODE* = mode

when defined(rs) or defined(randsig):
  const DILITHIUM_RANDOMIZED_SIGNING* = true
elif defined(nors) or defined(norandsig):
  const DILITHIUM_RANDOMIZED_SIGNING* = false
else:
  const DILITHIUM_RANDOMIZED_SIGNING* = true

const
  SEEDBYTES* = 32
  CRHBYTES* = 64
  TRBYTES* = 64
  RNDBYTES* = 32
  N* = 256
  Q* = 8_380_417
  D* = 13
  ROOT_OF_UNITY* = 1753

static: doAssert DILITHIUM_MODE in {2, 3, 5}, "Unsupported DILITHIUM_MODE"

when DILITHIUM_MODE == 2:
  const
    K* = 4
    L* = 4
    ETA* = 2
    TAU* = 39
    BETA* = 78
    GAMMA1* = 1 shl 17
    GAMMA2* = (Q - 1) div 88
    OMEGA* = 80
    CTILDEBYTES* = 32
elif DILITHIUM_MODE == 3:
  const
    K* = 6
    L* = 5
    ETA* = 4
    TAU* = 49
    BETA* = 196
    GAMMA1* = 1 shl 19
    GAMMA2* = (Q - 1) div 32
    OMEGA* = 55
    CTILDEBYTES* = 48
elif DILITHIUM_MODE == 5:
  const
    K* = 8
    L* = 7
    ETA* = 2
    TAU* = 60
    BETA* = 120
    GAMMA1* = 1 shl 19
    GAMMA2* = (Q - 1) div 32
    OMEGA* = 75
    CTILDEBYTES* = 64

const
  POLYT1_PACKEDBYTES* = 320
  POLYT0_PACKEDBYTES* = 416
  POLYVECH_PACKEDBYTES* = OMEGA + K

when GAMMA1 == (1 shl 17):
  const POLYZ_PACKEDBYTES* = 576
elif GAMMA1 == (1 shl 19):
  const POLYZ_PACKEDBYTES* = 640
else:
  static: doAssert false, "Unsupported GAMMA1"

when GAMMA2 == (Q - 1) div 88:
  const POLYW1_PACKEDBYTES* = 192
elif GAMMA2 == (Q - 1) div 32:
  const POLYW1_PACKEDBYTES* = 128
else:
  static: doAssert false, "Unsupported GAMMA2"

when ETA == 2:
  const POLYETA_PACKEDBYTES* = 96
elif ETA == 4:
  const POLYETA_PACKEDBYTES* = 128
else:
  static: doAssert false, "Unsupported ETA"

const
  CRYPTO_PUBLICKEYBYTES* = SEEDBYTES + K * POLYT1_PACKEDBYTES
  CRYPTO_SECRETKEYBYTES* = 2 * SEEDBYTES +
                           TRBYTES +
                           L * POLYETA_PACKEDBYTES +
                           K * POLYETA_PACKEDBYTES +
                           K * POLYT0_PACKEDBYTES
  CRYPTO_BYTES* = CTILDEBYTES + L * POLYZ_PACKEDBYTES + POLYVECH_PACKEDBYTES
