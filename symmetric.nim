# symmetric.nim — Kyber symmetric primitives (SHA3/SHAKE wrappers)

import params
import "../private/sha3/sha3_256"
import "../private/sha3/sha3_512"
import "../private/sha3/shake128"
import "../private/sha3/shake256"
import "../private/sha3/keccak"

type
  XofState* = keccak.KeccakState

## SHAKE128 rate in bytes
const
  XOF_BLOCKBYTES* = 168  # SHAKE128_RATE (1344 bits)

# -----------------------------------------------------------------------------
# Hashes: H = SHA3-256, G = SHA3-512
# -----------------------------------------------------------------------------

proc hash_h*(output: var openArray[byte]; input: openArray[byte]) =
  ## H(msg) = SHA3-256(msg)
  when not defined(release):
    doAssert output.len >= 32
  var ctx = newSha3_256Ctx()
  ctx.update(input)
  let dig = ctx.digest()            # returns 32 bytes
  copyMem(addr output[0], unsafeAddr dig[0], 32)

proc hash_g*(output: var openArray[byte]; input: openArray[byte]) =
  ## G(msg) = SHA3-512(msg)
  when not defined(release):
    doAssert output.len >= 64
  var ctx = newSha3_512Ctx()
  ctx.update(input)
  let dig = ctx.digest()            # returns 64 bytes
  copyMem(addr output[0], unsafeAddr dig[0], 64)

# -----------------------------------------------------------------------------
# XOF: specialized SHAKE128 absorb/squeeze for Kyber
# -----------------------------------------------------------------------------

proc xof_absorb*(state: var XofState; seed: openArray[byte]; x, y: byte) =
  ## Absorb seed || x || y into SHAKE128 sponge (no finalize yet).
  var extseed: array[KYBER_SYMBYTES + 2, byte]
  copyMem(addr extseed[0], unsafeAddr seed[0], KYBER_SYMBYTES)
  extseed[KYBER_SYMBYTES] = x
  extseed[KYBER_SYMBYTES + 1] = y

  # Keccak-f[1600]: capacity = 256 bits (32 bytes) → rate = 200 - 32 = 168 bytes
  let capacityBytes = 200 - XOF_BLOCKBYTES
  var s = keccak.keccakInit(capacityBytes, 24)
  discard keccak.keccakAbsorb(s, extseed)  # only absorb; DS/padding handled in squeeze
  state = s

proc xof_squeezeblocks*(output: var openArray[byte]; outblocks: int; state: var XofState) =
  ## Squeeze 'outblocks' * 168 bytes from SHAKE128 state (domain sep 0x1F).
  when not defined(release):
    doAssert output.len >= outblocks * XOF_BLOCKBYTES
  discard keccak.keccakSqueeze(state, output, outblocks * XOF_BLOCKBYTES, 0x1F)

# -----------------------------------------------------------------------------
# PRF / Rejection-key PRF via SHAKE256
# -----------------------------------------------------------------------------

proc prf*(output: var openArray[byte]; outlen: int; key: openArray[byte]; nonce: byte) =
  ## SHAKE256(PRF): out = SHAKE256(key || nonce, outlen)
  when not defined(release):
    doAssert key.len >= KYBER_SYMBYTES
    doAssert output.len >= outlen
  var extkey: array[KYBER_SYMBYTES + 1, byte]
  copyMem(addr extkey[0], unsafeAddr key[0], KYBER_SYMBYTES)
  extkey[KYBER_SYMBYTES] = nonce

  var ctx = newShake256Ctx()
  ctx.update(extkey)
  # read directly into caller's buffer
  ctx.read(output.toOpenArray(0, outlen - 1))

proc rkprf*(output: var openArray[byte]; key: openArray[byte]; input: openArray[byte]) =
  ## RKPRF: out = SHAKE256(key || input, KYBER_SSBYTES)
  when not defined(release):
    doAssert key.len >= KYBER_SYMBYTES
    doAssert output.len >= KYBER_SSBYTES
  var ctx = newShake256Ctx()
  ctx.update(key)
  ctx.update(input)
  ctx.read(output.toOpenArray(0, KYBER_SSBYTES - 1))
