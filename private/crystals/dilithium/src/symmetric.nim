# symmetric.nim
# Minimal wrappers to initialize Dilithium SHAKE streams and squeeze blocks.

import params
import ../private/sha3/keccak

export keccak

# --- Types matching the C aliases ---
type
  Stream128State* = KeccakState
  Stream256State* = KeccakState

# --- Rates (bytes) per FIPS 202 ---
const
  SHAKE128_RATE* = 168
  SHAKE256_RATE* = 136
  STREAM128_BLOCKBYTES* = SHAKE128_RATE
  STREAM256_BLOCKBYTES* = SHAKE256_RATE
  SHAKE_PADDING = 0x1F'u8
  ROUNDS = 24'u8

# --- Low-level SHAKE wrappers (names used by other modules) ---

proc shake128_init*(st: var KeccakState) =
  ## Initialize a SHAKE128 XOF state.
  ## capacity = 32 bytes → rate = 200 - 32 = 168
  st = keccakInit(32, ROUNDS)

proc shake256_init*(st: var KeccakState) =
  ## Initialize a SHAKE256 XOF state.
  ## capacity = 64 bytes → rate = 200 - 64 = 136
  st = keccakInit(64, ROUNDS)

proc shake128_absorb*(st: var KeccakState, data: openArray[byte]) =
  discard keccakAbsorb(st, data)

proc shake256_absorb*(st: var KeccakState, data: openArray[byte]) =
  discard keccakAbsorb(st, data)

proc shake128_finalize*(st: var KeccakState) =
  keccakFinish(st, SHAKE_PADDING)

proc shake256_finalize*(st: var KeccakState) =
  keccakFinish(st, SHAKE_PADDING)

proc shake128_squeezeblocks*(output: var openArray[byte], outBlocks: int,
    st: var KeccakState) =
  ## Squeeze exactly outBlocks * SHAKE128_RATE bytes.
  let total = outBlocks * SHAKE128_RATE
  doAssert output.len >= total
  discard keccakSqueeze(st, output, total, SHAKE_PADDING)

proc shake256_squeezeblocks*(output: var openArray[byte], outBlocks: int,
    st: var KeccakState) =
  ## Squeeze exactly outBlocks * SHAKE256_RATE bytes.
  let total = outBlocks * SHAKE256_RATE
  doAssert output.len >= total
  discard keccakSqueeze(st, output, total, SHAKE_PADDING)

# --- Dilithium stream initializers (seed || nonce[LE]) ---

proc dilithium_shake128_stream_init*(state: var KeccakState,
                                     seed: openArray[byte],
                                     nonce: uint16) =
  ## Equivalent to C: shake128_init; absorb(seed); absorb(nonce LE); finalize.
  doAssert seed.len == SEEDBYTES
  shake128_init(state)
  shake128_absorb(state, seed)
  var t: array[2, byte]
  t[0] = byte(nonce and 0xFF)
  t[1] = byte((nonce shr 8) and 0xFF)
  shake128_absorb(state, t)
  shake128_finalize(state)

proc dilithium_shake256_stream_init*(state: var KeccakState,
                                     seed: openArray[byte],
                                     nonce: uint16) =
  ## Equivalent to C: shake256_init; absorb(seed); absorb(nonce LE); finalize.
  doAssert seed.len == CRHBYTES
  shake256_init(state)
  shake256_absorb(state, seed)
  var t: array[2, byte]
  t[0] = byte(nonce and 0xFF)
  t[1] = byte((nonce shr 8) and 0xFF)
  shake256_absorb(state, t)
  shake256_finalize(state)

# --- Convenience aliases used elsewhere in the port ---

proc stream128_init*(state: var Stream128State, seed: openArray[byte],
    nonce: uint16) =
  dilithium_shake128_stream_init(state, seed, nonce)

proc stream256_init*(state: var Stream256State, seed: openArray[byte],
    nonce: uint16) =
  dilithium_shake256_stream_init(state, seed, nonce)

proc stream128_squeezeblocks*(output: var openArray[byte], outBlocks: int,
    state: var Stream128State) =
  shake128_squeezeblocks(output, outBlocks, state)

proc stream256_squeezeblocks*(output: var openArray[byte], outBlocks: int,
    state: var Stream256State) =
  shake256_squeezeblocks(output, outBlocks, state)
