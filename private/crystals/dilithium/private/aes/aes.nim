# src/rng_aes.nim
# Minimal AES-256 ECB single-block primitive for rng.c DRBG parity

include rijndael

const
  BlockBytes* = 16        # AES block size (128-bit)
  KeyBytes256* = 32       # 256-bit key

type
  RngAesCtx* = object
    st: BlockState

# Initialize with a 32-byte key (exactly like OpenSSL EVP_aes_256_ecb with no IV)
proc init*(ctx: var RngAesCtx; key: openArray[byte]) =
  doAssert key.len == KeyBytes256, "AES-256 key must be 32 bytes"
  var k: seq[byte]
  k.setLen(KeyBytes256)
  for i in 0 ..< KeyBytes256:
    k[i] = key[i]
  # NOTE: stateInit here is expected to take key length in BYTES.
  # If your stateInit wants bits, change k.len -> k.len * 8.
  discard stateInit(ctx.st, k, k.len)

# Encrypt exactly one 16-byte block (no padding, no chaining)
proc encryptBlock*(ctx: RngAesCtx,
                   input: array[BlockBytes, byte],
                   output: var array[BlockBytes, byte]) =
  rijndaelEncrypt(ctx.st.ek, ctx.st.rounds, input, output)

# Convenience one-shot (builds a temp ctx, encrypts one block)
proc aes256EcbBlock*(key: array[KeyBytes256, byte],
                     input: array[BlockBytes, byte],
                     output: var array[BlockBytes, byte]) =
  var c: RngAesCtx
  c.init(key)
  c.encryptBlock(input, output)
