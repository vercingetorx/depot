import std/strutils

include keccak


type Shake128Ctx = object
  state: KeccakState
  digestSize: int
  padding: byte


const
  DigestSize = 32
  Padding = 0x1F'u8
  Rounds = 24'u8


proc read*(ctx: var Shake128Ctx, length: int = DigestSize): seq[byte] =
  result = newSeq[byte](length)
  discard keccakSqueeze(ctx.state, result, length, ctx.padding)


proc read*(ctx: var Shake128Ctx, dst: var openArray[byte]) =
  discard keccakSqueeze(ctx.state, dst, dst.len, ctx.padding)


proc write*(ctx: var Shake128Ctx, data: openArray[byte]) =
  discard keccakAbsorb(ctx.state, data)


proc update*(ctx: var Shake128Ctx, data: openArray[byte]) =
  ctx.write(data)


proc update*(ctx: var Shake128Ctx, data: string) =
  ctx.write(data.toOpenArrayByte(0, data.len.pred))


proc digest*(ctx: var Shake128Ctx, length: int = DigestSize): seq[byte] =
  return ctx.read(length)


proc hexDigest*(ctx: var Shake128Ctx, length: int = DigestSize): string =
  ## produces a hex string of length length * 2
  result = newStringOfCap(length + length)
  let digest = ctx.read(length)
  for b in digest:
    result.add(b.toHex(2).toLowerAscii())

  return result


proc newShake128Ctx*(data: openArray[byte] = @[]): Shake128Ctx =
  ## shake128 XOF
  result.digestSize = DigestSize
  result.padding = Padding
  
  result.state = keccakInit(DigestSize, Rounds)

  if data.len > 0:
    result.update(data)


proc newShake128Ctx*(data: string): Shake128Ctx =
  return newShake128Ctx(data.toOpenArrayByte(0, data.len.pred))


when isMainModule:
  let message = "hello world"

  var ctx = newShake128Ctx(message)
  doAssert ctx.hexDigest() == "3a9159f071e4dd1c8c4f968607c30942e120d8156b8b1e72e0d376e8871cb8b8"
