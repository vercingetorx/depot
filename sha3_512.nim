import std/strutils

include keccak


type Sha3_512Ctx = object
  state: KeccakState
  blockSize: int
  digestSize: int
  padding: byte


const
  DigestSize = 64
  BlockSize = 72
  Padding = 0x06'u8
  Rounds = 24'u8


proc update*(ctx: var Sha3_512Ctx, data: openArray[byte]) =
  discard ctx.state.keccakAbsorb(data)


proc update*(ctx: var Sha3_512Ctx, data: string) =
  discard ctx.state.keccakAbsorb(data.toOpenArrayByte(0, data.len.pred))


proc digest*(ctx: var Sha3_512Ctx): array[DigestSize, byte] =
  discard keccakDigest(ctx.state, result, ctx.digestSize, ctx.padding)


proc hexDigest*(ctx: var Sha3_512Ctx): string =
  ## produces a hex string of length ctx.digestSize * 2
  result = newStringOfCap(ctx.digestSize + ctx.digestSize)
  let digest = ctx.digest()
  for b in digest:
    result.add(b.toHex(2).toLowerAscii())

  return result


proc newSha3_512Ctx*(data: openArray[byte] = @[]): Sha3_512Ctx =
  result.blockSize = BlockSize
  result.digestSize = DigestSize
  result.padding = Padding
  
  result.state = keccakInit(DigestSize + DigestSize, Rounds)

  if data.len > 0:
    result.update(data)


proc newSha3_512Ctx*(data: string): Sha3_512Ctx =
  return newSha3_512Ctx(data.toOpenArrayByte(0, data.len.pred))


when isMainModule:
  let message = "hello world"

  var ctx = newSha3_512Ctx(message)
  doAssert ctx.hexDigest() == "840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a"
