import std/[sysrand]
import ../private/chacha20
import ../private/poly1305

# XChaCha20-Poly1305 AEAD (24-byte nonce)
# - Nonce: 24 bytes. Uses HChaCha20 to derive a subkey; last 8 bytes as nonce.
# - Poly1305 one-time key from ChaCha20 block 0; payload encryption starts at block 1.

type
  AeadKey* = array[32, byte]
  AeadNonce24* = array[24, byte]

proc toBytes*(s: openArray[byte]): seq[byte] {.inline.} =
  result = newSeq[byte](s.len)
  for i, b in s: result[i] = b

proc le64(x: uint64): array[8, byte] {.inline.} =
  for i in 0 ..< 8:
    result[i] = byte((x shr (8*i)) and 0xff'u64)

proc zeroize*(s: var seq[byte]) {.inline.} =
  for i in 0 ..< s.len: s[i] = 0

proc aeadEncrypt*(key: AeadKey,
                  nonce: AeadNonce24,
                  plaintext, ad: openArray[byte]): tuple[ciphertext: seq[byte],
                      tag: array[16, byte]] =
  # Derive Poly1305 one-time key from block 0
  var ctx0 = newChaCha20Ctx(key, nonce)
  var empty: array[32, byte]
  let otkStream = ctx0.encrypt(empty)
  var r: array[16, byte]
  var s: array[16, byte]
  for i in 0 ..< 16: r[i] = otkStream[i]
  for i in 0 ..< 16: s[i] = otkStream[16 + i]

  # Encrypt starting from block 1
  var ctx = newChaCha20Ctx(key, nonce)
  ctx.seek(1'u64, 0'u64, 0'u) # start at block 1, offset 0

  result.ciphertext = newSeq[byte](plaintext.len)
  if plaintext.len > 0:
    ctx.encrypt(plaintext, result.ciphertext, plaintext.len)

  # Poly1305 over: AD || pad16 || C || pad16 || len(AD) || len(C)
  var mac = Poly1305Ctx()
  initWithRS(mac, r, s)
  if ad.len > 0: mac.update(ad)
  if (ad.len mod 16) != 0:
    var pad = newSeq[byte](16 - (ad.len mod 16))
    if pad.len > 0: mac.update(pad)
  if result.ciphertext.len > 0: mac.update(result.ciphertext)
  if (result.ciphertext.len mod 16) != 0:
    var pad2 = newSeq[byte](16 - (result.ciphertext.len mod 16))
    if pad2.len > 0: mac.update(pad2)
  var lens: array[16, byte]
  let adLen = le64(ad.len.uint64)
  let ctLen = le64(result.ciphertext.len.uint64)
  for i in 0 ..< 8: lens[i] = adLen[i]
  for i in 0 ..< 8: lens[8 + i] = ctLen[i]
  mac.update(lens)
  result.tag = mac.digest()

proc aeadDecrypt*(key: AeadKey,
                  nonce: AeadNonce24,
                  ciphertext, ad: openArray[byte],
                  tag: array[16, byte]): tuple[ok: bool, plaintext: seq[byte]] =
  # Derive Poly1305 one-time key from block 0
  var ctx0 = newChaCha20Ctx(key, nonce)
  var empty: array[32, byte]
  let otkStream = ctx0.encrypt(empty)
  var r: array[16, byte]
  var s: array[16, byte]
  for i in 0 ..< 16: r[i] = otkStream[i]
  for i in 0 ..< 16: s[i] = otkStream[16 + i]

  # Compute expected tag
  var mac = Poly1305Ctx()
  initWithRS(mac, r, s)
  if ad.len > 0: mac.update(ad)
  if (ad.len mod 16) != 0:
    var pad = newSeq[byte](16 - (ad.len mod 16))
    if pad.len > 0: mac.update(pad)
  if ciphertext.len > 0: mac.update(ciphertext)
  if (ciphertext.len mod 16) != 0:
    var pad2 = newSeq[byte](16 - (ciphertext.len mod 16))
    if pad2.len > 0: mac.update(pad2)
  var lens: array[16, byte]
  let adLen = le64(ad.len.uint64)
  let ctLen = le64(ciphertext.len.uint64)
  for i in 0 ..< 8: lens[i] = adLen[i]
  for i in 0 ..< 8: lens[8 + i] = ctLen[i]
  mac.update(lens)
  let expTag = mac.digest()
  var equal = true
  for i in 0 ..< 16:
    equal = equal and (expTag[i] == tag[i])
  if not equal:
    return (false, @[])

  # Decrypt starting from block 1
  var ctx = newChaCha20Ctx(key, nonce)
  ctx.seek(1'u64, 0'u64, 0'u)
  result.ok = true
  result.plaintext = newSeq[byte](ciphertext.len)
  if ciphertext.len > 0:
    ctx.decrypt(ciphertext, result.plaintext, ciphertext.len)

proc randomNonce24*(): AeadNonce24 =
  var tmp = urandom(24)
  for i in 0 ..< 24: result[i] = tmp[i]
