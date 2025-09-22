## XChaCha20-Poly1305 AEAD (24-byte nonce)
##
## This module provides a tiny, focused AEAD wrapper around the vendored
## ChaCha20 and Poly1305 primitives located under private/. The construction
## follows the XChaCha20-Poly1305 scheme (24-byte nonce) and the RFC 8439 AEAD
## layout for additional data and length blocks.
##
## Design notes
## - Nonce size: 24 bytes. The underlying chacha20 module implements XChaCha20
##   with HChaCha20 key derivation. We pass the 24-byte nonce straight through.
## - Poly1305 one-time key (OTK): derived from ChaCha20 block 0. The first 32
##   bytes of the keystream are split into r (first 16) and s (last 16). The
##   init routine for Poly1305 clamps r as required by the spec.
## - Encryption starts at block 1: block 0 is reserved for OTK, so the cipher
##   is sought to block 1 before encrypting/decrypting the payload.
## - MAC input order: AD || pad16 || C || pad16 || len(AD) || len(C), where
##   lengths are 64-bit little-endian per RFC 8439. pad16 is zero bytes to the
##   next 16-byte boundary when needed.
##
## Security footnotes
## - Never reuse a (key, nonce) pair. XChaCha20 allows nonces to be randomly
##   generated given its extended size, but uniqueness is still required.
## - Tag comparison here avoids early returns but is not guaranteed strictly
##   constant-time by the compiler. It is adequate for our CLI use case. If you
##   need hard constant-time behavior, use a dedicated constant-time comparison.
## - This module does not zeroize secrets by default except where explicitly
##   performed; callers should manage key material lifetimes appropriately.

import std/[sysrand]
import ../private/chacha20/chacha20
import ../private/chacha20/poly1305

type
  ## 256-bit secret key for XChaCha20.
  AeadKey* = array[32, byte]
  ## 192-bit nonce for XChaCha20 (HChaCha20 + 64-bit tail for stream).
  AeadNonce24* = array[24, byte]

proc toBytes*(s: openArray[byte]): seq[byte] {.inline.} =
  ## Copy an arbitrary byte-like slice into a distinct seq[byte]. Handy for
  ## turning array views into owned buffers when passing to callers.
  result = newSeq[byte](s.len)
  for i, b in s:
    result[i] = b

proc le64(x: uint64): array[8, byte] {.inline.} =
  ## Encode a 64-bit integer as little-endian bytes.
  for i in 0 ..< 8:
    result[i] = byte((x shr (8*i)) and 0xff'u64)

proc zeroize*(s: var seq[byte]) {.inline.} =
  ## Overwrite a seq in place. This is best-effort; compilers may elide writes.
  for i in 0 ..< s.len:
    s[i] = 0

proc aeadEncrypt*(key: AeadKey,
                  nonce: AeadNonce24,
                  plaintext, ad: openArray[byte]): tuple[ciphertext: seq[byte], tag: array[16, byte]] =
  ## Encrypt `plaintext` and authenticate both `ad` (associated data) and the
  ## resulting ciphertext. Returns the ciphertext and the 16-byte authentication
  ## tag.
  ##
  ## Layout used by the MAC: AD || pad16 || C || pad16 || len(AD) || len(C).
  ## Encryption keystream begins at block 1.
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

  # Poly1305 authenticator inputs follow RFC 8439 exactly:
  #   AD || pad16 || C || pad16 || len(AD) || len(C)
  # Where pad16 is zero-bytes to the next 16-byte boundary (if needed).
  var mac = Poly1305Ctx()
  initWithRS(mac, r, s)
  # 1) Associated data (AD)
  #    Poly1305 consumes 16-byte blocks. If AD length isn't a multiple of 16,
  #    we must append zero padding up to the next block boundary before moving
  #    on to the ciphertext section.
  if ad.len > 0:
    mac.update(ad)
  if (ad.len mod 16) != 0:
    # Nim zero-initializes the newly allocated seq[byte], which is exactly the
    # zero padding required by the spec.
    var pad = newSeq[byte](16 - (ad.len mod 16))
    if pad.len > 0: mac.update(pad)

  # 2) Ciphertext (C), followed by its own pad16 if needed
  if result.ciphertext.len > 0:
    mac.update(result.ciphertext)
  if (result.ciphertext.len mod 16) != 0:
    var pad2 = newSeq[byte](16 - (result.ciphertext.len mod 16))
    if pad2.len > 0: mac.update(pad2)

  # 3) Length block: two uint64 little-endian values concatenated.
  #    First is |AD|, second is |C|, both measured in bytes.
  var lens: array[16, byte]
  let adLen  = le64(ad.len.uint64)
  let ctLen  = le64(result.ciphertext.len.uint64)
  for i in 0 ..< 8: lens[i]     = adLen[i]
  for i in 0 ..< 8: lens[8 + i] = ctLen[i]
  mac.update(lens)
  result.tag = mac.digest()

proc aeadDecrypt*(key: AeadKey,
                  nonce: AeadNonce24,
                  ciphertext, ad: openArray[byte],
                  tag: array[16, byte]): tuple[ok: bool, plaintext: seq[byte]] =
  ## Authenticate and decrypt a ciphertext previously produced by aeadEncrypt.
  ## Returns ok=false if authentication fails. On success, plaintext is filled.
  ##
  ## Authentication is computed before decryption to avoid exposing plaintext
  ## under a forged tag.
  # Derive Poly1305 one-time key from block 0
  var ctx0 = newChaCha20Ctx(key, nonce)
  var empty: array[32, byte]
  let otkStream = ctx0.encrypt(empty)
  var r: array[16, byte]
  var s: array[16, byte]
  for i in 0 ..< 16: r[i] = otkStream[i]
  for i in 0 ..< 16: s[i] = otkStream[16 + i]

  # Compute expected tag over the exact same transcript layout
  var mac = Poly1305Ctx()
  initWithRS(mac, r, s)
  # 1) AD with pad16
  if ad.len > 0:
    mac.update(ad)
  if (ad.len mod 16) != 0:
    var pad = newSeq[byte](16 - (ad.len mod 16))
    if pad.len > 0: mac.update(pad)
  # 2) Ciphertext with pad16
  if ciphertext.len > 0:
    mac.update(ciphertext)
  if (ciphertext.len mod 16) != 0:
    var pad2 = newSeq[byte](16 - (ciphertext.len mod 16))
    if pad2.len > 0: mac.update(pad2)
  # 3) Length block: |AD| || |C|, each 64-bit LE
  var lens: array[16, byte]
  let adLen  = le64(ad.len.uint64)
  let ctLen  = le64(ciphertext.len.uint64)
  for i in 0 ..< 8: lens[i]     = adLen[i]
  for i in 0 ..< 8: lens[8 + i] = ctLen[i]
  mac.update(lens)
  let expTag = mac.digest()
  # Compare tags without an early return. See security note above.
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
  ## Generate a 24-byte random nonce for XChaCha20-Poly1305.
  ## The only hard requirement is uniqueness per key; XChaCha20's 192-bit
  ## nonce size makes random generation safe for non-extreme usage.
  var tmp = urandom(24)
  for i in 0 ..< 24:
    result[i] = tmp[i]
