## Handshake: TOFU identity pinning, Kyber KEM, Dilithium signatures, key derivation.
import std/[asyncdispatch, asyncnet, json, logging, os, strutils, sysrand, strformat]
import aead
import varint
import common
import protocol
import userconfig
import errors
import ../private/argon2/argon2
import ../private/blake2/blake2b
import ../private/crystals/kyber/kyber
import ../private/crystals/dilithium/dilithium

type
  ## Plain-socket I/O helpers for the handshake phase (before Session).
  HsSocketClosedError = object of CatchableError
  HsFormatError = object of CatchableError

proc hsRecvExact(sock: AsyncSocket, n: int): Future[seq[byte]] {.async.} =
  ## Read exactly n bytes from sock or raise HsSocketClosedError.
  var buf = newSeq[byte](n)
  var got = 0
  while got < n:
    let m = await sock.recvInto(addr buf[got], n - got)
    if m == 0:
      raise newException(HsSocketClosedError, "peer closed while reading body")
    got += m
  return buf

proc hsReadVarint(sock: AsyncSocket): Future[uint64] {.async.} =
  ## Read a varint from sock or raise HsSocketClosedError/HsFormatError.
  var tmp: seq[byte]
  var b: array[1, byte]
  while true:
    let n = await sock.recvInto(addr b[0], 1)
    if n == 0:
      raise newException(HsSocketClosedError, "peer closed while reading varint")
    tmp.add(b[0])
    try:
      let (v, next) = getUvar(tmp)
      if next == tmp.len:
        return v
    except VarintError:
      if tmp.len > 10:
        raise newException(HsFormatError, "invalid varint length header")

const protoVersion* = 1'u8
# Secure-by-default Argon2id parameters for session key derivation.
# Memory cost in KiB (64 MiB) and 2 passes provide strong hardness
# without overburdening typical hosts for a per-connection handshake.
const argon2MCost = 65536  # 64 MiB
const argon2TCost = 2

type
  HandshakeError* = object of CatchableError
    code*: errors.ErrorCode

proc newHandshakeError*(code: errors.ErrorCode, message: string): ref HandshakeError =
  result = newException(HandshakeError, message)
  result.code = code

proc configDir*(): string =
  ## Return the base configuration directory for Depot
  ## (typically ~/.config/depot or $XDG_CONFIG_HOME/depot).
  getEnv("XDG_CONFIG_HOME", getEnv("HOME") / ".config") / "depot"

proc ensureDirExists(path: string) =
  ## Create a directory if it does not already exist.
  if not dirExists(path): createDir(path)

proc readAllBytes(p: string): seq[byte] =
  ## Read the entire file at path 'p' into a byte sequence.
  var f = open(p, fmRead)
  defer: f.close()
  let sz = getFileSize(p)
  result = newSeq[byte](sz)
  discard f.readBytes(result, 0, sz)

proc writeAllBytes(p: string, data: openArray[byte]) =
  ## Write the entire 'data' buffer to file at path 'p', replacing contents.
  var f = open(p, fmWrite)
  defer: f.close()
  discard f.writeBytes(data, 0, data.len)

# Encrypted secret key file format (DPK1):
#  magic(4) = "DPK1" | len(4, LE) | salt16 | nonce24 | ciphertext(len) | tag16
const dpkMagic = "DPK1"

var serverKeyPassphrase* = ""

proc kdfKey(pass: openArray[byte], salt: openArray[byte]): array[32, byte] =
  let ctx = newArgon2Ctx(pass, salt=salt, timeCost=2, memoryCost=65536, digestSize=32)
  let km = ctx.digest()
  for i in 0 ..< 32: result[i] = km[i]

proc encryptSecret*(plain: openArray[byte], pass: openArray[byte]): seq[byte] =
  ## Encrypt plain secret with passphrase using Argon2id + XChaCha20-Poly1305.
  var salt: array[16, byte]
  let sb = urandom(16)
  for i in 0 ..< 16: salt[i] = sb[i]
  let key = kdfKey(pass, salt)
  let nb = urandom(24)
  var nonce: AeadNonce24
  for i in 0 ..< 24: nonce[i] = nb[i]
  let ad = toBytes(dpkMagic)
  let (ct, tag) = aeadEncrypt(key, nonce, plain, ad)
  var outp = newSeq[byte](4 + 4 + 16 + 24 + ct.len + 16)
  # magic
  for i, ch in dpkMagic: outp[i] = byte(ch)
  var idx = 4
  # len LE
  var ln = uint32(plain.len)
  for i in 0 ..< 4:
    outp[idx+i] = byte((ln shr (8*i)) and 0xff'u32)
  idx += 4
  # salt
  for i in 0 ..< 16: outp[idx+i] = salt[i]
  idx += 16
  # nonce
  for i in 0 ..< 24: outp[idx+i] = nonce[i]
  idx += 24
  # ct
  if ct.len > 0:
    copyMem(addr outp[idx], unsafeAddr ct[0], ct.len)
  idx += ct.len
  # tag
  for i in 0 ..< 16: outp[idx+i] = tag[i]
  outp

proc deriveRekey*(trafficSecret: array[32, byte], epochBytes: openArray[byte]): (array[48, byte], array[48, byte]) =
  ## Derive two 48-byte key blocks for c2s and s2c using BLAKE2b
  ## keyed by the session trafficSecret and epoch bytes.
  var ctx1 = newBlake2bCtx(digestSize=48)
  ctx1.update(trafficSecret); ctx1.update("c2s"); ctx1.update(epochBytes)
  let out1 = ctx1.digest()
  var ctx2 = newBlake2bCtx(digestSize=48)
  ctx2.update(trafficSecret); ctx2.update("s2c"); ctx2.update(epochBytes)
  let out2 = ctx2.digest()
  var a1: array[48, byte]
  var a2: array[48, byte]
  for i in 0 ..< 48: a1[i] = out1[i]
  for i in 0 ..< 48: a2[i] = out2[i]
  (a1, a2)

proc decryptSecret*(enc: openArray[byte], pass: openArray[byte]): tuple[ok: bool, plain: seq[byte]] =
  ## Decrypt DPK1-encrypted secret key with passphrase.
  if enc.len < 4 + 4 + 16 + 24 + 16: return (false, @[])
  if char(enc[0]) != 'D' or char(enc[1]) != 'P' or char(enc[2]) != 'K' or char(enc[3]) != '1':
    return (false, @[])
  var idx = 4
  var ln: uint32 = 0
  for i in 0 ..< 4:
    ln = ln or (uint32(enc[idx+i]) shl (8*i))
  idx += 4
  var salt: array[16, byte]
  for i in 0 ..< 16: salt[i] = enc[idx+i]
  idx += 16
  var nonce: AeadNonce24
  for i in 0 ..< 24: nonce[i] = enc[idx+i]
  idx += 24
  let ctLen = int(ln)
  if idx + ctLen + 16 > enc.len: return (false, @[])
  let ct = enc[idx ..< idx + ctLen]
  idx += ctLen
  var tag: array[16, byte]
  for i in 0 ..< 16: tag[i] = enc[idx+i]
  let key = kdfKey(pass, salt)
  let ad = toBytes(dpkMagic)
  let (ok, pt) = aeadDecrypt(key, nonce, ct, ad, tag)
  (ok, pt)

proc ensureServerIdentity*(): (PublicKey, SecretKey) =
  ## Load or generate the server's Dilithium identity keypair
  ## under configDir()/id.
  let dir = configDir() / "id"
  ensureDirExists(dir)
  let pkp = dir / "server_dilithium.pk"
  let skp = dir / "server_dilithium.sk"
  if fileExists(pkp) and fileExists(skp):
    var pk: PublicKey
    var sk: SecretKey
    let pkb = readAllBytes(pkp)
    let skb = readAllBytes(skp)
    doAssert pkb.len == pk.len
    for i in 0 ..< pk.len: pk[i] = pkb[i]
    # Secret: require DPK1-encrypted key; plaintext is not allowed.
    if not (skb.len >= 4 and char(skb[0]) == 'D' and char(skb[1]) == 'P' and char(skb[2]) == 'K' and char(skb[3]) == '1'):
      raise newException(HandshakeError, "server key must be encrypted (DPK1); plaintext keys are not supported")
    if serverKeyPassphrase.len == 0:
      raise newException(HandshakeError, "Encrypted server key requires --key-pass or --key-pass-file on server")
    let (ok, pt) = decryptSecret(skb, toBytes(serverKeyPassphrase))
    if not ok or pt.len != sk.len:
      raise newException(HandshakeError, "failed to decrypt server key")
    for i in 0 ..< sk.len: sk[i] = pt[i]
    return (pk, sk)
  else:
    # New identity generation requires a passphrase so the key at rest is encrypted.
    if serverKeyPassphrase.len == 0:
      raise newException(HandshakeError, "No server key found; --key-pass or --key-pass-file is required to generate an encrypted key")
    let (pk, sk) = generateKeypair()
    writeAllBytes(pkp, pk)
    let enc = encryptSecret(sk, toBytes(serverKeyPassphrase))
    writeAllBytes(skp, enc)
    return (pk, sk)

proc ensureClientIdentity*(): (PublicKey, SecretKey) =
  ## Load or generate the client's Dilithium identity keypair
  ## under configDir()/id.
  let dir = configDir() / "id"
  ensureDirExists(dir)
  let pkp = dir / "client_dilithium.pk"
  let skp = dir / "client_dilithium.sk"
  if fileExists(pkp) and fileExists(skp):
    var pk: PublicKey
    var sk: SecretKey
    let pkb = readAllBytes(pkp)
    let skb = readAllBytes(skp)
    doAssert pkb.len == pk.len
    doAssert skb.len == sk.len
    for i in 0 ..< pk.len: pk[i] = pkb[i]
    for i in 0 ..< sk.len: sk[i] = skb[i]
    return (pk, sk)
  else:
    let (pk, sk) = generateKeypair()
    writeAllBytes(pkp, pk)
    writeAllBytes(skp, sk)
    return (pk, sk)

proc pinPath*(remoteId: string): string =
  ## Return path to the pinned server public key file for 'remoteId'.
  let dir = configDir() / "trust"
  ensureDirExists(dir)
  dir / fmt"{remoteId}.pk"

proc loadPinned*(remoteId: string): (bool, PublicKey) =
  ## Load a pinned server public key for 'remoteId', if present.
  ## Returns (true, pk) on success, or (false, default) if missing/invalid.
  let p = pinPath(remoteId)
  if not fileExists(p): return (false, default(PublicKey))
  var pk: PublicKey
  let b = readAllBytes(p)
  if b.len != pk.len: return (false, default(PublicKey))
  for i in 0 ..< pk.len: pk[i] = b[i]
  (true, pk)

proc savePinned*(remoteId: string, pk: PublicKey) =
  ## Save a pinned server public key for 'remoteId'. Overwrites existing file.
  writeAllBytes(pinPath(remoteId), pk)

## Use shared helpers from depot/common

proc sendBlob(sock: AsyncSocket, t: uint8, blob: seq[byte]) {.async.} =
  ## Send a length-prefixed handshake blob: varint(len) | type | payload.
  var body = newSeq[byte](1 + blob.len)
  body[0] = byte(t)
  if blob.len > 0:
    copyMem(addr body[1], unsafeAddr blob[0], blob.len)
  var hdr = putUvar(uint64(body.len))
  await sock.send(toStr(hdr))
  await sock.send(toStr(body))

proc recvBlob(sock: AsyncSocket): Future[(uint8, seq[byte])] {.async.} =
  ## Receive a length-prefixed handshake blob; returns (type, payload).
  try:
    let ln = int(await hsReadVarint(sock))
    let rec = await hsRecvExact(sock, ln)
    return (rec[0], rec[1 ..< ln])
  except HsSocketClosedError:
    return (0'u8, @[])
  except HsFormatError:
    return (0'u8, @[])

# Handshake message types (plaintext, TOFU-protected):
# 0x00: CLIENT_HELLO (json)
# 0x01: SERVER_ID  = Dilithium public key
# 0x02: KEM_PK     = Kyber public key || dilithium_sig(kyber_pk)
# 0x03: KEM_ENV    = Kyber envelope || c2sPrefix16 || s2cPrefix16
# 0x04: SERVER_HELLO (json)
# 0x05: CLIENT_AUTH (optional: Dilithium client PK + signature)

proc clientHandshake*(sock: AsyncSocket, remoteId: string): Future[Session] {.async.} =
  ## Client side of the TOFU-based handshake:
  ## - Exchanges hello messages (JSON) and server identity
  ## - Verifies Kyber PK via Dilithium signature, pins server key on first use
  ## - Derives traffic keys via Kyber KEM + Argon2id (bound to transcript)
  ## - Optionally authenticates the client using Dilithium
  let cfg = readConfig()
  let clientPsk = cfg.client.psk
  # 1) Send CLIENT_HELLO
  let clientHelloObj = %* {"version": 1, "ciphers": @["kyber-xchacha20"],
                           "psk": clientPsk.len > 0,
                           "clientAuth": true,
                           "features": @["dlAckV1"]}
  var clientHelloJson = $clientHelloObj
  await sendBlob(sock, 0x00'u8, bytesCopy(clientHelloJson.toOpenArrayByte(0, clientHelloJson.high)))
  # Phase 2: receive SERVER_HELLO (JSON)
  let (tServerHello, serverHelloBlob) = await recvBlob(sock)
  if tServerHello == 0x06'u8:
    let ec = if serverHelloBlob.len == 1: fromByte(serverHelloBlob[0]) else: ecUnknown
    raise newHandshakeError(ec, "")
  if tServerHello != 0x04'u8: raise newHandshakeError(ecBadPayload, "expected SERVER_HELLO")
  let serverHello = parseJson(cast[string](serverHelloBlob))
  if serverHello["version"].getInt() != 1: raise newHandshakeError(ecCompat, "version mismatch")
  var dlAck = false
  var srvSandbox = true
  if serverHello.hasKey("features"):
    for f in serverHello["features"]:
      if f.getStr() == "dlAckV1": dlAck = true
  if serverHello.hasKey("sandbox"):
    srvSandbox = serverHello["sandbox"].getBool(true)
  if not dlAck:
    raise newHandshakeError(ecCompat, "server missing required feature dlAckV1")
  let requirePsk = serverHello.getOrDefault("requirePsk").getBool(false)
  let requireClientAuth = serverHello.getOrDefault("requireClientAuth").getBool(false)
  if requirePsk and clientPsk.len == 0:
    raise newHandshakeError(ecAuth, "server requires PSK")
  # Phase 3: receive SERVER_ID (Dilithium PK)
  let (t1, sIdBlob) = await recvBlob(sock)
  if t1 == 0x06'u8:
    let ec = if sIdBlob.len == 1: fromByte(sIdBlob[0]) else: ecUnknown
    raise newHandshakeError(ec, "")
  if t1 != 0x01'u8:
    error "handshake: expected SERVER_ID, got ", t1
    raise newHandshakeError(ecBadPayload, "expected SERVER_ID")
  var serverSignPk: PublicKey
  if sIdBlob.len != serverSignPk.len: raise newHandshakeError(ecBadPayload, "bad SERVER_ID size")
  for i in 0 ..< serverSignPk.len: serverSignPk[i] = sIdBlob[i]
  let (havePin, pinned) = loadPinned(remoteId)
  if havePin:
    # Verify the pin matches
    var pinOk = true
    for i in 0 ..< pinned.len: pinOk = pinOk and (pinned[i] == serverSignPk[i])
    if not pinOk: raise newHandshakeError(ecAuth, "server identity changed; aborting")
  else:
    # First use: pin it
    savePinned(remoteId, serverSignPk)

  # Phase 4: receive KEM_PK (Kyber PK + signature)
  let (tKem, kemBlob) = await recvBlob(sock)
  if tKem == 0x06'u8:
    let ec = if kemBlob.len == 1: fromByte(kemBlob[0]) else: ecUnknown
    raise newHandshakeError(ec, "")
  if tKem != 0x02'u8: raise newHandshakeError(ecBadPayload, "expected KEM_PK")
  if kemBlob.len != kyber.PublicKeyBytes + dilithium.SignatureBytes:
    error "handshake: bad KEM_PK size=", kemBlob.len
    raise newHandshakeError(ecBadPayload, "bad KEM_PK blob size")
  var kyberPk = newSeq[byte](kyber.PublicKeyBytes)
  for i in 0 ..< kyber.PublicKeyBytes: kyberPk[i] = kemBlob[i]
  var kyberPkSig: Signature
  for i in 0 ..< dilithium.SignatureBytes: kyberPkSig[i] = kemBlob[kyber.PublicKeyBytes + i]
  # Verify signature over kyberPk
  let signatureOk = verifyDetached(kyberPkSig, kyberPk, serverSignPk)
  if not signatureOk:
    error "handshake: kyber pk signature invalid"
    raise newHandshakeError(ecAuth, "kyber pk signature invalid")

  # Phase 5: send KEM_ENV (envelope + prefixes)
  let (envelope, sharedSecret) = createEnvelope(kyberPk)
  var c2sPrefix: array[16, byte]
  var s2cPrefix: array[16, byte]
  let r1 = urandom(16)
  let r2 = urandom(16)
  for i in 0 ..< 16: c2sPrefix[i] = r1[i]
  for i in 0 ..< 16: s2cPrefix[i] = r2[i]
  var kemEnvBlob = newSeq[byte](EnvelopeBytes + 32)
  for i in 0 ..< EnvelopeBytes: kemEnvBlob[i] = envelope[i]
  for i in 0 ..< 16: kemEnvBlob[EnvelopeBytes + i] = c2sPrefix[i]
  for i in 0 ..< 16: kemEnvBlob[EnvelopeBytes + 16 + i] = s2cPrefix[i]
  await sendBlob(sock, 0x03, kemEnvBlob)

  # Phase 6: derive traffic keys (Argon2id)
  var salt = newSeq[byte](32)
  for i in 0 ..< 16: salt[i] = c2sPrefix[i]
  for i in 0 ..< 16: salt[16 + i] = s2cPrefix[i]
  # Phase 7: bind keys to handshake transcript (BLAKE2b)
  var transcriptHasher = newBlake2bCtx(digestSize=32)
  transcriptHasher.update(@[byte(protoVersion)])
  transcriptHasher.update(cast[string](serverHelloBlob))
  transcriptHasher.update(clientHelloJson)
  transcriptHasher.update(serverSignPk)        # server Dilithium PK (pinned by client)
  transcriptHasher.update(kyberPk)             # server Kyber PK
  transcriptHasher.update(envelope)            # envelope we generated (client side)
  transcriptHasher.update(c2sPrefix)
  transcriptHasher.update(s2cPrefix)
  if clientPsk.len > 0:
    transcriptHasher.update(clientPsk)
  let transcript = transcriptHasher.digest()
  let argon2Ctx = newArgon2Ctx(sharedSecret, salt=salt, assocData=transcript, timeCost=argon2TCost, memoryCost=argon2MCost, digestSize=64)
  let keyMaterial = argon2Ctx.digest()
  var sess: Session
  new(sess)
  sess.sock = sock
  for i in 0 ..< 32: sess.kTx[i] = keyMaterial[i]
  for i in 0 ..< 32: sess.kRx[i] = keyMaterial[32 + i]
  for i in 0 ..< 16: sess.pTx[i] = c2sPrefix[i]
  for i in 0 ..< 16: sess.pRx[i] = s2cPrefix[i]
  sess.seqTx = 0
  sess.seqRx = 0
  sess.dlAck = dlAck
  # Rekey initialization
  var th = newBlake2bCtx(digestSize=32)
  th.update(keyMaterial)
  let tsec = th.digest()
  for i in 0 ..< 32: sess.trafficSecret[i] = tsec[i]
  sess.epoch = 0'u32
  sess.rekeyIntervalMs = 15 * 60 * 1000
  sess.lastRekeyMs = common.monoMs()
  sess.pendingEpoch = 0'u32
  sess.ioTimeoutMs = 120000
  sess.srvSandboxed = srvSandbox
  # Optional client authentication (Dilithium)
  if requireClientAuth:
    # Load/generate client identity
    let (cpk, csk) = ensureClientIdentity()
    let sig = signDetached(transcript, csk)
    var authBlob = newSeq[byte](cpk.len + sig.len)
    for i in 0 ..< cpk.len: authBlob[i] = cpk[i]
    for i in 0 ..< sig.len: authBlob[cpk.len + i] = sig[i]
    await sendBlob(sock, 0x05, authBlob)
  return sess

proc serverHandshake*(sock: AsyncSocket, srvSandboxed: bool): Future[Session] {.async.} =
  ## Server side of the handshake; mirrors clientHandshake.
  try:
    let cfg = readConfig()
    let requirePsk = cfg.server.psk.len > 0
    let requireClientAuth = cfg.server.requireClientAuth
    # Receive CLIENT_HELLO
    let (tc, chelloBlob) = await recvBlob(sock)
    if tc != 0x00'u8: raise newHandshakeError(ecBadPayload, "expected CLIENT_HELLO")
    let chello = parseJson(cast[string](chelloBlob))
    if chello["version"].getInt() != 1: raise newHandshakeError(ecCompat, "version mismatch")
    # Respond SERVER_HELLO (advertise features)
    var dlAckSrv = false
    if chello.hasKey("features"):
      for f in chello["features"]:
        if f.getStr() == "dlAckV1": dlAckSrv = true
    if not dlAckSrv:
      raise newHandshakeError(ecCompat, "client missing required feature dlAckV1")
    let serverHelloObj = %* {"version": 1, "cipher": "kyber-xchacha20",
                             "requirePsk": requirePsk, "requireClientAuth": requireClientAuth,
                             "features": @["dlAckV1"],
                             "sandbox": srvSandboxed}
    var serverHelloStr = $serverHelloObj
    await sendBlob(sock, 0x04'u8, bytesCopy(serverHelloStr.toOpenArrayByte(0, serverHelloStr.high)))
    # Load or create identity
    let (signPk, signSk) =
      try:
        ensureServerIdentity()
      except HandshakeError as e:
        # Wrap with server-config code if it lacked a code
        if e.code != ecUnknown: raise
        raise newHandshakeError(ecConfig, e.msg)

    # 1) Send SERVER_ID (Dilithium PK)
    await sendBlob(sock, 0x01, bytesCopy(signPk))

    # 2) Send KEM_PK (Kyber PK + signature)
    var kyberKeys = generateKeys()
    var kemSig = signDetached(kyberKeys.publicKey, signSk)
    var kemBlob = newSeq[byte](kyberKeys.publicKey.len + kemSig.len)
    for i in 0 ..< kyberKeys.publicKey.len: kemBlob[i] = kyberKeys.publicKey[i]
    for i in 0 ..< kemSig.len: kemBlob[kyberKeys.publicKey.len + i] = kemSig[i]
    await sendBlob(sock, 0x02, kemBlob)

    # 3) Receive KEM_ENV
    let (t3, envBlob) = await recvBlob(sock)
    if t3 != 0x03'u8:
      error "handshake: expected KEM_ENV, got ", t3
      raise newHandshakeError(ecBadPayload, "expected KEM_ENV")
    if envBlob.len != EnvelopeBytes + 32:
      error "handshake: bad KEM_ENV size=", envBlob.len
      raise newHandshakeError(ecBadPayload, "bad KEM_ENV size")
    var envelope: Envelope
    envelope.setLen(EnvelopeBytes)
    for i in 0 ..< EnvelopeBytes: envelope[i] = envBlob[i]
    var c2sPrefix: array[16, byte]
    var s2cPrefix: array[16, byte]
    for i in 0 ..< 16: c2sPrefix[i] = envBlob[EnvelopeBytes + i]
    for i in 0 ..< 16: s2cPrefix[i] = envBlob[EnvelopeBytes + 16 + i]
    let sharedSecret = openEnvelope(kyberKeys.privateKey, envelope)

    # Derive traffic keys using Argon2 with per-session salt = c2sPref||s2cPref
    var salt = newSeq[byte](32)
    for i in 0 ..< 16: salt[i] = c2sPrefix[i]
    for i in 0 ..< 16: salt[16 + i] = s2cPrefix[i]
    # Bind keys to handshake transcript via assocData (BLAKE2b)
    var h = newBlake2bCtx(digestSize=32)
    h.update(@[byte(protoVersion)])
    h.update(serverHelloStr)
    h.update(cast[string](chelloBlob))
    h.update(signPk)                # server Dilithium PK
    h.update(kyberKeys.publicKey)   # server Kyber PK
    h.update(envelope)              # received envelope
    h.update(c2sPrefix)
    h.update(s2cPrefix)
    if requirePsk:
      h.update(cfg.server.psk)
    let transcript = h.digest()
    let a2 = newArgon2Ctx(sharedSecret, salt=salt, assocData=transcript, timeCost=argon2TCost, memoryCost=argon2MCost, digestSize=64)
    let keyMaterial = a2.digest()
    var sess: Session
    new(sess)
    sess.sock = sock
    for i in 0 ..< 32: sess.kTx[i] = keyMaterial[32 + i]
    for i in 0 ..< 32: sess.kRx[i] = keyMaterial[i]
    for i in 0 ..< 16: sess.pTx[i] = s2cPrefix[i]
    for i in 0 ..< 16: sess.pRx[i] = c2sPrefix[i]
    sess.seqTx = 0
    sess.seqRx = 0
    sess.dlAck = dlAckSrv
    # Rekey initialization
    var th = newBlake2bCtx(digestSize=32)
    th.update(keyMaterial)
    let tsec = th.digest()
    for i in 0 ..< 32: sess.trafficSecret[i] = tsec[i]
    sess.epoch = 0'u32
    sess.rekeyIntervalMs = 15 * 60 * 1000
    sess.lastRekeyMs = common.monoMs()
    sess.pendingEpoch = 0'u32
    sess.ioTimeoutMs = 120000
    sess.srvSandboxed = srvSandboxed
    # Optional client authentication
    if requireClientAuth:
      let (ta, blob) = await recvBlob(sock)
      if ta != 0x05'u8: raise newHandshakeError(ecBadPayload, "expected CLIENT_AUTH")
      var cpk: PublicKey
      var sig: Signature
      for i in 0 ..< cpk.len: cpk[i] = blob[i]
      for i in 0 ..< sig.len: sig[i] = blob[cpk.len + i]
      # Load server trust store of clients
      let trustDir = configDir() / "trust" / "clients"
      var clientOk = false
      if dirExists(trustDir):
        for f in walkDir(trustDir):
          if f.kind == pcFile and f.path.toLowerAscii().endsWith(".pk"):
            let pkb = readAllBytes(f.path)
            if pkb.len == cpk.len:
              var tpk: PublicKey
              for i in 0 ..< tpk.len: tpk[i] = pkb[i]
              # Compare
              var same = true
              for i in 0 ..< tpk.len:
                if tpk[i] != cpk[i]: same = false
              if same: clientOk = true
      # Verify signature on transcript
      clientOk = clientOk and verifyDetached(sig, transcript, cpk)
      if not clientOk: raise newHandshakeError(ecAuth, "client auth failed")
    return sess
  except HandshakeError as e:
    # Return only an error code byte to client
    try:
      await sendBlob(sock, 0x06'u8, @[toByte(e.code)])
    except CatchableError:
      discard
    raise e
  except CatchableError as e:
    try:
      await sendBlob(sock, 0x06'u8, @[toByte(ecUnknown)])
    except CatchableError:
      discard
    raise e
