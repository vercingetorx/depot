## Encrypted record channel: framing, encryption, and I/O primitives.
import std/[asyncdispatch, asyncnet, logging, os]
import aead
import common
import varint

type
  ## Session-wide transfer statistics (client-maintained; zero-initialized).
  SessionStats* = object
    sentFiles*: int
    sentBytes*: int64
    recvFiles*: int
    recvBytes*: int64
    skipped*: int
    failed*: int

  ## Encrypted record channel with keys, nonces, and sequence counters.
  Session* = ref object
    sock*: AsyncSocket
    # Traffic keys
    kTx*: array[32, byte]
    kRx*: array[32, byte]
    # Nonce prefixes (16 bytes)
    pTx*: array[16, byte]
    pRx*: array[16, byte]
    # Sequence counters
    seqTx*: uint64
    seqRx*: uint64
    # Negotiated features
    dlAck*: bool
    # Connection I/O timeout (ms) for reads in server loop
    ioTimeoutMs*: int
    # Server properties advertised during handshake
    srvSandboxed*: bool
    # Rekeying state
    trafficSecret*: array[32, byte]
    epoch*: uint32
    rekeyIntervalMs*: int
    lastRekeyMs*: int64
    pendingEpoch*: uint32
    pendingKTx*: array[32, byte]
    pendingKRx*: array[32, byte]
    pendingPTx*: array[16, byte]
    pendingPRx*: array[16, byte]
    # Client-side session statistics (unused on server)
    stats*: SessionStats

type
  SocketClosedError = object of CatchableError
  RecordFormatError = object of CatchableError

proc recvExact(s: Session, n: int): Future[seq[byte]] {.async.} =
  ## Read exactly n bytes or raise SocketClosedError if peer closes.
  var buf = newSeq[byte](n)
  var got = 0
  while got < n:
    let m = await s.sock.recvInto(addr buf[got], n - got)
    if m == 0:
      raise newException(SocketClosedError, "peer closed while reading body")
    got += m
  return buf

proc readVarint(s: Session): Future[uint64] {.async.} =
  ## Read a varint from the socket or raise on close/format error.
  var varintBuf: seq[byte]
  var oneByte: array[1, byte]
  while true:
    let n = await s.sock.recvInto(addr oneByte[0], 1)
    if n == 0:
      raise newException(SocketClosedError, "peer closed while reading varint")
    varintBuf.add(oneByte[0])
    try:
      let (value, next) = getUvar(varintBuf)
      if next == varintBuf.len:
        return value
    except VarintError:
      if varintBuf.len > 10:
        raise newException(RecordFormatError, "invalid varint length header")

proc buildNonce(prefix: array[16, byte], seq: uint64): AeadNonce24 {.inline.} =
  ## Construct a 24-byte nonce as prefix||seq (little-endian).
  for i in 0 ..< 16: result[i] = prefix[i]
  var s = seq
  for i in 0 ..< 8:
    result[16 + i] = byte((s shr (8*i)) and 0xff'u64)

proc sendRecord*(s: Session, rtype: uint8, payload: seq[byte]) {.async.} =
  ## Encrypt and send a single record as a single write:
  ## varint(len) | type | ciphertext | tag
  # Phase: build associated data (type + tx sequence + epoch)
  var associatedData = newSeq[byte](1)
  associatedData[0] = byte(rtype)
  associatedData.add(putUvar(uint64(s.seqTx)))
  associatedData.add(putUvar(uint64(s.epoch)))
  # Phase: seal payload
  let nonce = buildNonce(s.pTx, s.seqTx)
  let (ciphertext, tag) = aeadEncrypt(s.kTx, nonce, payload, associatedData)
  # Phase: build full frame buffer (varint length prefix + body)
  let bodyLen = 1 + ciphertext.len + tag.len
  let hdr = putUvar(uint64(bodyLen))
  let frameLen = hdr.len + bodyLen
  var frame = newString(frameLen)
  var idx = 0
  if hdr.len > 0:
    copyMem(addr frame[0], unsafeAddr hdr[0], hdr.len)
    idx = hdr.len
  frame[idx] = char(rtype)
  inc idx
  if ciphertext.len > 0:
    copyMem(addr frame[idx], unsafeAddr ciphertext[0], ciphertext.len)
    idx += ciphertext.len
  # tag is 16 bytes
  copyMem(addr frame[idx], unsafeAddr tag[0], tag.len)
  # Phase: single send
  await s.sock.send(frame)
  inc s.seqTx

proc sendRecord*(s: Session, rtype: uint8, payload: openArray[byte]): Future[void] =
  return sendRecord(s, rtype, bytesCopy(payload))

proc recvRecord*(s: Session): Future[(uint8, seq[byte])] {.async.} =
  ## Read and decrypt a single record from the session.
  ## Frame: varint(len) | type(1) | ciphertext | tag(16).
  ## AEAD associated data binds (type, seqRx, epoch). seqRx advances on success.
  try:
    # Phase: parse length prefix
    let recLenU = await s.readVarint()
    let recLen = int(recLenU)
    if recLen < 17:
      error "recvRecord: invalid record length ", recLen
      return (0'u8, @[])
    # Phase: read body into buffer
    let body = await s.recvExact(recLen)
    # Phase: split fields (type | ciphertext | tag)
    let rtype = body[0]
    let tagStart = recLen - 16
    let ciphertext = body[1 ..< tagStart]
    var tag: array[16, byte]
    for i in 0 ..< 16: tag[i] = body[tagStart + i]
    # Phase: open and authenticate
    var associatedData = newSeq[byte](1)
    associatedData[0] = byte(rtype)
    associatedData.add(putUvar(uint64(s.seqRx)))
    associatedData.add(putUvar(uint64(s.epoch)))
    let nonce = buildNonce(s.pRx, s.seqRx)
    let (authOk, plaintext) = aeadDecrypt(s.kRx, nonce, ciphertext, associatedData, tag)
    if not authOk:
      error "recvRecord: AEAD authentication failed (type=", rtype, ", seq=", s.seqRx, ")"
      return (0'u8, @[])
    # Phase: advance sequence and return
    inc s.seqRx
    return (rtype, plaintext)
  except SocketClosedError:
    debug "recvRecord: peer closed"
    return (0'u8, @[])
  except RecordFormatError as e:
    error "recvRecord: ", e.msg
    return (0'u8, @[])

proc encodePathOpen*(relativePath: string, fileSize: int64, modificationTimeUnix: int64, permissions: set[FilePermission]): seq[byte] =
  ## Encode PathOpen payload for a single file announcement on the stream:
  ## varint(pathLen) | path | varint(fileSize) | varint(mtimeUnix) | varint(count) | ordinals[count]
  var buf = putUvar(uint64(relativePath.len))
  buf.add(toBytes(relativePath))
  buf.add(putUvar(uint64(fileSize)))
  buf.add(putUvar(uint64(modificationTimeUnix)))
  # encode permissions as a compact list of enum ordinals
  var ords: seq[byte]
  for fp in FilePermission:
    if fp in permissions:
      ords.add(byte(ord(fp)))
  buf.add(putUvar(uint64(ords.len)))
  if ords.len > 0:
    # Append raw ordinals after the count to avoid extra varints per bit
    buf.setLen(buf.len + ords.len)
    copyMem(addr buf[buf.high - ords.len + 1], unsafeAddr ords[0], ords.len)
  buf

proc parsePathOpen*(payload: openArray[byte]): tuple[relativePath: string, fileSize: int64, modificationTimeUnix: int64, permissions: set[FilePermission]] =
  ## Decode PathOpen payload (required metadata fields present):
  ## varint(pathLen) | path | varint(fileSize) | varint(mtimeUnix) | varint(count) | ordinals[count]
  var offset = 0
  let (pathLenU, nextOffset) = getUvar(payload, offset)
  let pathLen = int(pathLenU)
  offset = nextOffset
  if offset + pathLen > payload.len:
    return ("", -1, 0'i64, {})
  let relativePath = fromBytes(payload[offset ..< offset + pathLen])
  offset += pathLen
  let (fileSizeU, next2) =
    try:
      getUvar(payload, offset)
    except VarintError:
      return (relativePath, -1, 0'i64, {})
  offset = next2
  var mtime: int64 = 0
  try:
    let (mtU, n3) = getUvar(payload, offset)
    offset = n3
    let (cntU, n4) = getUvar(payload, offset)
    offset = n4
    mtime = int64(mtU)
    let cnt = int(cntU)
    var pset: set[FilePermission] = {}
    # read cnt ordinals as single bytes
    if offset + cnt <= payload.len:
      # Interpret each ordinal as a FilePermission member
      var i = 0
      while i < cnt:
        let ordv = int(payload[offset + i])
        for fp in FilePermission:
          if ord(fp) == ordv:
            pset.incl(fp)
            break
        inc i
      return (relativePath, int64(fileSizeU), mtime, pset)
    else:
      return (relativePath, int64(fileSizeU), mtime, {})
  except VarintError:
    return (relativePath, int64(fileSizeU), 0'i64, {})

proc encodePathParam*(path: string): seq[byte] =
  ## Encode a single path string as varint(len) | path bytes
  var buf = putUvar(uint64(path.len))
  buf.add(toBytes(path))
  buf

proc decodePathParam*(data: openArray[byte], offset: int = 0): tuple[path: string, next: int] =
  ## Decode varint(len) | path from data starting at offset.
  ## Returns (path, nextIndex). If invalid/truncated, returns next = -1.
  let (lenU, next1) =
    try:
      getUvar(data, offset)
    except VarintError:
      return ("", -1)
  let plen = int(lenU)
  if next1 + plen > data.len:
    return ("", -1)
  let p = fromBytes(data[next1 ..< next1 + plen])
  (p, next1 + plen)

proc encodeUploadOpen*(relativePath: string, modificationTimeUnix: int64, permissions: set[FilePermission]): seq[byte] =
  ## Encode UploadOpen payload:
  ## varint(pathLen) | path | varint(mtimeUnix) | varint(count) | ordinals[count]
  var buf = putUvar(uint64(relativePath.len))
  buf.add(toBytes(relativePath))
  buf.add(putUvar(uint64(modificationTimeUnix)))
  var ords: seq[byte]
  for fp in FilePermission:
    if fp in permissions:
      ords.add(byte(ord(fp)))
  buf.add(putUvar(uint64(ords.len)))
  if ords.len > 0:
    buf.setLen(buf.len + ords.len)
    copyMem(addr buf[buf.high - ords.len + 1], unsafeAddr ords[0], ords.len)
  buf

proc parseUploadOpen*(payload: openArray[byte]): tuple[relativePath: string, modificationTimeUnix: int64, permissions: set[FilePermission]] =
  ## Decode UploadOpen payload (required metadata):
  ## varint(pathLen) | path | varint(mtimeUnix) | varint(count) | ordinals[count]
  var off = 0
  let (plenU, next1) = getUvar(payload, off)
  let plen = int(plenU)
  off = next1
  if off + plen > payload.len:
    return ("", 0'i64, {})
  let relativePath = fromBytes(payload[off ..< off + plen])
  off += plen
  let (mtU, next2) = getUvar(payload, off)
  off = next2
  let (cntU, next3) = getUvar(payload, off)
  off = next3
  let cnt = int(cntU)
  var pset: set[FilePermission] = {}
  if off + cnt <= payload.len:
    var i = 0
    while i < cnt:
      let ordv = int(payload[off + i])
      for fp in FilePermission:
        if ord(fp) == ordv:
          pset.incl(fp)
          break
      inc i
  return (relativePath, int64(mtU), pset)

proc encodeListItem*(relativePath: string, fileSize: int64, kind: uint8): seq[byte] =
  ## Encode a directory listing entry:
  ## - varint(pathLen) | path | varint(fileSize) | kind (0=file, 1=dir).
  var b = putUvar(uint64(relativePath.len))
  b.add(toBytes(relativePath))
  b.add(putUvar(uint64(fileSize)))
  b.setLen(b.len + 1)
  b[b.high] = byte(kind)
  b

proc parseListChunk*(payload: openArray[byte]): seq[tuple[relativePath: string, fileSize: int64, kind: uint8]] =
  ## Parse a sequence of list items from a payload buffer. Returns a list
  ## of (relativePath, fileSize, kind), ignoring any trailing malformed item.
  var off = 0
  while off < payload.len:
    let (p, next1) = decodePathParam(payload, off)
    if next1 < 0: break
    if next1 >= payload.len: break
    let (szU, next2) =
      try:
        getUvar(payload, next1)
      except VarintError:
        break
    if next2 >= payload.len: break
    let k = payload[next2]
    # kind=1 means directory (size ignored); kind=0 means file (size meaningful)
    off = next2 + 1
    result.add((p, int64(szU), k))
