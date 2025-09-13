## Server: accepts connections, enforces sandbox rules, streams data.
import std/[os, asyncnet, asyncdispatch, logging, strutils, sysrand, times, strformat]
when defined(posix): import posix
when defined(windows): import winlean
import errors
import common
import handshake
import paths
import protocol
import records
import ../private/blake2/blake2b

const bufSize = 1024 * 1024 # 1 MiB

var sandboxed*: bool = true
var allowOverwrite*: bool = false

proc newSessionId(): string =
  let b = urandom(8)
  for by in b:
    result.add(by.toHex(2))

proc ensureBaseDirs*(base: string): tuple[exportDir, importDir: string] =
  ## Ensure base/depot/{export,import} exist; return their absolute paths.
  ## Raises on failure to create.
  let depotRoot = base / "depot"
  let exportDir = depotRoot / "export"
  let importDir = depotRoot / "import"
  # Create parent chain proactively; treat failure as fatal
  createDir(exportDir)
  createDir(importDir)
  # BUG: existsOrCreateDir was creating exportDir/importDir but returning false
  # discard existsOrCreateDir(base)
  # discard existsOrCreateDir(depotRoot)
  # if existsOrCreateDir(exportDir) == false:
  #   raise newException(CatchableError, fmt"failed to create export directory: {exportDir}")
  # if existsOrCreateDir(importDir) == false:
  #   raise newException(CatchableError, fmt"failed to create import directory: {importDir}")
  return (exportDir, importDir)

## String/byte helpers moved to depot/common.nim

type ClientState = object
  sid: string
  sock: AsyncSocket
  session: Session
  baseDir: string
  exportDir: string
  importDir: string
  currentFile: File
  currentPath: string
  partialPath: string
  uploadHasher: Blake2bCtx
  pendingMtimeUnix: int64
  pendingPermissions: set[FilePermission]

proc infoSid(st: ClientState, msg: string) = info fmt"[{st.sid}] {msg}"
proc errorSid(st: ClientState, msg: string) = error fmt"[{st.sid}] {msg}"

proc sendErrorCode(st: var ClientState, ec: ErrorCode) {.async.} =
  ## Send an application ErrorRec with a single error code byte.
  await st.session.sendRecord(ErrorRec.uint8, @[toByte(ec)])

proc handleUploadOpen(st: var ClientState, payload: seq[byte]) {.async.} =
  # payload: encoded path + mtime + permissions
  let (relativeDestPath, srcMtimeUnix, srcPerms) = parseUploadOpen(payload)
  if relativeDestPath.len == 0:
    await st.session.sendRecord(UploadFail.uint8, @[toByte(ecBadPath)])
    return
  var destAbs: string
  if sandboxed:
    if relativeDestPath.len > 0 and relativeDestPath[0] == '/':
      errorSid(st, encodeServer(ecAbsolute, "client sent absolute path in sandbox mode: " & relativeDestPath))
      await st.session.sendRecord(UploadFail.uint8, @[toByte(ecAbsolute)])
      return
    try:
      destAbs = cleanJoin(st.importDir, relativeDestPath)
    except CatchableError:
      errorSid(st, encodeServer(ecUnsafePath, "client sent unsafe path: " & relativeDestPath))
      await st.session.sendRecord(UploadFail.uint8, @[toByte(ecUnsafePath)])
      return
  else:
    if relativeDestPath.len > 0 and relativeDestPath[0] == '/':
      destAbs = normalizedPath(relativeDestPath)
    else:
      destAbs = normalizedPath(st.importDir / relativeDestPath)
  st.currentPath = destAbs
  st.partialPath = common.partPath(st.currentPath)
  infoSid(st, fmt"upload start: {relativeDestPath}")
  st.uploadHasher = newBlake2bCtx(digestSize = 32)
  st.pendingMtimeUnix = srcMtimeUnix
  st.pendingPermissions = srcPerms
  # refuse early if destination already exists (unless server allows overwrite)
  if fileExists(st.currentPath) and not allowOverwrite:
    errorSid(st, encodeServer(ecExists, "destination file exists: " & st.currentPath))
    await st.session.sendRecord(UploadFail.uint8, @[toByte(ecExists)])
    return
  # ensure parent directories exist and aren't symlinks
  let parentDir = splitFile(st.currentPath).dir
  if parentDir.len > 0:
    discard existsOrCreateDir(parentDir)
    try:
      let info = getFileInfo(parentDir)
      if info.kind == pcLinkToDir:
        errorSid(st, encodeServer(ecUnsafePath, "parent directory is a symlink: " & parentDir))
        await st.session.sendRecord(UploadFail.uint8, @[toByte(ecUnsafePath)])
        return
    except OSError:
      discard
  try:
    st.currentFile = open(st.partialPath, fmWrite)
  except OSError as e:
    let ec = errors.osErrorToCode(e, ecOpenFail)
    errorSid(st, encodeServer(ec, "failed to open partial file for writing: " & st.partialPath & " " & e.msg))
    await st.session.sendRecord(UploadFail.uint8, @[toByte(ec)])
    return
  await st.session.sendRecord(UploadOk.uint8, newSeq[byte]())

proc handleUploadDataChunk(st: var ClientState, payload: seq[byte]) =
  if st.currentFile != nil:
    try:
      discard st.currentFile.writeBytes(payload, 0, payload.len)
      st.uploadHasher.update(payload)
    except OSError as e:
      let ec = errors.osErrorToCode(e, ecWriteFail)
      errorSid(st, encodeServer(ec, "failed to write to partial file: " & st.partialPath & " " & e.msg))
      try: st.currentFile.close() except: discard
      st.currentFile = nil
      discard tryRemoveFile(st.partialPath)
      asyncCheck st.session.sendRecord(ErrorRec.uint8, @[toByte(ec)])

proc handleUploadCommit(st: var ClientState, payload: seq[byte]) {.async.} =
  if st.currentFile != nil:
    st.currentFile.close()
    # verify checksum payload
    if payload.len != 32:
      errorSid(st, encodeServer(ecChecksum, "invalid checksum length: " & $payload.len))
      discard tryRemoveFile(st.partialPath)
      await sendErrorCode(st, ecChecksum)
      st.currentFile = nil
      st.currentPath = ""
      st.partialPath = ""
      return
    let got = st.uploadHasher.digest()
    var match = got.len == 32
    if match:
      for i in 0 ..< 32:
        if got[i] != payload[i]: match = false
    if not match:
      errorSid(st, encodeServer(ecChecksum, "checksum mismatch for " & st.currentPath))
      discard tryRemoveFile(st.partialPath)
      await sendErrorCode(st, ecChecksum)
      st.currentFile = nil
      st.currentPath = ""
      st.partialPath = ""
      return
    if fileExists(st.currentPath) and not allowOverwrite:
      errorSid(st, encodeServer(ecExists, "destination file exists and overwrite is disabled: " & st.currentPath))
      discard tryRemoveFile(st.partialPath)
      await sendErrorCode(st, ecExists)
    else:
      try:
        # moveFile overwrites on most platforms; if not, remove and move
        if fileExists(st.currentPath) and allowOverwrite:
          discard tryRemoveFile(st.currentPath)
        moveFile(st.partialPath, st.currentPath)
        # Apply metadata from client after moving into place
        try:
          setLastModificationTime(st.currentPath, fromUnix(st.pendingMtimeUnix))
        except CatchableError:
          discard
        try:
          setFilePermissions(st.currentPath, st.pendingPermissions)
        except CatchableError:
          discard
        infoSid(st, fmt"upload complete: {st.currentPath}")
        await st.session.sendRecord(UploadDone.uint8, newSeq[byte]())
      except OSError as e:
        let ec = errors.osErrorToCode(e, ecOpenFail)
        errorSid(st, encodeServer(ec, "failed to move partial file to destination: " & e.msg))
        discard tryRemoveFile(st.partialPath)
        await sendErrorCode(st, ec)
    st.currentFile = nil
    st.currentPath = ""
    st.partialPath = ""
    st.pendingMtimeUnix = 0
    st.pendingPermissions = {}

proc streamFileIfAccepted(st: var ClientState, relativePath: string) {.async.} =
  # Opportunistic time-based rekey at file boundary
  if (common.monoMs() - st.session.lastRekeyMs) > st.session.rekeyIntervalMs and
      st.session.pendingEpoch == 0'u32:
    var epochBytes: array[4, byte]
    let newEpoch = st.session.epoch + 1'u32
    epochBytes[0] = byte(newEpoch and 0xff)
    epochBytes[1] = byte((newEpoch shr 8) and 0xff)
    epochBytes[2] = byte((newEpoch shr 16) and 0xff)
    epochBytes[3] = byte((newEpoch shr 24) and 0xff)
    # derive pending keys for server (Rx=c2s, Tx=s2c)
    let (out1, out2) = handshake.deriveRekey(st.session.trafficSecret, epochBytes)
    for i in 0 ..< 32: st.session.pendingKRx[i] = out1[i]
    for i in 0 ..< 16: st.session.pendingPRx[i] = out1[32 + i]
    for i in 0 ..< 32: st.session.pendingKTx[i] = out2[i]
    for i in 0 ..< 16: st.session.pendingPTx[i] = out2[32 + i]
    st.session.pendingEpoch = newEpoch
    infoSid(st, fmt"rekey propose: epoch={newEpoch}")
    await st.session.sendRecord(RekeyReq.uint8, epochBytes)
    # derive pending keys and apply after sending ack (handled in dispatch loop)
  # Send path + size + metadata in PathOpen payload
  var absPath: string
  if sandboxed:
    absPath = cleanJoin(st.exportDir, relativePath)
  else:
    if relativePath.len > 0 and relativePath[0] == '/':
      absPath = normalizedPath(relativePath)
    else:
      absPath = normalizedPath(st.exportDir / relativePath)
  if not isSafeFile(absPath):
    errorSid(st, encodeServer(ecUnsafePath, "unsafe file path detected: " & absPath))
    await st.session.sendRecord(ErrorRec.uint8, @[toByte(ecUnsafePath)])
    return
  let fileSize = getFileSize(absPath)
  # Collect metadata for preservation on client
  let mtimeUnix: int64 = int64(getLastModificationTime(absPath).toUnix())
  let permissionSet = getFilePermissions(absPath)
  let payload = protocol.encodePathOpen(relativePath, int64(fileSize),
      mtimeUnix, permissionSet)
  await st.session.sendRecord(PathOpen.uint8, payload)
  # Wait for client ack if negotiated
  if st.session.dlAck:
    let (atk, apl) = await st.session.recvRecord()
    if atk == PathSkip.uint8:
      # Expect 1-byte reason code
      var codeName = reasonUnknown
      if apl.len == 1:
        case apl[0]
        of byte(SkipReason.srExists): codeName = reasonExists
        of byte(SkipReason.srFilter): codeName = reasonFilter
        of byte(SkipReason.srAbsolute): codeName = reasonAbsolute
        of byte(SkipReason.srUnsafePath): codeName = reasonUnsafePath
        of byte(SkipReason.srBadPayload): codeName = reasonBadPayload
        of byte(SkipReason.srPerms): codeName = reasonPerms
        of byte(SkipReason.srNoSpace): codeName = reasonNoSpace
        of byte(SkipReason.srTimeout): codeName = reasonTimeout
        else: codeName = reasonUnknown
      else:
        codeName = reasonUnknown
      # Suppress logs for list operations (handled via List* records now)
      if codeName != reasonFilter:
        infoSid(st, fmt"client skipped: {relativePath} (reason: {codeName})")
      return
    elif atk == 0'u8:
      # Unexpected/empty ack; do not fail silently. Log and treat as skip.
      infoSid(st, "unexpected ack, treating as skip: type=0")
      return
    elif atk != PathAccept.uint8:
      var codeName = reasonUnknown
      if apl.len == 1:
        case apl[0]
        of byte(SkipReason.srExists): codeName = reasonExists
        of byte(SkipReason.srFilter): codeName = reasonFilter
        of byte(SkipReason.srAbsolute): codeName = reasonAbsolute
        of byte(SkipReason.srUnsafePath): codeName = reasonUnsafePath
        of byte(SkipReason.srBadPayload): codeName = reasonBadPayload
        of byte(SkipReason.srPerms): codeName = reasonPerms
        of byte(SkipReason.srNoSpace): codeName = reasonNoSpace
        of byte(SkipReason.srTimeout): codeName = reasonTimeout
        else: discard
      if codeName != reasonFilter:
        infoSid(st, fmt"unexpected ack, treating as skip: type={atk}, reason: {codeName}")
      return
  # Only announce send after explicit accept
  infoSid(st, fmt"send file: {relativePath} ({fileSize} bytes)")
  try:
    var f = open(absPath, fmRead)
    defer: f.close()
    # Hasher to compute and send checksum for integrity verification
    var fileSendHasher = newBlake2bCtx(digestSize = 32)
    var buf = newSeq[byte](bufSize)
    while true:
      let n = f.readBytes(buf, 0, buf.len)
      if n <= 0: break
      fileSendHasher.update(buf.toOpenArray(0, n-1))
      await st.session.sendRecord(FileData.uint8, buf.toOpenArray(0, n-1))
    let dig = fileSendHasher.digest()
    await st.session.sendRecord(FileClose.uint8, dig)
    infoSid(st, fmt"send complete: {relativePath}")
  except OSError as e:
    let ec = errors.osErrorToCode(e, ecReadFail)
    errorSid(st, encodeServer(ec, "failed to read from file: " & absPath & " " & e.msg))
    await st.session.sendRecord(ErrorRec.uint8, @[toByte(ec)])

proc handleDownloadRequest(st: var ClientState, payload: seq[byte]) {.async.} =
  # payload: varint path len | path bytes
  let (relReqFull, nextIdx) = decodePathParam(payload)
  if nextIdx < 0:
    await st.session.sendRecord(ErrorRec.uint8, @[toByte(ecBadPayload)]); return
  if relReqFull.len == 0:
    await st.session.sendRecord(ErrorRec.uint8, @[toByte(ecBadPath)]); return
  var absReq: string
  if sandboxed:
    if relReqFull.len > 0 and relReqFull[0] == '/':
      errorSid(st, encodeServer(ecAbsolute, "client sent absolute path in sandbox mode: " & relReqFull))
      await st.session.sendRecord(ErrorRec.uint8, @[toByte(ecAbsolute)])
      return
    try:
      absReq = cleanJoin(st.exportDir, relReqFull)
    except CatchableError:
      errorSid(st, encodeServer(ecUnsafePath, "client sent unsafe path: " & relReqFull))
      await st.session.sendRecord(ErrorRec.uint8, @[toByte(ecUnsafePath)])
      return
  else:
    if relReqFull.len > 0 and relReqFull[0] == '/':
      absReq = normalizedPath(relReqFull)
    else:
      absReq = normalizedPath(st.exportDir / relReqFull)

  if fileExists(absReq):
    infoSid(st, fmt"download request: {relReqFull}")
    let relativePath = if absReq.isRelativeTo(st.exportDir): absReq.relativePath(
        st.exportDir).replace(DirSep, '/') else: relReqFull
    await streamFileIfAccepted(st, relativePath)
    await st.session.sendRecord(DownloadDone.uint8, newSeq[byte]())
  elif dirExists(absReq):
    infoSid(st, fmt"download request (dir): {relReqFull}")
    let base = absReq
    var count = 0
    for p in walkDirRec(base):
      if dirExists(p): continue
      # Compute relative path to the requested base dir (not exportRoot),
      # falling back to relReqFull when not under exportDir.
      let relativePath = p.relativePath(base).replace(DirSep, '/')
      await streamFileIfAccepted(st, relativePath)
      inc count
    await st.session.sendRecord(DownloadDone.uint8, newSeq[byte]())
    infoSid(st, fmt"download directory complete: {relReqFull} ({count} files)")
  else:
    errorSid(st, encodeServer(ecNotFound, "requested path not found: " & absReq))
    await st.session.sendRecord(ErrorRec.uint8, @[toByte(ecNotFound)])

proc handleListRequest(st: var ClientState, payload: seq[byte]) {.async.} =
  # payload: varint path len | path bytes (relative in sandbox)
  let (relReqFull, nextIdx) = decodePathParam(payload)
  if nextIdx < 0:
    await st.session.sendRecord(ErrorRec.uint8, @[toByte(ecBadPayload)]); return
  if relReqFull.len == 0:
    await st.session.sendRecord(ErrorRec.uint8, @[toByte(ecBadPath)]); return
  var absReq: string
  if sandboxed:
    if relReqFull.len > 0 and relReqFull[0] == '/':
      errorSid(st, encodeServer(ecAbsolute, "client sent absolute path in sandbox mode: " & relReqFull))
      await st.session.sendRecord(ErrorRec.uint8, @[toByte(ecAbsolute)])
      return
    try:
      absReq = cleanJoin(st.exportDir, relReqFull)
    except CatchableError:
      errorSid(st, encodeServer(ecUnsafePath, "client sent unsafe path: " & relReqFull))
      await st.session.sendRecord(ErrorRec.uint8, @[toByte(ecUnsafePath)])
      return
  else:
    if relReqFull.len > 0 and relReqFull[0] == '/':
      absReq = normalizedPath(relReqFull)
    else:
      absReq = normalizedPath(st.exportDir / relReqFull)
  if fileExists(absReq):
    let relativePath = if absReq.isRelativeTo(st.exportDir): absReq.relativePath(
        st.exportDir).replace(DirSep, '/') else: relReqFull
    let size = getFileSize(absReq)
    var buf = newSeq[byte]()
    let item = protocol.encodeListItem(relativePath, int64(size), 0'u8)
    buf.add(item)
    await st.session.sendRecord(ListChunk.uint8, buf)
    await st.session.sendRecord(ListDone.uint8, newSeq[byte]())
    infoSid(st, fmt"list file: {relReqFull}")
  elif dirExists(absReq):
    infoSid(st, fmt"list dir: {relReqFull}")
    var chunk = newSeq[byte]()
    var count = 0
    for it in walkDir(absReq):
      let p = it.path
      let isDir = (it.kind == pcDir)
      if isDir:
        let relativePath = p.relativePath(absReq).replace(DirSep, '/')
        let item = protocol.encodeListItem(relativePath, 0'i64, 1'u8)
        if chunk.len + item.len > 64*1024:
          await st.session.sendRecord(ListChunk.uint8, chunk)
          chunk.setLen(0)
        chunk.add(item)
        inc count
      else:
        let relativePath = p.relativePath(absReq).replace(DirSep, '/')
        let size = getFileSize(p)
        let item = protocol.encodeListItem(relativePath, int64(size), 0'u8)
        if chunk.len + item.len > 64*1024:
          await st.session.sendRecord(ListChunk.uint8, chunk)
          chunk.setLen(0)
        chunk.add(item)
        inc count
    if chunk.len > 0:
      await st.session.sendRecord(ListChunk.uint8, chunk)
    await st.session.sendRecord(ListDone.uint8, newSeq[byte]())
    infoSid(st, fmt"list complete: {relReqFull} ({count} entries)")
  else:
    errorSid(st, encodeServer(ecNotFound, "requested path not found: " & absReq))
    await st.session.sendRecord(ErrorRec.uint8, @[toByte(ecNotFound)])

proc handleClient*(sock: AsyncSocket, baseDir: string) {.async.} =
  ## Handle a single client session: perform handshake, then process
  ## upload/download records until the socket closes.
  var st: ClientState
  st.sid = newSessionId()
  st.sock = sock
  st.baseDir = baseDir

  infoSid(st, fmt"client connected: {getPeerAddr(sock)}")
  # Perform handshake; if it fails, log and close this client without
  # impacting the main accept loop.
  try:
    st.session = await serverHandshake(sock, sandboxed)
  except CatchableError as e:
    errorSid(st, e.msg)
    try: sock.close() except: discard
    infoSid(st, "client disconnected")
    return
  infoSid(st, "handshake complete")
  (st.exportDir, st.importDir) = ensureBaseDirs(baseDir)

  try:
    # Phase: record dispatch loop
    while true:
      # Apply a per-connection read timeout to avoid hangs
      let fut = st.session.recvRecord()
      # withTimeout returns true if the future completed before the timeout,
      # and false if it timed out. Treat false as a timeout condition.
      if not await withTimeout(fut, st.session.ioTimeoutMs):
        await st.session.sendRecord(ErrorRec.uint8, @[toByte(ecTimeout)])
        infoSid(st, "session timeout; closing connection")
        break
      let (t, payload) = await fut
      if payload.len == 0 and t == 0'u8:
        break
      case t
      of uint8(UploadOpen):
        await handleUploadOpen(st, payload)
      of uint8(FileData):
        handleUploadDataChunk(st, payload)
      of uint8(FileClose):
        await handleUploadCommit(st, payload)
      of uint8(DownloadOpen):
        await handleDownloadRequest(st, payload)
      of uint8(ListOpen):
        await handleListRequest(st, payload)
      of uint8(ErrorRec):
        if payload.len == 1:
          let ec = fromByte(payload[0])
          errorSid(st, encodeServer(ec))
        else:
          errorSid(st, encodeServer(ecUnknown, "client sent invalid error record"))
      else:
        discard
  except CatchableError as e:
    errorSid(st, fmt"session error: {e.msg}")
  except OSError as e:
    errorSid(st, fmt"session I/O error: {e.msg}")
  finally:
    # Phase: cleanup
    if st.currentFile != nil:
      st.currentFile.close()
      discard tryRemoveFile(st.partialPath) # cleanup partial on abrupt end
    sock.close()
    infoSid(st, "client disconnected")

proc serve*(listen: string, port: int, baseDir: string) {.async.} =
  ## Accept loop: binds and accepts clients, spawning handleClient for each.
  let srv = newAsyncSocket()
  srv.setSockOpt(OptReuseAddr, true)
  srv.bindAddr(Port(port), listen)
  srv.listen()
  while true:
    let c = await srv.accept()
    asyncCheck handleClient(c, baseDir)
