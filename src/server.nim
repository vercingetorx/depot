## Server: accepts connections, enforces sandbox rules, streams data.
import std/[os, asyncnet, asyncdispatch, logging, strutils, sysrand, times]
when defined(posix): import posix
when defined(windows): import winlean
import common
import errors
import handshake
import paths
import progress
import protocol
import records
import userconfig
import ../private/blake2/blake2b

const bufSize = 1024 * 1024  # 1 MiB

var sandboxed*: bool = true
var allowOverwrite*: bool = false
var overrideExportRoot*: string
var overrideImportRoot*: string

proc newSessionId(): string =
  let b = urandom(8)
  for by in b:
    result.add(by.toHex(2))

proc ensureBaseDirs*(base: string): tuple[exportDir, importDir: string] =
  let cfg = readConfig()
  var exportDir: string
  var importDir: string
  if overrideExportRoot.len > 0:
    exportDir = overrideExportRoot
  elif cfg.server.exportRoot.len > 0:
    exportDir = cfg.server.exportRoot
  else:
    exportDir = base / "depot" / "export"
  if overrideImportRoot.len > 0:
    importDir = overrideImportRoot
  elif cfg.server.importRoot.len > 0:
    importDir = cfg.server.importRoot
  else:
    importDir = base / "depot" / "import"
  discard existsOrCreateDir(exportDir)
  discard existsOrCreateDir(importDir)
  (exportDir, importDir)

## String/byte helpers moved to depot/common.nim

proc handleClient*(sock: AsyncSocket, baseDir: string) {.async.} =
  ## Handle a single client session: perform handshake, then process
  ## upload/download records until the socket closes.
  # Phase: handshake + session setup
  let sid = newSessionId()
  proc infoSid(msg: string) = info "[" & sid & "] " & msg
  proc errorSid(msg: string) = error "[" & sid & "] " & msg

  infoSid("client connected: " & $getPeerAddr(sock))
  # Perform handshake; if it fails, log and close this client without
  # impacting the main accept loop.
  var session: Session
  try:
    session = await serverHandshake(sock, sandboxed)
  except CatchableError as e:
    # Convert client-coded handshake message to server-coded log line
    let (codeStr, _) = errors.splitReason(e.msg)
    var ec = ecUnknown
    if codeStr.len > 0:
      case codeStr
      of reasonBadPayload: ec = ecBadPayload
      of reasonCompat: ec = ecCompat
      of reasonAuth: ec = ecAuth
      of reasonConfig: ec = ecConfig
      of reasonTimeout: ec = ecTimeout
      of reasonNotFound: ec = ecNotFound
      of reasonPerms: ec = ecPerms
      of reasonNoSpace: ec = ecNoSpace
      else: ec = ecUnknown
    errorSid(errors.encodeServer(ec))
    try: sock.close() except: discard
    infoSid("client disconnected")
    return
  infoSid("handshake complete")
  let (exportDir, importDir) = ensureBaseDirs(baseDir)
  # Phase: mutable transfer state (per-connection)
  var currentFile: File
  var currentPath: string
  var partialPath: string
  # Hasher for verifying integrity of uploaded file data
  var uploadHasher: Blake2bCtx
  # Metadata received from client for the current upload (applied on commit)
  var pendingMtimeUnix: int64
  var pendingPermissions: set[FilePermission]
  
  # Phase: message handlers (small, focused)
  proc chooseCode(e: ref OSError, fallback: ErrorCode): ErrorCode =
    when defined(posix):
      let c = cint(e.errorCode)
      if c == ENOSPC: return ecNoSpace
      if c == EACCES or c == EPERM: return ecPerms
    elif defined(windows):
      let c = int32(e.errorCode)
      if c == ERROR_DISK_FULL.int32 or c == ERROR_HANDLE_DISK_FULL.int32: return ecNoSpace
      if c == ERROR_ACCESS_DENIED.int32 or c == ERROR_WRITE_PROTECT.int32 or c == ERROR_SHARING_VIOLATION.int32: return ecPerms
    return fallback
  proc sendErrorCode(ec: ErrorCode) {.async.} =
    ## Send an application ErrorRec with a single error code byte.
    await session.sendRecord(ErrorRec.uint8, @[toByte(ec)])

  ## Begin an upload session for a single file. Validates path against
  ## sandbox rules, creates the parent directory, opens a .part file,
  ## and replies UploadOk or UploadFail with a reason.
  proc handleUploadOpen(payload: seq[byte]) {.async.} =
    # payload: encoded path + mtime + permissions
    let (relativeDestPath, srcMtimeUnix, srcPerms) = parseUploadOpen(payload)
    if relativeDestPath.len == 0:
      await session.sendRecord(UploadFail.uint8, @[toByte(ecBadPath)])
      return
    var destAbs: string
    if sandboxed:
      if relativeDestPath.len > 0 and relativeDestPath[0] == '/':
        errorSid(errors.encodeServer(ecAbsolute))
        await session.sendRecord(UploadFail.uint8, @[toByte(ecAbsolute)])
        return
      try:
        destAbs = cleanJoin(importDir, relativeDestPath)
      except CatchableError:
        errorSid(errors.encodeServer(ecUnsafePath))
        await session.sendRecord(UploadFail.uint8, @[toByte(ecUnsafePath)])
        return
    else:
      if relativeDestPath.len > 0 and relativeDestPath[0] == '/':
        destAbs = normalizedPath(relativeDestPath)
      else:
        destAbs = normalizedPath(importDir / relativeDestPath)
    currentPath = destAbs
    partialPath = currentPath & ".part"
    infoSid("upload start: " & relativeDestPath)
    uploadHasher = newBlake2bCtx(digestSize=32)
    pendingMtimeUnix = srcMtimeUnix
    pendingPermissions = srcPerms
    # refuse early if destination already exists (unless server allows overwrite)
    if fileExists(currentPath) and not allowOverwrite:
      errorSid(errors.encodeServer(ecExists))
      await session.sendRecord(UploadFail.uint8, @[toByte(ecExists)])
      return
    # ensure parent directories exist and aren't symlinks
    let parentDir = splitFile(currentPath).dir
    if parentDir.len > 0:
      discard existsOrCreateDir(parentDir)
      try:
        let info = getFileInfo(parentDir)
        if info.kind == pcLinkToDir:
          errorSid(errors.encodeServer(ecUnsafePath))
          await session.sendRecord(UploadFail.uint8, @[toByte(ecUnsafePath)])
          return
      except OSError:
        discard
    try:
      currentFile = open(partialPath, fmWrite)
    except OSError as e:
      let ec = chooseCode(e, ecOpenFail)
      errorSid(errors.encodeServer(ec))
      await session.sendRecord(UploadFail.uint8, @[toByte(ec)])
      return
    await session.sendRecord(UploadOk.uint8, newSeq[byte]())

  ## Handle a file data chunk for the current upload. Appends to the
  ## .part file and maps write failures to precise reasons.
  proc handleUploadDataChunk(payload: seq[byte]) =
    if currentFile != nil:
      try:
        discard currentFile.writeBuffer(unsafeAddr payload[0], payload.len)
        uploadHasher.update(payload)
      except OSError as e:
        let ec = chooseCode(e, ecOpenFail)
        errorSid(errors.encodeServer(ec))
        try: currentFile.close() except: discard
        currentFile = nil
        discard tryRemoveFile(partialPath)
        asyncCheck session.sendRecord(ErrorRec.uint8, @[toByte(ec)])

  ## Finalize the current upload: close the .part, atomically move into
  ## place (if not overwriting), and reply UploadDone or ErrorRec.
  proc handleUploadCommit(payload: seq[byte]) {.async.} =
    if currentFile != nil:
      currentFile.close()
      # verify checksum payload
      if payload.len != 32:
        errorSid(errors.encodeServer(ecChecksum))
        discard tryRemoveFile(partialPath)
        await sendErrorCode(ecChecksum)
        currentFile = nil
        currentPath = ""
        partialPath = ""
        return
      let got = uploadHasher.digest()
      var match = got.len == 32
      if match:
        for i in 0 ..< 32:
          if got[i] != payload[i]: match = false
      if not match:
        errorSid(errors.encodeServer(ecChecksum))
        discard tryRemoveFile(partialPath)
        await sendErrorCode(ecChecksum)
        currentFile = nil
        currentPath = ""
        partialPath = ""
        return
      if fileExists(currentPath) and not allowOverwrite:
        errorSid(errors.encodeServer(ecExists))
        discard tryRemoveFile(partialPath)
        await sendErrorCode(ecExists)
      else:
        try:
          # moveFile overwrites on most platforms; if not, remove and move
          if fileExists(currentPath) and allowOverwrite:
            discard tryRemoveFile(currentPath)
          moveFile(partialPath, currentPath)
          # Apply metadata from client after moving into place
          try:
            setLastModificationTime(currentPath, fromUnix(pendingMtimeUnix))
          except CatchableError:
            discard
          try:
            setFilePermissions(currentPath, pendingPermissions)
          except CatchableError:
            discard
          infoSid("upload complete: " & currentPath)
          await session.sendRecord(UploadDone.uint8, newSeq[byte]())
        except OSError as e:
          let ec = chooseCode(e, ecOpenFail)
          errorSid(errors.encodeServer(ec))
          discard tryRemoveFile(partialPath)
          await sendErrorCode(ec)
      currentFile = nil
      currentPath = ""
      partialPath = ""
      pendingMtimeUnix = 0
      pendingPermissions = {}

  ## Handle a client download request: for a file, send PathOpen + stream
  ## after client PathAccept; for a directory, iterate children and stream
  ## each accepted file. Ends with DownloadDone.
  proc handleDownloadRequest(payload: seq[byte]) {.async.} =
    # payload: varint path len | path bytes
    let (relReqFull, nextIdx) = decodePathParam(payload)
    if nextIdx < 0:
      await session.sendRecord(ErrorRec.uint8, @[toByte(ecBadPayload)]); return
    if relReqFull.len == 0:
      await session.sendRecord(ErrorRec.uint8, @[toByte(ecBadPath)]); return
    var absReq: string
    if sandboxed:
      if relReqFull.len > 0 and relReqFull[0] == '/':
        errorSid(errors.encodeServer(ecAbsolute))
        await session.sendRecord(ErrorRec.uint8, @[toByte(ecAbsolute)])
        return
      try:
        absReq = cleanJoin(exportDir, relReqFull)
      except CatchableError:
        errorSid(errors.encodeServer(ecUnsafePath))
        await session.sendRecord(ErrorRec.uint8, @[toByte(ecUnsafePath)])
        return
    else:
      if relReqFull.len > 0 and relReqFull[0] == '/':
        absReq = normalizedPath(relReqFull)
      else:
        absReq = normalizedPath(exportDir / relReqFull)
    
    ## Send a single file to the client. Sends PathOpen with path/size,
    ## waits for PathAccept/PathSkip, then streams FileData + FileClose
    ## on accept. Logs send start/complete lines.
    proc streamFileIfAccepted(relativePath: string) {.async.} =
      # Opportunistic time-based rekey at file boundary
      if (nowMs() - session.lastRekeyMs) > session.rekeyIntervalMs and session.pendingEpoch == 0'u32:
        var epochBytes: array[4, byte]
        let newEpoch = session.epoch + 1'u32
        epochBytes[0] = byte(newEpoch and 0xff)
        epochBytes[1] = byte((newEpoch shr 8) and 0xff)
        epochBytes[2] = byte((newEpoch shr 16) and 0xff)
        epochBytes[3] = byte((newEpoch shr 24) and 0xff)
        # derive pending keys for server (Rx=c2s, Tx=s2c)
        var ctx1 = newBlake2bCtx(digestSize=48)
        ctx1.update(session.trafficSecret); ctx1.update("c2s"); ctx1.update(epochBytes)
        let out1 = ctx1.digest()
        var ctx2 = newBlake2bCtx(digestSize=48)
        ctx2.update(session.trafficSecret); ctx2.update("s2c"); ctx2.update(epochBytes)
        let out2 = ctx2.digest()
        for i in 0 ..< 32: session.pendingKRx[i] = out1[i]
        for i in 0 ..< 16: session.pendingPRx[i] = out1[32 + i]
        for i in 0 ..< 32: session.pendingKTx[i] = out2[i]
        for i in 0 ..< 16: session.pendingPTx[i] = out2[32 + i]
        session.pendingEpoch = newEpoch
        infoSid("rekey propose: epoch=" & $newEpoch)
        await session.sendRecord(RekeyReq.uint8, epochBytes)
        # derive pending keys and apply after sending ack (handled in dispatch loop)
      # Send path + size + metadata in PathOpen payload
      let absPath = cleanJoin(exportDir, relativePath)
      if not isSafeFile(absPath):
        errorSid(errors.encodeServer(ecUnsafePath))
        await session.sendRecord(ErrorRec.uint8, @[toByte(ecUnsafePath)])
        return
      let fileSize = getFileSize(absPath)
      # Collect metadata for preservation on client
      let mtimeUnix: int64 = int64(getLastModificationTime(absPath).toUnix())
      let permissionSet = getFilePermissions(absPath)
      let payload = protocol.encodePathOpen(relativePath, int64(fileSize), mtimeUnix, permissionSet)
      await session.sendRecord(PathOpen.uint8, payload)
      # Wait for client ack if negotiated
      if session.dlAck:
        let (atk, apl) = await session.recvRecord()
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
            infoSid("client skipped: " & relativePath & " (reason: " & codeName & ")")
          return
        elif atk == 0'u8:
          # Unexpected/empty ack; do not fail silently. Log and treat as skip.
          infoSid("unexpected ack, treating as skip: type=0")
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
            infoSid("unexpected ack, treating as skip: type=" & $atk & ", reason: " & codeName & ")")
          return
      # Only announce send after explicit accept
      infoSid("send file: " & relativePath & " (" & $fileSize & " bytes)")
      try:
        var f = open(absPath, fmRead)
        # Hasher to compute and send checksum for integrity verification
        var fileSendHasher = newBlake2bCtx(digestSize=32)
        var buf = newSeq[byte](bufSize)
        while true:
          let n = f.readBytes(buf, 0, buf.len)
          if n <= 0: break
          fileSendHasher.update(buf.toOpenArray(0, n-1))
          await session.sendRecord(FileData.uint8, buf.toOpenArray(0, n-1))
        f.close()
        let dig = fileSendHasher.digest()
        await session.sendRecord(FileClose.uint8, dig)
        infoSid("send complete: " & relativePath)
      except OSError as e:
        let ec = chooseCode(e, ecReadFail)
        errorSid(errors.encodeServer(ec))
        await session.sendRecord(ErrorRec.uint8, @[toByte(ec)])

    if fileExists(absReq):
      infoSid("download request: " & relReqFull)
      let relativePath = if absReq.isRelativeTo(exportDir): absReq.relativePath(exportDir).replace(DirSep, '/') else: relReqFull
      await streamFileIfAccepted(relativePath)
      await session.sendRecord(DownloadDone.uint8, newSeq[byte]())
    elif dirExists(absReq):
      infoSid("download request (dir): " & relReqFull)
      let base = absReq
      var count = 0
      for p in walkDirRec(base):
        if dirExists(p): continue
        let relativePath = p.relativePath(exportDir).replace(DirSep, '/')
        await streamFileIfAccepted(relativePath)
        inc count
      await session.sendRecord(DownloadDone.uint8, newSeq[byte]())
      infoSid("download directory complete: " & relReqFull & " (" & $count & " files)")
    else:
      errorSid(errors.encodeServer(ecNotFound))
      await session.sendRecord(ErrorRec.uint8, @[toByte(ecNotFound)])

  ## Handle a listing request: stream batched directory entries using
  ## ListChunk records and end with ListDone. Non-recursive.
  proc handleListRequest(payload: seq[byte]) {.async.} =
    # payload: varint path len | path bytes (relative in sandbox)
    let (relReqFull, nextIdx) = decodePathParam(payload)
    if nextIdx < 0:
      await session.sendRecord(ErrorRec.uint8, @[toByte(ecBadPayload)]); return
    if relReqFull.len == 0:
      await session.sendRecord(ErrorRec.uint8, @[toByte(ecBadPath)]); return
    var absReq: string
    if sandboxed:
      if relReqFull.len > 0 and relReqFull[0] == '/':
        errorSid(errors.encodeServer(ecAbsolute))
        await session.sendRecord(ErrorRec.uint8, @[toByte(ecAbsolute)])
        return
      try:
        absReq = cleanJoin(exportDir, relReqFull)
      except CatchableError:
        errorSid(errors.encodeServer(ecUnsafePath))
        await session.sendRecord(ErrorRec.uint8, @[toByte(ecUnsafePath)])
        return
    else:
      if relReqFull.len > 0 and relReqFull[0] == '/':
        absReq = normalizedPath(relReqFull)
      else:
        absReq = normalizedPath(exportDir / relReqFull)
    if fileExists(absReq):
      let relativePath = if absReq.isRelativeTo(exportDir): absReq.relativePath(exportDir).replace(DirSep, '/') else: relReqFull
      let size = getFileSize(absReq)
      var buf = newSeq[byte]()
      let item = protocol.encodeListItem(relativePath, int64(size), 0'u8)
      buf.add(item)
      await session.sendRecord(ListChunk.uint8, buf)
      await session.sendRecord(ListDone.uint8, newSeq[byte]())
      infoSid("list file: " & relReqFull)
    elif dirExists(absReq):
      infoSid("list dir: " & relReqFull)
      var chunk = newSeq[byte]()
      var count = 0
      for it in walkDir(absReq):
        let p = it.path
        let isDir = (it.kind == pcDir)
        if isDir:
          let relativePath = p.relativePath(exportDir).replace(DirSep, '/')
          let item = protocol.encodeListItem(relativePath, 0'i64, 1'u8)
          if chunk.len + item.len > 64*1024:
            await session.sendRecord(ListChunk.uint8, chunk)
            chunk.setLen(0)
          chunk.add(item)
          inc count
        else:
          let relativePath = p.relativePath(exportDir).replace(DirSep, '/')
          let size = getFileSize(p)
          let item = protocol.encodeListItem(relativePath, int64(size), 0'u8)
          if chunk.len + item.len > 64*1024:
            await session.sendRecord(ListChunk.uint8, chunk)
            chunk.setLen(0)
          chunk.add(item)
          inc count
      if chunk.len > 0:
        await session.sendRecord(ListChunk.uint8, chunk)
      await session.sendRecord(ListDone.uint8, newSeq[byte]())
      infoSid("list complete: " & relReqFull & " (" & $count & " entries)")
    else:
      errorSid(errors.encodeServer(ecNotFound))
      await session.sendRecord(ErrorRec.uint8, @[toByte(ecNotFound)])
  try:
    # Phase: record dispatch loop
    while true:
      # Apply a per-connection read timeout to avoid hangs
      let fut = session.recvRecord()
      # withTimeout returns true if the future completed before the timeout,
      # and false if it timed out. Treat false as a timeout condition.
      if not await withTimeout(fut, session.ioTimeoutMs):
        await session.sendRecord(ErrorRec.uint8, @[toByte(ecTimeout)])
        infoSid("session timeout; closing connection")
        break
      let (t, payload) = await fut
      if payload.len == 0 and t == 0'u8:
        break
      case t
      of uint8(UploadOpen):
        await handleUploadOpen(payload)
      of uint8(FileData):
        handleUploadDataChunk(payload)
      of uint8(FileClose):
        await handleUploadCommit(payload)
      of uint8(DownloadOpen):
        await handleDownloadRequest(payload)
      of uint8(ListOpen):
        await handleListRequest(payload)
      of uint8(ErrorRec):
        if payload.len == 1:
          let ec = fromByte(payload[0])
          errorSid(errors.encodeServer(ec))
        else:
          errorSid(errors.encodeServer(ecUnknown))
      else:
        discard
  except CatchableError as e:
    errorSid("session error: " & e.msg)
  except OSError as e:
    errorSid("session I/O error: " & e.msg)
  finally:
    # Phase: cleanup
    if currentFile != nil:
      currentFile.close()
      discard tryRemoveFile(partialPath) # cleanup partial on abrupt end
    sock.close()
    infoSid("client disconnected")

proc serve*(listen: string, port: int, baseDir: string) {.async.} =
  ## Accept loop: binds and accepts clients, spawning handleClient for each.
  let srv = newAsyncSocket()
  srv.setSockOpt(OptReuseAddr, true)
  srv.bindAddr(Port(port), listen)
  srv.listen()
  while true:
    let c = await srv.accept()
    asyncCheck handleClient(c, baseDir)
