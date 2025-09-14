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

const bufSize = 1024 * 1024  # 1 MiB

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

proc handleClient*(sock: AsyncSocket, baseDir: string) {.async.} =
  ## Handle a single client session: perform handshake, then process
  ## upload/download records until the socket closes.
  # Phase: handshake + session setup
  let sid = newSessionId()
  proc infoSid(msg: string) = info fmt"[{sid}] {msg}"
  proc errorSid(msg: string) = error fmt"[{sid}] {msg}"

  infoSid(errors.encodeServer(icClientConnected, details=fmt"{getPeerAddr(sock)}"))
  # Perform handshake; if it fails, log and close this client without
  # impacting the main accept loop.
  var session: Session
  try:
    session = await serverHandshake(sock, sandboxed)
  except CatchableError as e:
    # Convert client-coded handshake message to server-coded log line and include details
    let (codeStr, text) = errors.splitReason(e.msg)
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
    errorSid(errors.encodeServer(ec, details=text))
    try: sock.close() except: discard
    infoSid(errors.encodeServer(icClientDisconnected))
    return
  infoSid(errors.encodeServer(icHandshakeComplete))
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
      errorSid(errors.encodeServer(ecBadPath, details=relativeDestPath))
      await session.sendRecord(UploadFail.uint8, @[toByte(ecBadPath)])
      return
    var destAbs: string
    if sandboxed:
      if relativeDestPath.len > 0 and relativeDestPath[0] == '/':
        errorSid(errors.encodeServer(ecAbsolute, details=relativeDestPath))
        await session.sendRecord(UploadFail.uint8, @[toByte(ecAbsolute)])
        return
      try:
        destAbs = cleanJoin(importDir, relativeDestPath)
      except CatchableError as e:
        errorSid(errors.encodeServer(ecUnsafePath, details=e.msg))
        await session.sendRecord(UploadFail.uint8, @[toByte(ecUnsafePath)])
        return
    else:
      if relativeDestPath.len > 0 and relativeDestPath[0] == '/':
        destAbs = normalizedPath(relativeDestPath)
      else:
        destAbs = normalizedPath(importDir / relativeDestPath)
    currentPath = destAbs
    partialPath = common.partPath(currentPath)
    infoSid(errors.encodeServer(icUploadStart, details=relativeDestPath))
    uploadHasher = newBlake2bCtx(digestSize=32)
    pendingMtimeUnix = srcMtimeUnix
    pendingPermissions = srcPerms
    # refuse early if destination already exists (unless server allows overwrite)
    if fileExists(currentPath) and not allowOverwrite:
      errorSid(errors.encodeServer(ecExists, details=currentPath))
      await session.sendRecord(UploadFail.uint8, @[toByte(ecExists)])
      return
    # ensure parent directories exist and aren't symlinks
    let parentDir = splitFile(currentPath).dir
    if parentDir.len > 0:
      createDir(parentDir)
      try:
        let info = getFileInfo(parentDir)
        if info.kind == pcLinkToDir:
          errorSid(errors.encodeServer(ecUnsafePath, details=parentDir))
          await session.sendRecord(UploadFail.uint8, @[toByte(ecUnsafePath)])
          return
      except OSError as e:
        errorSid(errors.encodeServer(ecPerms, details=e.msg))
        await session.sendRecord(UploadFail.uint8, @[toByte(ecPerms)])
        return
    try:
      currentFile = open(partialPath, fmWrite)
    except OSError as e:
      let ec = errors.osErrorToCode(e, ecOpenFail)
      errorSid(errors.encodeServer(ec, details=e.msg))
      await session.sendRecord(UploadFail.uint8, @[toByte(ec)])
      return
    await session.sendRecord(UploadOk.uint8, @[toByte(scUploadOk)])

  ## Handle a file data chunk for the current upload. Appends to the
  ## .part file and maps write failures to precise reasons.
  proc handleUploadDataChunk(payload: seq[byte]) =
    if currentFile != nil:
      try:
        discard currentFile.writeBytes(payload, 0, payload.len)
        uploadHasher.update(payload)
      except OSError as e:
        let ec = errors.osErrorToCode(e, ecWriteFail)
        errorSid(errors.encodeServer(ec, details=e.msg))
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
        errorSid(errors.encodeServer(ecExists, details=currentPath))
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
          infoSid(errors.encodeServer(scUploadDone, details=currentPath))
          await session.sendRecord(UploadDone.uint8, @[toByte(scUploadDone)])
        except OSError as e:
          let ec = errors.osErrorToCode(e, ecOpenFail)
          errorSid(errors.encodeServer(ec, details=e.msg))
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
      errorSid(errors.encodeServer(ecBadPayload))
      await session.sendRecord(ErrorRec.uint8, @[toByte(ecBadPayload)]); return
    if relReqFull.len == 0:
      errorSid(errors.encodeServer(ecBadPath))
      await session.sendRecord(ErrorRec.uint8, @[toByte(ecBadPath)]); return
    var absReq: string
    if sandboxed:
      if relReqFull.len > 0 and relReqFull[0] == '/':
        errorSid(errors.encodeServer(ecAbsolute, details=relReqFull))
        await session.sendRecord(ErrorRec.uint8, @[toByte(ecAbsolute)])
        return
      try:
        absReq = cleanJoin(exportDir, relReqFull)
      except CatchableError as e:
        errorSid(errors.encodeServer(ecUnsafePath, details=e.msg))
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
      if (common.monoMs() - session.lastRekeyMs) > session.rekeyIntervalMs and session.pendingEpoch == 0'u32:
        var epochBytes: array[4, byte]
        let newEpoch = session.epoch + 1'u32
        epochBytes[0] = byte(newEpoch and 0xff)
        epochBytes[1] = byte((newEpoch shr 8) and 0xff)
        epochBytes[2] = byte((newEpoch shr 16) and 0xff)
        epochBytes[3] = byte((newEpoch shr 24) and 0xff)
        # derive pending keys for server (Rx=c2s, Tx=s2c)
        let (out1, out2) = handshake.deriveRekey(session.trafficSecret, epochBytes)
        for i in 0 ..< 32: session.pendingKRx[i] = out1[i]
        for i in 0 ..< 16: session.pendingPRx[i] = out1[32 + i]
        for i in 0 ..< 32: session.pendingKTx[i] = out2[i]
        for i in 0 ..< 16: session.pendingPTx[i] = out2[32 + i]
        session.pendingEpoch = newEpoch
        infoSid(errors.encodeServer(icRekeyPropose, details=fmt"epoch={newEpoch}"))
        await session.sendRecord(RekeyReq.uint8, epochBytes)
        # derive pending keys and apply after sending ack (handled in dispatch loop)
      # Send path + size + metadata in PathOpen payload
      var absPath: string
      if sandboxed:
        absPath = cleanJoin(exportDir, relativePath)
      else:
        if relativePath.len > 0 and relativePath[0] == '/':
          absPath = normalizedPath(relativePath)
        else:
          absPath = normalizedPath(exportDir / relativePath)
      if not isSafeFile(absPath):
        errorSid(errors.encodeServer(ecUnsafePath, details=absPath))
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
            infoSid(errors.encodeServer(icClientSkipped, details=fmt"{relativePath} (reason: {codeName})"))
          return
        elif atk == 0'u8:
          # Unexpected/empty ack; do not fail silently. Log and treat as skip.
          infoSid(errors.encodeServer(icUnexpectedAck, details="type=0"))
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
            infoSid(errors.encodeServer(icUnexpectedAck, details=fmt"type={atk}, reason: {codeName}"))
          return
      # Only announce send after explicit accept
      infoSid(errors.encodeServer(icSendFile, details=fmt"{relativePath} ({fileSize} bytes)"))
      try:
        var f = open(absPath, fmRead)
        defer: f.close()
        # Hasher to compute and send checksum for integrity verification
        var fileSendHasher = newBlake2bCtx(digestSize=32)
        var buf = newSeq[byte](bufSize)
        while true:
          let n = f.readBytes(buf, 0, buf.len)
          if n <= 0: break
          fileSendHasher.update(buf.toOpenArray(0, n-1))
          await session.sendRecord(FileData.uint8, buf.toOpenArray(0, n-1))
        let dig = fileSendHasher.digest()
        await session.sendRecord(FileClose.uint8, dig)
        infoSid(errors.encodeServer(icSendComplete, details=relativePath))
      except OSError as e:
        let ec = errors.osErrorToCode(e, ecReadFail)
        errorSid(errors.encodeServer(ec, details=e.msg))
        await session.sendRecord(ErrorRec.uint8, @[toByte(ec)])

    if fileExists(absReq):
      infoSid(errors.encodeServer(icDownloadRequest, details=relReqFull))
      let relativePath = if absReq.isRelativeTo(exportDir): absReq.relativePath(exportDir).replace(DirSep, '/') else: relReqFull
      await streamFileIfAccepted(relativePath)
      await session.sendRecord(DownloadDone.uint8, @[toByte(scDownloadDone)])
    elif dirExists(absReq):
      infoSid(errors.encodeServer(icDownloadRequestDir, details=relReqFull))
      let base = absReq
      var count = 0
      for p in walkDirRec(base):
        if dirExists(p): continue
        # Compute relative path to the requested base dir (not exportRoot),
        # falling back to relReqFull when not under exportDir.
        let relativePath = p.relativePath(base).replace(DirSep, '/')
        await streamFileIfAccepted(relativePath)
        inc count
      await session.sendRecord(DownloadDone.uint8, @[toByte(scDownloadDone)])
      infoSid(errors.encodeServer(scDownloadDone, details=fmt"{relReqFull} ({count} files)"))
    else:
      errorSid(errors.encodeServer(ecNotFound, details=relReqFull))
      await session.sendRecord(ErrorRec.uint8, @[toByte(ecNotFound)])

  ## Handle a listing request: stream batched directory entries using
  ## ListChunk records and end with ListDone. Non-recursive.
  proc handleListRequest(payload: seq[byte]) {.async.} =
    # payload: varint path len | path bytes (relative in sandbox)
    let (relReqFull, nextIdx) = decodePathParam(payload)
    if nextIdx < 0:
      errorSid(errors.encodeServer(ecBadPayload))
      await session.sendRecord(ErrorRec.uint8, @[toByte(ecBadPayload)]); return
    if relReqFull.len == 0:
      errorSid(errors.encodeServer(ecBadPath))
      await session.sendRecord(ErrorRec.uint8, @[toByte(ecBadPath)]); return
    var absReq: string
    if sandboxed:
      if relReqFull.len > 0 and relReqFull[0] == '/':
        errorSid(errors.encodeServer(ecAbsolute, details=relReqFull))
        await session.sendRecord(ErrorRec.uint8, @[toByte(ecAbsolute)])
        return
      try:
        absReq = cleanJoin(exportDir, relReqFull)
      except CatchableError as e:
        errorSid(errors.encodeServer(ecUnsafePath, details=e.msg))
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
      await session.sendRecord(ListDone.uint8, @[toByte(scListDone)])
      infoSid(errors.encodeServer(icListFile, details=relReqFull))
    elif dirExists(absReq):
      infoSid(errors.encodeServer(icListDir, details=relReqFull))
      var chunk = newSeq[byte]()
      var count = 0
      for it in walkDir(absReq):
        let p = it.path
        let isDir = (it.kind == pcDir)
        if isDir:
          let relativePath = p.relativePath(absReq).replace(DirSep, '/')
          let item = protocol.encodeListItem(relativePath, 0'i64, 1'u8)
          if chunk.len + item.len > 64*1024:
            await session.sendRecord(ListChunk.uint8, chunk)
            chunk.setLen(0)
          chunk.add(item)
          inc count
        else:
          let relativePath = p.relativePath(absReq).replace(DirSep, '/')
          let size = getFileSize(p)
          let item = protocol.encodeListItem(relativePath, int64(size), 0'u8)
          if chunk.len + item.len > 64*1024:
            await session.sendRecord(ListChunk.uint8, chunk)
            chunk.setLen(0)
          chunk.add(item)
          inc count
      if chunk.len > 0:
        await session.sendRecord(ListChunk.uint8, chunk)
      await session.sendRecord(ListDone.uint8, @[toByte(scListDone)])
      infoSid(errors.encodeServer(scListDone, details=fmt"{relReqFull} ({count} entries)"))
    else:
      errorSid(errors.encodeServer(ecNotFound, details=relReqFull))
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
        infoSid(errors.encodeServer(icTimeoutClose))
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
    errorSid(errors.encodeServer(icSessionError, details=e.msg))
  except OSError as e:
    errorSid(errors.encodeServer(icSessionIoError, details=e.msg))
  finally:
    # Phase: cleanup
    if currentFile != nil:
      currentFile.close()
      discard tryRemoveFile(partialPath) # cleanup partial on abrupt end
    sock.close()
    infoSid(errors.encodeServer(icClientDisconnected))

proc serve*(listen: string, port: int, baseDir: string) {.async.} =
  ## Accept loop: binds and accepts clients, spawning handleClient for each.
  let srv = newAsyncSocket()
  srv.setSockOpt(OptReuseAddr, true)
  srv.bindAddr(Port(port), listen)
  srv.listen()
  while true:
    let c = await srv.accept()
    asyncCheck handleClient(c, baseDir)
