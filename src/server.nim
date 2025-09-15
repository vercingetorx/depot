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

var sandboxed*: bool = true          # Constrain requests under depot/export & depot/import
var allowOverwrite*: bool = false    # Allow overwriting existing files on upload

proc newSessionId(): string =
  ## Generate a short, log-friendly session identifier (hex-encoded 8 bytes).
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
  return (exportDir, importDir)

## String/byte helpers moved to depot/common.nim

proc handleClient*(sock: AsyncSocket, baseDir: string) {.async.} =
  ## Handle a single client session: perform handshake, then process
  ## upload/download records until the socket closes.
  # Phase: handshake + session setup
  let sid = newSessionId()
  proc infoSid(msg: string) = info fmt"[{sid}] {msg}"
  proc errorSid(msg: string) = error fmt"[{sid}] {msg}"

  infoSid(errors.encodeOk(errors.scConnected, fmt"client connected: {getPeerAddr(sock)}"))
  # Perform handshake; if it fails, log and close this client without
  # impacting the main accept loop.
  var session: Session
  try:
    session = await serverHandshake(sock, sandboxed)
  except handshake.HandshakeError as e:
    let logMsg = if e.msg.len > 0: fmt"{errors.encodeServer(e.code)}: {e.msg}" else: errors.encodeServer(e.code)
    errorSid(logMsg)
    try: sock.close() except: discard
    infoSid(errors.encodeOk(errors.scDisconnected, "client disconnected"))
    return
  infoSid(errors.encodeOk(errors.scHandshake, "handshake complete"))
  let (exportDir, importDir) = ensureBaseDirs(baseDir)
  # Phase: mutable transfer state (per-connection)
  # currentFile: open handle for the active upload (.part file)
  # currentPath/partialPath: absolute destination and staging path (.part)
  # uploadHasher: rolling BLAKE2b used to verify integrity at commit
  # pendingMtimeUnix/pendingPermissions: metadata applied after commit
  var currentFile: File
  var currentPath: string
  var partialPath: string
  # Hasher for verifying integrity of uploaded file data
  var uploadHasher: Blake2bCtx
  # Metadata received from client for the current upload (applied on commit)
  var pendingMtimeUnix: int64
  var pendingPermissions: set[FilePermission]
  
  # Phase: message handlers (small, focused)
  # These helpers encapsulate specific protocol tasks; they capture 'session',
  # 'exportDir', and 'importDir' from the outer scope.
  proc sendErrorCode(ec: ErrorCode) {.async.} =
    ## Send an application ErrorRec with a single error code byte.
    await session.sendRecord(ErrorRec.uint8, @[toByte(ec)])

  proc replyError(ec: ErrorCode, context: string = "") {.async.} =
    ## Log a server-coded error and send an ErrorRec with that code.
    if context.len > 0:
      errorSid(fmt"{errors.encodeServer(ec)}: {context}")
    else:
      errorSid(errors.encodeServer(ec))
    await session.sendRecord(ErrorRec.uint8, @[toByte(ec)])

  # Focused helpers for non-recursive listing
  proc listSingleFile(absReq: string, relReqFull: string) {.async.} =
    ## Emit a single file entry. Use a relative path under exportDir when sandboxed,
    ## otherwise preserve the request path as provided by the client.
    # When sandboxed, the client sees paths relative to exportDir so it can
    # reconstruct the same tree under its destination.
    let relativePath = if absReq.isRelativeTo(exportDir): absReq.relativePath(exportDir).replace(DirSep, '/') else: relReqFull
    let size = getFileSize(absReq)
    var buf = newSeq[byte]()
    let item = protocol.encodeListItem(relativePath, int64(size), 0'u8)
    buf.add(item)
    await session.sendRecord(ListChunk.uint8, buf)
    await session.sendRecord(ListDone.uint8, newSeq[byte]())
    infoSid(errors.encodeOk(errors.scListFile, fmt"{relReqFull}"))

  proc listDirectory(absReq: string, relReqFull: string) {.async.} =
    ## Stream a non-recursive listing for 'absReq'. Entries are batched into
    ## ~64 KiB ListChunk frames and closed with a ListDone record. Paths are
    ## made relative to 'absReq' and use forward slashes for the wire format.
    infoSid(errors.encodeOk(errors.scListDir, fmt"{relReqFull}"))
    var chunk = newSeq[byte]()
    var count = 0
    for it in walkDir(absReq):
      let p = it.path
      let relativePath = p.relativePath(absReq).replace(DirSep, '/')
      if it.kind == pcDir:
        # Directory items advertise kind=1 and size=0
        let item = protocol.encodeListItem(relativePath, 0'i64, 1'u8)
        # Flush the current batch if adding this item would exceed ~64 KiB.
        # This keeps ListChunk records reasonably sized for lower latency
        # and avoids building very large frames on busy directories.
        if chunk.len + item.len > 64*1024:
          await session.sendRecord(ListChunk.uint8, chunk)
          chunk.setLen(0)
        chunk.add(item)
        inc count
      else:
        # Regular files advertise kind=0 with byte size
        let size = getFileSize(p)
        let item = protocol.encodeListItem(relativePath, int64(size), 0'u8)
        # Same batching policy for files: cap ~64 KiB per ListChunk.
        if chunk.len + item.len > 64*1024:
          await session.sendRecord(ListChunk.uint8, chunk)
          chunk.setLen(0)
        chunk.add(item)
        inc count
    if chunk.len > 0:
      await session.sendRecord(ListChunk.uint8, chunk)
    await session.sendRecord(ListDone.uint8, newSeq[byte]())
    infoSid(errors.encodeOk(errors.scListComplete, fmt"{relReqFull} ({count} entries)"))

  ## Begin an upload session for a single file.
  ##
  ## Validates the destination path (sandbox rules), prepares the parent
  ## directory, opens a temporary .part file to stream into, and replies
  ## with UploadOk or UploadFail. Any I/O failure is mapped to a precise
  ## error code for the client.
  proc handleUploadOpen(payload: seq[byte]) {.async.} =
    # payload: encoded path + mtime + permissions
    let (relativeDestPath, srcMtimeUnix, srcPerms) = parseUploadOpen(payload)
    if relativeDestPath.len == 0:
      await session.sendRecord(UploadFail.uint8, @[toByte(ecBadPath)])
      return
    var destAbs: string
    if sandboxed:
      # In sandbox, absolute destinations are forbidden.
      if relativeDestPath.len > 0 and relativeDestPath[0] == '/':
        errorSid(errors.encodeServer(ecAbsolute))
        await session.sendRecord(UploadFail.uint8, @[toByte(ecAbsolute)])
        return
      try:
        # Constrain destination under depot/import, rejecting traversal.
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
    partialPath = common.partPath(currentPath)
    infoSid(errors.encodeOk(errors.scUploadStart, fmt"upload start: {relativeDestPath}"))
    uploadHasher = newBlake2bCtx(digestSize=32)
    pendingMtimeUnix = srcMtimeUnix
    pendingPermissions = srcPerms
    # Refuse early if destination exists (unless overwriting is enabled).
    if fileExists(currentPath) and not allowOverwrite:
      errorSid(errors.encodeServer(ecExists))
      await session.sendRecord(UploadFail.uint8, @[toByte(ecExists)])
      return
    # Ensure parent directories exist and aren't symlinks (avoid trickery).
    let parentDir = splitFile(currentPath).dir
    if parentDir.len > 0:
      createDir(parentDir)
      try:
        let info = getFileInfo(parentDir)
        if info.kind == pcLinkToDir:
          errorSid(errors.encodeServer(ecUnsafePath))
          await session.sendRecord(UploadFail.uint8, @[toByte(ecUnsafePath)])
          return
      except OSError:
        # If we cannot stat the parent, proceed and let file open fail explicitly.
        discard
    try:
      currentFile = open(partialPath, fmWrite)
    except OSError as e:
      let ec = errors.osErrorToCode(e, ecOpenFail)
      errorSid(errors.encodeServer(ec))
      await session.sendRecord(UploadFail.uint8, @[toByte(ec)])
      return
    await session.sendRecord(UploadOk.uint8, newSeq[byte]())

  ## Handle a file data chunk for the current upload.
  ##
  ## Appends to the .part file and updates a rolling BLAKE2b hash used for
  ## integrity verification on commit. On write failure, the partial file is
  ## removed and the error is sent to the client.
  proc handleUploadDataChunk(payload: seq[byte]) =
    if currentFile != nil:
      try:
        discard currentFile.writeBytes(payload, 0, payload.len)
        uploadHasher.update(payload)  # rolling hash for integrity verification
      except OSError as e:
        let ec = errors.osErrorToCode(e, ecWriteFail)
        errorSid(errors.encodeServer(ec))
        try: currentFile.close() except: discard
        currentFile = nil
        discard tryRemoveFile(partialPath)
        asyncCheck session.sendRecord(ErrorRec.uint8, @[toByte(ec)])

  ## Finalize the current upload.
  ##
  ## Closes the .part file, verifies the checksum provided by the client,
  ## optionally removes an existing file (if overwriting is enabled), then
  ## atomically moves the .part into place and applies mtime/permissions.
  ## Replies UploadDone or an ErrorRec.
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
          infoSid(errors.encodeOk(errors.scUploadComplete, fmt"{currentPath}"))
          await session.sendRecord(UploadDone.uint8, newSeq[byte]())
        except OSError as e:
          let ec = errors.osErrorToCode(e, ecOpenFail)
          errorSid(errors.encodeServer(ec))
          discard tryRemoveFile(partialPath)
          await sendErrorCode(ec)
      currentFile = nil
      currentPath = ""
      partialPath = ""
      pendingMtimeUnix = 0
      pendingPermissions = {}

  ## Handle a client download request.
  ##
  ## If the target is a file: send PathOpen, await PathAccept (if required),
  ## stream FileData chunks, then FileClose with checksum. If the target is a
  ## directory: iterate files recursively and perform the same for each entry.
  ## Always end the transfer with DownloadDone.
  proc handleDownloadRequest(payload: seq[byte]) {.async.} =
    # payload: varint path len | path bytes
    let (relReqFull, nextIdx) = decodePathParam(payload)
    if nextIdx < 0:
      await replyError(ecBadPayload, "decode path"); return
    if relReqFull.len == 0:
      await replyError(ecBadPath, "empty path"); return
    var absReq: string
    if sandboxed:
      # In sandbox, require a relative request under exportDir.
      if relReqFull.len > 0 and relReqFull[0] == '/':
        await replyError(ecAbsolute, relReqFull); return
      try:
        absReq = cleanJoin(exportDir, relReqFull)
      except CatchableError:
        await replyError(ecUnsafePath, relReqFull); return
    else:
      if relReqFull.len > 0 and relReqFull[0] == '/':
        absReq = normalizedPath(relReqFull)
      else:
        absReq = normalizedPath(exportDir / relReqFull)
    
    # Focused helpers for sending data to the client
    proc proposeRekeyIfNeeded() {.async.} =
      ## Opportunistically propose a rekey based on elapsed time since last rekey.
      ## A new epoch and pending keys are derived and announced via RekeyReq.
      if (common.monoMs() - session.lastRekeyMs) > session.rekeyIntervalMs and session.pendingEpoch == 0'u32:
        var epochBytes: array[4, byte]
        let newEpoch = session.epoch + 1'u32
        epochBytes[0] = byte(newEpoch and 0xff)
        epochBytes[1] = byte((newEpoch shr 8) and 0xff)
        epochBytes[2] = byte((newEpoch shr 16) and 0xff)
        epochBytes[3] = byte((newEpoch shr 24) and 0xff)
        let (out1, out2) = handshake.deriveRekey(session.trafficSecret, epochBytes)
        # Stash pending keys to be activated after the client acknowledges (RekeyAck)
        for i in 0 ..< 32: session.pendingKRx[i] = out1[i]
        for i in 0 ..< 16: session.pendingPRx[i] = out1[32 + i]
        for i in 0 ..< 32: session.pendingKTx[i] = out2[i]
        for i in 0 ..< 16: session.pendingPTx[i] = out2[32 + i]
        session.pendingEpoch = newEpoch
        infoSid(errors.encodeOk(errors.scRekey, fmt"propose epoch={newEpoch}"))
        await session.sendRecord(RekeyReq.uint8, epochBytes)

    proc absFromRel(baseAbs: string, relativePath: string): string =
      ## Resolve a filesystem path from a base and a relative path.
      ## - If baseAbs is a file, join relative to its parent directory.
      ## - If relativePath is absolute, normalize and return it unchanged.
      # Example: if baseAbs = /root/dir/file.txt and relativePath = "sub/a.bin",
      # join under /root/dir so that file requests don't duplicate the filename.
      if relativePath.len > 0 and relativePath[0] == '/':
        return normalizedPath(relativePath)
      let baseRoot = if fileExists(baseAbs): splitFile(baseAbs).dir else: baseAbs
      normalizedPath(baseRoot / relativePath)

    proc awaitAck(relativePath: string): Future[bool] {.async.} =
      ## Await client ack (PathAccept/PathSkip) if negotiated.
      ## Logs [skip] with context and returns false on skip.
      if session.dlAck:
        let (atk, _) = await session.recvRecord()
        if atk == PathAccept.uint8: return true
        if atk == PathSkip.uint8:
          infoSid(errors.encodeSkip(fmt"client skipped: {relativePath}"))
          return false
        infoSid(errors.encodeSkip(fmt"unexpected ack, treating as skip: type={atk}"))
        return false
      return true

    proc sendFileToClient(fsRel: string, wireRel: string) {.async.} =
      ## Stream one file to the client.
      ##
      ## Announces via PathOpen(wireRel), awaits ack (if negotiated), sends
      ## FileData chunks, then FileClose with checksum. Rejects symlinks or
      ## special files via isSafeFile.
      await proposeRekeyIfNeeded()
      # absReq may be a file (single-file request) or a directory (tree request).
      # absFromRel handles both cases safely.
      let absPath = absFromRel(absReq, fsRel)
      if not isSafeFile(absPath):
        await replyError(ecUnsafePath, absPath)
        return
      let fileSize = getFileSize(absPath)
      let mtimeUnix: int64 = int64(getLastModificationTime(absPath).toUnix())
      let permissionSet = getFilePermissions(absPath)
      let payload = protocol.encodePathOpen(wireRel, int64(fileSize), mtimeUnix, permissionSet)
      # PathOpen payload includes: relative path, file size, mtime (unix), and permissions
      await session.sendRecord(PathOpen.uint8, payload)
      if not await awaitAck(wireRel): return
      infoSid(errors.encodeOk(errors.scSendStart, fmt"{wireRel} ({fileSize} bytes)"))
      try:
        var f = open(absPath, fmRead)
        defer: f.close()
        var fileSendHasher = newBlake2bCtx(digestSize=32)
        var buf = newSeq[byte](bufSize)
        while true:
          let n = f.readBytes(buf, 0, buf.len)
          if n <= 0: break
          fileSendHasher.update(buf.toOpenArray(0, n-1))
          await session.sendRecord(FileData.uint8, buf.toOpenArray(0, n-1))
        let dig = fileSendHasher.digest()
        await session.sendRecord(FileClose.uint8, dig)
        infoSid(errors.encodeOk(errors.scSendComplete, fmt"{wireRel}"))
      except OSError as e:
        let ec = errors.osErrorToCode(e, ecReadFail)
        await replyError(ec, e.msg)

    proc sendTreeToClient(baseAbs: string) {.async.} =
      ## Walk a directory tree and send each regular file.
      ## The top-level directory name is prefixed on the wire path so the
      ## client reconstructs the same shape under its destination.
      var count = 0
      let baseName = extractFilename(baseAbs)  # top-level directory name for client presentation
      for p in walkDirRec(baseAbs):
        if dirExists(p): continue
        let fsRel = p.relativePath(baseAbs)
        let relWithTop = if baseName.len > 0: (baseName & "/" & fsRel) else: fsRel
        await sendFileToClient(fsRel, common.toWirePath(relWithTop))
        inc count
      await session.sendRecord(DownloadDone.uint8, newSeq[byte]())
      infoSid(errors.encodeOk(errors.scDownloadComplete, fmt"{relReqFull} ({count} files)"))

    if fileExists(absReq):
      infoSid(errors.encodeOk(errors.scDownloadRequest, fmt"{relReqFull}"))
      let fsRel = if absReq.isRelativeTo(exportDir): absReq.relativePath(exportDir) else: relReqFull
      let wireRel = common.toWirePath(fsRel)
      await sendFileToClient(fsRel, wireRel)
      await session.sendRecord(DownloadDone.uint8, newSeq[byte]())
    elif dirExists(absReq):
      infoSid(errors.encodeOk(errors.scDownloadRequest, fmt"dir {relReqFull}"))
      await sendTreeToClient(absReq)
    else:
      await replyError(ecNotFound, relReqFull)

  ## Handle a listing request.
  ##
  ## Streams batched directory entries using ListChunk records and ends with
  ## ListDone. Listing is non-recursive and respects sandbox path checks.
  proc handleListRequest(payload: seq[byte]) {.async.} =
    # payload: varint path len | path bytes (relative in sandbox)
    let (relReqFull, nextIdx) = decodePathParam(payload)
    if nextIdx < 0:
      await replyError(ecBadPayload, "decode path"); return
    if relReqFull.len == 0:
      await replyError(ecBadPath, "empty path"); return
    var absReq: string
    if sandboxed:
      if relReqFull.len > 0 and relReqFull[0] == '/':
        await replyError(ecAbsolute, relReqFull); return
      try:
        absReq = cleanJoin(exportDir, relReqFull)
      except CatchableError:
        await replyError(ecUnsafePath, relReqFull); return
    else:
      if relReqFull.len > 0 and relReqFull[0] == '/':
        absReq = normalizedPath(relReqFull)
      else:
        absReq = normalizedPath(exportDir / relReqFull)
    if fileExists(absReq):
      await listSingleFile(absReq, relReqFull)
    elif dirExists(absReq):
      await listDirectory(absReq, relReqFull)
    else:
      await replyError(ecNotFound, relReqFull)
  try:
    # Phase: record dispatch loop
    while true:
      # Apply a per-connection read timeout to avoid hangs
      let fut = session.recvRecord()
      # withTimeout returns true if the future completed before the timeout,
      # and false if it timed out. Treat false as a timeout condition.
      if not await withTimeout(fut, session.ioTimeoutMs):
        await session.sendRecord(ErrorRec.uint8, @[toByte(ecTimeout)])
        errorSid(fmt"{errors.encodeServer(ecTimeout)}: session timeout; closing connection")
        break
      let (t, payload) = await fut
      if payload.len == 0 and t == 0'u8:
        break
      case t
      of uint8(UploadOpen):
        # Client is initiating an upload: path+metadata in payload
        await handleUploadOpen(payload)
      of uint8(FileData):
        # Upload data chunk for the current file
        handleUploadDataChunk(payload)
      of uint8(FileClose):
        # End of upload for the current file (includes checksum)
        await handleUploadCommit(payload)
      of uint8(DownloadOpen):
        # Client requests a download of a file or directory
        await handleDownloadRequest(payload)
      of uint8(ListOpen):
        # Client requests a non-recursive listing
        await handleListRequest(payload)
      of uint8(ErrorRec):
        # Client surfaced an error; log code if present
        if payload.len == 1:
          let ec = fromByte(payload[0])
          errorSid(errors.encodeServer(ec))
        else:
          errorSid(errors.encodeServer(ecUnknown))
      else:
        discard
  except CatchableError as e:
    errorSid(errors.renderClient(e))
  except OSError as e:
    errorSid(fmt"{errors.encodeServer(ecReadFail)}: {e.msg}")
  finally:
    # Phase: cleanup
    if currentFile != nil:
      currentFile.close()
      discard tryRemoveFile(partialPath) # cleanup partial on abrupt end
    sock.close()
    infoSid(errors.encodeOk(errors.scDisconnected, "client disconnected"))

proc serve*(listen: string, port: int, baseDir: string) {.async.} =
  ## Accept loop: binds and accepts clients, spawning handleClient for each.
  let srv = newAsyncSocket()
  srv.setSockOpt(OptReuseAddr, true)
  srv.bindAddr(Port(port), listen)
  srv.listen()
  while true:
    let c = await srv.accept()
    asyncCheck handleClient(c, baseDir)
