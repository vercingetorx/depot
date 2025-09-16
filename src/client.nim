## Client-side transfer logic and utilities.
import std/[asyncdispatch, asyncnet, os, strutils, times, strformat]
import common
import errors
import handshake
import paths
import progress
import protocol
import records
import ../private/blake2/blake2b
when defined(posix): import posix
when defined(windows): import winlean

const bufSize = 1024 * 1024 # 1 MiB (matches server bufSize for throughput)

## All transfer errors are represented by coded exceptions (errors.CodedError)
## carrying an ErrorCode and optional context string. Legacy exception types
## are removed to keep a single, typed error mechanism end-to-end.

## Shared helpers and record types are imported from depot/common and depot/records

## Failure collection for batch reporting (written once at end by CLI)
var failureLines*: seq[string] = @[]

proc resetFailures*() {.inline.} =
  failureLines.setLen(0)

proc addFailure*(op, path: string, code: errors.ErrorCode) {.inline.} =
  failureLines.add(fmt"{op} {path} [{errors.errorName(code)}]")

proc failuresCount*(): int {.inline.} = failureLines.len

proc writeFailures*(filePath: string) =
  if failureLines.len == 0: return
  # Atomic-ish write: write to temp then move
  let tmp = filePath & ".part"
  writeFile(tmp, failureLines.join("\n") & "\n")
  moveFile(tmp, filePath)

# Session summary helpers (client-side only)
proc resetSessionStats*(sess: Session) {.inline.} =
  sess.stats.sentFiles = 0
  sess.stats.sentBytes = 0
  sess.stats.recvFiles = 0
  sess.stats.recvBytes = 0
  sess.stats.skipped = 0
  sess.stats.failed = 0

proc incSent*(sess: Session, bytes: int64) {.inline.} =
  inc sess.stats.sentFiles
  sess.stats.sentBytes += bytes

proc incRecv*(sess: Session, bytes: int64) {.inline.} =
  inc sess.stats.recvFiles
  sess.stats.recvBytes += bytes

proc incSkip*(sess: Session) {.inline.} =
  inc sess.stats.skipped

proc incFail*(sess: Session) {.inline.} =
  inc sess.stats.failed

proc isRemoteSpec*(s: string): bool =
  ## True if string matches a remote spec of the form host[:port]:path.
  let i = s.find(':')
  if i <= 0: return false
  # find second ':' after host[:port]
  let j = s.find(':', i+1)
  return j >= 0

proc parseRemote*(s: string): (string, int, string) =
  ## Parse a remote spec into (host, port, path).
  ## Supports 'host:path' (implicit default port 60006) and 'host:port:path'.
  let parts = s.split(':', maxsplit=2)
  if parts.len == 2:
    if parts[0].len == 0 or parts[1].len == 0:
      raise errors.newCodedError(ecBadRemote, "")
    return (parts[0], 60006, parts[1])
  elif parts.len == 3:
    if parts[0].len == 0 or parts[1].len == 0 or parts[2].len == 0:
      raise errors.newCodedError(ecBadRemote, "")
    let port = try: parseInt(parts[1]) except: 60006
    return (parts[0], port, parts[2])
  else:
    raise errors.newCodedError(ecBadRemote, "")

proc openSession*(remote: string, port: int): Future[Session] {.async.} =
  ## Establish a TCP connection to 'remote:port' and complete the secure
  ## Depot handshake.
  ##
  ## On success returns a Session with negotiated keys, features and timeouts
  ## ready for record I/O; on failure throws a coded error.
  # Phase: connect TCP
  let s = newAsyncSocket()
  try:
    await s.connect(remote, Port(port))
  except OSError as e:
    raise errors.newCodedError(ecConnect, fmt"{remote}:{port}: {e.msg}")
  # Phase: cryptographic handshake
  let id = fmt"{remote}:{port}"
  try:
    return await clientHandshake(s, id)
  except handshake.HandshakeError as he:
    s.close()
    raise errors.newCodedError(he.code, he.msg)
  except CatchableError as e:
    s.close()
    raise e

## Progress helpers are provided by depot/progress.nim

## Upload a single local file to the server.
## Sends mtime + permissions in UploadOpen, streams FileData, sends FileClose
## with checksum, and awaits UploadDone. Progress is cleared on success.
proc sendFile*(sess: Session, localPath: string, remotePath: string) {.async.} =
  ## Upload a single local file to a remote destination path.
  ## Includes metadata, streams data with progress, and verifies server commit.
  # Phase A: open upload with destination
  proc openUpload(destRel: string, srcPath: string) {.async.} =
    ## Send UploadOpen (path + metadata) and await UploadOk/UploadFail.
    let mtimeUnix = int64(getLastModificationTime(srcPath).toUnix())
    let perms = getFilePermissions(srcPath)
    let openPayload = encodeUploadOpen(destRel, mtimeUnix, perms)
    await sess.sendRecord(UploadOpen.uint8, openPayload)
    # Wait for UploadOk/UploadFail, but handle RekeyReq interleaved
    while true:
      let (t, payload) = await sess.recvRecord()
      if t == 0'u8:
        raise errors.newCodedError(ecClosed, "")
      if t == RekeyReq.uint8:
        # Handle server-initiated rekey: derive, Ack, and activate
        if payload.len == 4:
          let eb = payload
          let (out1, out2) = handshake.deriveRekey(sess.trafficSecret, eb)
          for i in 0 ..< 32: sess.pendingKTx[i] = out1[i]
          for i in 0 ..< 16: sess.pendingPTx[i] = out1[32 + i]
          for i in 0 ..< 32: sess.pendingKRx[i] = out2[i]
          for i in 0 ..< 16: sess.pendingPRx[i] = out2[32 + i]
          sess.pendingEpoch = uint32(eb[0]) or (uint32(eb[1]) shl 8) or (uint32(eb[2]) shl 16) or (uint32(eb[3]) shl 24)
          await sess.sendRecord(RekeyAck.uint8, payload)
          # Activate negotiated keys and reset sequence counters
          sess.epoch = sess.pendingEpoch
          for i in 0 ..< 32: sess.kTx[i] = sess.pendingKTx[i]
          for i in 0 ..< 32: sess.kRx[i] = sess.pendingKRx[i]
          for i in 0 ..< 16: sess.pTx[i] = sess.pendingPTx[i]
          for i in 0 ..< 16: sess.pRx[i] = sess.pendingPRx[i]
          sess.seqTx = 0; sess.seqRx = 0
          sess.lastRekeyMs = common.monoMs()
          sess.pendingEpoch = 0'u32
        continue
      if t == RekeyAck.uint8:
        # Server Ack shouldn't arrive here; ignore defensively
        continue
      if t == UploadFail.uint8:
        var ec = ecUnknown
        if payload.len == 1: ec = fromByte(payload[0])
        if ec == ecExists:
          raise errors.newCodedError(ecExists, "")
        raise errors.newCodedError(ec, "")
      if t == UploadOk.uint8:
        break
      # Unexpected type while opening upload
      raise errors.newCodedError(ecProtocol, "")

  # Phase B: stream file data
  # Hasher for the current upload; used to compute checksum for FileClose
  var uploadHasher = newBlake2bCtx(digestSize=32)
  proc streamFile(path: string) {.async.} =
    ## Stream the local file contents as FileData records with progress.
    var fileIn: File
    try:
      fileIn = open(path, fmRead)
    except OSError as e:
      let ec = errors.osErrorToCode(e, ecReadFail)
      raise errors.newCodedError(ec, e.msg)
    let totalBytes = getFileSize(path).int64
    var sentBytes: int64 = 0
    let startMs = nowMs()
    var buf = newSeq[byte](bufSize)
    while true:
      let n = fileIn.readBytes(buf, 0, buf.len)
      if n <= 0: break
      uploadHasher.update(buf.toOpenArray(0, n-1))
      await sess.sendRecord(FileData.uint8, buf.toOpenArray(0, n-1))
      sentBytes += n.int64
      printProgress2("[uploading]", extractFilename(path), sentBytes, totalBytes, startMs)
    fileIn.close()

  # Phase C: close and await commit
  proc awaitCommit() {.async.} =
    ## Close the upload with checksum and wait for UploadDone/ErrorRec, allowing
    ## RekeyReq interleaved from the server.
    let dig = uploadHasher.digest()
    await sess.sendRecord(FileClose.uint8, dig)
    while true:
      let (t, payload) = await sess.recvRecord()
      if t == 0'u8:
        raise errors.newCodedError(ecClosed, "")
      if t == RekeyReq.uint8:
        if payload.len == 4:
          let eb = payload
          let (out1, out2) = handshake.deriveRekey(sess.trafficSecret, eb)
          for i in 0 ..< 32: sess.pendingKTx[i] = out1[i]
          for i in 0 ..< 16: sess.pendingPTx[i] = out1[32 + i]
          for i in 0 ..< 32: sess.pendingKRx[i] = out2[i]
          for i in 0 ..< 16: sess.pendingPRx[i] = out2[32 + i]
          sess.pendingEpoch = uint32(eb[0]) or (uint32(eb[1]) shl 8) or (uint32(eb[2]) shl 16) or (uint32(eb[3]) shl 24)
          await sess.sendRecord(RekeyAck.uint8, payload)
          sess.epoch = sess.pendingEpoch
          for i in 0 ..< 32: sess.kTx[i] = sess.pendingKTx[i]
          for i in 0 ..< 32: sess.kRx[i] = sess.pendingKRx[i]
          for i in 0 ..< 16: sess.pTx[i] = sess.pendingPTx[i]
          for i in 0 ..< 16: sess.pRx[i] = sess.pendingPRx[i]
          sess.seqTx = 0; sess.seqRx = 0
          sess.lastRekeyMs = common.monoMs()
          sess.pendingEpoch = 0'u32
        continue
      if t == RekeyAck.uint8:
        continue
      if t == ErrorRec.uint8:
        var ec = ecUnknown
        if payload.len == 1: ec = fromByte(payload[0])
        raise errors.newCodedError(ec, "")
      if t == UploadDone.uint8:
        # Success: clear progress line
        clearProgress()
        break
      # Unexpected type while awaiting commit
      raise errors.newCodedError(ecProtocol, "")

  await openUpload(remotePath, localPath)
  await streamFile(localPath)
  await awaitCommit()
  # Count success in session stats (single file)
  try:
    incSent(sess, getFileSize(localPath))
  except CatchableError:
    # If getting size fails, still count file
    incSent(sess, 0)

## Receive a single remote file into a local path.
# Removed: not used by current flows (recvTree handles single files too).

## Send a directory tree rooted at localRoot into a remote directory (relative).
## Includes the top-level directory name under remoteDir, prints per-file [done]
## or [skip] lines, and a summary. Aborts the batch on session/local fatal.
proc sendTree*(sess: Session, localRoot: string, remoteDir: string, skipExisting: bool = false) {.async.} =
  ## Recursively upload a directory tree.
  ##
  ## The top-level directory name is included in the remote path, and each
  ## file is sent via sendFile with progress and error aggregation.
  # Phase: base path resolution
  var base = common.toWirePath(remoteDir)
  if sess.srvSandboxed:
    if base.len > 0 and base[0] == '/':
      raise errors.newCodedError(ecAbsolute, "")
    if hasDotDot(base):
      raise errors.newCodedError(ecUnsafePath, base)
  if base.len == 0: base = "."
  if not base.endsWith("/"): base &= "/"

  # Phase: helpers for each upload unit
  proc uploadSingleFile(path: string) {.async.} =
    ## Upload a single file (non-directory) under the computed base.
    try:
      # Single file goes under base using its filename
      let remoteRel = base & extractFilename(path)
      await sendFile(sess, path, remoteRel)
      clearProgress()
      echo errors.status(errors.scDone, fmt"{path} ({formatBytes(getFileSize(path))})")
    except CatchableError as e:
      let code = errors.getErrorCode(e)
      if errors.isSessionFatal(code) or errors.isLocalFatal(code):
        stderr.writeLine(errors.render(e, errors.auClient))
        raise
      elif code == ecExists and skipExisting:
        echo errors.status(errors.scSkip, fmt"existing {path}")
        incSkip(sess)
      else:
        addFailure("export", absolutePath(path), code)
        stderr.writeLine(errors.render(e, errors.auClient))
        incFail(sess)

  proc uploadDirTree(rootPath: string) {.async.} =
    ## Walk directory tree and upload each regular file under base/topName.
    let root = absolutePath(rootPath)
    let topName = extractFilename(root)
    for p in walkDirRec(rootPath):
      if dirExists(p): continue
      let relativeSubpath = p.relativePath(root)
      try:
        let remoteRel = base & (if topName.len > 0: (common.toWirePath(topName) & "/") else: "") & common.toWirePath(relativeSubpath)
        await sendFile(sess, p, remoteRel)
        clearProgress()
        echo errors.status(errors.scDone, fmt"{p} ({formatBytes(getFileSize(p))})")
      except CatchableError as e:
        let code = errors.getErrorCode(e)
        if errors.isSessionFatal(code) or errors.isLocalFatal(code):
          stderr.writeLine(errors.render(e, errors.auClient))
          raise
        elif code == ecExists and skipExisting:
          echo errors.status(errors.scSkip, fmt"existing {p}")
          incSkip(sess)
        else:
          addFailure("export", absolutePath(p), code)
          stderr.writeLine(errors.render(e, errors.auClient))
          incFail(sess)

  # Phase: dispatch by source type
  if dirExists(localRoot):
    await uploadDirTree(localRoot)
  elif fileExists(localRoot):
    await uploadSingleFile(localRoot)
  else:
    stderr.writeLine(fmt"{errors.encodeError(ecNotFound, errors.auClient)}: {localRoot}")
  # No per-tree summary; session summary is printed by sendMany

## Download a remote file or directory tree into localDest.
## Includes the top-level directory name locally, handles PathAccept/Skip,
## writes <path>.part and verifies checksum before moving into place.
proc recvTree*(sess: Session, remotePath: string, localDest: string, skipExisting: bool = false) {.async.} =
  ## Download a remote file or directory tree into localDest.
  ##
  ## Uses PathAccept/Skip per-file when dlAck is enabled. Writes to .part files
  ## and verifies checksums before moving into place. Applies metadata.
  # Phase: send request
  let rp = common.toWirePath(remotePath)
  if sess.srvSandboxed:
    if rp.len > 0 and rp[0] == '/':
      raise errors.newCodedError(ecAbsolute, "")
    if hasDotDot(rp):
      raise errors.newCodedError(ecUnsafePath, rp)
  let srcNorm = rp
  let p = encodePathParam(srcNorm)
  await sess.sendRecord(DownloadOpen.uint8, p)

  # Phase: local transfer state
  var firstFile = true
  var fileOpen = false
  var partFile: File
  var targetPath: string
  var totalBytes: int64 = -1
  var receivedBytes: int64 = 0
  var startMs = nowMs()
  # Per-call tallies removed; session-level stats are maintained on sess
  var skipCurrent = false
  var pendingErr = ""
  # Hasher for the current file within a directory download
  var directoryDownloadHasher = newBlake2bCtx(digestSize=32)
  var currentMtime: int64 = 0
  var currentPerms: set[FilePermission]

  # Phase: per-record handlers
  proc startNewFile(relativePath: string, fileSize: int64) =
    ## Begin writing a new target file under localDest, creating parents.
    ## The remote path is a forward-slash separated relative path.
    totalBytes = fileSize
    if dirExists(localDest):
      let full = normalizedPath(localDest / relativePath)
      let parent = splitFile(full).dir
      if parent.len > 0: createDir(parent)
      targetPath = full
    else:
      if firstFile:
        targetPath = localDest
      else:
        raise errors.newCodedError(ecConflict, "")
    if skipExisting and fileExists(targetPath):
      echo errors.status(errors.scSkip, fmt"existing {targetPath} ({formatBytes(totalBytes)})")
      incSkip(sess)
      skipCurrent = true
    else:
      partFile = open(common.partPath(targetPath), fmWrite)
      fileOpen = true
    firstFile = false
    receivedBytes = 0
    startMs = nowMs()
    directoryDownloadHasher = newBlake2bCtx(digestSize=32)

  # onPathOpen logic is handled inline in the receive loop to allow awaiting

  proc onFileData(payload: seq[byte]) =
    ## Handle a data chunk during directory download; writes or discards.
    if skipCurrent:
      discard
    elif fileOpen and partFile != nil and payload.len > 0:
      directoryDownloadHasher.update(payload)
      try:
        discard partFile.writeBytes(payload, 0, payload.len)
      except OSError as e:
        let ec = errors.osErrorToCode(e, ecWriteFail)
        if partFile != nil:
          partFile.close()
        discard tryRemoveFile(common.partPath(targetPath))
        asyncCheck sess.sendRecord(ErrorRec.uint8, @[toByte(ec)])
        raise errors.newCodedError(ec, e.msg)
      receivedBytes += payload.len.int64
      printProgress2("[downloading]", extractFilename(targetPath), receivedBytes, totalBytes, startMs)

  proc onFileClose(payload: seq[byte]) {.async.} =
    ## Complete the current file during directory download.
    if skipCurrent:
      clearProgress()
      skipCurrent = false
      fileOpen = false
    elif fileOpen and partFile != nil:
      partFile.close()
      if payload.len != 32:
        await sess.sendRecord(ErrorRec.uint8, @[toByte(ecChecksum)])
        discard tryRemoveFile(common.partPath(targetPath))
        clearProgress()
        raise errors.newCodedError(ecChecksum, targetPath)
      let dig2 = directoryDownloadHasher.digest()
      var match = dig2.len == 32
      if match:
        for i in 0 ..< 32:
          if dig2[i] != payload[i]: match = false
      if not match:
        await sess.sendRecord(ErrorRec.uint8, @[toByte(ecChecksum)])
        discard tryRemoveFile(common.partPath(targetPath))
        clearProgress()
        raise errors.newCodedError(ecChecksum, targetPath)
      if fileExists(targetPath):
        discard tryRemoveFile(fmt"{targetPath}.part")
        clearProgress()
        raise errors.newCodedError(ecExists, targetPath)
      moveFile(common.partPath(targetPath), targetPath)
      # Apply metadata
      try:
        setLastModificationTime(targetPath, fromUnix(currentMtime))
      except CatchableError:
        discard
      try:
        setFilePermissions(targetPath, currentPerms)
      except CatchableError:
        discard
      clearProgress()
      echo errors.status(errors.scDone, fmt"{targetPath} ({formatBytes(totalBytes)})")
      # Count success in session stats for this file
      if totalBytes >= 0:
        incRecv(sess, totalBytes)
      else:
        incRecv(sess, getFileSize(targetPath))
      fileOpen = false

  proc onServerError(payload: seq[byte]) =
    ## Handle server ErrorRec during directory download, cleaning up state.
    if fileOpen and partFile != nil:
      partFile.close()
      discard tryRemoveFile(common.partPath(targetPath))
    var ec = ecUnknown
    if payload.len == 1: ec = fromByte(payload[0])
    raise errors.newCodedError(ec, "")

  # Phase: main receive loop
  while true:
    let (t, payload) = await sess.recvRecord()
    if t == 0'u8:
      if fileOpen and partFile != nil:
        partFile.close()
        discard tryRemoveFile(fmt"{targetPath}.part")
      raise errors.newCodedError(ecClosed, "")
    case t
    of uint8(PathOpen):
      let (relativePath, fileSize, mtimeU, perms) = parsePathOpen(payload)
      let fullPath = (if dirExists(localDest): normalizedPath(localDest / relativePath) else: localDest)
      let existsLocally = fileExists(fullPath)
      if existsLocally:
        await sess.sendRecord(PathSkip.uint8, newSeq[byte]())
        skipCurrent = true
        if skipExisting:
          echo errors.status(errors.scSkip, fmt"existing {fullPath} ({formatBytes(fileSize)})")
        else:
          # Defer a local existence error until end-of-item to mirror behavior
          # while ensuring render() does not duplicate encoded text.
          pendingErr = fullPath
        continue
      else:
        await sess.sendRecord(PathAccept.uint8, newSeq[byte]())
        startNewFile(relativePath, fileSize)
        currentMtime = mtimeU
        currentPerms = perms
    of uint8(FileData): onFileData(payload)
    of uint8(FileClose): await onFileClose(payload)
    of uint8(DownloadDone):
      if pendingErr.len > 0:
        # Surface the local error after telling server to skip
        raise errors.newCodedError(ecExists, pendingErr)
      break
    of uint8(ErrorRec): onServerError(payload)
    of uint8(RekeyReq):
      # Derive pending keys, Ack, and activate during download
      if payload.len == 4:
        let eb = payload
        let (out1, out2) = handshake.deriveRekey(sess.trafficSecret, eb)
        for i in 0 ..< 32: sess.pendingKTx[i] = out1[i]
        for i in 0 ..< 16: sess.pendingPTx[i] = out1[32 + i]
        for i in 0 ..< 32: sess.pendingKRx[i] = out2[i]
        for i in 0 ..< 16: sess.pendingPRx[i] = out2[32 + i]
        sess.pendingEpoch = uint32(eb[0]) or (uint32(eb[1]) shl 8) or (uint32(eb[2]) shl 16) or (uint32(eb[3]) shl 24)
        await sess.sendRecord(RekeyAck.uint8, payload)
        sess.epoch = sess.pendingEpoch
        for i in 0 ..< 32: sess.kTx[i] = sess.pendingKTx[i]
        for i in 0 ..< 32: sess.kRx[i] = sess.pendingKRx[i]
        for i in 0 ..< 16: sess.pTx[i] = sess.pendingPTx[i]
        for i in 0 ..< 16: sess.pRx[i] = sess.pendingPRx[i]
        sess.seqTx = 0; sess.seqRx = 0
        sess.lastRekeyMs = common.monoMs()
        sess.pendingEpoch = 0'u32
    of uint8(RekeyAck):
      discard
    else: discard

## List files or a single file at remotePath. Emits a simple text listing.
proc list*(sess: Session, remotePath: string) {.async.} =
  ## List directory entries or a single file on the server without downloading.
  ## Prints a minimal text format for CLI output.
  let rp = common.toWirePath(remotePath)
  if sess.srvSandboxed:
    if rp.len > 0 and rp[0] == '/':
      raise errors.newCodedError(ecAbsolute, "")
    if hasDotDot(rp):
      raise errors.newCodedError(ecUnsafePath, rp)
  let req = encodePathParam(if rp.len == 0: "." else: rp)
  await sess.sendRecord(ListOpen.uint8, req)
  while true:
    let (t, payload) = await sess.recvRecord()
    if t == 0'u8:
      raise errors.newCodedError(ecClosed, "")
    case t
    of uint8(ListChunk):
      let items = parseListChunk(payload)
      for it in items:
        let kindStr = if it.kind == 1'u8: "[dir] " else: ""
        echo fmt"{kindStr}{it.relativePath} ({formatBytes(it.fileSize)})"
    of uint8(ListDone):
      break
    of uint8(ErrorRec):
      # Server sends a single-byte error code for ErrorRec
      if payload.len == 1:
        let ec = fromByte(payload[0])
        raise errors.newCodedError(ec, remotePath)
      else:
        raise errors.newCodedError(ecBadPayload, "invalid ErrorRec payload: " & remotePath)
    else:
      discard

## Send multiple local sources into a remote directory.
## Files go to remoteDir/basename; directories are sent with top-level included.
proc sendMany*(sess: Session, sources: seq[string], remoteDir: string, skipExisting: bool = false) {.async.} =
  ## Upload multiple sources. Directories are sent with top-level included; files
  ## are uploaded to remoteDir/basename. Aggregates per-item errors.
  resetSessionStats(sess)
  var fatalAbort = false
  var base = common.toWirePath(remoteDir)
  if sess.srvSandboxed:
    if base.len > 0 and base[0] == '/':
      raise errors.newCodedError(ecAbsolute, "")
    if hasDotDot(base):
      raise errors.newCodedError(ecUnsafePath, base)
  if base.len == 0: base = "."
  if not base.endsWith("/"): base &= "/"
  for src in sources:
    try:
      if dirExists(src):
        await sendTree(sess, src, base, skipExisting)
      elif fileExists(src):
        let remoteRel = base & extractFilename(src)
        await sendFile(sess, src, remoteRel)
        clearProgress()
        echo errors.status(errors.scDone, fmt"{src} ({formatBytes(getFileSize(src))})")
      else:
        stderr.writeLine(fmt"{errors.encodeError(ecNotFound, errors.auClient)}: {src}")
    except CatchableError as e:
      let code = errors.getErrorCode(e)
      if errors.isSessionFatal(code) or errors.isLocalFatal(code):
        stderr.writeLine(errors.render(e, errors.auClient))
        fatalAbort = true
        break
      else:
        if code == ecExists and skipExisting:
          echo errors.status(errors.scSkip, fmt"existing {src}")
          incSkip(sess)
        else:
          addFailure("export", absolutePath(src), code)
          stderr.writeLine(errors.render(e, errors.auClient))
          incFail(sess)
  # Print session summary
  let skippedSuffix = if sess.stats.skipped > 0: fmt", skipped {sess.stats.skipped}" else: ""
  let failedSuffix = if sess.stats.failed > 0: fmt", failed {sess.stats.failed}" else: ""
  echo errors.status(errors.scTransferred, fmt"{sess.stats.sentFiles} file(s), {formatBytes(sess.stats.sentBytes)}{skippedSuffix}{failedSuffix}")
  if fatalAbort or sess.stats.failed > 0:
    quit(1)

## Receive multiple remote items into a local destination.
## Each remote path is handled by recvTree and may be a file or a directory.
proc recvMany*(sess: Session, remotePaths: seq[string], localDest: string, skipExisting: bool = false) {.async.} =
  ## Download multiple remote paths into localDest. Each item may be a file or dir.
  resetSessionStats(sess)
  var fatalAbort = false
  for rp in remotePaths:
    try:
      await recvTree(sess, rp, localDest, skipExisting)
    except CatchableError as e:
      let code = errors.getErrorCode(e)
      if errors.isSessionFatal(code) or errors.isLocalFatal(code):
        stderr.writeLine(errors.render(e, errors.auClient))
        fatalAbort = true
        break
      else:
        addFailure("import", rp, code)
        stderr.writeLine(errors.render(e, errors.auClient))
        incFail(sess)
  # Print session summary
  let skippedSuffix2 = if sess.stats.skipped > 0: fmt", skipped {sess.stats.skipped}" else: ""
  let failedSuffix2 = if sess.stats.failed > 0: fmt", failed {sess.stats.failed}" else: ""
  echo errors.status(errors.scTransferred, fmt"{sess.stats.recvFiles} file(s), {formatBytes(sess.stats.recvBytes)}{skippedSuffix2}{failedSuffix2}")
  if fatalAbort or sess.stats.failed > 0:
    quit(1)
