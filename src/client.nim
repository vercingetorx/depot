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
    let (t, payload) = await sess.recvRecord()
    if t == 0'u8:
      raise errors.newCodedError(ecClosed, "")
    if t == UploadFail.uint8:
      var ec = ecUnknown
      if payload.len == 1: ec = fromByte(payload[0])
      if ec == ecExists:
        raise errors.newCodedError(ecExists, "")
      raise errors.newCodedError(ec, "")
    if t != UploadOk.uint8:
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
    ## Close the upload with checksum and wait for the server's UploadDone or ErrorRec.
    let dig = uploadHasher.digest()
    await sess.sendRecord(FileClose.uint8, dig)
    let (t, payload) = await sess.recvRecord()
    if t == 0'u8:
      raise errors.newCodedError(ecClosed, "")
    if t == ErrorRec.uint8:
      var ec = ecUnknown
      if payload.len == 1: ec = fromByte(payload[0])
      raise errors.newCodedError(ec, "")
    if t != UploadDone.uint8:
      raise errors.newCodedError(ecProtocol, "")
    # Success: clear progress line
    clearProgress()

  await openUpload(remotePath, localPath)
  # Opportunistic time-based rekey at file boundary
  if (common.monoMs() - sess.lastRekeyMs) > sess.rekeyIntervalMs and sess.pendingEpoch == 0'u32:
    var epochBytes: array[4, byte]
    let newEpoch = sess.epoch + 1'u32
    epochBytes[0] = byte(newEpoch and 0xff)
    epochBytes[1] = byte((newEpoch shr 8) and 0xff)
    epochBytes[2] = byte((newEpoch shr 16) and 0xff)
    epochBytes[3] = byte((newEpoch shr 24) and 0xff)
    await sess.sendRecord(RekeyReq.uint8, epochBytes)
  await streamFile(localPath)
  await awaitCommit()

## Receive a single remote file (relative to export root) into a concrete local path.
## Writes to <path>.part, verifies checksum from FileClose, applies mtime/perms,
## then atomically moves into place. Raises coded errors on conflicts or I/O.
proc recvFile*(sess: Session, remotePath: string, localPath: string) {.async.} =
  proc requestFile(relativePath: string) {.async.} =
    ## Send DownloadOpen for a single file request under the server's export root.
    let req = encodePathParam(relativePath)
    await sess.sendRecord(DownloadOpen.uint8, req)

  var outFile: File
  var downloadHasher = newBlake2bCtx(digestSize=32)
  var totalBytes: int64 = -1
  var receivedBytes: int64 = 0
  var skipped = false
  var pendingErr = ""
  let startMs = nowMs()
  let requestPath = remotePath

  proc cleanupPartial() =
    ## Remove partial file and close handle if present.
    if outFile != nil:
      outFile.close()
    discard tryRemoveFile(common.partPath(localPath))

  var recvMtime: int64 = 0
  var recvPerms: set[FilePermission]

  proc onPathOpen(payload: seq[byte]) {.async.} =
    ## Handle PathOpen announcement for a single-file download.
    let (_, size, mtimeU, perms) = parsePathOpen(payload)
    totalBytes = size
    recvMtime = mtimeU
    recvPerms = perms
    if fileExists(localPath):
      if sess.dlAck:
        await sess.sendRecord(PathSkip.uint8, newSeq[byte]())
        skipped = true
        pendingErr = localPath
      else:
        raise errors.newCodedError(ecExists, localPath)
    else:
      outFile = open(common.partPath(localPath), fmWrite)
      if sess.dlAck:
        await sess.sendRecord(PathAccept.uint8, newSeq[byte]())

  proc onFileData(payload: seq[byte]) =
    ## Append data to the current partial file and update checksum.
    if outFile != nil:
      downloadHasher.update(payload)
      try:
        discard outFile.writeBytes(payload, 0, payload.len)
      except OSError as e:
        let ec = errors.osErrorToCode(e, ecWriteFail)
        cleanupPartial()
        asyncCheck sess.sendRecord(ErrorRec.uint8, @[toByte(ec)])
        raise errors.newCodedError(ec, e.msg)
      receivedBytes += payload.len.int64
      printProgress2("[downloading]", extractFilename(localPath), receivedBytes, totalBytes, startMs)

  proc onFileClose(payload: seq[byte]) {.async.} =
    ## Verify checksum, move .part atomically, and apply metadata.
    if outFile != nil:
      outFile.close()
      if payload.len != 32:
        await sess.sendRecord(ErrorRec.uint8, @[toByte(ecChecksum)])
        cleanupPartial()
        clearProgress()
        raise errors.newCodedError(ecChecksum, localPath)
      let dig = downloadHasher.digest()
      var match = dig.len == 32
      if match:
        for i in 0 ..< 32:
          if dig[i] != payload[i]: match = false
      if not match:
        await sess.sendRecord(ErrorRec.uint8, @[toByte(ecChecksum)])
        cleanupPartial()
        clearProgress()
        raise errors.newCodedError(ecChecksum, localPath)
      if fileExists(localPath):
        cleanupPartial()
        clearProgress()
        raise errors.newCodedError(ecExists, localPath)
      moveFile(common.partPath(localPath), localPath)
      try:
        setLastModificationTime(localPath, fromUnix(recvMtime))
      except CatchableError:
        discard
      try:
        setFilePermissions(localPath, recvPerms)
      except CatchableError:
        discard
      clearProgress()

  proc onServerError(payload: seq[byte]) =
    ## Handle server-side error for single-file receive; cleans up partial.
    cleanupPartial()
    var ec = ecUnknown
    if payload.len == 1: ec = fromByte(payload[0])
    raise errors.newCodedError(ec, requestPath)

  await requestFile(remotePath)
  while true:
    let (t, payload) = await sess.recvRecord()
    if t == 0'u8:
      cleanupPartial()
      raise errors.newCodedError(ecClosed, "")
    case t
    of uint8(PathOpen): await onPathOpen(payload)
    of uint8(FileData): onFileData(payload)
    of uint8(FileClose):
      await onFileClose(payload)
      break
    of uint8(DownloadDone):
      if skipped and pendingErr.len > 0:
        raise errors.newCodedError(ecExists, pendingErr)
      break
    of uint8(ErrorRec): onServerError(payload)
    of uint8(RekeyReq):
      # Rekey request carries the new epoch (4 bytes). Derive pending key
      # material keyed by the trafficSecret and ack before activating.
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
    of uint8(RekeyAck):
      discard
    else: discard

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

  # Pre-scan: compute total file count and bytes for summary/progress
  var totalFiles = 0
  var totalBytes: int64 = 0
  if dirExists(localRoot):
    for p in walkDirRec(localRoot):
        if dirExists(p): continue
        inc totalFiles
        totalBytes += getFileSize(p)
  elif fileExists(localRoot):
    inc totalFiles
    totalBytes += getFileSize(localRoot)

  var sentAllBytes: int64 = 0
  var failed = 0
  var skipped = 0
  var succeeded = 0

  # Phase: helpers for each upload unit
  proc uploadSingleFile(path: string) {.async.} =
    ## Upload a single file (non-directory) under the computed base.
    try:
      # Single file goes under base using its filename
      let remoteRel = base & extractFilename(path)
      await sendFile(sess, path, remoteRel)
      clearProgress()
      sentAllBytes += getFileSize(path)
      inc succeeded
      echo errors.encodeOk(errors.scDone, fmt"{path} ({formatBytes(getFileSize(path))})")
    except CatchableError as e:
      let code = errors.getErrorCode(e)
      if errors.isSessionFatal(code) or errors.isLocalFatal(code):
        stderr.writeLine(errors.renderClient(e))
        raise
      elif code == ecExists and skipExisting:
        echo errors.encodeSkip(fmt"existing {path}")
        inc skipped
      else:
        addFailure("export", absolutePath(path), code)
        stderr.writeLine(errors.renderClient(e))
        inc failed

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
        sentAllBytes += getFileSize(p)
        inc succeeded
        clearProgress()
        echo errors.encodeOk(errors.scDone, fmt"{p} ({formatBytes(getFileSize(p))})")
      except CatchableError as e:
        let code = errors.getErrorCode(e)
        if errors.isSessionFatal(code) or errors.isLocalFatal(code):
          stderr.writeLine(errors.renderClient(e))
          raise
        elif code == ecExists and skipExisting:
          echo errors.encodeSkip(fmt"existing {p}")
          inc skipped
        else:
          addFailure("export", absolutePath(p), code)
          stderr.writeLine(errors.renderClient(e))
          inc failed

  # Phase: dispatch by source type
  if dirExists(localRoot):
    await uploadDirTree(localRoot)
  elif fileExists(localRoot):
    await uploadSingleFile(localRoot)
  else:
    stderr.writeLine(fmt"{errors.encodeClient(ecNotFound)}: {localRoot}")

  # Phase: summary
  let skippedSuffix = if skipped > 0: fmt", skipped {skipped}" else: ""
  echo errors.encodeOk(errors.scTransferred, fmt"{succeeded}/{totalFiles} file(s), {formatBytes(sentAllBytes)}{skippedSuffix}")
  if failed > 0:
    quit(1)

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
  # Tallying for summary, mirroring sendTree
  var totalFiles = 0             # all files announced by server
  var succeeded = 0              # files successfully received
  var skipped = 0                # files skipped due to local existence
  var failed = 0                 # files that resulted in a local conflict/error but transfer continued
  var totalBytesAll: int64 = 0
  var receivedBytesAll: int64 = 0
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
    totalBytesAll += fileSize
    if dirExists(localDest):
      let full = normalizedPath(localDest / relativePath)
      let parent = splitFile(full).dir
      if parent.len > 0: discard existsOrCreateDir(parent)
      targetPath = full
    else:
      if firstFile:
        targetPath = localDest
      else:
        raise errors.newCodedError(ecConflict, "")
    if skipExisting and fileExists(targetPath):
      echo errors.encodeSkip(fmt"existing {targetPath} ({formatBytes(totalBytes)})")
      inc skipped
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
      receivedBytesAll += payload.len.int64
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
      inc succeeded
      echo errors.encodeOk(errors.scDone, fmt"{targetPath} ({formatBytes(totalBytes)})")
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
      inc totalFiles
      let fullPath = (if dirExists(localDest): normalizedPath(localDest / relativePath) else: localDest)
      let existsLocally = fileExists(fullPath)
      if existsLocally:
        await sess.sendRecord(PathSkip.uint8, newSeq[byte]())
        skipCurrent = true
        if skipExisting:
          echo errors.encodeSkip(fmt"existing {fullPath} ({formatBytes(fileSize)})")
          inc skipped
        else:
          pendingErr = fmt"{errors.encodeClient(ecExists)}: {fullPath}"
          inc failed
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
      let skippedSuffix = if skipped > 0: fmt", skipped {skipped}" else: ""
      echo errors.encodeOk(errors.scTransferred, fmt"{succeeded}/{totalFiles} file(s), {formatBytes(receivedBytesAll)}{skippedSuffix}")
      break
    of uint8(ErrorRec): onServerError(payload)
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
        echo errors.encodeOk(errors.scDone, fmt"{src} ({formatBytes(getFileSize(src))})")
      else:
        stderr.writeLine(fmt"{errors.encodeClient(ecNotFound)}: {src}")
    except CatchableError as e:
      let code = errors.getErrorCode(e)
      if errors.isSessionFatal(code) or errors.isLocalFatal(code):
        stderr.writeLine(errors.renderClient(e))
        break
      else:
        if code == ecExists and skipExisting:
          echo errors.encodeSkip(fmt"existing {src}")
        else:
          addFailure("export", absolutePath(src), code)
          stderr.writeLine(errors.renderClient(e))

## Receive multiple remote items into a local destination.
## Each remote path is handled by recvTree and may be a file or a directory.
proc recvMany*(sess: Session, remotePaths: seq[string], localDest: string, skipExisting: bool = false) {.async.} =
  ## Download multiple remote paths into localDest. Each item may be a file or dir.
  for rp in remotePaths:
    try:
      await recvTree(sess, rp, localDest, skipExisting)
    except CatchableError as e:
      let code = errors.getErrorCode(e)
      if errors.isSessionFatal(code) or errors.isLocalFatal(code):
        stderr.writeLine(errors.renderClient(e))
        break
      else:
        addFailure("import", rp, code)
        stderr.writeLine(errors.renderClient(e))
