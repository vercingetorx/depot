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

type UploadExists* = object of CatchableError

## Shared helpers and record types are imported from depot/common and depot/records

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
  let parts = s.split(':', maxsplit = 2)
  if parts.len == 2:
    if parts[0].len == 0 or parts[1].len == 0:
      raise newException(CatchableError, "invalid remote spec")
    return (parts[0], 60006, parts[1])
  elif parts.len == 3:
    if parts[0].len == 0 or parts[1].len == 0 or parts[2].len == 0:
      raise newException(CatchableError, "invalid remote spec")
    let port = try: parseInt(parts[1]) except: 60006
    return (parts[0], port, parts[2])
  else:
    raise newException(CatchableError, "invalid remote spec")

proc openSession*(remote: string, port: int): Future[Session] {.async.} =
  ## Establish a TCP connection to 'remote:port' and complete the secure
  ## Depot handshake. Returns a Session ready for record I/O.
  # Phase: connect TCP
  let s = newAsyncSocket()
  try:
    await s.connect(remote, Port(port))
  except OSError as e:
    raise newException(CatchableError, fmt"connect failed to {remote}:{port}: {e.msg}")
  # Phase: cryptographic handshake
  let id = fmt"{remote}:{port}"
  try:
    return await clientHandshake(s, id)
  except CatchableError as e:
    s.close()
    # Pass through standardized coded message as-is
    raise newException(CatchableError, e.msg)

## Progress helpers are provided by depot/progress.nim

proc uploadFile*(sess: Session, srcPath, relDest: string) {.async.} =
  ## Upload a single local file to the server at the given relative destination
  ## under the server import root. Streams data then awaits server commit.
  # Phase A: open upload with destination
  proc openUpload(destRel: string, srcPath: string) {.async.} =
    ## Send UploadOpen (path + metadata) and await UploadOk/UploadFail.
    let mtimeUnix = int64(getLastModificationTime(srcPath).toUnix())
    let perms = getFilePermissions(srcPath)
    let openPayload = encodeUploadOpen(destRel, mtimeUnix, perms)
    await sess.sendRecord(UploadOpen.uint8, openPayload)
    let (t, payload) = await sess.recvRecord()
    if t == 0'u8:
      raise newException(CatchableError, "connection closed by server during upload open")
    if t == UploadFail.uint8:
      var ec = ecUnknown
      if payload.len == 1: ec = fromByte(payload[0])
      if ec == ecExists:
        raise newException(UploadExists, errors.encodeClient(ec))
      raise newException(CatchableError, errors.encodeClient(ec))
    if t != UploadOk.uint8:
      raise newException(CatchableError, errors.encodeReason(
          errors.reasonUnknown, "server refused upload"))

  # Phase B: stream file data
  # Hasher for the current upload; used to compute checksum for FileClose
  var uploadHasher = newBlake2bCtx(digestSize = 32)
  proc streamFile(path: string) {.async.} =
    ## Stream the local file contents as FileData records.
    var fileIn = open(path, fmRead)
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
      printProgress2("uploading", extractFilename(path), sentBytes, totalBytes, startMs)
    fileIn.close()

  # Phase C: close and await commit
  proc awaitCommit() {.async.} =
    ## Close the upload with checksum and wait for the server's UploadDone or ErrorRec.
    let dig = uploadHasher.digest()
    await sess.sendRecord(FileClose.uint8, dig)
    clearProgress()
    let (t, payload) = await sess.recvRecord()
    if t == 0'u8:
      raise newException(CatchableError, "connection closed by server after file data")
    if t == ErrorRec.uint8:
      var ec = ecUnknown
      if payload.len == 1: ec = fromByte(payload[0])
      raise newException(CatchableError, errors.encodeClient(ec))
    if t != UploadDone.uint8:
      raise newException(CatchableError, errors.encodeReason(
          errors.reasonUnknown, "upload failed to commit on server"))

  await openUpload(relDest, srcPath)
  # Opportunistic time-based rekey at file boundary
  if (common.monoMs() - sess.lastRekeyMs) > sess.rekeyIntervalMs and
      sess.pendingEpoch == 0'u32:
    var epochBytes: array[4, byte]
    let newEpoch = sess.epoch + 1'u32
    epochBytes[0] = byte(newEpoch and 0xff)
    epochBytes[1] = byte((newEpoch shr 8) and 0xff)
    epochBytes[2] = byte((newEpoch shr 16) and 0xff)
    epochBytes[3] = byte((newEpoch shr 24) and 0xff)
    await sess.sendRecord(RekeyReq.uint8, epochBytes)
  await streamFile(srcPath)
  await awaitCommit()

proc downloadFile*(sess: Session, relSrc, destPath: string) {.async.} =
  ## Download a single remote file (relative to export root) into a concrete
  ## local path (not a directory). Uses PathOpen/PathAccept handshake.
  # Phase A: request file
  proc requestFile(relativePath: string) {.async.} =
    ## Send DownloadOpen for a single file identified by relativePath.
    let req = encodePathParam(relativePath)
    await sess.sendRecord(DownloadOpen.uint8, req)

  # Phase B: handle incoming records with optional ack
  var outFile: File
  # Hasher to verify integrity of the downloaded file against FileClose digest
  var downloadHasher = newBlake2bCtx(digestSize = 32)
  var totalBytes: int64 = -1
  var receivedBytes: int64 = 0
  var accepted = false
  var skipped = false
  var pendingErr = ""
  let startMs = nowMs()

  proc cleanupPartial() =
    if outFile != nil:
      outFile.close()
    discard tryRemoveFile(common.partPath(destPath))

  var recvMtime: int64 = 0
  var recvPerms: set[FilePermission]

  proc onPathOpen(payload: seq[byte]) {.async.} =
    ## Receive PathOpen and decide accept/skip based on local path.
    let (_, size, mtimeU, perms) = parsePathOpen(payload)
    totalBytes = size
    recvMtime = mtimeU
    recvPerms = perms
    # Decide whether to accept or skip
    if fileExists(destPath):
      if sess.dlAck:
        var b: array[1, byte]
        b[0] = byte(SkipReason.srExists)
        await sess.sendRecord(PathSkip.uint8, b)
        skipped = true
        pendingErr = fmt"{errFileExists}{destPath}"
      else:
        raise newException(CatchableError, fmt"file exists: {destPath}")
    else:
      # Prepare to receive and ack accept if negotiated
      outFile = open(common.partPath(destPath), fmWrite)
      accepted = true
      if sess.dlAck:
        await sess.sendRecord(PathAccept.uint8, newSeq[byte]())

  proc onFileData(payload: seq[byte]) =
    ## Append a file data chunk to the output .part file.
    if outFile != nil:
      downloadHasher.update(payload)
      try:
        discard outFile.writeBytes(payload, 0, payload.len)
      except OSError as e:
        let ec = errors.osErrorToCode(e, ecWriteFail)
        cleanupPartial()
        asyncCheck sess.sendRecord(ErrorRec.uint8, @[toByte(ec)])
        raise newException(CatchableError, errors.encodeClient(ec))
      receivedBytes += payload.len.int64
      printProgress2("[downloading]", extractFilename(destPath), receivedBytes,
          totalBytes, startMs)

  proc onFileClose(payload: seq[byte]) {.async.} =
    ## Finalize the .part file and move into place atomically.
    if outFile != nil:
      outFile.close()
      if payload.len != 32:
        # Report checksum error to server using 1-byte code
        await sess.sendRecord(ErrorRec.uint8, @[toByte(ecChecksum)])
        cleanupPartial()
        clearProgress()
        raise newException(CatchableError, fmt"checksum mismatch: {destPath}")
      let dig = downloadHasher.digest()
      var match = dig.len == 32
      if match:
        for i in 0 ..< 32:
          if dig[i] != payload[i]: match = false
      if not match:
        await sess.sendRecord(ErrorRec.uint8, @[toByte(ecChecksum)])
        cleanupPartial()
        clearProgress()
        raise newException(CatchableError, fmt"checksum mismatch: {destPath}")
      if fileExists(destPath):
        cleanupPartial()
        clearProgress()
        raise newException(CatchableError, fmt"file exists: {destPath}")
      moveFile(common.partPath(destPath), destPath)
      # Apply metadata
      try:
        setLastModificationTime(destPath, fromUnix(recvMtime))
      except CatchableError:
        discard
      try:
        setFilePermissions(destPath, recvPerms)
      except CatchableError:
        discard
      clearProgress()

  proc onServerError(payload: seq[byte]) =
    ## Translate an ErrorRec payload into an exception and cleanup (code-based).
    cleanupPartial()
    var ec = ecUnknown
    if payload.len == 1: ec = fromByte(payload[0])
    raise newException(CatchableError, errors.encodeClient(ec))

  await requestFile(relSrc)
  while true:
    let (t, payload) = await sess.recvRecord()
    if t == 0'u8:
      cleanupPartial()
      raise newException(CatchableError, "connection closed by server during download")
    case t
    of uint8(PathOpen): await onPathOpen(payload)
    of uint8(FileData): onFileData(payload)
    of uint8(FileClose):
      await onFileClose(payload)
      break
    of uint8(DownloadDone):
      if skipped and pendingErr.len > 0:
        raise newException(CatchableError, pendingErr)
      break
    of uint8(ErrorRec): onServerError(payload)
    of uint8(RekeyReq):
      if payload.len == 4:
        let eb = payload
        let (out1, out2) = handshake.deriveRekey(sess.trafficSecret, eb)
        for i in 0 ..< 32: sess.pendingKTx[i] = out1[i]
        for i in 0 ..< 16: sess.pendingPTx[i] = out1[32 + i]
        for i in 0 ..< 32: sess.pendingKRx[i] = out2[i]
        for i in 0 ..< 16: sess.pendingPRx[i] = out2[32 + i]
        sess.pendingEpoch = uint32(eb[0]) or (uint32(eb[1]) shl 8) or (uint32(
            eb[2]) shl 16) or (uint32(eb[3]) shl 24)
        await sess.sendRecord(RekeyAck.uint8, payload)
        # activate
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

type UploadState = object
  base: string
  skipExisting: bool
  sentAllBytes: int64
  succeeded: int
  failed: int
  skipped: int
  totalFiles: int

proc uploadSingleFile(sess: Session, path: string, st: var UploadState) {.async.} =
  let destRel = fmt"{st.base}{extractFilename(path)}"
  try:
    await uploadFile(sess, path, destRel)
    st.sentAllBytes += getFileSize(path)
    inc st.succeeded
    echo fmt"done {path} ({formatBytes(getFileSize(path))})"
  except UploadExists as e:
    if st.skipExisting:
      echo fmt"skip existing {path}"
      inc st.skipped
    else:
      stderr.writeLine(e.msg)
      inc st.failed
  except CatchableError as e:
    stderr.writeLine(e.msg)
    inc st.failed
  except OSError as e:
    stderr.writeLine(e.msg)
    inc st.failed

proc uploadDirTree(sess: Session, rootPath: string, st: var UploadState) {.async.} =
  let root = absolutePath(rootPath)
  let topName = extractFilename(root)
  for p in walkDirRec(rootPath):
    if dirExists(p): continue
    let relativeSubpath = p.relativePath(root)
    let destRel = fmt"{st.base}{topName}/{relativeSubpath.replace(DirSep, '/')}"
    try:
      await uploadFile(sess, p, destRel)
      st.sentAllBytes += getFileSize(p)
      inc st.succeeded
      echo fmt"done {p} ({formatBytes(getFileSize(p))})"
    except UploadExists as e:
      if st.skipExisting:
        echo fmt"skip existing {p}"
        inc st.skipped
      else:
        stderr.writeLine(e.msg)
        inc st.failed
    except CatchableError as e:
      stderr.writeLine(e.msg)
      inc st.failed
    except OSError as e:
      stderr.writeLine(e.msg)
      inc st.failed

proc uploadPaths*(sess: Session, sources: seq[string], remoteDir: string,
    skipExisting: bool = false) {.async.} =
  ## Upload one or more files/directories into a remote directory (relative to
  ## the server import root). Creates remote directories as needed.
  var st: UploadState
  st.base = remoteDir.replace("\\", "/")
  if sess.srvSandboxed:
    if st.base.len > 0 and st.base[0] == '/':
      raise newException(CatchableError, "absolute remote path not allowed in sandbox mode (use --no-sandbox on server)")
    if hasDotDot(st.base):
      raise newException(CatchableError, "'..' path segments are not allowed in remote paths under sandbox mode")
  if st.base.len == 0: st.base = "."
  if not st.base.endsWith("/"): st.base &= "/"

  st.skipExisting = skipExisting

  # Pre-scan: compute totals
  for src in sources:
    if dirExists(src):
      for p in walkDirRec(src):
        if dirExists(p): continue
        inc st.totalFiles
    elif fileExists(src):
      inc st.totalFiles

  # Phase: dispatch by source type
  for src in sources:
    if dirExists(src):
      await uploadDirTree(sess, src, st)
    elif fileExists(src):
      await uploadSingleFile(sess, src, st)
    else:
      stderr.writeLine(fmt"not found: {src}")

  # Phase: summary
  let skippedSuffix = if st.skipped > 0: fmt", skipped {st.skipped}" else: ""
  echo fmt"Transferred {st.succeeded}/{st.totalFiles} file(s), {formatBytes(st.sentAllBytes)}{skippedSuffix}"
  if st.failed > 0:
    quit(1)

type DownloadState = object
  firstFile: bool
  fileOpen: bool
  partFile: File
  targetPath: string
  totalBytes: int64
  receivedBytes: int64
  startMs: int64
  fileCount: int
  totalBytesAll: int64
  receivedBytesAll: int64
  skipCurrent: bool
  pendingErr: string
  directoryDownloadHasher: Blake2bCtx
  currentMtime: int64
  currentPerms: set[FilePermission]
  localDest: string

proc startNewFile(st: var DownloadState, relativePath: string, fileSize: int64, skipExisting: bool) =
  ## Begin writing a new target file under localDest, creating parents.
  ## The remote path is a forward-slash separated relative path.
  st.totalBytes = fileSize
  inc st.fileCount
  st.totalBytesAll += fileSize
  if dirExists(st.localDest):
    let full = normalizedPath(st.localDest / relativePath)
    let parent = splitFile(full).dir
    if parent.len > 0: discard existsOrCreateDir(parent)
    st.targetPath = full
  else:
    if st.firstFile:
      st.targetPath = st.localDest
    else:
      raise newException(CatchableError,
          "destination is a file but multiple files requested")
  if skipExisting and fileExists(st.targetPath):
    echo fmt"skip existing {st.targetPath} ({formatBytes(st.totalBytes)})"
    st.skipCurrent = true
  else:
    st.partFile = open(common.partPath(st.targetPath), fmWrite)
    st.fileOpen = true
  st.firstFile = false
  st.receivedBytes = 0
  st.startMs = nowMs()
  st.directoryDownloadHasher = newBlake2bCtx(digestSize=32)

proc onFileData(sess: Session, st: var DownloadState, payload: seq[byte]) =
  ## Handle a data chunk during directory download; writes or discards.
  if st.skipCurrent:
    discard
  elif st.fileOpen and st.partFile != nil and payload.len > 0:
    st.directoryDownloadHasher.update(payload)
    try:
      discard st.partFile.writeBytes(payload, 0, payload.len)
    except OSError as e:
      let ec = errors.osErrorToCode(e, ecWriteFail)
      if st.partFile != nil:
        st.partFile.close()
      discard tryRemoveFile(common.partPath(st.targetPath))
      asyncCheck sess.sendRecord(ErrorRec.uint8, @[toByte(ec)])
      raise newException(CatchableError, errors.encodeClient(ec))
    st.receivedBytes += payload.len.int64
    st.receivedBytesAll += payload.len.int64
    printProgress2("downloading", extractFilename(st.targetPath),
        st.receivedBytes, st.totalBytes, st.startMs)

proc onFileClose(sess: Session, st: var DownloadState, payload: seq[byte]) {.async.} =
  ## Complete the current file during directory download.
  if st.skipCurrent:
    clearProgress()
    st.skipCurrent = false
    st.fileOpen = false
  elif st.fileOpen and st.partFile != nil:
    st.partFile.close()
    if payload.len != 32:
      await sess.sendRecord(ErrorRec.uint8, @[toByte(ecChecksum)])
      discard tryRemoveFile(common.partPath(st.targetPath))
      clearProgress()
      raise newException(CatchableError, fmt"checksum mismatch: {st.targetPath}")
    let dig2 = st.directoryDownloadHasher.digest()
    var match = dig2.len == 32
    if match:
      for i in 0 ..< 32:
        if dig2[i] != payload[i]: match = false
    if not match:
      await sess.sendRecord(ErrorRec.uint8, @[toByte(ecChecksum)])
      discard tryRemoveFile(common.partPath(st.targetPath))
      clearProgress()
      raise newException(CatchableError, fmt"checksum mismatch: {st.targetPath}")
    if fileExists(st.targetPath):
      discard tryRemoveFile(fmt"{st.targetPath}.part")
      clearProgress()
      raise newException(CatchableError, fmt"file exists: {st.targetPath}")
    moveFile(common.partPath(st.targetPath), st.targetPath)
    # Apply metadata
    try:
      setLastModificationTime(st.targetPath, fromUnix(st.currentMtime))
    except CatchableError:
      discard
    try:
      setFilePermissions(st.targetPath, st.currentPerms)
    except CatchableError:
      discard
    clearProgress()
    echo fmt"done {st.targetPath} ({formatBytes(st.totalBytes)})"
    st.fileOpen = false

proc onServerError(st: var DownloadState, payload: seq[byte]) =
  ## Handle server ErrorRec during directory download, cleaning up state.
  if st.fileOpen and st.partFile != nil:
    st.partFile.close()
    discard tryRemoveFile(common.partPath(st.targetPath))
  var ec = ecUnknown
  if payload.len == 1: ec = fromByte(payload[0])
  raise newException(CatchableError, errors.encodeClient(ec))

proc downloadTo*(sess: Session, remotePath: string, localDest: string,
                 skipExisting: bool = false) {.async.} =
  ## Download a remote file or directory tree (relative to export root) into a
  ## local destination directory or file. When downloading a directory tree,
  ## creates local subdirectories under localDest.
  # Phase: send request
  let rp = remotePath.replace("\\", "/")
  if sess.srvSandboxed:
    if rp.len > 0 and rp[0] == '/':
      raise newException(CatchableError,
          "absolute remote path not allowed in sandbox mode (use --no-sandbox on server)")
    if hasDotDot(rp):
      raise newException(CatchableError,
          "'..' path segments are not allowed in remote paths under sandbox mode")
  let srcNorm = rp
  let p = encodePathParam(srcNorm)
  await sess.sendRecord(DownloadOpen.uint8, p)

  # Phase: local transfer state
  var st: DownloadState
  st.firstFile = true
  st.startMs = nowMs()
  st.directoryDownloadHasher = newBlake2bCtx(digestSize=32)
  st.localDest = localDest

  # Phase: main receive loop
  while true:
    let (t, payload) = await sess.recvRecord()
    if t == 0'u8:
      if st.fileOpen and st.partFile != nil:
        st.partFile.close()
        discard tryRemoveFile(fmt"{st.targetPath}.part")
      raise newException(CatchableError,
          "connection closed by server during directory download")
    case t
    of uint8(PathOpen):
      let (relativePath, fileSize, mtimeU, perms) = parsePathOpen(payload)
      let fullPath = (if dirExists(localDest): normalizedPath(
          localDest / relativePath) else: localDest)
      let existsLocally = fileExists(fullPath)
      if existsLocally:
        var b: array[1, byte]
        b[0] = byte(SkipReason.srExists)
        await sess.sendRecord(PathSkip.uint8, b)
        st.skipCurrent = true
        if skipExisting:
          echo fmt"skip existing {fullPath} ({formatBytes(fileSize)})"
        else:
          st.pendingErr = fmt"{errFileExists}{fullPath}"
        continue
      else:
        await sess.sendRecord(PathAccept.uint8, newSeq[byte]())
        startNewFile(st, relativePath, fileSize, skipExisting)
        st.currentMtime = mtimeU
        st.currentPerms = perms
    of uint8(FileData): onFileData(sess, st, payload)
    of uint8(FileClose): await onFileClose(sess, st, payload)
    of uint8(DownloadDone):
      if st.pendingErr.len > 0:
        # Surface the local error after telling server to skip
        raise newException(CatchableError, st.pendingErr)
      echo fmt"Transferred {st.fileCount} file(s), {formatBytes(st.receivedBytesAll)}"
      break
    of uint8(ErrorRec): onServerError(st, payload)
    else: discard

proc listRemote*(sess: Session, remotePath: string) {.async.} =
  ## List files or a single file under a remote path without transferring data.
  ## Emits a simple text listing; consider adding JSON in the future.
  let rp = remotePath.replace("\\", "/")
  if sess.srvSandboxed:
    if rp.len > 0 and rp[0] == '/':
      raise newException(CatchableError, "absolute remote path not allowed in sandbox mode (use --no-sandbox on server)")
    if hasDotDot(rp):
      raise newException(CatchableError, "'..' path segments are not allowed in remote paths under sandbox mode")
  let req = encodePathParam(if rp.len == 0: "." else: rp)
  await sess.sendRecord(ListOpen.uint8, req)
  while true:
    let (t, payload) = await sess.recvRecord()
    if t == 0'u8:
      raise newException(CatchableError, "connection closed by server during list")
    case t
    of uint8(ListChunk):
      let items = parseListChunk(payload)
      for it in items:
        let kindStr = if it.kind == 1'u8: "[dir] " else: ""
        echo kindStr, it.relativePath, " (", formatBytes(it.fileSize), ")"
    of uint8(ListDone):
      break
    of uint8(ErrorRec):
      # Server sends a single-byte error code for ErrorRec
      if payload.len == 1:
        let ec = fromByte(payload[0])
        raise newException(CatchableError, errors.encodeClient(ec))
      else:
        raise newException(CatchableError, errors.encodeReason(
            errors.reasonBadPayload, "invalid ErrorRec payload"))
    else:
      discard
