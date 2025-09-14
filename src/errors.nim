## Shared error/status message constants used in depot protocol payloads.
import std/strutils
when defined(posix): import posix
when defined(windows): import winlean

const
  errBadPath* = "bad path"
  errBadPayload* = "bad payload"
  errUnsafePath* = "unsafe path: "
  errAbsolutePathSandbox* = "absolute path not allowed in sandbox: "
  errOpenFail* = "open fail"
  errWriteFail* = "write fail"
  errCommitFail* = "commit fail"
  errFileExists* = "file exists: "
  errReadFail* = "read fail"
  errNotFound* = "not found: "
  errChecksumMismatch* = "checksum mismatch"

# Standard reason codes (short, for logs/protocol payloads)
const
  reasonExists* = "exists"
  reasonFilter* = "filter"
  reasonNoSpace* = "no-space"
  reasonPerms* = "perms"
  reasonAbsolute* = "absolute"
  reasonUnsafePath* = "unsafe-path"
  reasonBadPath* = "bad-path"
  reasonBadPayload* = "bad-payload"
  reasonOpenFail* = "open-fail"
  reasonWriteFail* = "write-fail"
  reasonReadFail* = "read-fail"
  reasonNotFound* = "not-found"
  reasonTimeout* = "timeout"
  reasonUnknown* = "unknown"
  reasonChecksum* = "checksum"
  # Handshake/administrative categories
  reasonConfig* = "server-config"
  reasonCompat* = "compat"
  reasonAuth*   = "auth"
  # Success codes
  reasonUploadOk* = "upload-ok"
  reasonUploadDone* = "upload-done"
  reasonDownloadDone* = "download-done"
  reasonListDone* = "list-done"
  reasonDone* = "done"
  reasonSkip* = "skipped"
  reasonTransfer* = "transferred"
  reasonList* = "list-item"
  reasonAbort* = "aborting"
  reasonConnected* = "client-connected"
  reasonDisconnected* = "client-disconnected"
  reasonHandshake* = "handshake-complete"
  reasonUpload* = "upload-start"
  reasonRekey* = "rekey-propose"
  reasonSkipped* = "client-skipped"
  reasonAck* = "unexpected-ack"
  reasonSend* = "send-file"
  reasonSendDone* = "send-complete"
  reasonDownload* = "download-request"
  reasonDownloadDir* = "download-request-dir"
  reasonListFile* = "list-file"
  reasonListDir* = "list-dir"
  reasonTimeoutClose* = "timeout-closing"
  reasonSessionError* = "session-error"
  reasonSessionIoError* = "session-io-error"

type
  ErrorCode* = enum
    ecUnknown = 0'u8
    ecExists
    ecFilter
    ecNoSpace
    ecPerms
    ecAbsolute
    ecUnsafePath
    ecBadPath
    ecBadPayload
    ecOpenFail
    ecWriteFail
    ecReadFail
    ecNotFound
    ecTimeout
    ecChecksum
    ecConfig
    ecCompat
    ecAuth
    ecSourceNotFound
    ecFatal
    ecAborting
  SuccessCode* = enum
    scUploadOk = 0'u8
    scUploadDone
    scDownloadDone
    scListDone
  InfoCode* = enum
    icDone = 0'u8
    icSkipped
    icTransferred
    icListItem
    icClientConnected
    icClientDisconnected
    icHandshakeComplete
    icUploadStart
    icRekeyPropose
    icClientSkipped
    icUnexpectedAck
    icSendFile
    icSendComplete
    icDownloadRequest
    icDownloadRequestDir
    icListFile
    icListDir
    icTimeoutClose
    icSessionError
    icSessionIoError

proc codeName*(c: ErrorCode): string =
  case c
  of ecExists: reasonExists
  of ecFilter: reasonFilter
  of ecNoSpace: reasonNoSpace
  of ecPerms: reasonPerms
  of ecAbsolute: reasonAbsolute
  of ecUnsafePath: reasonUnsafePath
  of ecBadPath: reasonBadPath
  of ecBadPayload: reasonBadPayload
  of ecOpenFail: reasonOpenFail
  of ecWriteFail: reasonWriteFail
  of ecReadFail: reasonReadFail
  of ecNotFound: reasonNotFound
  of ecTimeout: reasonTimeout
  of ecChecksum: reasonChecksum
  of ecConfig: reasonConfig
  of ecCompat: reasonCompat
  of ecAuth: reasonAuth
  of ecSourceNotFound: reasonNotFound
  of ecFatal: reasonUnknown
  of ecAborting: reasonAbort
  else: reasonUnknown

proc codeName*(c: SuccessCode): string =
  case c
  of scUploadOk: reasonUploadOk
  of scUploadDone: reasonUploadDone
  of scDownloadDone: reasonDownloadDone
  of scListDone: reasonListDone

proc codeName*(c: InfoCode): string =
  case c
  of icDone: reasonDone
  of icSkipped: reasonSkip
  of icTransferred: reasonTransfer
  of icListItem: reasonList
  of icClientConnected: reasonConnected
  of icClientDisconnected: reasonDisconnected
  of icHandshakeComplete: reasonHandshake
  of icUploadStart: reasonUpload
  of icRekeyPropose: reasonRekey
  of icClientSkipped: reasonSkipped
  of icUnexpectedAck: reasonAck
  of icSendFile: reasonSend
  of icSendComplete: reasonSendDone
  of icDownloadRequest: reasonDownload
  of icDownloadRequestDir: reasonDownloadDir
  of icListFile: reasonListFile
  of icListDir: reasonListDir
  of icTimeoutClose: reasonTimeoutClose
  of icSessionError: reasonSessionError
  of icSessionIoError: reasonSessionIoError

proc toByte*(c: ErrorCode): byte = byte(c)
proc fromByte*(b: byte): ErrorCode =
  let v = uint8(b)
  if v <= uint8(high(ErrorCode)): ErrorCode(v) else: ecUnknown

proc toByte*(c: SuccessCode): byte = byte(c)
proc fromByteSc*(b: byte): SuccessCode =
  let v = uint8(b)
  if v <= uint8(high(SuccessCode)): SuccessCode(v) else: scUploadOk

proc toByte*(c: InfoCode): byte = byte(c)
proc fromByteIc*(b: byte): InfoCode =
  let v = uint8(b)
  if v <= uint8(high(InfoCode)): InfoCode(v) else: icDone

proc clientMessage*(c: ErrorCode): string =
  case c
  of ecExists: "file exists on remote server"
  of ecFilter: "skipped by filter"
  of ecNoSpace: "no space left"
  of ecPerms: "permission denied"
  of ecAbsolute: "absolute path not allowed"
  of ecUnsafePath: "unsafe path"
  of ecBadPath: "bad path"
  of ecBadPayload: "bad payload"
  of ecOpenFail: "open failed"
  of ecWriteFail: "write failed"
  of ecReadFail: "read failed"
  of ecNotFound: "item not found"
  of ecTimeout: "timeout"
  of ecChecksum: "checksum mismatch"
  of ecConfig: "server misconfigured"
  of ecCompat: "incompatible client/server"
  of ecAuth: "authentication required or failed"
  of ecSourceNotFound: "source not found"
  of ecFatal: "fatal error"
  of ecAborting: "aborting"
  else: "error"

proc clientMessage*(c: SuccessCode): string =
  case c
  of scUploadOk: "upload ok"
  of scUploadDone: "upload done"
  of scDownloadDone: "download done"
  of scListDone: "list done"

proc clientMessage*(c: InfoCode): string =
  case c
  of icDone: "done"
  of icSkipped: "skipped"
  of icTransferred: "transferred"
  of icListItem: ""

proc serverMessage*(c: ErrorCode): string =
  case c
  of ecExists: "refusing overwrite"
  of ecFilter: "filtered"
  of ecNoSpace: "disk full"
  of ecPerms: "access denied"
  of ecAbsolute: "absolute path not allowed"
  of ecUnsafePath: "unsafe path rejected"
  of ecBadPath: "bad path"
  of ecBadPayload: "bad payload"
  of ecOpenFail: "open failed"
  of ecWriteFail: "write failed"
  of ecReadFail: "read failed"
  of ecNotFound: "not found"
  of ecTimeout: "timeout"
  of ecChecksum: "checksum mismatch"
  of ecConfig: "server configuration error"
  of ecCompat: "feature/version mismatch"
  of ecAuth: "client authentication error"
  of ecSourceNotFound: "source not found"
  of ecFatal: "fatal error"
  of ecAborting: "aborting"
  else: "unknown"

proc serverMessage*(c: SuccessCode): string =
  case c
  of scUploadOk: "upload ok"
  of scUploadDone: "upload done"
  of scDownloadDone: "download done"
  of scListDone: "list done"

proc serverMessage*(c: InfoCode): string =
  case c
  of icDone: "done"
  of icSkipped: "skipped"
  of icTransferred: "transferred"
  of icListItem: "list item"
  of icClientConnected: "client connected"
  of icClientDisconnected: "client disconnected"
  of icHandshakeComplete: "handshake complete"
  of icUploadStart: "upload start"
  of icRekeyPropose: "rekey propose"
  of icClientSkipped: "client skipped"
  of icUnexpectedAck: "unexpected ack"
  of icSendFile: "send file"
  of icSendComplete: "send complete"
  of icDownloadRequest: "download request"
  of icDownloadRequestDir: "download request (dir)"
  of icListFile: "list file"
  of icListDir: "list dir"
  of icTimeoutClose: "session timeout; closing connection"
  of icSessionError: "session error"
  of icSessionIoError: "session I/O error"

import std/strformat

proc encodeClient*(c: ErrorCode, details: string = ""): string =
  var msg = fmt"[{codeName(c)}] {clientMessage(c)}"
  if details.len > 0:
    msg.add(fmt": {details}")
  msg
proc encodeClient*(c: SuccessCode): string = fmt"[{codeName(c)}] {clientMessage(c)}"
proc encodeClient*(c: InfoCode, details: string = ""): string =
  var msg = fmt"[{codeName(c)}] {clientMessage(c)}"
  if details.len > 0:
    msg.add(fmt": {details}")
  msg

proc encodeServer*(c: ErrorCode, details: string = ""): string =
  var msg = fmt"[{codeName(c)}] {serverMessage(c)}"
  if details.len > 0:
    msg.add(fmt": {details}")
  msg

proc encodeServer*(c: SuccessCode, details: string = ""): string =
  var msg = fmt"[{codeName(c)}] {serverMessage(c)}"
  if details.len > 0:
    msg.add(fmt": {details}")
  msg

proc encodeServer*(c: InfoCode, details: string = ""): string =
  var msg = fmt"[{codeName(c)}] {serverMessage(c)}"
  if details.len > 0:
    msg.add(fmt": {details}")
  msg

proc encodeReason*(code, message: string): string = fmt"[{code}] {message}"

proc splitReason*(msg: string): tuple[code, text: string] =
  ## If `msg` starts with "[code] ", extract code and remainder; otherwise code="".
  if msg.len >= 3 and msg[0] == '[':
    let idx = msg.find(']')
    if idx > 1 and idx+2 <= msg.high:
      let code = msg[1 .. idx-1]
      let rest = msg[min(idx+2, msg.len) .. ^1]
      return (code, rest)
  ("", msg)

proc reasonFromServerMsg*(msg: string): string =
  ## Map a server error message to a short reason code.
  ## Prefers a leading "[code] " prefix; falls back to heuristics.
  let (code, _) = splitReason(msg)
  if code.len > 0: return code
  if msg.startsWith(errFileExists): return reasonExists
  if msg.startsWith(errAbsolutePathSandbox): return reasonAbsolute
  if msg.startsWith(errUnsafePath): return reasonUnsafePath
  if msg.startsWith(errBadPath): return reasonBadPath
  if msg.startsWith(errBadPayload): return reasonBadPayload
  if msg.startsWith(errOpenFail): return reasonOpenFail
  if msg.startsWith(errWriteFail): return reasonWriteFail
  if msg.startsWith(errReadFail): return reasonReadFail
  if msg.startsWith(errNotFound): return reasonNotFound
  if msg.startsWith(errChecksumMismatch): return reasonChecksum
  return reasonUnknown

proc formatClientError*(msg: string): string =
  ## Standardize client-facing error messages using structured reason codes.
  ## If `msg` has a leading "[code] ", preserve it. Otherwise, infer a code
  ## from known error prefixes and wrap: "[code] message".
  let m = msg.strip()
  if m.len > 2 and m[0] == '[':
    return m
  # Prefer mapping via known server/client message prefixes
  let code = reasonFromServerMsg(m)
  if code != reasonUnknown:
    return encodeReason(code, m)
  # Add a generic code for unclassified messages
  return encodeReason(reasonUnknown, m)

proc osErrorToCode*(e: ref OSError, fallback: ErrorCode): ErrorCode =
  ## Map platform-specific OSError codes to protocol ErrorCode variants.
  when defined(posix):
    let c = cint(e.errorCode)
    if c == ENOSPC: return ecNoSpace
    if c == EACCES or c == EPERM: return ecPerms
  elif defined(windows):
    let c = int32(e.errorCode)
    if c == ERROR_DISK_FULL.int32 or c == ERROR_HANDLE_DISK_FULL.int32: return ecNoSpace
    if c == ERROR_ACCESS_DENIED.int32 or c == ERROR_WRITE_PROTECT.int32 or c == ERROR_SHARING_VIOLATION.int32: return ecPerms
  return fallback
