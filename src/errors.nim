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
  reasonClosed* = "closed"
  reasonConnect* = "connect"
  reasonProtocol* = "protocol"
  reasonCommitFail* = "commit-fail"
  reasonConflict* = "conflict"
  reasonBadRemote* = "bad-remote"
  # Handshake/administrative categories
  reasonConfig* = "server-config"
  reasonCompat* = "compat"
  reasonAuth*   = "auth"

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
    ecClosed
    ecConnect
    ecProtocol
    ecCommitFail
    ecConflict
    ecBadRemote
    ecConfig
    ecCompat
    ecAuth

proc errorName*(c: ErrorCode): string =
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
  of ecClosed: reasonClosed
  of ecConnect: reasonConnect
  of ecProtocol: reasonProtocol
  of ecCommitFail: reasonCommitFail
  of ecConflict: reasonConflict
  of ecBadRemote: reasonBadRemote
  of ecConfig: reasonConfig
  of ecCompat: reasonCompat
  of ecAuth: reasonAuth
  else: reasonUnknown

proc toByte*(c: ErrorCode): byte = byte(c)
proc fromByte*(b: byte): ErrorCode =
  let v = uint8(b)
  if v <= uint8(high(ErrorCode)): ErrorCode(v) else: ecUnknown

type
  Audience* = enum
    auClient, auServer

proc messageText*(c: ErrorCode, a: Audience): string =
  ## Return a short human-oriented message for an ErrorCode, tailored by audience.
  case a
  of auClient:
    case c
    of ecExists: "file exists"
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
    of ecClosed: "connection closed unexpectedly"
    of ecConnect: "couldn't connect to server"
    of ecProtocol: "protocol error"
    of ecCommitFail: "commit failed on server"
    of ecConflict: "conflicting destination"
    of ecBadRemote: "invalid remote spec"
    of ecConfig: "server misconfigured"
    of ecCompat: "incompatible client/server"
    of ecAuth: "authentication required or failed"
    else: "error"
  of auServer:
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
    of ecClosed: "peer closed connection"
    of ecConnect: "client connection error"
    of ecProtocol: "protocol violation"
    of ecCommitFail: "commit failed"
    of ecConflict: "conflict"
    of ecBadRemote: "bad remote spec"
    of ecConfig: "server configuration error"
    of ecCompat: "feature/version mismatch"
    of ecAuth: "client authentication error"
    else: "unknown"

import std/strformat

type
  CodedError* = object of CatchableError
    code*: ErrorCode

proc newCodedError*(code: ErrorCode, message: string): ref CodedError =
  ## Construct a coded exception carrying an ErrorCode and a message.
  result = newException(CodedError, message)
  result.code = code

proc encodeError*(c: ErrorCode, a: Audience): string = fmt"[{errorName(c)}] {messageText(c, a)}"

# Success/status codes (typed)
type
  SuccessCode* = enum
    scConnected
    scHandshake
    scUploadStart
    scUploadComplete
    scSendStart
    scSendComplete
    scDownloadRequest
    scDownloadComplete
    scListFile
    scListDir
    scListComplete
    scRekey
    scDisconnected
    scTransferred
    scDone
    scSkip
    scAbort

proc successName*(c: SuccessCode): string =
  case c
  of scConnected: "connected"
  of scHandshake: "handshake"
  of scUploadStart: "upload-start"
  of scUploadComplete: "upload-complete"
  of scSendStart: "send-start"
  of scSendComplete: "send-complete"
  of scDownloadRequest: "download-request"
  of scDownloadComplete: "download-complete"
  of scListFile: "list-file"
  of scListDir: "list-dir"
  of scListComplete: "list-complete"
  of scRekey: "rekey"
  of scDisconnected: "disconnected"
  of scTransferred: "transferred"
  of scDone: "\e[32mdone\e[00m"
  of scSkip: "skip"
  of scAbort: "abort"

proc status*(code: SuccessCode, message: string): string = fmt"[{successName(code)}] {message}"

proc render*(e: ref CatchableError, a: Audience): string =
  ## Render a CatchableError as an audience-facing "[code] message" string.
  if e of CodedError:
    let ce = cast[ref CodedError](e)
    if ce.msg.len > 0:
      return fmt"{encodeError(ce.code, a)}: {ce.msg}"
    return encodeError(ce.code, a)
  # Fallback for non-coded errors
  let m = e.msg.strip()
  if m.len == 0: return encodeError(ecUnknown, a) else: fmt"{encodeError(ecUnknown, a)}: {m}"

# Error severity policy helpers
proc getErrorCode*(e: ref CatchableError): ErrorCode =
  if e of CodedError: return cast[ref CodedError](e).code
  ecUnknown

proc isSessionFatal*(c: ErrorCode): bool =
  c in {ecClosed, ecTimeout, ecProtocol, ecCompat, ecAuth, ecConfig, ecConnect}

proc isLocalFatal*(c: ErrorCode): bool =
  c in {ecNoSpace, ecPerms, ecOpenFail, ecWriteFail, ecReadFail}

proc isPerItem*(c: ErrorCode): bool =
  c in {ecExists, ecNotFound, ecBadPath, ecUnsafePath, ecAbsolute, ecChecksum, ecFilter}

# Legacy PathSkip reason mapping has been removed; PathSkip carries no payload.

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
