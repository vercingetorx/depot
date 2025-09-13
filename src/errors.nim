## Shared error/status message constants used in depot protocol payloads.
import std/strutils
when defined(posix): import posix
when defined(windows): import winlean

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
  reasonAuth* = "auth"
  reasonCommitFail* = "server failed to commit"
  reasonSkipped* = "file skipped"

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
    ecCommitFail
    ecSkipped

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
  of ecCommitFail: reasonCommitFail
  of ecSkipped: reasonSkipped
  else: reasonUnknown

proc toByte*(c: ErrorCode): byte = byte(c)
proc fromByte*(b: byte): ErrorCode =
  let v = uint8(b)
  if v <= uint8(high(ErrorCode)): ErrorCode(v) else: ecUnknown

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
  else: "error"

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
  else: "unknown"

import std/strformat

proc encodeClient*(c: ErrorCode): string = fmt"[{codeName(c)}] {clientMessage(c)}"
proc encodeServer*(c: ErrorCode): string = fmt"[{codeName(c)}] {serverMessage(c)}"

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


proc osErrorToCode*(e: ref OSError, fallback: ErrorCode): ErrorCode =
  ## Map platform-specific OSError codes to protocol ErrorCode variants.
  when defined(posix):
    let c = cint(e.errorCode)
    if c == ENOSPC: return ecNoSpace
    if c == EACCES or c == EPERM: return ecPerms
  elif defined(windows):
    let c = int32(e.errorCode)
    if c == ERROR_DISK_FULL.int32 or c ==
        ERROR_HANDLE_DISK_FULL.int32: return ecNoSpace
    if c == ERROR_ACCESS_DENIED.int32 or c == ERROR_WRITE_PROTECT.int32 or c ==
        ERROR_SHARING_VIOLATION.int32: return ecPerms
  return fallback
