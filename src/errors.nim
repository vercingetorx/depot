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
  reasonChecksum* = "checksum"
  # Handshake/administrative categories
  reasonConfig* = "server-config"
  reasonCompat* = "compat"
  reasonAuth* = "auth"
  reasonUnknown* = "unknown"

  # Success reasons
  reasonSuccess* = "success"
  reasonUploaded* = "uploaded"
  reasonDownloaded* = "downloaded"
  reasonListed* = "listed"
  reasonSkipped* = "skipped"

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
    ecSkipped

  SuccessCode* = enum
    scSuccess = 128'u8 # Start success codes from 128 to avoid overlap with error codes
    scUploaded
    scDownloaded
    scListed
    scSkipped

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
  of ecSkipped: reasonSkipped
  else: reasonUnknown

proc codeName*(c: SuccessCode): string =
  case c
  of scUploaded: reasonUploaded
  of scDownloaded: reasonDownloaded
  of scListed: reasonListed
  of scSkipped: reasonSkipped
  else: reasonSuccess

proc toByte*(c: ErrorCode): byte = byte(c)
proc toByte*(c: SuccessCode): byte = byte(c)

proc fromByte*(b: byte): ErrorCode =
  let v = uint8(b)
  if v <= uint8(high(ErrorCode)): ErrorCode(v) else: ecUnknown

proc clientMessage*(c: ErrorCode): string =
  case c
  of ecExists: "File exists on remote server."
  of ecFilter: "File skipped by filter."
  of ecNoSpace: "No space left on device."
  of ecPerms: "Permission denied."
  of ecAbsolute: "Absolute paths are not allowed."
  of ecUnsafePath: "Unsafe path detected."
  of ecBadPath: "Invalid path specified."
  of ecBadPayload: "Invalid data received from server."
  of ecOpenFail: "Failed to open file."
  of ecWriteFail: "Failed to write to file."
  of ecReadFail: "Failed to read from file."
  of ecNotFound: "File or directory not found."
  of ecTimeout: "Connection timed out."
  of ecChecksum: "File checksum mismatch."
  of ecConfig: "Server is misconfigured."
  of ecCompat: "Incompatible client/server version."
  of ecAuth: "Authentication failed."
  of ecSkipped: "File skipped."
  else: "An unknown error occurred."

proc serverMessage*(c: ErrorCode, detail: string = ""): string =
  let baseMsg = case c
    of ecExists: "Refusing to overwrite existing file."
    of ecFilter: "File skipped by filter."
    of ecNoSpace: "Disk full."
    of ecPerms: "Access denied."
    of ecAbsolute: "Absolute path rejected."
    of ecUnsafePath: "Unsafe path rejected."
    of ecBadPath: "Invalid path specified."
    of ecBadPayload: "Invalid data received from client."
    of ecOpenFail: "Failed to open file."
    of ecWriteFail: "Failed to write to file."
    of ecReadFail: "Failed to read from file."
    of ecNotFound: "File or directory not found."
    of ecTimeout: "Connection timed out."
    of ecChecksum: "File checksum mismatch."
    of ecConfig: "Server configuration error."
    of ecCompat: "Feature or version mismatch."
    of ecAuth: "Client authentication error."
    of ecSkipped: "File skipped by client."
    else: "An unknown error occurred."
  if detail.len > 0:
    baseMsg & " " & detail
  else:
    baseMsg

proc clientMessage*(c: SuccessCode): string =
  case c
  of scUploaded: "File uploaded successfully."
  of scDownloaded: "File downloaded successfully."
  of scListed: "Directory listed successfully."
  of scSkipped: "File skipped."
  else: "Operation completed successfully."

proc serverMessage*(c: SuccessCode, detail: string = ""): string =
  let baseMsg = case c
    of scUploaded: "File uploaded successfully."
    of scDownloaded: "File downloaded successfully."
    of scListed: "Directory listed successfully."
    of scSkipped: "File skipped."
    else: "Operation completed successfully."
  if detail.len > 0:
    baseMsg & " " & detail
  else:
    baseMsg

import std/strformat

proc encodeClient*(c: ErrorCode): string = fmt"[{codeName(c)}] {clientMessage(c)}"
proc encodeClient*(c: SuccessCode): string = fmt"[{codeName(c)}] {clientMessage(c)}"
proc encodeServer*(c: ErrorCode, detail: string = ""): string = fmt"[{codeName(c)}] {serverMessage(c, detail)}"
proc encodeServer*(c: SuccessCode, detail: string = ""): string = fmt"[{codeName(c)}] {serverMessage(c, detail)}"

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
