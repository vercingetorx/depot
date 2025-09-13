import std/[os, parsecfg, streams, strutils]

type
  ServerDefaults* = object
    listen*: string
    port*: int
    base*: string
    exportRoot*: string
    importRoot*: string
    sandbox*: bool
    psk*: string
    requireClientAuth*: bool
  ClientDefaults* = object
    host*: string
    port*: int
    log*: string
    base*: string
    psk*: string

proc configPath*(): string =
  ## Return the path to the user's depot configuration file.
  getEnv("XDG_CONFIG_HOME", getEnv("HOME") / ".config") / "depot" / "depot.conf"

proc parseBool(s: string): bool =
  let v = s.toLowerAscii()
  v in ["1", "true", "yes", "on"]

proc readConfig*(): tuple[server: ServerDefaults, client: ClientDefaults] =
  ## Load configuration from configPath(), overlaying hard defaults.
  # Hard defaults
  result.server.listen = "0.0.0.0"
  result.server.port = 60006
  result.server.base = getEnv("XDG_DOWNLOAD_DIR", getEnv("HOME") / "Downloads")
  result.server.exportRoot = ""
  result.server.importRoot = ""
  result.server.sandbox = true
  result.server.psk = ""
  result.server.requireClientAuth = false
  result.client.host = "localhost"
  result.client.port = 60006
  result.client.log = "info"
  result.client.base = getEnv("XDG_DOWNLOAD_DIR", getEnv("HOME") / "Downloads")
  result.client.psk = ""

  let path = configPath()
  if not fileExists(path):
    return

  var fs = newFileStream(path, fmRead)
  if fs.isNil: return
  var p: CfgParser
  open(p, fs, path)
  var section = ""
  while true:
    let e = next(p)
    case e.kind
    of cfgEof: break
    of cfgSectionStart:
      section = e.section
    of cfgKeyValuePair:
      case section
      of "Server":
        case e.key.toLowerAscii()
        of "listen": result.server.listen = e.value
        of "port":
          try: result.server.port = parseInt(e.value) except: discard
        of "base": result.server.base = e.value
        of "exportroot": result.server.exportRoot = e.value
        of "importroot": result.server.importRoot = e.value
        of "sandbox":
          result.server.sandbox = parseBool(e.value)
        of "psk": result.server.psk = e.value
        of "requireclientauth":
          result.server.requireClientAuth = parseBool(e.value)
        else: discard
      of "Client":
        case e.key.toLowerAscii()
        of "host": result.client.host = e.value
        of "port":
          try: result.client.port = parseInt(e.value) except: discard
        of "log": result.client.log = e.value
        of "base": result.client.base = e.value
        of "psk": result.client.psk = e.value
        else: discard
      else: discard
    else: discard
  close(p)
