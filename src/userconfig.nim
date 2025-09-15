import std/[os, parsecfg, streams, strutils]

type
  ## Server-side defaults loaded from config with sensible fallbacks.
  ServerDefaults* = object
    listen*: string             ## IP address to bind (e.g., 0.0.0.0)
    port*: int                  ## TCP port
    base*: string               ## Base directory used for depot roots
    sandbox*: bool              ## Whether server enforces sandboxed paths
    psk*: string                ## Optional pre-shared key (binds handshake)
    requireClientAuth*: bool    ## Require client identity pinning/auth
  ## Client-side defaults loaded from config with sensible fallbacks.
  ClientDefaults* = object
    host*: string               ## Default server host for CLI
    port*: int                  ## Default server port for CLI
    log*: string                ## Default log level for CLI
    base*: string               ## Default local base directory
    psk*: string                ## Optional pre-shared key

proc configPath*(): string =
  ## Return the path to the user's depot configuration file.
  getEnv("XDG_CONFIG_HOME", getEnv("HOME") / ".config") / "depot" / "depot.conf"

proc parseBool(s: string): bool =
  ## Parse a common set of boolean string forms.
  let v = s.toLowerAscii()
  v in ["1", "true", "yes", "on"]

proc readConfig*(): tuple[server: ServerDefaults, client: ClientDefaults] =
  ## Load configuration from configPath(), overlaying hard defaults.
  ## Unknown keys are ignored to allow forward-compatible additions.
  # Hard defaults
  result.server.listen = "0.0.0.0"
  result.server.port = 60006
  result.server.base = getEnv("XDG_DOWNLOAD_DIR", getEnv("HOME") / "Downloads")
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

  # Parse INI-like config using std/parsecfg
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
      # Apply recognized keys in a section-scoped switch
      case section
      of "Server":
        case e.key.toLowerAscii()
        of "listen": result.server.listen = e.value
        of "port":
          try: result.server.port = parseInt(e.value) except: discard
        of "base": result.server.base = e.value
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
