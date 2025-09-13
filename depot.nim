## CLI entrypoint: subcommand parsing and dispatch to server/client.
import std/[os, strutils, parseopt, logging, asyncdispatch]
import src/[client, handshake, server, userconfig]

const version* = "0.1.0"
# const commit* {.strdefine.}: string = "unknown"

proc printVersion() =
  echo "depot v" & version


proc writeDefaultConfig(defaults: tuple[server: userconfig.ServerDefaults, client: userconfig.ClientDefaults], force: bool) =
  let path = userconfig.configPath()
  let confDir = splitFile(path).dir
  discard existsOrCreateDir(confDir)
  if fileExists(path) and not force:
    echo "Config already exists: ", path
    echo "Use --force to overwrite."
    return
  let tpl = """# depot configuration

[Server]
# listen = 0.0.0.0
# port = 60006
# base = """ & defaults.server.base & """
# When sandbox = true (default), absolute paths from clients are rejected,
# and all paths must resolve within the roots below.
sandbox = true

# Absolute roots for the server share (used in sandbox mode)
# exportRoot = """ & defaults.server.base & "/depot/export" & "\n" &
               "# importRoot = " & defaults.server.base & "/depot/import" & """

[Client]
""" &
             ("# host = " & defaults.client.host & "\n" &
              "# port = " & $defaults.client.port & "\n" &
              "# log  = " & defaults.client.log & "\n" &
              "# base = " & defaults.client.base & "\n")
  writeFile(path, tpl)
  echo "Wrote config: ", path

proc usage() =
  echo "depot: secure file transfer (Kyber + XChaCha20-Poly1305)"
  echo "usage:"
  echo "  depot --version"
  echo "  depot --init [--force]"
  echo "  depot serve [--help]"
  echo "  depot export [--help]"
  echo "  depot import [--help]"
  echo "  depot ls [--help]"
  echo "  depot config --init [--force]          # scaffold ~/.config/depot/depot.conf"
  echo ""
  echo "Use 'depot <subcommand> --help' to see all options."

proc usageServe() =
  echo "depot serve [options]"
  echo "  --listen IP            Bind address (default from config)"
  echo "  --port N               TCP port to listen on"
  echo "  --base DIR             Base directory for default roots"
  echo "  --log LEVEL            Log level: debug|info|warn|error"
  echo "  --unsafe-fs            Disable sandbox (allow absolute paths)"
  echo "  --no-sandbox           Alias of --unsafe-fs"
  echo "  --export-root DIR      Override export root (sandbox mode)"
  echo "  --import-root DIR      Override import root (sandbox mode)"
  echo "  --allow-overwrite      Allow uploads to overwrite existing files"
  echo "  --key-pass PASS        Encrypt/load server key with this passphrase"

proc usageConfig() =
  echo "depot config --init [--force]"
  echo "  --init  Scaffold ~/.config/depot/depot.conf"
  echo "  --force Overwrite existing config"

proc usageExport() =
  echo "depot export FILE... [options]"
  echo "  --host HOST            Server host"
  echo "  --port N               Server port (alias: --rport)"
  echo "  --rport N              Server port"
  echo "  --remote-dir DIR       Remote base directory (see below)"
  echo "  --here                 Resolve FILE relative to current directory"
  echo "  --all                  Export the entire default export root"
  echo "  --skip-existing        Skip files that already exist on server"
  echo "  --log LEVEL            Log level: debug|info|warn|error"
  echo ""
  echo "Sandboxed server: --remote-dir must be relative and maps under importRoot."
  echo "No-sandbox server: --remote-dir may be absolute."

proc usageImport() =
  echo "depot import ITEM... [options]"
  echo "  --host HOST            Server host"
  echo "  --port N               Server port (alias: --rport)"
  echo "  --rport N              Server port"
  echo "  --remote-dir DIR       Remote base directory (see below)"
  echo "  --dest LOCAL_DIR       Local destination directory"
  echo "  --local-dir LOCAL_DIR  Alias of --dest"
  echo "  --here                 Use current directory as destination"
  echo "  --all                  Import entire tree from remote source ('.')"
  echo "  --skip-existing        Skip local files that already exist"
  echo "  --log LEVEL            Log level: debug|info|warn|error"
  echo ""
  echo "Sandboxed server: --remote-dir must be relative and maps under exportRoot."
  echo "No-sandbox server: --remote-dir may be absolute."

proc usageLs() =
  echo "depot ls [options]"
  echo "  --host HOST            Server host"
  echo "  --port N               Server port (alias: --rport)"
  echo "  --rport N              Server port"
  echo "  --remote-dir DIR       Remote directory or file to list"
  echo "  --log LEVEL            Log level: debug|info|warn|error"
  echo ""
  echo "Sandboxed server: --remote-dir must be relative and maps under exportRoot."
  echo "No-sandbox server: --remote-dir may be absolute."

proc usageFor(mode: string) =
  case mode
  of "serve": usageServe()
  of "export": usageExport()
  of "import": usageImport()
  of "ls": usageLs()
  of "config": usageConfig()
  else: usage()

proc setupLogging(level: string) =
  ## Configure console logger with a consistent format and chosen level.
  var h = newConsoleLogger()
  h.fmtStr = "[$date $time] [$levelname] "
  addHandler(h)
  case level.toLowerAscii()
  of "debug": setLogFilter(lvlDebug)
  of "info": setLogFilter(lvlInfo)
  of "warn", "warning": setLogFilter(lvlWarn)
  of "error": setLogFilter(lvlError)
  else: setLogFilter(lvlInfo)

proc runConfig(defaults: tuple[server: userconfig.ServerDefaults, client: userconfig.ClientDefaults]) =
  ## Handle `depot config` subcommand. Currently supports `--init` and `--force`.
  var doInit = false
  var force = false
  var helpFlag = false
  var unknownFlags: seq[string]
  for kind, key, val in getopt():
    if kind in {cmdLongOption, cmdShortOption}:
      case key
      of "init": doInit = true
      of "force": force = true
      of "help", "h": helpFlag = true
      else:
        let flag = (if kind == cmdLongOption: "--" & key else: "-" & key)
        unknownFlags.add(flag)
  if helpFlag:
    echo "depot config --init [--force]"
    echo "  --init  Scaffold ~/.config/depot/depot.conf"
    echo "  --force Overwrite existing config"
    return
  if unknownFlags.len > 0:
    var msg = "Unknown option(s) for 'config': "
    for i, f in unknownFlags:
      if i > 0: msg &= ", "
      msg &= f
    stderr.writeLine(msg)
    stderr.writeLine("Valid: --init, --force")
    quit(1)
  if doInit:
    writeDefaultConfig(defaults, force)
    return
  usage()
  return

proc runServe(listen: string, port: int, baseDir: string, unsafeFs: bool, exportRootCli, importRootCli: string) =
  ## Handle `depot serve` subcommand.
  # Phase: configure sandbox + overrides, then start accept loop
  server.sandboxed = not unsafeFs
  if exportRootCli.len > 0: server.overrideExportRoot = exportRootCli
  if importRootCli.len > 0: server.overrideImportRoot = importRootCli
  info "server starting: listen=" & listen & ", port=" & $port & ", sandbox=" & $(server.sandboxed) & ", base=" & baseDir
  asyncCheck server.serve(listen, port, baseDir)
  runForever()

proc runExport(argsIn: var seq[string], hereFlag, allFlag: bool,
               remoteDest: string, skipExisting: bool,
               defaults: tuple[server: userconfig.ServerDefaults, client: userconfig.ClientDefaults],
               host: string, remotePort: int) =
  ## Handle `depot export` subcommand. Resolves paths based on flags and defaults,
  ## opens a session, and performs upload(s).
  # Phase 1: collect and resolve sources
  var args = argsIn
  try:
    if args.len == 0:
      if allFlag:
        let srcRoot = if hereFlag: getCurrentDir() else: defaults.client.base / "depot" / "export"
        args = @[srcRoot]
      elif hereFlag:
        args = @[getCurrentDir()]
      else:
        usage(); return
    else:
      if not hereFlag:
        var resolved: seq[string]
        let baseExport = defaults.client.base / "depot" / "export"
        for a in args:
          if a.len > 0 and a[0] == DirSep:
            resolved.add(a)
          elif a.len >= 2 and a[0] == '.' and (a[1] == DirSep or (a.len >= 3 and a[1] == '.' and a[2] == DirSep)):
            resolved.add(a)
          else:
            resolved.add(baseExport / a)
        args = resolved
    # Phase 2: open session and upload
    var sess = waitFor client.openSession(host, remotePort)
    waitFor client.uploadPaths(sess, args, remoteDest, skipExisting)
  except CatchableError as e:
    stderr.writeLine(e.msg)
    quit(1)
  except OSError as e:
    stderr.writeLine(e.msg)
    quit(1)

proc runImport(args: seq[string], hereFlag, allFlag: bool,
               remoteSource: string, localDestIn: string,
               host: string, remotePort: int, skipExisting: bool) =
  ## Handle `depot import` subcommand. Downloads file or directory tree.
  try:
    # Phase 1: resolve destination and items
    var localDest = localDestIn
    var items = args
    if allFlag:
      items = @["."]
    if items.len < 1:
      usage(); return
    if hereFlag:
      localDest = getCurrentDir()
    if localDest.len > 0:
      discard existsOrCreateDir(localDest)
    # Phase 2: open session and download
    var sess = waitFor client.openSession(host, remotePort)
    for item in items:
      let remotePath = if remoteSource.len > 0: (remoteSource / item).replace("\\", "/") else: item
      waitFor client.downloadTo(sess, remotePath, localDest, skipExisting)
  except CatchableError as e:
    stderr.writeLine(e.msg)
    quit(1)
  except OSError as e:
    stderr.writeLine(e.msg)
    quit(1)

proc runLs(remotePath: string,
            defaults: tuple[server: userconfig.ServerDefaults, client: userconfig.ClientDefaults],
            host: string, remotePort: int) =
  ## Handle `depot ls` subcommand. Lists files remotely without copying.
  try:
    var sess = waitFor client.openSession(host, remotePort)
    waitFor client.listRemote(sess, remotePath)
  except CatchableError as e:
    stderr.writeLine(e.msg)
    quit(1)
  except OSError as e:
    stderr.writeLine(e.msg)
    quit(1)

proc main() =
  let defaults = userconfig.readConfig()
  var listen = defaults.server.listen
  var port = defaults.server.port
  var base = defaults.server.base
  var args: seq[string]
  var mode = ""
  var logLevel = defaults.client.log
  var host = defaults.client.host
  var remotePort = defaults.client.port
  var remoteDest = ""
  var remoteSource = ""
  var remoteList = ""
  var localDest = defaults.client.base / "depot" / "import"
  var allFlag = false
  var unsafeFs = defaults.server.sandbox == false
  var exportRootCli = ""
  var importRootCli = ""
  var hereFlag = false
  var helpFlag = false
  var skipExisting = false
  var allowOverwrite = false
  var versionFlag = false
  var topInitFlag = false
  var topForceFlag = false
  var keyPass = ""
  var unknownFlags: seq[string]
  var expectValueFor = ""
  # Option helpers to DRY up parsing/apply logic
  proc needsValue(opt: string): bool =
    ## Return true if this option expects a value
    case opt
    of "listen", "port", "base", "log", "host",
       "remote-dir", "dest", "local-dir", "rport",
       "export-root", "import-root", "key-pass": true
    else: false

  proc applyOpt(opt: string, val: string) =
    ## Apply a normalized (hyphenated, lowercase) option to state.
    case opt
    of "listen": listen = val
    of "port":
      port = parseInt(val); remotePort = port
    of "base": base = val
    of "log": logLevel = val
    of "version", "v": versionFlag = true
    of "init": topInitFlag = true
    of "force": topForceFlag = true
    of "host": host = val
    of "remote-dir":
      if mode == "export": remoteDest = val
      elif mode == "import": remoteSource = val
      elif mode == "ls": remoteList = val
    of "dest", "local-dir":
      if mode == "import": localDest = val
    of "rport": remotePort = parseInt(val)
    of "all": allFlag = true
    of "unsafe-fs", "no-sandbox": unsafeFs = true
    of "export-root": exportRootCli = val
    of "import-root": importRootCli = val
    of "allow-overwrite": allowOverwrite = true
    of "key-pass": keyPass = val
    of "here": hereFlag = true
    of "help", "h": helpFlag = true
    of "skip-existing", "skip": skipExisting = true
    else:
      let flag = if opt.len > 1 and opt[0] == '-': opt else: "--" & opt
      unknownFlags.add(flag)
  for kind, key, val in getopt():
    case kind
    of cmdArgument:
      if expectValueFor.len > 0:
        applyOpt(expectValueFor, key)
        expectValueFor = ""
      else:
        if mode == "":
          if key == "help": helpFlag = true else: mode = key
        else:
          args.add(key)
    of cmdLongOption, cmdShortOption:
      let kcanon = key.replace('_', '-')
      if needsValue(kcanon) and val.len == 0:
        expectValueFor = kcanon
        continue
      if needsValue(kcanon):
        applyOpt(kcanon, val)
      else:
        applyOpt(kcanon, "")
    of cmdEnd: discard

  # Handle options that were missing their value (e.g., --remote-dir without DIR)
  if expectValueFor.len > 0:
    unknownFlags.add("--" & expectValueFor & " (missing value)")

  setupLogging(logLevel)
  # Global version
  if versionFlag and mode == "":
    printVersion(); quit(0)

  # Top-level init convenience (alias of `depot config --init`)
  if topInitFlag and mode == "":
    writeDefaultConfig(defaults, topForceFlag)
    quit(0)

  # Global/subcommand help
  if helpFlag:
    usageFor(mode)
    quit(0)
  # Report any unknown flags early (e.g., misspelled --here)
  if unknownFlags.len > 0:
    var msg = "Unknown option(s): "
    for i, f in unknownFlags:
      if i > 0: msg &= ", "
      msg &= f
    stderr.writeLine(msg)
    usageFor(mode)
    quit(1)
  case mode
  of "config":
    runConfig(defaults)
  of "serve":
    server.allowOverwrite = allowOverwrite
    handshake.serverKeyPassphrase = keyPass
    runServe(listen, port, base, unsafeFs, exportRootCli, importRootCli)
  of "export":
    runExport(args, hereFlag, allFlag, remoteDest, skipExisting, defaults, host, remotePort)
  of "import":
    runImport(args, hereFlag, allFlag, remoteSource, localDest, host, remotePort, skipExisting)
  of "ls":
    runLs(remoteList, defaults, host, remotePort)
  else:
    usage()

when isMainModule:
  try:
    main()
  except CatchableError as e:
    stderr.writeLine(e.msg)
    quit(1)
  except OSError as e:
    stderr.writeLine(e.msg)
    quit(1)
