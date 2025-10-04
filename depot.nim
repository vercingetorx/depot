## CLI entrypoint: subcommand parsing and dispatch to server/client.
import std/[os, strutils, parseopt, logging, asyncdispatch, strformat, times]
import src/[client, handshake, server, userconfig, errors]

const version* = "0.1.0"
# const commit* {.strdefine.}: string = "unknown"


proc printVersion() =
  ## Print program version. Keep simple for piping/grepping.
  echo fmt"depot v{version}"


proc writeDefaultConfig(defaults: tuple[server: userconfig.ServerDefaults, client: userconfig.ClientDefaults], force: bool) =
  let path = userconfig.configPath()
  let confDir = splitFile(path).dir
  discard existsOrCreateDir(confDir)
  if fileExists(path) and not force:
    echo "Config already exists: ", path
    echo "Use --force to overwrite."
    return
  let tpl = fmt"""# depot configuration

[Server]
# listen = 0.0.0.0
# port = 60006
# base = "{defaults.server.base}"
# When sandbox = true (default), absolute paths from clients are rejected,
# and all paths must resolve within server-managed roots derived from --base.
sandbox = true

[Client]
# host = {defaults.client.host}
# port = {defaults.client.port}
# log  = {defaults.client.log}
# base = {defaults.client.base}
"""
  writeFile(path, tpl)
  echo "Wrote config: ", path


proc usage() =
  stderr.writeLine("depot: secure file transfer (Kyber + XChaCha20-Poly1305)")
  stderr.writeLine("usage:")
  stderr.writeLine("  depot --version")
  stderr.writeLine("  depot --init [--force]")
  stderr.writeLine("  depot serve [--help]")
  stderr.writeLine("  depot export [--help]")
  stderr.writeLine("  depot import [--help]")
  stderr.writeLine("  depot ls [--help]")
  stderr.writeLine("  depot config --init [--force]          # scaffold ~/.config/depot/depot.conf")
  stderr.writeLine("")
  stderr.writeLine("Use 'depot <subcommand> --help' to see all options.")


proc usageServe() =
  stderr.writeLine("depot serve [options]")
  stderr.writeLine("  --listen IP            Bind address (default from config)")
  stderr.writeLine("  --port N               TCP port to listen on")
  stderr.writeLine("  --base DIR             Base directory for default roots")
  stderr.writeLine("  --log LEVEL            Log level: debug|info|warn|error")
  stderr.writeLine("  --no-sandbox           Disable sandbox (allow absolute paths)")
  stderr.writeLine("  --allow-overwrite      Allow uploads to overwrite existing files")
  stderr.writeLine("  --key-pass PASS        Encrypt/load server key with this passphrase")
  stderr.writeLine("  --key-pass-file PATH   Read key passphrase from file")
  stderr.writeLine("")
  stderr.writeLine("Key management:")
  stderr.writeLine("  - First run requires a passphrase (\"--key-pass\" or \"--key-pass-file\") to")
  stderr.writeLine("    generate and store an encrypted server key (DPK1).")
  stderr.writeLine("  - Subsequent runs require the same passphrase to load the key.")
  stderr.writeLine("  - Plaintext server keys are not supported.")


proc usageConfig() =
  stderr.writeLine("depot config --init [--force]")
  stderr.writeLine("  --init  Scaffold ~/.config/depot/depot.conf")
  stderr.writeLine("  --force Overwrite existing config")


proc usageExport() =
  stderr.writeLine("depot export FILE... [options]")
  stderr.writeLine("  --host HOST            Server host")
  stderr.writeLine("  --port N               Server port (alias: --rport)")
  stderr.writeLine("  --rport N              Server port")
  stderr.writeLine("  --remote-dir DIR       Remote base directory (see below)")
  stderr.writeLine("  --here                 Resolve FILE relative to current directory")
  stderr.writeLine("  --all                  Export the entire default export root")
  stderr.writeLine("  --skip-existing        Skip files that already exist on server")
  stderr.writeLine("  --log LEVEL            Log level: debug|info|warn|error")
  stderr.writeLine("")
  stderr.writeLine("Sandboxed server: --remote-dir must be relative to the server's upload area.")
  stderr.writeLine("No-sandbox server: --remote-dir may be absolute.")


proc usageImport() =
  stderr.writeLine("depot import ITEM... [options]")
  stderr.writeLine("  --host HOST            Server host")
  stderr.writeLine("  --port N               Server port (alias: --rport)")
  stderr.writeLine("  --rport N              Server port")
  stderr.writeLine("  --remote-dir DIR       Remote base directory (see below)")
  stderr.writeLine("  --dest LOCAL_DIR       Local destination directory")
  stderr.writeLine("  --local-dir LOCAL_DIR  Alias of --dest")
  stderr.writeLine("  --here                 Use current directory as destination")
  stderr.writeLine("  --all                  Import entire tree from remote source ('.')")
  stderr.writeLine("  --skip-existing        Skip local files that already exist")
  stderr.writeLine("  --log LEVEL            Log level: debug|info|warn|error")
  stderr.writeLine("")
  stderr.writeLine("Sandboxed server: --remote-dir must be relative to the server's download area.")
  stderr.writeLine("No-sandbox server: --remote-dir may be absolute.")


proc usageLs() =
  stderr.writeLine("depot ls [options]")
  stderr.writeLine("  --host HOST            Server host")
  stderr.writeLine("  --port N               Server port (alias: --rport)")
  stderr.writeLine("  --rport N              Server port")
  stderr.writeLine("  --remote-dir DIR       Remote directory or file to list")
  stderr.writeLine("  --log LEVEL            Log level: debug|info|warn|error")
  stderr.writeLine("")
  stderr.writeLine("Sandboxed server: --remote-dir must be relative to the server's download area.")
  stderr.writeLine("No-sandbox server: --remote-dir may be absolute.")


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
  # Parse CLI args with std/parseopt (supports long/short opts and args).
  for kind, key, val in getopt():
    if kind in {cmdLongOption, cmdShortOption}:
      case key
      of "init": doInit = true
      of "force": force = true
      of "help", "h": helpFlag = true
      else:
        let flag = (if kind == cmdLongOption: fmt"--{key}" else: fmt"-{key}")
        unknownFlags.add(flag)
  if helpFlag:
    stderr.writeLine("depot config --init [--force]")
    stderr.writeLine("  --init  Scaffold ~/.config/depot/depot.conf")
    stderr.writeLine("  --force Overwrite existing config")
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


proc runServe(listen: string, port: int, baseDir: string, unsafeFs: bool) =
  ## Handle `depot serve` subcommand.
  # Phase: configure sandbox + overrides, then start accept loop
  server.sandboxed = not unsafeFs
  # Preflight: ensure server identity is available before listening. This
  # prevents starting a misconfigured server that would only fail on handshake.
  try:
    discard handshake.ensureServerIdentity()
  except handshake.HandshakeError as e:
    stderr.writeLine(e.msg)
    quit(1)
  # Preflight: ensure base/depot/export and base/depot/import exist
  try:
    discard server.ensureBaseDirs(baseDir)
  except CatchableError as e:
    stderr.writeLine(fmt"failed to prepare base directories: {e.msg}")
    quit(1)
  info fmt"server starting: listen={listen}, port={port}, sandbox={server.sandboxed}, base={baseDir}"
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
        usageExport(); return
    else:
      if not hereFlag:
        # When not using --here, resolve relative args against the default
        # export base so `depot export foo/bar` finds $BASE/depot/export/foo/bar.
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
    waitFor client.sendMany(sess, args, remoteDest, skipExisting)
  except CatchableError as e:
    stderr.writeLine(errors.render(e, errors.auClient))
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
      usageImport(); return
    if hereFlag:
      localDest = getCurrentDir()
    if localDest.len > 0:
      createDir(localDest)
    # Phase 2: open session and download
    var sess = waitFor client.openSession(host, remotePort)
    var rps: seq[string]
    for item in items:
      # Join source directory and item, normalizing to forward slashes for wire.
      let rp = if remoteSource.len > 0: (remoteSource / item).replace("\\", "/") else: item
      rps.add(rp)
    # Perform a single multi-item receive to avoid duplicate attempts and
    # ensure one session-wide summary is printed.
    waitFor client.recvMany(sess, rps, localDest, skipExisting)
  except CatchableError as e:
    stderr.writeLine(errors.render(e, errors.auClient))
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
    waitFor client.list(sess, remotePath)
  except CatchableError as e:
    stderr.writeLine(errors.render(e, errors.auClient))
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
  var hereFlag = false
  var helpFlag = false
  var skipExisting = false
  var allowOverwrite = false
  var versionFlag = false
  var topInitFlag = false
  var topForceFlag = false
  var keyPass = ""
  var keyPassFilePath = ""
  var unknownFlags: seq[string]
  var expectValueFor = ""
  var failures = false
  # Option helpers to DRY up parsing/apply logic
  proc needsValue(opt: string): bool =
    ## Return true if this option expects a value
    case opt
    of "listen", "port", "base", "log", "host",
       "remote-dir", "dest", "local-dir", "rport",
       "key-pass", "key-pass-file", "failures": true
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
    of "no-sandbox": unsafeFs = true
    of "allow-overwrite": allowOverwrite = true
    of "key-pass": keyPass = val
    of "key-pass-file": keyPassFilePath = val
    of "failures": failures = true
    of "here": hereFlag = true
    of "help", "h": helpFlag = true
    of "skip-existing", "skip": skipExisting = true
    else:
      let flag = if opt.len > 1 and opt[0] == '-': opt else: fmt"--{opt}"
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
    unknownFlags.add(fmt"--{expectValueFor} (missing value)")

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
    let msg = "Unknown option(s): " & unknownFlags.join(", ")
    stderr.writeLine(msg)
    usageFor(mode)
    quit(1)
  # If a passphrase file was specified, load it now (unless --key-pass already set)
  if keyPass.len == 0 and keyPassFilePath.len > 0:
    try:
      keyPass = readFile(keyPassFilePath).strip()
    except CatchableError as e:
      stderr.writeLine(fmt"failed to read --key-pass-file: {keyPassFilePath}: {e.msg}")
      quit(1)
  case mode
  of "config":
    runConfig(defaults)
  of "serve":
    server.allowOverwrite = allowOverwrite
    handshake.serverKeyPassphrase = keyPass
    runServe(listen, port, base, unsafeFs)
  of "export":
    client.resetFailures()
    runExport(args, hereFlag, allFlag, remoteDest, skipExisting, defaults, host, remotePort)
    if failures:
      let n = client.failuresCount()
      if n > 0:
        let ts = now()
        let outFile = defaults.client.base / "depot" / fmt"failures-{ts.year:04}{ts.month:02}{ts.monthday:02}-{ts.hour:02}{ts.minute:02}{ts.second:02}.txt"
        client.writeFailures(outFile)
        echo fmt"Failures: {n} (see {outFile})"
  of "import":
    client.resetFailures()
    runImport(args, hereFlag, allFlag, remoteSource, localDest, host, remotePort, skipExisting)
    if failures:
      let n = client.failuresCount()
      if n > 0:
        let ts = now()
        let outFile = defaults.client.base / "depot" / fmt"failures-{ts.year:04}{ts.month:02}{ts.monthday:02}-{ts.hour:02}{ts.minute:02}{ts.second:02}.txt"
        client.writeFailures(outFile)
        echo fmt"Failures: {n} (see {outFile})"
  of "ls":
    runLs(remoteList, defaults, host, remotePort)
  else:
    usage()


when isMainModule:
  try:
    main()
  except CatchableError as e:
    stderr.writeLine(errors.render(e, errors.auClient))
    quit(1)
  except OSError as e:
    stderr.writeLine(e.msg)
    quit(1)
