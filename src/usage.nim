import std/[os, strutils, parseopt, logging, asyncdispatch, strformat]

proc usage*() =
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

proc usageServe*() =
  echo "depot serve [options]"
  echo "  --listen IP            Bind address (default from config)"
  echo "  --port N               TCP port to listen on"
  echo "  --base DIR             Base directory for default roots"
  echo "  --log LEVEL            Log level: debug|info|warn|error"
  echo "  --no-sandbox           Disable sandbox (allow absolute paths)"
  echo "  --allow-overwrite      Allow uploads to overwrite existing files"
  echo "  --key-pass PASS        Encrypt/load server key with this passphrase"
  echo "  --key-pass-file PATH   Read key passphrase from file"
  echo ""
  echo "Key management:"
  echo "  - First run requires a passphrase (\"--key-pass\" or \"--key-pass-file\") to"
  echo "    generate and store an encrypted server key (DPK1)."
  echo "  - Subsequent runs require the same passphrase to load the key."
  echo "  - Plaintext server keys are not supported."

proc usageConfig*() =
  echo "depot config --init [--force]"
  echo "  --init  Scaffold ~/.config/depot/depot.conf"
  echo "  --force Overwrite existing config"

proc usageExport*() =
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
  echo "Sandboxed server: --remote-dir must be relative to the server's upload area."
  echo "No-sandbox server: --remote-dir may be absolute."

proc usageImport*() =
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
  echo "Sandboxed server: --remote-dir must be relative to the server's download area."
  echo "No-sandbox server: --remote-dir may be absolute."

proc usageLs*() =
  echo "depot ls [options]"
  echo "  --host HOST            Server host"
  echo "  --port N               Server port (alias: --rport)"
  echo "  --rport N              Server port"
  echo "  --remote-dir DIR       Remote directory or file to list"
  echo "  --log LEVEL            Log level: debug|info|warn|error"
  echo ""
  echo "Sandboxed server: --remote-dir must be relative to the server's download area."
  echo "No-sandbox server: --remote-dir may be absolute."

proc usageFor*(mode: string) =
  case mode
  of "serve": usageServe()
  of "export": usageExport()
  of "import": usageImport()
  of "ls": usageLs()
  of "config": usageConfig()
  else: usage()
