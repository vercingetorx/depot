# <CURRENTLY IN ALPHA>

<!-- Center align -->
<div align="center">
  <img src="https://raw.githubusercontent.com/vercingetorx/depot/refs/heads/main/resources/depot_icon_with_letters_small.png" alt="depot_logo" width="250">
</div>

# depot — Secure File Transfer (Kyber + XChaCha20)

depot is a simple, post‑quantum‑ready file transfer tool. It favors a clean CLI, strong defaults, and explicit safety:

- Modern cryptography with CRYSTALS‑Kyber (KEM), CRYSTALS‑Dilithium (identity), Argon2 (KDF) and XChaCha20‑Poly1305 (AEAD).
- Sandboxed filesystem mode by default (no absolute paths; no escaping the share root).
- Clear, standardized error codes and live progress with a growing file history.

## Security Overview (brief)

- TOFU identity pinning with CRYSTALS‑Dilithium; Kyber KEM for session keys; Argon2 (session keys and key‑at‑rest); XChaCha20‑Poly1305 for records.
- Sandboxed filesystem mode by default (no absolute paths; normalized under roots).
- Atomic write/commit with integrity‑on‑commit checksums; partials removed on abort.

For full details (algorithms, transcript binding, nonce layout, rekey, wire formats), see CORE.md.

## Build

Requires Nim 2.x.

```
nim c -d:release depot.nim
```

## Quick Start

1) Scaffold a config (optional but recommended):

```
depot config --init
```

Edit `~/.config/depot/depot.conf` to set server/client defaults (see below).

2) Start the server (sandboxed by default):

```
depot serve --listen 0.0.0.0 --port 60006 --log info
```

3) Export files and directories (client → server import root):

```
# Use client default export root for relative names (server writes under importRoot)
depot export picture.jpg --host server

# Export into a specific remote subdirectory (sandbox requires relative)
depot export picture.jpg --host server --remote-dir photos/trips

# Export current directory instead of default export root (includes the top-level directory name)
depot export --here --all --host server
```

4) Import files (server export root → client):

```
# Default client destination: base/depot/import
depot import movie.mp4 --host server

# From a specific remote subdirectory (sandbox requires relative)
depot import movie.mp4 --host server --remote-dir videos/2024 --here

# Into current directory
depot import folder --host server --here

# Pull the entire share
depot import --all --host server
```

## CLI

```
depot serve [--listen IP] [--port N] [--base DIR] [--log LEVEL]
          [--unsafe-fs] [--export-root PATH] [--import-root PATH]

depot export FILE... [--host HOST] [--port N]
                   [--remote-dir DIR] [--here] [--all] [--log LEVEL]

depot import ITEM... [--host HOST] [--port N]
                   [--remote-dir DIR] [--dest LOCAL_DIR] [--here] [--all] [--log LEVEL]

depot config --init [--force]
# (alias)
depot --init [--force]

depot --version
```

Tips:
- In sandboxed mode (default), the server rejects absolute remote paths. Use relative paths under the share root; `..` segments are not allowed.
- In no-sandbox mode (`depot serve --no-sandbox`), absolute `--remote-dir` is allowed, and paths are resolved on the server as-is.
- `--here` on export with no FILE args exports the current directory; on import it writes to CWD.
- Run the client with `--log warn` for a clean progress line; raise to `info`/`debug` for troubleshooting.

## Config

`~/.config/depot/depot.conf`:

```
[Server]
listen = 0.0.0.0
port   = 60006
base   = /home/user/Downloads
sandbox = true

[Client]
host = your.server
port = 60006
log  = info
base = /home/user/Downloads
```

## Messages and Codes

- Wire carries only an error code (1 byte); both sides render standardized messages:
  - Client: `[code] <clientMessage(code)>`
  - Server: `[code] <serverMessage(code)>`
- Success and skip messages are local only (not sent on wire) and use typed success codes:
  - Examples: `[connected] ...`, `[handshake] ...`, `[send-start] ...`, `[send-complete] ...`, `[download-request] ...`, `[download-complete] ...`, `[list-*] ...`, `[skip] ...`, `[done] ...`, `[transferred] ...`.
- Progress: single‑line live update and a growing history of completed files.

See CORE.md for the canonical code list and mappings.

## Design Notes

- AEAD framing uses varint length + type + ciphertext + tag; type + sequence + epoch bind metadata.
- Nonces use a per-direction 16-byte prefix and a 64-bit counter; keys are derived with Argon2id bound to the handshake transcript.
- The server does not invoke a shell to parse paths; the protocol is structured and binary.

## Protocol Summary

- Record framing over TCP with AEAD; directory listings and file streaming records.
- Upload/Download completion is signaled with a checksum and commit.
- Ack for downloads uses `PathAccept` / `PathSkip` records without payloads; the record type is the signal.

For exact wire formats and record layouts, see CORE.md.

## Transfer Semantics

- Uploads write to `<dest>.part` and move into place only after checksum verification. On any error, partial files are removed.
- Downloads write to `<dest>.part` and move into place only after checksum verification.
- Metadata preservation: server → client and client → server preserve `mtime` and file permissions (portable FilePermission set).
- Directory export/import:
  - Exporting a directory includes the top‑level directory name (e.g., `dir1/...`).
  - Paths are normalized to forward slashes on the wire.
- Summary line: `Transferred X/Y file(s), SIZE[, skipped N]` where:
  - Y = total files discovered before transfer
  - X = successful transfers only (failures and skips are not added)
  - Exit code is non‑zero if any failures occurred
