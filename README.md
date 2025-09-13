# WIP

# Depot — Secure File Transfer (Kyber + XChaCha20)

Depot is a simple, post‑quantum‑ready file transfer tool. It favors a clean CLI, strong defaults, and explicit safety:

- Modern cryptography with CRYSTALS‑Kyber (KEM), CRYSTALS‑Dilithium (identity), Argon2 (KDF), XChaCha20‑Poly1305 (AEAD).
- Sandboxed filesystem mode by default (no absolute paths; no escaping the share root).
- Clear, friendly error messages and live progress with a growing file history.

## Security Overview

- Handshake
  - KEM: CRYSTALS‑Kyber derives a 32‑byte shared secret.
  - Identity: CRYSTALS‑Dilithium public key is sent by the server and pinned on first use (TOFU). Subsequent connects must match the pinned key.
  - Key Schedule: Argon2id (64 MiB, 2 passes) over the Kyber secret, salted with per‑direction 16‑byte prefixes and bound to the handshake transcript (BLAKE2b). Output is split into client→server and server→client traffic keys.
  - Server private key at rest: if `--key-pass PASS` is provided when generating/starting the server, the key is stored encrypted (Argon2id KDF + XChaCha20‑Poly1305) in a DPK1 format. Without a passphrase, it is stored in plaintext (not recommended on multi‑user systems).

- Records (data and control)
  - AEAD: XChaCha20-Poly1305 with a 24-byte nonce = 16-byte per-direction prefix || 64-bit sequence; epoch is also bound in AD.
  - Associated Data: record type + sequence + epoch bind metadata to ciphertext (prevents reordering/splicing across types).
  - Integrity-on-commit: For each file transfer, the sender computes BLAKE2b-256 over the file and sends the 32-byte digest in `FileClose`. The receiver verifies before committing the file (atomic move). On mismatch, the receiver aborts, removes the `.part`, and errors. When the client detects a mismatch while downloading, it also informs the server via an `ErrorRec` `[checksum] checksum mismatch`.

- Filesystem safety (server)
  - Sandboxed mode (default):
    - Rejects absolute paths from clients.
    - Relative paths are normalized and constrained to the configured roots: exportRoot (download) and importRoot (upload).
    - Attempts to prevent path traversal and symlink escapes by canonical checks on the target’s parent directory.
  - Unsafe mode (opt‑in):
    - `--unsafe-fs` (or `[Server] sandbox=false` in config) accepts absolute and relative paths anywhere the server account can access (like scp).
  - Atomic writes: uploads stream into `.part` then atomically rename to the final path; partials are removed on abort.

Note: For the strongest containment guarantees, deploy the server in a chroot/container or a dedicated account with minimal privileges. Depot enforces a share root by normalization and parent checks, but kernel‑enforced jails provide hard isolation.

## Build

Requires Nim 2.x.

```
nim c -d:release depot.nim
```

## Quick Start

1) Scaffold a config (optional but recommended):

```
depot --init
```

Edit `~/.config/depot/depot.conf` to set server/client defaults (see below).

2) Start the server (sandboxed by default):

```
depot serve --listen 0.0.0.0 --port 60006 --log info
```

3) Export files (client → server import root):

```
# Use client default export root for relative names (server writes under importRoot)
depot export picture.jpg --host server

# Export into a specific remote subdirectory (sandbox requires relative)
depot export picture.jpg --host server --remote-dir photos/trips

# Export current directory instead of default export root
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

# Optional absolute roots (used in sandbox mode)
# exportRoot = /home/user/Downloads/depot/export
# importRoot = /home/user/Downloads/depot/import

[Client]
host = your.server
port = 60006
log  = info
base = /home/user/Downloads
```

## Errors and Logging

- Client
  - Friendly messages for connect/handshake failures and mid‑transfer disconnects (no async backtraces).
  - Server errors are passed through verbatim: `server error: not found: /path`.
  - Progress: single‑line live update (truncated to terminal width) and a growing history of completed files.

- Server
  - Logs handshake and detailed transfer activity:
    - `upload start/complete`, `download request (file/dir)`, per‑file `send file/complete`, and directory totals.
  - Rejects with explicit reasons: `absolute path in sandbox`, `unsafe path`, `not found`, AEAD auth failures.

## Design Notes

- AEAD framing uses varint length + type + ciphertext + tag; type + sequence + epoch bind metadata.
- Nonces use a per-direction 16-byte prefix and a 64-bit counter; keys are derived with Argon2id bound to the handshake transcript.
- The server does not invoke a shell to parse paths; the protocol is structured and binary.

## Protocol Summary

- PathOpen (server→client): payload = varint(pathLen) | path | varint(size)
- PathAccept (client→server): payload = empty (proceed to send data)
- PathSkip (client→server): payload = 1-byte reason code (exists, filter, absolute, unsafe-path, etc.)
- FileData (sender→receiver): payload = file bytes (chunked, typically 1 MiB)
- FileClose (sender→receiver): payload = 32-byte BLAKE2b digest of the full file (integrity-on-commit)
- DownloadDone / UploadDone: empty payload (end-of-transfer sentinel)
- ListOpen / ListChunk / ListDone: directory listings in batched chunks; each entry = varint(pathLen) | path | varint(size) | kind(0=file,1=dir)
- RekeyReq / RekeyAck: epoch rotation for traffic keys; epoch is included in AEAD associated data. Rekey occurs at file boundaries.

Rekeying: A RekeyReq carries a 4-byte epoch. Both peers derive new traffic keys and 16-byte nonce prefixes from a per-session traffic secret and the epoch, reset sequence counters, and start using the new epoch (bound into AEAD AD). The current build triggers a rekey at file boundaries on a time interval by default (15 minutes).
