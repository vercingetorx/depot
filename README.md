# Depot — Secure File Transfer (ML-KEM + XChaCha20)

Depot is a simple, post-quantum-ready file transfer tool. It favors a clean CLI, strong defaults, and explicit safety:

- Modern cryptography with ML-KEM (KEM), ML-DSA (identity), Argon2 (KDF), BLAKE3 (hashing), and XChaCha20-Poly1305 (AEAD).
- Sandboxed filesystem mode by default (no absolute paths; no escaping the server root).
- Clear, standardized error codes and explicit batch outcomes.

## Security Overview (brief)

- TOFU identity pinning with ML-DSA; ML-KEM for session keys; Argon2 for key-at-rest and handshake key schedule; XChaCha20-Poly1305 for records.
- Sandboxed filesystem mode by default (no absolute paths; normalized under the server root).
- Atomic write/commit with integrity-on-commit checksums; partials removed on abort.

For architectural details, crate boundaries, and implementation notes, see [ARCHITECTURE.md](/media/extra/documents/coding/rust/depot_rust/ARCHITECTURE.md).

## Build

Requires Rust and Cargo.

```bash
cargo build --release
```

## Quick Start

1. Scaffold a config for stable defaults like host, port, log level, sandbox, and auth settings:

```bash
depot config --init
```

Edit `~/.config/depot/depot.conf` to set those defaults if you want them.

2. Start the server from the directory you want to share:

```bash
cd /srv/media
depot serve --listen 0.0.0.0 --port 60006 --key-pass "change-me"
```

First run requires `--key-pass` or `--key-pass-file` to generate an encrypted server identity key. Later runs must use the same passphrase.

3. Export files and directories from your current directory:

```bash
depot export picture.jpg --host server

# Export into a specific remote subdirectory
depot export picture.jpg --host server --dest photos/trips

# Export the contents of the current directory
depot export --all --host server
```

4. Import files into your current directory:

```bash
depot import movie.mp4 --host server

# Pull the entire shared root
depot import --all --host server

# Download into a different local destination
depot import folder --host server --dest ~/Downloads/inbox

# List remote content
depot ls --host server
```

## CLI

```text
depot serve [--listen IP] [--port N] [--root DIR] [--log LEVEL]
            [--no-sandbox] [--allow-overwrite]
            [--key-pass PASS | --key-pass-file PATH]

depot export FILE... [--host HOST] [--port N]
                     [--dest DIR] [--all]
                     [--skip-existing] [--no-skip | --noskip] [--log LEVEL]

depot import ITEM... [--host HOST] [--port N]
                     [--dest DIR] [--all]
                     [--skip-existing] [--no-skip | --noskip] [--log LEVEL]

depot ls [PATH] [--host HOST] [--port N] [--log LEVEL]

depot config --init [--force]

depot --version
```

Tips:

- In sandboxed mode, the server rejects absolute remote paths and `..` traversal.
- In no-sandbox mode (`depot serve --no-sandbox`), absolute remote paths are allowed.
- `depot serve` uses the current directory as the server root unless `--root` is provided.
- `depot export` and `depot import` use the current directory by default.
- Skip-existing behavior is on by default for export/import; use `--no-skip` or `--noskip` to disable it.

## Config

`~/.config/depot/depot.conf`:

```text
[server]
# listen = 0.0.0.0
# port = 60006
sandbox = true

[client]
# host = your.server
# port = 60006
# log = info
```

Config is only for stable preferences. Server pathing is not configured here. `depot serve` serves the current directory unless `--root` is provided.

## Identity And Trust

- Depot stores identity and trust material under the Depot config directory.
- The server identity lives under `~/.config/depot/id/` and is created lazily on first successful `serve`.
- The server secret key is encrypted at rest in `DPK1` format and requires `--key-pass` or `--key-pass-file`.
- The client uses TOFU pinning and stores pinned server public keys under `~/.config/depot/trust/`.
- Client identity lives under `~/.config/depot/id/` and is always used for client authentication.
- Server-side trusted client public keys live under `~/.config/depot/trust/clients/`.

## Messages and Codes

- Wire carries only an error code; both sides render standardized messages:
  - Client: `[code] <client message>`
  - Server: `[code] <server message>`
- Success and skip messages are local only and use typed local status rendering.
- Batch runs report transferred, skipped, and failed items explicitly.

## Design Notes

- AEAD framing uses typed encrypted records over TCP.
- Nonces use a per-direction prefix and counter.
- The server does not invoke a shell to parse paths; the protocol is structured and binary.
- The Rust implementation uses `latebra` as its crypto library.

## Transfer Semantics

- Uploads write to `<dest>.part` and move into place only after checksum verification. On error, partial files are removed.
- Downloads write to `<dest>.part` and move into place only after checksum verification.
- Metadata preservation: server to client and client to server preserve `mtime` and file permissions.
- Directory export/import:
  - Exporting a directory includes the top-level directory name.
  - Importing a directory includes the top-level directory name.
  - Relative remote paths are resolved from the server root.
  - Relative local paths are resolved from the client current working directory.
- Exit status is non-zero if any failures occurred in a batch.
