# Depot Rust

Rust rewrite of Depot around the finalized v3 product model:

- one server root
- current working directory defaults
- `--root` only as a runtime server override
- `--dest` as the explicit placement override
- sandboxed remote path enforcement
- no managed `depot/import` or `depot/export` tree

The protocol and runtime are implemented in this workspace. The CLI is now real and uses explicit key files for server identity and optional client authentication.

## Current Commands

```bash
depot keygen --secret-out server.key --public-out server.pub
depot serve --identity-file server.key [--root DIR]
depot ls [PATH] --server-pubkey-file server.pub
depot export SRC... --server-pubkey-file server.pub [--dest REMOTE_DIR]
depot import SRC... --server-pubkey-file server.pub [--dest LOCAL_DIR]
```

Optional client authentication is explicit:

```bash
depot serve \
  --identity-file server.key \
  --require-client-auth \
  --trust-client-pubkey-file client.pub

depot export file.txt \
  --server-pubkey-file server.pub \
  --client-identity-file client.key
```

## Path Model

- `depot serve` exposes one server root.
- The server root defaults to the server process current working directory.
- `depot serve --root DIR` changes the served root explicitly.
- Local relative paths resolve from the client current working directory.
- Remote relative paths resolve from the server root.
- In sandbox mode, absolute remote paths are rejected.
- In sandbox mode, remote paths may not escape the server root.
- `--dest` is the only placement override.

## Transfer Behavior

- `export` uploads files and directories to the remote destination base.
- `import` downloads files and directories to the local destination base.
- Directory transfer includes the top-level directory name by default.
- `--all` disables top-level directory wrapping by using `.` as the source.
- Transfers use `.part` files and atomic commit.
- File content is checksum-verified before commit.
- `mtime` and permissions are preserved where supported.
- Batch runs distinguish skipped items, per-item failures, and fatal session errors.

## Key Material

- `depot keygen` writes a raw ML-DSA-87 secret key file and matching public key file.
- `--identity-file` expects the raw secret-key bytes.
- `--server-pubkey-file` and `--trust-client-pubkey-file` expect raw public-key bytes.
- The client pins the server identity explicitly through `--server-pubkey-file`.
- There is no hidden trust store and no fallback trust behavior.

## Config

Config is optional and strict. Current scope:

- server listen host
- server port
- server sandbox
- optional PSK
- optional client auth requirement
- client host
- client port
- client log level

Config does not define:

- server root
- transfer path defaults
- trust material paths

## Status

Implemented end to end:

- authenticated handshake
- encrypted session transport
- `ls`
- `export`
- `import`
- real `depot` binary wiring

Verification:

- `cargo fmt`
- `cargo test`

See [ARCHITECTURE.md](/media/extra/documents/coding/rust/depot_rust/ARCHITECTURE.md) for the architectural boundaries and crate topology.
