# Depot Rust Architecture

## Purpose

This repository is not a line-by-line port of the Nim implementation. It is a Rust rewrite of Depot around the finalized v3 product behavior:

- one server root
- current working directory defaults
- `--root` only as a runtime server override
- `--dest` as the explicit placement override
- sandboxed server path enforcement
- no `depot/import` or `depot/export` model

The Nim codebase is reference material for behavior, UX, and transfer semantics. It is not the module template for the Rust codebase.

## Current Status

The workspace is past scaffolding. It now contains:

- a real authenticated handshake over `latebra`
- an encrypted record transport
- end-to-end `ls`
- end-to-end `export`
- end-to-end `import`
- a real `depot` binary entrypoint

The current user-facing trust model is explicit:

- `depot keygen` generates raw ML-DSA-87 key files
- `depot serve --identity-file server.key`
- client commands require `--server-pubkey-file server.pub`
- optional client authentication uses `--client-identity-file` and `--trust-client-pubkey-file`

There is no compatibility layer, trust-store fallback, or hidden key discovery.

## Design Goals

- Preserve the product behavior that is now considered correct.
- Rebuild the internals in a Rust-native shape.
- Use `latebra` as the canonical crypto substrate.
- Keep security-sensitive logic explicit and testable.
- Keep path policy, protocol, crypto, transport, and CLI concerns separated.
- Avoid compatibility shims, legacy paths, and transitional abstractions.

## Non-Goals

- Byte-for-byte wire compatibility with the Nim implementation.
- Preservation of Nim internal module layout.
- Embedding ad hoc crypto directly inside the application.
- Config-driven path magic.

## Behavioral Contract To Preserve

These are the user-facing rules the Rust implementation should keep fixed unless there is an intentional product decision to change them.

### Path Model

- `depot serve` serves one root directory.
- The server root defaults to the server process current working directory.
- `depot serve --root DIR` explicitly overrides the served root.
- Local relative paths resolve from the client current working directory.
- Remote relative paths resolve from the server root.
- In sandbox mode, remote paths may not escape the server root.
- In sandbox mode, absolute remote paths are rejected.
- `--dest` is the explicit placement override.

### Commands

- `depot serve`
- `depot export SRC... [--dest DIR]`
- `depot import SRC... [--dest DIR]`
- `depot ls [PATH]`
- `depot keygen --secret-out FILE --public-out FILE`

### Transfer Semantics

- Export uploads files/directories from the local machine into the remote destination base.
- Import downloads files/directories from the remote machine into the local destination base.
- Directory transfer includes the top-level directory name by default when that is the chosen behavior.
- Downloads and uploads use temporary `.part` files and atomic commit on successful checksum verification.
- Metadata preservation remains explicit: at minimum `mtime` and permissions where supported.
- Batch operations distinguish per-item failures from session-fatal failures.

### Security Model

- Server root defines the exposed remote namespace.
- Sandbox mode is the default.
- Absolute remote paths and path escape attempts are distinct error conditions.
- Errors must be explicit and typed; no silent fallback behavior.
- The client pins the server identity explicitly with a public-key file.
- Server identity and optional client identity are file-backed runtime inputs, not config defaults.

## Architecture Principles

### 1. Separate Product Semantics From Runtime Mechanics

The code that defines what Depot means must not be tangled with Tokio sockets, frame parsing, or terminal output.

### 2. Keep Security-Sensitive Logic Narrow

Path resolution, handshake state, record framing, and key schedule code should live in small focused modules with explicit inputs and outputs.

### 3. Use Rust-Native Boundaries

Do not transliterate Nim modules into Rust modules. Build around Rust’s strengths:

- explicit state machines
- typed errors
- narrow ownership boundaries
- isolated binary codecs
- explicit async runtime boundaries

### 4. Make Testing Layered

- pure unit tests for path, codec, and error policy
- service tests for upload/download/list orchestration
- integration tests for real client/server transfers

## Workspace Topology

The repository should be a Cargo workspace. The intended crate layout is:

```text
depot_rust/
  Cargo.toml
  crates/
    depot-cli/
    depot-app/
    depot-core/
    depot-protocol/
    depot-crypto/
    depot-transport/
    depot-fs/
    depot-config/
    depot-ui/
  tests/
    integration/
```

This is the intended end state. Some crates may be introduced in phases, but the dependency direction should match this topology from the beginning.

## Crate Responsibilities

### `depot-core`

Owns the domain model.

Contents:

- command model
- operation kinds
- transfer intent
- path intent types
- sandbox policy types
- user-visible error codes
- error severity and batch abort policy
- transfer outcome model

Must not depend on:

- Tokio
- filesystem I/O
- crypto implementation
- terminal output

This crate is where the behavioral contract lives.

### `depot-protocol`

Owns the wire model.

Contents:

- record enums
- handshake message enums
- payload schemas
- binary codecs
- varint encoding/decoding
- frame format definitions
- metadata payload encoding/decoding

Must not depend on:

- sockets
- filesystem
- CLI

This crate turns typed protocol values into bytes and back.

### `depot-crypto`

Owns Depot’s adaptation layer over `latebra`.

Contents:

- handshake cryptographic operations
- transcript binding
- AEAD sealing/opening
- session key derivation
- rekey derivation
- identity verification primitives
- secret material wrappers where needed

Must not own:

- socket I/O
- command parsing
- path logic

This crate should remain intentionally small. It exists to express how Depot uses `latebra`, not to build a second crypto framework.

### `depot-transport`

Owns runtime transport state.

Contents:

- Tokio socket integration
- client handshake state machine
- server handshake state machine
- secure channel framing
- session state
- idle timeout enforcement
- rekey lifecycle
- read/write sequencing guarantees

This crate owns “a connection carrying Depot protocol messages.”

It should not own:

- filesystem policy
- CLI semantics
- config parsing

### `depot-fs`

Owns filesystem and path policy.

Contents:

- server root handling
- remote path resolution under sandbox rules
- atomic `.part` commit handling
- metadata extraction/application
- safe directory traversal
- listing helpers
- upload/download file stream helpers

This crate should absorb the security-sensitive path logic that was previously spread across multiple Nim modules.

### `depot-config`

Owns strict config loading.

Contents:

- config schema
- parsing
- validation

Scope:

- host
- port
- sandbox
- logging defaults
- psk
- auth requirements

Not in scope:

- server root
- path defaults beyond the runtime model

### `depot-ui`

Owns terminal-facing rendering.

Contents:

- progress display
- status formatting
- error rendering
- color policy

This crate should contain no business logic.
It may depend on protocol/domain display types needed for terminal rendering.

### `depot-app`

Owns orchestration.

Contents:

- command execution for `serve`, `export`, `import`, `ls`
- client-side operation planning
- server-side request handling
- batch orchestration
- translation between domain model and runtime services

This is the application layer that composes:

- `depot-core`
- `depot-protocol`
- `depot-crypto`
- `depot-transport`
- `depot-fs`
- `depot-config`
- `depot-ui`

### `depot-cli`

Owns the command-line entrypoint.

Contents:

- `clap` definitions
- argument parsing
- process exit codes
- startup wiring

This crate should remain thin. It should delegate command execution to `depot-app`.

## Dependency Direction

The dependency graph should remain one-way:

```text
depot-cli
  -> depot-app

depot-app
  -> depot-core
  -> depot-protocol
  -> depot-crypto
  -> depot-transport
  -> depot-fs
  -> depot-config
  -> depot-ui

depot-transport
  -> depot-core
  -> depot-protocol
  -> depot-crypto

depot-fs
  -> depot-core

depot-config
  -> depot-core

depot-ui
  -> depot-core
  -> depot-protocol

depot-crypto
  -> latebra

depot-protocol
  -> depot-core
```

Rules:

- `depot-core` depends on nothing in the workspace.
- `depot-protocol` must not depend on `depot-transport`.
- `depot-fs` must not depend on `depot-transport`.
- `depot-ui` must not depend on transport or crypto.
- `depot-cli` must not directly own application logic.

## Domain Model

The Rust rewrite should define a small set of explicit types early.

Examples of the right level of abstraction:

- `ServerRoot`
- `RemotePath`
- `LocalPath`
- `SandboxPolicy`
- `Command`
- `TransferMode`
- `BatchResult`
- `Outcome`
- `DepotError`
- `ErrorCode`

The point is not maximal abstraction. The point is to make unsafe or ambiguous states hard to represent.

## Protocol Model

The protocol should be rebuilt as typed messages, not ad hoc byte payload handling spread across runtime code.

Expected categories:

- handshake messages
- session records
- path metadata payloads
- list payloads
- error payloads
- rekey payloads

Recommended rule:

- codec code lives in `depot-protocol`
- transport code never manually assembles message bytes outside that crate

## Transport Model

The transport layer should be built around explicit state machines.

### Handshake State

Client and server handshake flows should be modeled as explicit phases rather than a single long function.

Suggested shape:

- client hello phase
- server hello phase
- identity verification phase
- key agreement phase
- transcript finalization phase
- optional client auth phase
- secure session establishment phase

### Secure Channel

The secure channel should own:

- frame encoding/decoding
- sequence numbers
- nonce construction
- authenticated data construction
- rekey state
- serialized write discipline
- idle tracking

The Nim bug around timeout-triggered concurrent writes is exactly the kind of issue this boundary should make harder to create.

## Filesystem Model

Path policy should be explicit and centralized.

Server-side path handling must answer:

- is the incoming path absolute
- is the incoming path syntactically unsafe
- does it escape the server root
- does it traverse forbidden symlink components
- what is the resolved filesystem target

This should not be spread across command handlers.

Transfer commit handling should also be centralized:

- open `.part`
- stream bytes
- verify checksum
- atomically commit
- apply metadata
- clean up partial on abort

## Error Model

Errors should be typed and layered.

At minimum there should be:

- product-level error codes
- protocol decode/encode errors
- transport/session errors
- filesystem/path errors
- config errors

User-facing rendering should be separate from error construction.

Do not use ad hoc strings as the primary contract between layers.

## Config Model

Config should remain strict.

Expected config scope:

- server listen host
- server port
- server sandbox
- optional psk
- optional client auth requirement
- client host
- client port
- client log level

Config should not define:

- server root
- transfer destination semantics
- path behavior overrides that weaken the v3 model
- identity or trust material paths

## CLI Runtime Model

The current CLI contract is explicit and runtime-driven.

### Server Startup

- `depot serve --identity-file server.key`
- optional `--root DIR`
- optional `--require-client-auth`
- optional repeated `--trust-client-pubkey-file client.pub`

### Client Commands

- `depot ls [PATH] --server-pubkey-file server.pub`
- `depot export SRC... --server-pubkey-file server.pub [--dest REMOTE_DIR]`
- `depot import SRC... --server-pubkey-file server.pub [--dest LOCAL_DIR]`
- optional `--client-identity-file client.key`

### Key Generation

- `depot keygen --secret-out server.key --public-out server.pub`

Key files are raw ML-DSA-87 bytes. The CLI is responsible for loading these files and constructing runtime identities. Config does not participate in key discovery.

## Testing Strategy

### Unit Tests

Test pure logic without network or disk where possible:

- varint codecs
- frame codecs
- handshake payload codecs
- path validation
- error severity policy
- metadata payload parsing

### Service Tests

Test component behavior with controlled runtime helpers:

- upload commit logic
- download stream logic
- listing behavior
- rekey transitions
- timeout handling

### Integration Tests

Run real client/server flows:

- upload single file
- download single file
- mixed batch transfer
- directory transfer semantics
- skip-existing behavior
- sandbox rejection behavior
- absolute versus unsafe path distinction

### Security Regression Tests

Must include:

- record/frame size limits
- handshake size limits
- invalid config rejection
- sandbox path escape attempts
- symlink component rejection
- concurrent write discipline on secure channel

## Recommended Dependencies

Use a small, deliberate set of crates.

- `tokio` for async runtime and networking
- `clap` for CLI
- `bytes` for byte buffers
- `tracing` and `tracing-subscriber` for logging
- `serde` only where it provides clear value
- `toml` if config format is TOML
- `tempfile` for tests
- `walkdir` if needed for traversal
- `latebra` for cryptography

Avoid introducing abstraction-heavy frameworks early.

## Nim Reference Mapping

This mapping is conceptual, not one-to-one.

- `depot.nim` -> `depot-cli` + `depot-app`
- `userconfig.nim` -> `depot-config`
- `errors.nim` + `outcome.nim` -> `depot-core`
- `records.nim` + `varint.nim` + protocol payload codecs -> `depot-protocol`
- encrypted session machinery from `protocol.nim` -> `depot-transport`
- crypto-heavy parts of `handshake.nim` -> `depot-crypto`
- handshake flow from `handshake.nim` -> `depot-transport`
- `paths.nim` -> `depot-fs`
- `server_*` and `client_*` handlers -> `depot-app`
- `progress.nim` -> `depot-ui`

## Build Order

Implement bottom-up.

### Phase 1

- create workspace
- create `depot-core`
- create `depot-protocol`
- create `depot-crypto`

### Phase 2

- create `depot-fs`
- create `depot-transport`

### Phase 3

- create `depot-app`
- create `depot-config`
- create `depot-ui`

### Phase 4

- create `depot-cli`
- add integration tests

### Phase 5

- parity pass against Nim behavior
- remove design mistakes discovered during implementation

## Initial Acceptance Criteria

The first complete Rust version should satisfy all of the following:

- serves one root with cwd default
- supports `serve`, `export`, `import`, and `ls`
- enforces sandbox path policy correctly
- preserves batch semantics
- uses `latebra` as the crypto backend
- keeps config strict
- passes end-to-end transfer tests
- passes security regression tests for path handling and framing limits
- exposes a real CLI and binary entrypoint
- uses explicit file-backed identity inputs rather than placeholder flags

## Final Guiding Rule

The Nim implementation is the completed prototype. The Rust implementation should be the long-term architecture.

If a Nim design choice exists because it defines Depot’s product behavior, preserve it.

If a Nim design choice exists because it was convenient in Nim or survived from older iterations, redesign it.
