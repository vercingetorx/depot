# Depot Rust Parity TODO

This is a source-driven backlog for bringing the Rust rewrite into behavioral parity with the original Nim implementation.

The standard for every item here is:

- read the original Nim source first
- identify the exact user-visible behavior
- implement that behavior in Rust
- add or update tests that prove the Rust behavior matches the original contract

Nothing in this list should be treated as optional polish unless marked explicitly.

## Priority 0: Correctness and Trust Gaps

These are the highest-risk mismatches because they affect protocol behavior, data safety, or basic operator trust.

### 1. Reintroduce full session rekey behavior

Original Nim sources:

- [/media/extra/documents/coding/nim/depot/src/server_common.nim](/media/extra/documents/coding/nim/depot/src/server_common.nim)
- [/media/extra/documents/coding/nim/depot/src/client_session.nim](/media/extra/documents/coding/nim/depot/src/client_session.nim)
- [/media/extra/documents/coding/nim/depot/src/protocol.nim](/media/extra/documents/coding/nim/depot/src/protocol.nim)
- [/media/extra/documents/coding/nim/depot/src/records.nim](/media/extra/documents/coding/nim/depot/src/records.nim)

Current Rust gap:

- [src/transport.rs](/media/extra/documents/coding/rust/depot_rust/src/transport.rs) has rekey fields and `apply_rekey`, but no actual rekey record flow.
- [src/protocol.rs](/media/extra/documents/coding/rust/depot_rust/src/protocol.rs) does not model `RekeyReq` / `RekeyAck`.
- [src/app.rs](/media/extra/documents/coding/rust/depot_rust/src/app.rs) never proposes, receives, or acknowledges rekeys.

Required work:

- Add rekey record types to the Rust protocol.
- Implement server-side rekey proposal and activation flow.
- Implement client-side rekey acknowledgement and activation flow.
- Reset epoch and sequence counters exactly as the session model requires.
- Preserve current traffic secret derivation rules or replace them only with a deliberate parity decision documented from source.
- Add end-to-end tests that force at least one rekey during transfer and prove the session remains valid.

Acceptance criteria:

- Long-running transfers survive automatic rekey.
- Rekey is exercised in tests, not just unit helpers.
- No ad hoc silent fallback to “never rekey”.

### 2. Reintroduce enforced idle timeout behavior

Original Nim source:

- [/media/extra/documents/coding/nim/depot/src/server_session.nim](/media/extra/documents/coding/nim/depot/src/server_session.nim)

Current Rust gap:

- [src/transport.rs](/media/extra/documents/coding/rust/depot_rust/src/transport.rs) stores `io_timeout` and last activity timestamps.
- No Rust server task actually enforces timeout-driven disconnects.

Required work:

- Implement server-side idle timeout enforcement against real encrypted-channel activity.
- Match the Nim fix: do not inject concurrent encrypted timeout records that can corrupt framing.
- Ensure timeout behavior is observable at the CLI/user layer.
- Ensure partial uploads/downloads clean up correctly when timeout closes the connection.

Acceptance criteria:

- A stalled session is closed after the configured timeout.
- Timeout failure surfaces as the correct error path.
- Timeout behavior is covered by integration tests.

### 3. Fix import overwrite semantics

Original Nim source:

- [/media/extra/documents/coding/nim/depot/src/client_download.nim](/media/extra/documents/coding/nim/depot/src/client_download.nim)

Current Rust gap:

- [src/app.rs](/media/extra/documents/coding/rust/depot_rust/src/app.rs) overwrites local files on import when `skip_existing` is false.
- Nim does not overwrite on import. It skips the file at protocol level and then reports `exists`.

Required work:

- Remove local overwrite-on-import behavior.
- Match Nim’s per-file behavior:
  - send `PathSkip` when the destination already exists
  - count it as skipped
  - if skip mode is disabled, preserve the deferred `exists` error behavior instead of overwriting
- Audit batch result accounting to ensure it matches original severity and exit behavior.

Acceptance criteria:

- Existing local files are never overwritten by import.
- `--no-skip` behavior matches Nim rather than acting like overwrite mode.
- Integration tests cover:
  - skip-existing on import
  - no-skip on import with existing destination

### 4. Fix single-file `import --dest FILE` semantics

Original Nim source:

- [/media/extra/documents/coding/nim/depot/src/client_download.nim](/media/extra/documents/coding/nim/depot/src/client_download.nim)

Current Rust gap:

- Rust always treats `--dest` as a destination root directory.
- Nim treats a non-directory destination as the target filename for the first imported file.

Required work:

- Reproduce Nim’s first-file behavior exactly.
- Preserve conflict behavior for additional files when a file target was already consumed.
- Ensure directory imports and multi-file imports behave correctly with this rule.

Acceptance criteria:

- Single-file import to explicit file path matches Nim.
- Multi-file import to explicit file path raises conflict instead of mangling paths.
- Tests cover file target, directory target, and multi-item conflict cases.

### 5. Restore per-session server log IDs

Original Nim sources:

- [/media/extra/documents/coding/nim/depot/src/server.nim](/media/extra/documents/coding/nim/depot/src/server.nim)
- [/media/extra/documents/coding/nim/depot/src/server_common.nim](/media/extra/documents/coding/nim/depot/src/server_common.nim)
- [/media/extra/documents/coding/nim/depot/src/server_ctx.nim](/media/extra/documents/coding/nim/depot/src/server_ctx.nim)

Current Rust gap:

- No per-connection session ID exists in the Rust server runtime.
- Server-side logs are not tagged by session.

Required work:

- Add a generated session ID per accepted connection.
- Thread it through server runtime context instead of formatting ad hoc strings at random call sites.
- Prefix all server connection/session logs with `[sid]`.
- Recreate the important server-side status points from Nim:
  - connected
  - handshake complete
  - upload start/complete
  - download request/start/complete
  - list start/complete
  - rekey
  - disconnect
  - timeout
  - protocol/auth/error events

Acceptance criteria:

- Server logs can be correlated by session.
- Session IDs are unique per connection.
- The logging structure is systematic, not piecemeal.

## Priority 1: CLI and Config Parity

These are user-facing contract mismatches.

### 6. Restore top-level `depot --init [--force]`

Original source:

- [/media/extra/documents/coding/nim/depot/depot.nim](/media/extra/documents/coding/nim/depot/depot.nim)

Current Rust gap:

- Rust rejects top-level `--init`.
- Nim supports it as an alias for `depot config --init`.

Required work:

- Add the top-level alias.
- Preserve `config --init` as the subcommand form if desired, but the top-level form must work.
- Add executable tests for both forms.

Acceptance criteria:

- `depot --init`
- `depot --init --force`
- `depot config --init`

all behave correctly.

### 7. Restore original config file format

Original source:

- [/media/extra/documents/coding/nim/depot/src/userconfig.nim](/media/extra/documents/coding/nim/depot/src/userconfig.nim)
- [/media/extra/documents/coding/nim/depot/depot.nim](/media/extra/documents/coding/nim/depot/depot.nim)

Current Rust gap:

- Rust config parsing uses TOML-like lowercase `[server]` / `[client]`.
- The original tool used INI-style `[Server]` / `[Client]`.
- The current Rust binary rejects the original config file format.

Required work:

- Replace the config parser with one that accepts the original format and strictness rules.
- Match original key casing/section behavior or document any deliberate deviation.
- Remove format drift from config scaffolding.

Acceptance criteria:

- Rust accepts original-style config files.
- `config --init` writes original-style config files.
- Unknown keys remain rejected.

### 8. Remove or justify global `--config`

Original source:

- [/media/extra/documents/coding/nim/depot/depot.nim](/media/extra/documents/coding/nim/depot/depot.nim)

Current Rust gap:

- Rust added global `--config`.
- Nim did not expose that flag.

Required work:

- Decide whether this is a deliberate product change or parity violation.
- If parity is the goal, remove it.
- If kept, explicitly document it as a post-port intentional addition and test it accordingly.

Acceptance criteria:

- No hidden CLI drift remains unexplained.

### 9. Restore original help/usage behavior or explicitly accept divergence

Original source:

- [/media/extra/documents/coding/nim/depot/depot.nim](/media/extra/documents/coding/nim/depot/depot.nim)

Current Rust gap:

- Rust uses Clap-generated help and error text.
- Nim used explicit hand-written usage text and subcommand help.

Required work:

- Decide whether literal help parity is required.
- If yes, replace or tightly control Clap help output to match the original contract.
- If no, document that this is an intentional non-behavioral divergence.

Acceptance criteria:

- There is an explicit decision here, not drift by convenience.

### 10. Restore version string parity

Original source:

- [/media/extra/documents/coding/nim/depot/depot.nim](/media/extra/documents/coding/nim/depot/depot.nim)

Current Rust gap:

- Nim prints `depot v0.1.0`
- Rust currently prints `depot 0.1.0`

Required work:

- Make the version output match or document the deliberate difference.

Acceptance criteria:

- `depot --version` behavior is intentional and tested.

## Priority 2: Transfer UX and Batch Semantics

These are user-visible and operationally important, but less catastrophic than the correctness gaps above.

### 11. Restore original `ls` output format

Original source:

- [/media/extra/documents/coding/nim/depot/src/client_download.nim](/media/extra/documents/coding/nim/depot/src/client_download.nim)

Current Rust gap:

- Rust prints only names and a trailing slash for directories.
- Nim prints directory markers and file sizes.

Required work:

- Match Nim `ls` output shape:
  - files with size
  - directories with `[dir]`
- Audit whether exact spacing/formatting matters to your workflow.

Acceptance criteria:

- `ls` output is source-driven and tested.

### 12. Restore original transfer progress/status output

Original sources:

- [/media/extra/documents/coding/nim/depot/src/client_batch.nim](/media/extra/documents/coding/nim/depot/src/client_batch.nim)
- [/media/extra/documents/coding/nim/depot/src/client_upload.nim](/media/extra/documents/coding/nim/depot/src/client_upload.nim)
- [/media/extra/documents/coding/nim/depot/src/client_download.nim](/media/extra/documents/coding/nim/depot/src/client_download.nim)
- [/media/extra/documents/coding/nim/depot/src/errors.nim](/media/extra/documents/coding/nim/depot/src/errors.nim)

Current Rust gap:

- Rust summarizes outcomes after the batch.
- Nim emits `[done]`, `[skip]`, and `[transferred]` lines in the course of the operation.

Required work:

- Audit the full client-facing status model from Nim.
- Decide whether exact progress rendering matters or only final statuses.
- Recreate per-item done/skip output if parity is required.

Acceptance criteria:

- Batch output no longer drifts by accident.

### 13. Match export batch handling for missing local sources

Original source:

- [/media/extra/documents/coding/nim/depot/src/client_batch.nim](/media/extra/documents/coding/nim/depot/src/client_batch.nim)

Current Rust gap:

- Nim reports missing local sources and continues.
- Rust fails batch collection immediately.

Required work:

- Align batch continuation/abort policy with Nim.
- Ensure per-item outcomes and exit codes match the original severity rules.

Acceptance criteria:

- Missing one local source does not accidentally change the entire batch policy.

### 14. Audit exact skip/fail/fatal accounting

Original sources:

- [/media/extra/documents/coding/nim/depot/src/client_batch.nim](/media/extra/documents/coding/nim/depot/src/client_batch.nim)
- [/media/extra/documents/coding/nim/depot/src/outcome.nim](/media/extra/documents/coding/nim/depot/src/outcome.nim)
- [/media/extra/documents/coding/nim/depot/src/errors.nim](/media/extra/documents/coding/nim/depot/src/errors.nim)

Current Rust risk:

- Batch accounting is similar, but not yet proven identical across all item/fatal/session errors.

Required work:

- Build a matrix of:
  - item error
  - skip
  - session fatal
  - local fatal
  - auth/config/connect failures
- Verify exit code and summary behavior against Nim.

Acceptance criteria:

- Batch semantics are driven by tests, not by approximation.

## Priority 3: Filesystem and Cleanup Edge Cases

### 15. Audit partial-file cleanup across every failure path

Original sources:

- [/media/extra/documents/coding/nim/depot/src/client_download.nim](/media/extra/documents/coding/nim/depot/src/client_download.nim)
- [/media/extra/documents/coding/nim/depot/src/server_upload.nim](/media/extra/documents/coding/nim/depot/src/server_upload.nim)
- [/media/extra/documents/coding/nim/depot/src/server_session.nim](/media/extra/documents/coding/nim/depot/src/server_session.nim)

Current Rust risk:

- `.part` handling exists, but cleanup is not yet parity-audited on all failure/close/timeout/protocol paths.

Required work:

- Enumerate every upload/download failure path.
- Ensure `.part` files are removed exactly where the Nim implementation removes them.
- Test abnormal close, checksum failure, timeout, protocol violation, and local I/O failure.

Acceptance criteria:

- No stale partial files remain after failure cases that should clean up.

### 16. Audit symlink and non-regular-file behavior during traversal

Original sources:

- [/media/extra/documents/coding/nim/depot/src/paths.nim](/media/extra/documents/coding/nim/depot/src/paths.nim)
- [/media/extra/documents/coding/nim/depot/src/server_download.nim](/media/extra/documents/coding/nim/depot/src/server_download.nim)

Current Rust risk:

- Core sandbox path rejection exists, but traversal-time safety for all download/upload cases should be verified against Nim.

Required work:

- Audit regular-file-only assumptions during directory walks.
- Add tests for symlink-in-tree and non-regular-file cases.

Acceptance criteria:

- Filesystem traversal behavior matches the original security boundary.

## Priority 4: Logging and Log-Level Behavior

### 17. Make `--log` actually control runtime logging

Original source:

- [/media/extra/documents/coding/nim/depot/depot.nim](/media/extra/documents/coding/nim/depot/depot.nim)

Current Rust gap:

- Rust parses `--log`, but runtime logging is not actually driven by it.

Required work:

- Add a real logging backend and wire log-level filtering into it.
- Ensure server-side operational logs respect the configured level.
- Avoid replacing structured parity with ad hoc println noise.

Acceptance criteria:

- `--log debug|info|warn|error` materially changes runtime logs.

### 18. Restore key server-side operational logs

Original sources:

- [/media/extra/documents/coding/nim/depot/src/server.nim](/media/extra/documents/coding/nim/depot/src/server.nim)
- [/media/extra/documents/coding/nim/depot/src/server_upload.nim](/media/extra/documents/coding/nim/depot/src/server_upload.nim)
- [/media/extra/documents/coding/nim/depot/src/server_download.nim](/media/extra/documents/coding/nim/depot/src/server_download.nim)
- [/media/extra/documents/coding/nim/depot/src/server_list.nim](/media/extra/documents/coding/nim/depot/src/server_list.nim)
- [/media/extra/documents/coding/nim/depot/src/server_session.nim](/media/extra/documents/coding/nim/depot/src/server_session.nim)

Current Rust gap:

- Rust logs far less server activity than the original server.

Required work:

- Recreate the operational status points from the Nim server.
- Keep them structured and session-scoped.

Acceptance criteria:

- Server logs are useful to an operator in the same way the Nim logs were.

## Priority 5: Protocol and Auth Flow Audit

These are not all confirmed wrong, but they are high-risk enough to audit explicitly before claiming parity.

### 19. Audit handshake transcript and authentication semantics line by line

Original source:

- [/media/extra/documents/coding/nim/depot/src/handshake.nim](/media/extra/documents/coding/nim/depot/src/handshake.nim)

Current risk:

- The Rust handshake was redesigned because compatibility was not required.
- That is acceptable architecturally, but user-visible trust behavior still needs an explicit audit.

Required work:

- Verify first-use pinning behavior.
- Verify identity-change rejection behavior.
- Verify when client identity is created and loaded.
- Verify server-side trust-store semantics.
- Verify how auth/config/compat errors surface to the CLI.

Acceptance criteria:

- Trust model parity is documented and tested.
- Any intentional divergence is written down explicitly.

### 20. Audit server/client error rendering paths

Original sources:

- [/media/extra/documents/coding/nim/depot/src/errors.nim](/media/extra/documents/coding/nim/depot/src/errors.nim)
- [/media/extra/documents/coding/nim/depot/depot.nim](/media/extra/documents/coding/nim/depot/depot.nim)

Current risk:

- Many error strings are aligned, but render paths and fallback formatting still differ.

Required work:

- Compare exact client/server render paths for:
  - coded depot errors
  - handshake/auth errors
  - local OS errors
  - bad CLI usage
- Decide where exact textual parity matters and where category parity is enough.

Acceptance criteria:

- Error rendering drift is either fixed or explicitly documented.

## Parity Test Matrix To Build

This test suite should exist before claiming parity again.

### CLI and config

- `depot --version`
- `depot --help`
- `depot --init`
- `depot --init --force`
- `depot config --init`
- original config file syntax loads
- unknown config keys reject
- `--no-skip` and `--noskip`

### Trust and auth

- first-use TOFU pin creation
- pinned server identity accepted
- changed server identity rejected
- missing trusted client rejected
- trusted client accepted
- encrypted server key generation and reload with passphrase

### Paths

- sandbox rejects absolute remote path
- sandbox rejects `..`
- sandbox rejects symlink escape
- `export dir` preserves top-level directory
- `import dir` preserves top-level directory
- `--all` flattens top level correctly
- single-file import to explicit file target
- multi-file import to explicit file target conflicts

### Transfer

- export single file
- export directory tree
- import single file
- import directory tree
- import existing target with skip mode
- import existing target with no-skip mode
- missing local source during export batch
- checksum mismatch cleanup
- abnormal close cleanup
- timeout cleanup

### Session runtime

- session rekeys during transfer
- idle timeout closes session
- session-scoped log IDs appear on server logs

## Working Rule Going Forward

Do not claim parity for any behavior area until:

1. the original Nim behavior has been read directly
2. the Rust implementation has been compared against it
3. tests exist that lock that behavior in

Until then, the area remains unverified.
