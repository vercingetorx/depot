# Depot Core Modules

- depot.nim
  - CLI entrypoint; parses subcommands and dispatches to server/client.
  - Phases marked inside each subcommand for readability.
  - DRY option parsing via `applyOpt`/`needsValue`; single `usageFor(mode)`
    to avoid duplicated help blocks.
  - Top‑level `--init` is an alias of `config --init`.

- server.nim
  - Accept loop and per-connection handler (`handleClient`).
  - Enforces sandbox rules, streams uploads/downloads.
  - Clear per‑record handlers.
  - Uploads and downloads always write to `<path>.part` and atomically move
    into place after checksum verification. Partial files are removed on abort.
  - Metadata preservation: applies `mtime` and `FilePermission` received from
    the client after a successful upload commit.
  - Errors are emitted as 1‑byte codes only (no reason text on the wire).
    Logging uses a standardized server mapping: `[code] <serverMessage(code)>`.

- client.nim
  - Client-side session setup and transfers.
  - Uploads: `uploadFile`, `uploadPaths`; Downloads: `downloadFile`, `downloadTo`.
  - Progress UI is delegated to `progress.nim`.
  - Directory export includes the top‑level directory name (e.g., `dir1/...`).
  - Metadata preservation: restores `mtime` and `FilePermission` received in
    PathOpen after successful download commit.
  - Errors are code‑only from the server and are mapped to standardized
    client messages: `[code] <clientMessage(code)>`.

- handshake.nim
  - TOFU pinning, Kyber KEM, Dilithium signatures, Argon2id key derivation.
  - Both client/server paths are annotated with phase markers for scanning.
  - Server identity keys are generated lazily during the first successful
    client handshake; use `--key-pass` to generate/store an encrypted key.
  - On handshake failure, only a 1‑byte error code is sent to the peer.

- protocol.nim
  - Encrypted record channel (`Session`), framing and AEAD send/recv helpers.
  - Helpers for reading varints and exact-length socket reads.
  - PathOpen payload: varint(pathLen) | path | varint(size) | varint(mtimeUnix)
    | varint(count) | ordinals[count] (portable `FilePermission` set).
  - UploadFail / ErrorRec payloads are a single error code byte.

- progress.nim
  - TTY progress rendering (`printProgress2`), `clearProgress`, and `formatBytes`.

- varint.nim, paths.nim, records.nim, common.nim, errors.nim
  - Small, focused utilities for encoding, path safety, record constants,
    byte/string conversions.
- errors.nim defines `ErrorCode` (single source of truth) and the mappings
  used by both client and server. Wire payloads contain only the code.

---

## Cryptography and Handshake (details)

- Identity & TOFU: Server sends a Dilithium public key; the client pins it on first use and enforces it on subsequent connections.
- KEM & Key Schedule: CRYSTALS‑Kyber derives a shared secret; Argon2id (64 MiB, 2 passes) derives 64 bytes of key material bound to a BLAKE2b handshake transcript (includes both hellos, server identity, Kyber PK, envelope, prefixes, optional PSK). Keys are split into Tx/Rx and per‑direction 16‑byte nonce prefixes.
- Nonce & AD: XChaCha20‑Poly1305 with 24‑byte nonce = 16‑byte prefix || 64‑bit sequence; AD = [type || seq || epoch].
- Rekey: RekeyReq carries 4‑byte epoch; both sides derive new keys/prefixes and reset sequence counters; epoch is included in AD. Rekey is proposed at file boundaries by time (15 minutes) by default.
- Server identity keys: generated lazily on first handshake. Use `--key-pass` to generate/store encrypted at rest (DPK1: Argon2id + XChaCha20‑Poly1305).

## Protocol & Wire (details)

- Framing: varint(length) | type | ciphertext | tag(16).
- PathOpen (server→client): varint(pathLen) | path | varint(size) | varint(mtimeUnix) | varint(count) | ordinals[count], where ordinals encode a portable `FilePermission` set.
- PathAccept/PathSkip: client acknowledges or skips; PathSkip payload is a 1‑byte code.
- FileData: file bytes (chunked, typically 1 MiB).
- FileClose: BLAKE2b‑256 of the full file; receiver verifies before commit.
- ListOpen/ListChunk/ListDone: non‑recursive listings; each entry = varint(pathLen) | path | varint(size) | kind(0=file,1=dir).
- Error payloads (UploadFail / ErrorRec / handshake error 0x06): 1‑byte error code only.

## Errors (canonical)

- Wire: only the 1‑byte code is transmitted.
- Rendering:
  - Client: `[code] <clientMessage(code)>`
  - Server: `[code] <serverMessage(code)>`
- Example code set: exists, filter, no‑space, perms, absolute, unsafe‑path, bad‑path, bad‑payload, open‑fail, read‑fail, not‑found, timeout, checksum, auth, compat, server‑config, unknown.

## Transfer Semantics (details)

- Integrity‑on‑commit: Sender computes BLAKE2b‑256 and sends in FileClose; receiver verifies, then atomically renames `<path>.part` → `<path>`. Partials are removed on abort.
- Metadata preservation: mtime and `FilePermission` are preserved server→client and client→server.
- Directory export includes the top‑level directory name (e.g., exporting `dir1` yields `dir1/...` on the destination).
- Paths use forward slashes on the wire; filesystem joins and normalization enforce the share roots in sandbox mode.
