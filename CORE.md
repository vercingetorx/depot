# Depot Core Modules

- depot.nim
  - CLI entrypoint; parses subcommands and dispatches to server/client.
  - Phases marked inside each subcommand for readability.

- server.nim
  - Accept loop and per-connection handler (`handleClient`).
  - Enforces sandbox rules, streams uploads/downloads.
  - Clear per-record handlers: `onUploadOpen`, `onFileData`, `onFileClose`, `onDownloadOpen`.

- client.nim
  - Client-side session setup and transfers.
  - Uploads: `uploadFile`, `uploadPaths`; Downloads: `downloadFile`, `downloadTo`.
  - Progress UI is delegated to `progress.nim`.

- handshake.nim
  - TOFU pinning, Kyber KEM, Dilithium signatures, Argon2id key derivation.
  - Both client/server paths are annotated with phase markers for scanning.

- protocol.nim
  - Encrypted record channel (`Session`), framing and AEAD send/recv helpers.
  - Helpers for reading varints and exact-length socket reads.

- progress.nim
  - TTY progress rendering (`printProgress2`), `clearProgress`, and `formatBytes`.

- varint.nim, paths.nim, records.nim, common.nim, errors.nim
  - Small, focused utilities for encoding, path safety, record constants,
    byte/string conversions, and shared error string constants.

