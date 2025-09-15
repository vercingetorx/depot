## Application record types used on the encrypted channel.
##
## Control plane and transfer messages are exchanged as framed records
## (see protocol.nim for framing). The enum values are stable wire codes.
type Rt* = enum
  UploadOpen   = 0x30'u8  ## client -> server: begin upload (path + metadata)
  UploadOk     = 0x31'u8  ## server -> client: upload is accepted; send data
  UploadFail   = 0x32'u8  ## server -> client: upload rejected (1-byte code)
  UploadDone   = 0x33'u8  ## server -> client: upload committed successfully
  DownloadOpen = 0x40'u8  ## client -> server: request file or directory
  DownloadDone = 0x41'u8  ## server -> client: end of current download batch
  PathOpen     = 0x21'u8  ## server -> client: announce file (path + meta)
  PathAccept   = 0x22'u8  ## client -> server: accept announced file
  PathSkip     = 0x23'u8  ## client -> server: skip announced file
  FileData     = 0x11'u8  ## either direction: opaque file data chunk
  FileClose    = 0x12'u8  ## either direction: checksum for the preceding file
  ErrorRec     = 0x13'u8  ## either direction: 1-byte error code
  ListOpen     = 0x50'u8  ## client -> server: request non-recursive listing
  ListChunk    = 0x51'u8  ## server -> client: batch of list items
  ListDone     = 0x52'u8  ## server -> client: listing complete
  RekeyReq     = 0x60'u8  ## either: propose new epoch (4 bytes)
  RekeyAck     = 0x61'u8  ## peer: acknowledge rekey proposal
