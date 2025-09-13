## Application record types used on the encrypted channel.
type Rt* = enum
  UploadOpen = 0x30'u8
  UploadOk = 0x31'u8
  UploadFail = 0x32'u8
  UploadDone = 0x33'u8
  DownloadOpen = 0x40'u8
  DownloadDone = 0x41'u8
  PathOpen = 0x21'u8
  PathAccept = 0x22'u8
  PathSkip = 0x23'u8
  FileData = 0x11'u8
  FileClose = 0x12'u8
  ErrorRec = 0x13'u8
  ListOpen = 0x50'u8
  ListChunk = 0x51'u8
  ListDone = 0x52'u8
  RekeyReq = 0x60'u8
  RekeyAck = 0x61'u8

