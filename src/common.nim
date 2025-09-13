# Common helpers shared by client/server for simple byte/string conversions.

proc toBytes*(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i, ch in s:
    result[i] = byte(ch)

proc fromBytes*(bs: openArray[byte]): string =
  result = newString(bs.len)
  for i, b in bs:
    result[i] = char(b)

proc toStr*(data: openArray[byte]): string =
  ## Convert byte-like data to a Nim string without reinterpretation.
  result = newString(data.len)
  for i, b in data:
    result[i] = char(b)

proc bytesCopy*(data: openArray[byte]): seq[byte] =
  ## Copy byte-like data into a seq[byte].
  result = newSeq[byte](data.len)
  if data.len > 0:
    copyMem(addr result[0], unsafeAddr data[0], data.len)
