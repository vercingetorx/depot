# Common helpers shared by client/server for simple byte/string conversions
# and small cross-cutting utilities.
import std/[times, strformat, strutils, sequtils]

proc fromBytes*(bs: openArray[byte]): string {.inline.} =
  result = newString(bs.len)
  for i, b in bs:
    result[i] = char(b)

proc toStr*(data: openArray[byte]): string {.inline.} =
  ## Convert byte-like data to a Nim string without reinterpretation.
  result = newString(data.len)
  for i, b in data:
    result[i] = char(b)

proc monoMs*(): int64 {.inline.} =
  ## Milliseconds since Unix epoch. Suitable for coarse intervals/timeouts.
  ## Note: Uses wall clock; consider monotonic if you switch Session fields.
  getMonotonicTime().inMilliseconds()

proc partPath*(p: string): string {.inline.} =
  ## Conventional on-disk name for partial/in-progress file operations.
  fmt"{p}.part"
