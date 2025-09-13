import std/sysrand


proc randombytes*(output: var openArray[byte]) =
  # Fills `output` with cryptographically secure random bytes.
  if not urandom(output):
    raise newException(OSError, "Could not obtain secure random bytes")
