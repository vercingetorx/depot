## Safe path utilities: constrain joins within a base directory and basic file safety checks.
import std/[os, strutils]

type
  ## Raised when a path would escape a base directory or is otherwise invalid.
  PathError* = object of CatchableError

proc hasDotDot*(p: string): bool =
  ## Detect path traversal attempts using ".." path components.
  ## This is a shallow check; canonicalization happens in cleanJoin.
  for part in p.split(DirSep):
    if part.len == 0 or part == ".": continue
    if part == "..": return true
  return false

proc cleanJoin*(baseDir, relative: string): string =
  ## Join and constrain a relative path strictly within baseDir.
  ## - Rejects absolute inputs and explicit ".." segments.
  ## - Normalizes, then validates the resulting absolute path remains under baseDir.
  if relative.len == 0: raise newException(PathError, "empty path")
  if os.isAbsolute(relative): raise newException(PathError, "absolute paths not allowed")
  # Disallow traversal components explicitly
  if hasDotDot(relative):
    raise newException(PathError, "'..' segments not allowed")
  # Join, then normalize platform separators
  let candidate = normalizedPath(baseDir / relative)
  # Ensure the resulting absolute path stays within base
  let baseCanon = absolutePath(baseDir)
  let candAbs = absolutePath(candidate)
  if not candAbs.isRelativeTo(baseCanon):
    raise newException(PathError, "path escapes base directory")
  return candidate

proc isSafeFile*(p: string): bool =
  ## True if path refers to a regular file or directory (no symlinks or devices).
  try:
    let k = getFileInfo(p)
    if k.kind == pcLinkToFile or k.kind == pcLinkToDir: return false
    if k.kind notin {pcFile, pcDir}: return false
    return true
  except OSError:
    return false
