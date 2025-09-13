import std/[math, os, times, strutils, terminal]

## State used to throttle/format progress output on TTYs.
var prLastLen*: int
var prLastMs*: int64
var prLastPct*: int = -1
let prIsTty* = isatty(stdout)

proc nowMs*(): int64 =
  ## Current wall-clock time in milliseconds since Unix epoch.
  int64(epochTime() * 1000)

proc fmt2(f: float): string =
  ## Format a floating-point number with 2 decimal places.
  formatFloat(f, ffDecimal, 2)

proc formatBytes*(x: int64): string =
  ## Pretty-print a byte count using IEC units (B, KiB, MiB, GiB).
  let b = x.float
  if b >= 1024.0*1024*1024:
    return fmt2(b/(1024*1024*1024)) & " GiB"
  elif b >= 1024.0*1024:
    return fmt2(b/(1024*1024)) & " MiB"
  elif b >= 1024.0:
    return fmt2(b/1024) & " KiB"
  else:
    return $x & " B"

proc clearProgress*() =
  ## Clear the current progress line from the terminal (if a TTY).
  ## Resets internal throttle state so the next update prints immediately.
  if prIsTty and prLastLen > 0:
    stdout.write("\r" & repeat(' ', prLastLen) & "\r")
    stdout.flushFile()
    prLastLen = 0
    prLastPct = -1
    prLastMs = 0

proc envCols(): int =
  ## Best-effort detection of terminal width, with sane minimum fallback.
  try:
    result = max(40, terminalWidth())
  except CatchableError:
    let s = getEnv("COLUMNS", "80")
    try:
      result = max(40, parseInt(s))
    except ValueError:
      result = 80

proc shortenName(name: string, maxLen: int): string =
  ## Abbreviate a file name to fit within maxLen by placing an ellipsis in
  ## the middle when necessary. Returns the original if it already fits.
  if name.len <= maxLen: return name
  if maxLen <= 3: return name.substr(0, max(0, maxLen-1)) & "…"
  let keep = (maxLen - 1) div 2
  return name.substr(0, keep) & "…" & name.substr(name.len - keep)

proc printProgress2*(action, name: string, done, total: int64, startMs: int64) =
  ## Render a one-line, throttled progress indicator with optional ETA.
  ##
  ## Parameters:
  ## - action: leading verb (e.g., "uploading", "downloading").
  ## - name:   file name shown (may be abbreviated to fit terminal width).
  ## - done:   bytes completed so far.
  ## - total:  total bytes (or <=0 if unknown).
  ## - startMs: timestamp from nowMs() when the transfer began.
  if not prIsTty:
    return
  let now = nowMs()
  let elapsedMs = max(now - startMs, 1)
  let bytesPerSec = (done.float * 1000.0 / elapsedMs.float)
  let pct = if total > 0: int((done.float / total.float) * 100.0) else: -1
  # Throttle to reduce flicker unless percent changes
  if prLastPct == pct and (now - prLastMs) < 100:
    return
  let rateStr = formatBytes(int64(bytesPerSec)) & "/s"
  var suffix: string
  if total > 0:
    suffix = " " & $pct & "% (" & formatBytes(done) & "/" & formatBytes(total) & ", " & rateStr & ")"
  else:
    suffix = " (" & formatBytes(done) & ", " & rateStr & ")"
  if total > 0 and bytesPerSec > 0.0 and done < total:
    let remain = (total.float - done.float) / bytesPerSec
    let secs = int(remain)
    let h = secs div 3600
    let m = (secs mod 3600) div 60
    let s = secs mod 60
    let eta = (if h > 0: $(h) & ":" else: "") & ($m).align(2, '0') & ":" & ($s).align(2, '0')
    suffix &= ", ETA " & eta
  let cols = envCols()
  let base = action & " "
  var nm = name
  let maxName = max(0, cols - (base.len + suffix.len))
  nm = shortenName(nm, maxName)
  let line = base & nm & suffix
  let pad = max(0, prLastLen - line.len)
  stdout.write("\r" & line & repeat(' ', pad))
  stdout.flushFile()
  prLastLen = line.len
  prLastPct = pct
  prLastMs = now

## (moved above for use within printProgress2)
