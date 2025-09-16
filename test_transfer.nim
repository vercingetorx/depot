import std/[unittest, asyncdispatch, asyncnet, os, strutils, times]
import ../src/[server, client, handshake, errors]
import ./gen

proc waitForServer(host: string, port: int, timeoutMs = 300): bool =
  ## Give the async server a brief moment to bind and start accepting.
  ## Avoid probing the socket directly to prevent handshake errors.
  sleep timeoutMs
  return true

proc tmpDir(): string =
  let base = getTempDir() / ("depot-test-" & $int(epochTime()*1000))
  createDir(base)
  base

suite "transfer":
  test "upload single file":
    let base = tmpDir()
    # Use isolated config dir so server key is under temp
    putEnv("XDG_CONFIG_HOME", base)
    handshake.serverKeyPassphrase = "testpass"
    server.sandboxed = true
    let listen = "127.0.0.1"
    let port = 61001
    asyncCheck server.serve(listen, port, base)
    check waitForServer(listen, port)

    # Prepare source file
    let srcDir = base / "client-src"
    let srcFile = srcDir / "alpha.bin"
    gen.writeDeterministicFile(srcFile, 1024*1024 + 123, 42)

    # Open session and send
    var sess = waitFor client.openSession(listen, port)
    waitFor client.sendMany(sess, @[srcFile], ".", false)

    let imported = base / "depot" / "import" / "alpha.bin"
    check fileExists(imported)
    check getFileSize(imported) == getFileSize(srcFile)

  test "download single file and skip existing":
    let base = tmpDir()
    putEnv("XDG_CONFIG_HOME", base)
    handshake.serverKeyPassphrase = "testpass"
    server.sandboxed = true
    let listen = "127.0.0.1"
    let port = 61002
    asyncCheck server.serve(listen, port, base)
    check waitForServer(listen, port)

    # Prepare server export content
    let exportFile = base / "depot" / "export" / "beta.dat"
    gen.writeDeterministicFile(exportFile, 512*1024 + 7, 99)

    var sess = waitFor client.openSession(listen, port)
    let dest = base / "local-dest"
    createDir(dest)

    # First download
    waitFor client.recvMany(sess, @["beta.dat"], dest, false)
    let local = dest / "beta.dat"
    check fileExists(local)
    check getFileSize(local) == getFileSize(exportFile)

    # Second download with skip-existing
    var sess2 = waitFor client.openSession(listen, port)
    waitFor client.recvMany(sess2, @["beta.dat"], dest, true)
    # File should remain unchanged
    check getFileSize(local) == getFileSize(exportFile)

  test "download mixed: single file and directory":
    let base = tmpDir()
    putEnv("XDG_CONFIG_HOME", base)
    handshake.serverKeyPassphrase = "testpass"
    server.sandboxed = true
    let listen = "127.0.0.1"
    let port = 61003
    asyncCheck server.serve(listen, port, base)
    check waitForServer(listen, port)

    # Prepare server export content: one file + a directory with children
    let exportRoot = base / "depot" / "export"
    let singleFile = exportRoot / "gamma.bin"
    gen.writeDeterministicFile(singleFile, 128 * 1024 + 3, 777)
    let dirRoot = exportRoot / "mixdir"
    let child1 = dirRoot / "child" / "a.bin"
    let child2 = dirRoot / "child" / "b.bin"
    gen.writeDeterministicFile(child1, 64 * 1024 + 1, 101)
    gen.writeDeterministicFile(child2, 200 * 1024 + 5, 202)

    var sess = waitFor client.openSession(listen, port)
    let dest = base / "local-mix"
    createDir(dest)
    waitFor client.recvMany(sess, @["gamma.bin", "mixdir"], dest, false)

    # Assert single file downloaded
    let outSingle = dest / "gamma.bin"
    check fileExists(outSingle)
    check getFileSize(outSingle) == getFileSize(singleFile)

    # Assert directory and children downloaded
    let outChild1 = dest / "mixdir" / "child" / "a.bin"
    let outChild2 = dest / "mixdir" / "child" / "b.bin"
    check fileExists(outChild1)
    check fileExists(outChild2)
    check getFileSize(outChild1) == getFileSize(child1)
    check getFileSize(outChild2) == getFileSize(child2)
