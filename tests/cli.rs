use depot::crypto::{HandshakeCryptoProvider, LatebraCrypto};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::tempdir;

const DPK1_MAGIC: &[u8; 4] = b"DPK1";

#[test]
fn version_flag_prints_version() {
    let output = run_depot_with_env(Path::new("."), &[], &["--version"]);
    assert_success(&output);
    assert_eq!(stdout_trimmed(&output), "depot 0.1.0");
}

#[test]
fn config_init_writes_default_config() {
    let temp = tempdir().unwrap();
    let output = run_depot_with_env(
        Path::new("."),
        &[("XDG_CONFIG_HOME", temp.path())],
        &["config", "--init"],
    );
    assert_success(&output);

    let config_path = temp.path().join("depot").join("depot.conf");
    let contents = std::fs::read_to_string(config_path).unwrap();
    assert!(contents.contains("[server]"));
    assert!(contents.contains("[client]"));
}

#[test]
fn serve_first_run_generates_encrypted_server_identity() {
    let temp = tempdir().unwrap();
    let server_cfg_home = temp.path().join("server-config");
    let client_cfg_home = temp.path().join("client-config");
    std::fs::create_dir_all(&server_cfg_home).unwrap();
    std::fs::create_dir_all(&client_cfg_home).unwrap();
    provision_trusted_client(&server_cfg_home, &client_cfg_home);

    let port = allocate_port();
    let mut server = spawn_server(
        &server_cfg_home,
        temp.path(),
        port,
        &[("XDG_CONFIG_HOME", server_cfg_home.as_path())],
    );
    wait_for_server(
        &[("XDG_CONFIG_HOME", client_cfg_home.as_path())],
        port,
        &mut server,
    );

    let id_dir = server_cfg_home.join("depot").join("id");
    let public_key = std::fs::read(id_dir.join("server_dilithium.pk")).unwrap();
    let secret_key = std::fs::read(id_dir.join("server_dilithium.sk")).unwrap();
    assert!(!public_key.is_empty());
    assert!(secret_key.starts_with(DPK1_MAGIC));
}

#[test]
fn cli_roundtrip_serve_export_import_and_ls_with_tofu() {
    let temp = tempdir().unwrap();
    let server_cfg_home = temp.path().join("server-config");
    let client_cfg_home = temp.path().join("client-config");
    let server_root = temp.path().join("server-root");
    let export_root = temp.path().join("export-root");
    let import_root = temp.path().join("import-root");
    std::fs::create_dir_all(&server_cfg_home).unwrap();
    std::fs::create_dir_all(&client_cfg_home).unwrap();
    std::fs::create_dir_all(&server_root).unwrap();
    std::fs::create_dir_all(&export_root).unwrap();
    std::fs::create_dir_all(&import_root).unwrap();
    std::fs::write(export_root.join("notes.txt"), b"alpha").unwrap();
    provision_trusted_client(&server_cfg_home, &client_cfg_home);

    let port = allocate_port();
    let mut server = spawn_server(
        &server_cfg_home,
        &server_root,
        port,
        &[("XDG_CONFIG_HOME", server_cfg_home.as_path())],
    );
    wait_for_server(
        &[("XDG_CONFIG_HOME", client_cfg_home.as_path())],
        port,
        &mut server,
    );

    let export_output = run_depot_with_env(
        &export_root,
        &[("XDG_CONFIG_HOME", client_cfg_home.as_path())],
        &[
            "export",
            "notes.txt",
            "--dest",
            "incoming",
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
        ],
    );
    assert_success(&export_output);
    assert_eq!(
        std::fs::read(server_root.join("incoming").join("notes.txt")).unwrap(),
        b"alpha"
    );

    let list_output = run_depot_with_env(
        Path::new("."),
        &[("XDG_CONFIG_HOME", client_cfg_home.as_path())],
        &[
            "ls",
            "incoming",
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
        ],
    );
    assert_success(&list_output);
    assert_eq!(stdout_trimmed(&list_output), "notes.txt (5 B)");

    let import_output = run_depot_with_env(
        &import_root,
        &[("XDG_CONFIG_HOME", client_cfg_home.as_path())],
        &[
            "import",
            "incoming/notes.txt",
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
        ],
    );
    assert_success(&import_output);
    let import_stdout = String::from_utf8_lossy(&import_output.stdout);
    assert!(import_stdout.contains("[done]"));
    assert!(import_stdout.contains("[transferred] 1 file(s), 5 B"));
    assert_eq!(
        std::fs::read(import_root.join("notes.txt")).unwrap(),
        b"alpha"
    );

    let trust_dir = client_cfg_home.join("depot").join("trust");
    let entries = std::fs::read_dir(trust_dir)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(entries.len(), 1);
}

#[test]
fn tofu_pin_is_saved_during_handshake_even_if_command_fails() {
    let temp = tempdir().unwrap();
    let server_cfg_home = temp.path().join("server-config");
    let client_cfg_home = temp.path().join("client-config");
    let server_root = temp.path().join("server-root");
    std::fs::create_dir_all(&server_cfg_home).unwrap();
    std::fs::create_dir_all(&client_cfg_home).unwrap();
    std::fs::create_dir_all(&server_root).unwrap();
    provision_trusted_client(&server_cfg_home, &client_cfg_home);

    let port = allocate_port();
    let mut server = spawn_server(
        &server_cfg_home,
        &server_root,
        port,
        &[("XDG_CONFIG_HOME", server_cfg_home.as_path())],
    );
    wait_for_server(
        &[("XDG_CONFIG_HOME", client_cfg_home.as_path())],
        port,
        &mut server,
    );

    let output = run_depot_with_env(
        Path::new("."),
        &[("XDG_CONFIG_HOME", client_cfg_home.as_path())],
        &[
            "ls",
            "missing",
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
        ],
    );
    assert!(!output.status.success());

    let trust_dir = client_cfg_home.join("depot").join("trust");
    let entries = std::fs::read_dir(trust_dir)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(entries.len(), 1);
}

#[test]
fn import_existing_file_without_skip_fails_and_preserves_local_file() {
    let temp = tempdir().unwrap();
    let server_cfg_home = temp.path().join("server-config");
    let client_cfg_home = temp.path().join("client-config");
    let server_root = temp.path().join("server-root");
    let import_root = temp.path().join("import-root");
    std::fs::create_dir_all(&server_cfg_home).unwrap();
    std::fs::create_dir_all(&client_cfg_home).unwrap();
    std::fs::create_dir_all(&server_root).unwrap();
    std::fs::create_dir_all(&import_root).unwrap();
    std::fs::write(server_root.join("film.mkv"), b"new").unwrap();
    std::fs::write(import_root.join("film.mkv"), b"old").unwrap();
    provision_trusted_client(&server_cfg_home, &client_cfg_home);

    let port = allocate_port();
    let mut server = spawn_server(
        &server_cfg_home,
        &server_root,
        port,
        &[("XDG_CONFIG_HOME", server_cfg_home.as_path())],
    );
    wait_for_server(
        &[("XDG_CONFIG_HOME", client_cfg_home.as_path())],
        port,
        &mut server,
    );

    let output = run_depot_with_env(
        &import_root,
        &[("XDG_CONFIG_HOME", client_cfg_home.as_path())],
        &[
            "import",
            "film.mkv",
            "--no-skip",
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
        ],
    );

    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("[transferred] 0 file(s), 0 B, skipped 1, failed 1"));
    assert_eq!(std::fs::read(import_root.join("film.mkv")).unwrap(), b"old");
}

#[test]
fn import_single_file_dest_can_be_explicit_file_path() {
    let temp = tempdir().unwrap();
    let server_cfg_home = temp.path().join("server-config");
    let client_cfg_home = temp.path().join("client-config");
    let server_root = temp.path().join("server-root");
    let import_root = temp.path().join("import-root");
    std::fs::create_dir_all(&server_cfg_home).unwrap();
    std::fs::create_dir_all(&client_cfg_home).unwrap();
    std::fs::create_dir_all(&server_root).unwrap();
    std::fs::create_dir_all(&import_root).unwrap();
    std::fs::write(server_root.join("film.mkv"), b"film").unwrap();
    provision_trusted_client(&server_cfg_home, &client_cfg_home);

    let port = allocate_port();
    let mut server = spawn_server(
        &server_cfg_home,
        &server_root,
        port,
        &[("XDG_CONFIG_HOME", server_cfg_home.as_path())],
    );
    wait_for_server(
        &[("XDG_CONFIG_HOME", client_cfg_home.as_path())],
        port,
        &mut server,
    );

    let output = run_depot_with_env(
        &import_root,
        &[("XDG_CONFIG_HOME", client_cfg_home.as_path())],
        &[
            "import",
            "film.mkv",
            "--dest",
            "renamed.mkv",
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
        ],
    );
    assert_success(&output);
    assert_eq!(
        std::fs::read(import_root.join("renamed.mkv")).unwrap(),
        b"film"
    );
}

#[test]
fn import_absolute_remote_path_surfaces_client_error() {
    let temp = tempdir().unwrap();
    let server_cfg_home = temp.path().join("server-config");
    let client_cfg_home = temp.path().join("client-config");
    std::fs::create_dir_all(&server_cfg_home).unwrap();
    std::fs::create_dir_all(&client_cfg_home).unwrap();
    provision_trusted_client(&server_cfg_home, &client_cfg_home);

    let port = allocate_port();
    let mut server = spawn_server(
        &server_cfg_home,
        temp.path(),
        port,
        &[("XDG_CONFIG_HOME", server_cfg_home.as_path())],
    );
    wait_for_server(
        &[("XDG_CONFIG_HOME", client_cfg_home.as_path())],
        port,
        &mut server,
    );

    let output = run_depot_with_env(
        Path::new("."),
        &[("XDG_CONFIG_HOME", client_cfg_home.as_path())],
        &[
            "import",
            "/tmp/file",
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
        ],
    );

    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");
    assert!(combined.contains("[absolute] absolute remote path not allowed"));
    assert!(combined.contains("/tmp/file"));
}

#[test]
fn server_logs_include_session_ids() {
    let temp = tempdir().unwrap();
    let server_cfg_home = temp.path().join("server-config");
    let client_cfg_home = temp.path().join("client-config");
    let server_root = temp.path().join("server-root");
    std::fs::create_dir_all(&server_cfg_home).unwrap();
    std::fs::create_dir_all(&client_cfg_home).unwrap();
    std::fs::create_dir_all(&server_root).unwrap();
    std::fs::write(server_root.join("movie.mkv"), b"alpha").unwrap();
    provision_trusted_client(&server_cfg_home, &client_cfg_home);

    let port = allocate_port();
    let mut server = spawn_server(
        &server_cfg_home,
        &server_root,
        port,
        &[("XDG_CONFIG_HOME", server_cfg_home.as_path())],
    );
    wait_for_server(
        &[("XDG_CONFIG_HOME", client_cfg_home.as_path())],
        port,
        &mut server,
    );

    let output = run_depot_with_env(
        Path::new("."),
        &[("XDG_CONFIG_HOME", client_cfg_home.as_path())],
        &[
            "ls",
            ".",
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
        ],
    );
    assert_success(&output);

    let (_stdout, stderr) = server.finish();
    assert!(stderr.contains("[connected]"));
    assert!(stderr.contains("[handshake]"));
    assert!(stderr.contains("[disconnected]"));
    assert!(stderr.contains("[list-complete]"));
    assert!(stderr.lines().any(has_session_prefix));
}

#[test]
fn unknown_client_can_pair_with_server_token_and_retry_same_command() {
    let temp = tempdir().unwrap();
    let server_cfg_home = temp.path().join("server-config");
    let client_cfg_home = temp.path().join("client-config");
    let server_root = temp.path().join("server-root");
    std::fs::create_dir_all(&server_cfg_home).unwrap();
    std::fs::create_dir_all(&client_cfg_home).unwrap();
    std::fs::create_dir_all(&server_root).unwrap();
    std::fs::write(server_root.join("movie.mkv"), b"alpha").unwrap();

    let port = allocate_port();
    let mut server = spawn_server_with_log_tap(
        &server_cfg_home,
        &server_root,
        port,
        &[("XDG_CONFIG_HOME", server_cfg_home.as_path())],
    );
    wait_for_server_port(port, &mut server);

    let mut client = Command::new(depot_bin())
        .current_dir(".")
        .args([
            "ls",
            ".",
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
        ])
        .env("XDG_CONFIG_HOME", &client_cfg_home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let token = wait_for_pairing_token(&server.stderr_rx);
    client
        .stdin
        .as_mut()
        .unwrap()
        .write_all(format!("{token}\n").as_bytes())
        .unwrap();

    let output = client.wait_with_output().unwrap();
    assert_success(&output);
    assert_eq!(stdout_trimmed(&output), "movie.mkv (5 B)");

    let trust_dir = server_cfg_home.join("depot").join("trust").join("clients");
    let entries = std::fs::read_dir(trust_dir)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(entries.len(), 1);

    let (_stdout, _stderr) = server.finish();
}

fn run_depot_with_env(current_dir: &Path, envs: &[(&str, &Path)], args: &[&str]) -> Output {
    let mut command = Command::new(depot_bin());
    command.current_dir(current_dir).args(args);
    for (key, value) in envs {
        command.env(key, value);
    }
    command.output().unwrap()
}

fn provision_trusted_client(server_config_home: &Path, client_config_home: &Path) {
    let crypto = LatebraCrypto;
    let identity = crypto.generate_signing_identity().unwrap();

    let client_id_dir = client_config_home.join("depot").join("id");
    std::fs::create_dir_all(&client_id_dir).unwrap();
    std::fs::write(
        client_id_dir.join("client_dilithium.pk"),
        identity.public_key.as_bytes(),
    )
    .unwrap();
    std::fs::write(
        client_id_dir.join("client_dilithium.sk"),
        identity.secret_key.as_bytes(),
    )
    .unwrap();

    let server_trust_dir = server_config_home
        .join("depot")
        .join("trust")
        .join("clients");
    std::fs::create_dir_all(&server_trust_dir).unwrap();
    std::fs::write(
        server_trust_dir.join("client_dilithium.pk"),
        identity.public_key.as_bytes(),
    )
    .unwrap();
}

fn spawn_server(config_home: &Path, root: &Path, port: u16, envs: &[(&str, &Path)]) -> ServerGuard {
    let mut command = Command::new(depot_bin());
    command
        .args([
            "serve",
            "--root",
            root.to_str().unwrap(),
            "--listen",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--key-pass",
            "testpass",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("XDG_CONFIG_HOME", config_home);
    for (key, value) in envs {
        command.env(key, value);
    }
    let child = command.spawn().unwrap();
    ServerGuard {
        child,
        stderr_rx: None,
        stderr_log: String::new(),
    }
}

fn spawn_server_with_log_tap(
    config_home: &Path,
    root: &Path,
    port: u16,
    envs: &[(&str, &Path)],
) -> ServerGuard {
    let mut guard = spawn_server(config_home, root, port, envs);
    let stderr = guard.child.stderr.take().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    let _ = tx.send(line.clone());
                }
                Err(_) => break,
            }
        }
    });
    guard.stderr_rx = Some(rx);
    guard
}

fn wait_for_server(envs: &[(&str, &Path)], port: u16, server: &mut ServerGuard) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = server.child.try_wait().unwrap() {
            let mut stdout = String::new();
            let mut stderr = String::new();
            if let Some(handle) = server.child.stdout.as_mut() {
                let _ = handle.read_to_string(&mut stdout);
            }
            if let Some(handle) = server.child.stderr.as_mut() {
                let _ = handle.read_to_string(&mut stderr);
            }
            panic!(
                "server exited early with {status} before accepting client commands: stdout={} stderr={}",
                stdout, stderr,
            );
        }

        let output = run_depot_with_env(
            Path::new("."),
            envs,
            &[
                "ls",
                ".",
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
            ],
        );
        if output.status.success() {
            return;
        }

        if Instant::now() >= deadline {
            panic!(
                "server did not become ready: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }

        thread::sleep(Duration::from_millis(50));
    }
}

fn wait_for_server_port(port: u16, server: &mut ServerGuard) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = server.child.try_wait().unwrap() {
            let (stdout, stderr) = server.collect_logs();
            panic!(
                "server exited early with {status} before opening port: stdout={} stderr={}",
                stdout, stderr,
            );
        }

        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }

        if Instant::now() >= deadline {
            if server.child.try_wait().unwrap().is_none() {
                let _ = server.child.kill();
                let _ = server.child.wait();
            }
            let (stdout, stderr) = server.collect_logs();
            panic!(
                "server did not open port: stdout={} stderr={}",
                stdout, stderr
            );
        }

        thread::sleep(Duration::from_millis(50));
    }
}

fn wait_for_pairing_token(stderr_rx: &Option<Receiver<String>>) -> String {
    let rx = stderr_rx.as_ref().expect("server stderr tap missing");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining) {
            Ok(line) => {
                if let Some(token) = extract_pairing_token(&line) {
                    return token;
                }
            }
            Err(_) => panic!("timed out waiting for pairing token"),
        }
    }
}

fn extract_pairing_token(line: &str) -> Option<String> {
    let marker = " token ";
    let start = line.find(marker)? + marker.len();
    Some(line[start..].trim().to_owned())
}

fn allocate_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn depot_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_depot"))
}

fn stdout_trimmed(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn assert_success(output: &Output) {
    if !output.status.success() {
        panic!(
            "command failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn has_session_prefix(line: &str) -> bool {
    let Some(rest) = line.strip_prefix('[') else {
        return false;
    };
    let Some((session_id, _)) = rest.split_once(']') else {
        return false;
    };
    session_id.len() == 16 && session_id.chars().all(|ch| ch.is_ascii_hexdigit())
}

struct ServerGuard {
    child: std::process::Child,
    stderr_rx: Option<Receiver<String>>,
    stderr_log: String,
}

impl ServerGuard {
    fn collect_logs(&mut self) -> (String, String) {
        let mut stdout = String::new();
        let mut stderr = std::mem::take(&mut self.stderr_log);
        if let Some(handle) = self.child.stdout.as_mut() {
            let _ = handle.read_to_string(&mut stdout);
        }
        if let Some(handle) = self.child.stderr.as_mut() {
            let _ = handle.read_to_string(&mut stderr);
        }
        if let Some(rx) = &self.stderr_rx {
            while let Ok(line) = rx.try_recv() {
                stderr.push_str(&line);
            }
        }
        (stdout, stderr)
    }

    fn finish(mut self) -> (String, String) {
        if self.child.try_wait().unwrap().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        self.collect_logs()
    }
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        if self.child.try_wait().unwrap().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
