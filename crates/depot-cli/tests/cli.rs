use std::net::TcpListener;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::tempdir;

const ML_DSA_87_SECRET_KEY_LEN: usize = 4896;
const ML_DSA_87_PUBLIC_KEY_LEN: usize = 2592;

#[test]
fn keygen_writes_secret_and_public_keys() {
    let temp = tempdir().unwrap();
    let secret = temp.path().join("server.key");
    let public = temp.path().join("server.pub");

    let output = run_depot(&[
        "keygen",
        "--secret-out",
        secret.to_str().unwrap(),
        "--public-out",
        public.to_str().unwrap(),
    ]);
    assert_success(&output);

    let secret_bytes = std::fs::read(&secret).unwrap();
    let public_bytes = std::fs::read(&public).unwrap();
    assert_eq!(secret_bytes.len(), ML_DSA_87_SECRET_KEY_LEN);
    assert_eq!(public_bytes.len(), ML_DSA_87_PUBLIC_KEY_LEN);
}

#[test]
fn cli_roundtrip_serve_export_import_and_ls() {
    let temp = tempdir().unwrap();
    let server_root = temp.path().join("server-root");
    let export_root = temp.path().join("export-root");
    let import_root = temp.path().join("import-root");
    std::fs::create_dir_all(&server_root).unwrap();
    std::fs::create_dir_all(&export_root).unwrap();
    std::fs::create_dir_all(&import_root).unwrap();

    let secret = temp.path().join("server.key");
    let public = temp.path().join("server.pub");
    assert_success(&run_depot(&[
        "keygen",
        "--secret-out",
        secret.to_str().unwrap(),
        "--public-out",
        public.to_str().unwrap(),
    ]));

    let local_file = export_root.join("notes.txt");
    std::fs::write(&local_file, b"alpha").unwrap();

    let port = allocate_port();
    let mut server = spawn_server(&secret, &server_root, port);
    wait_for_server(&public, port, &mut server);

    let export_output = run_depot_in(
        &export_root,
        &[
            "export",
            "notes.txt",
            "--dest",
            "incoming",
            "--server-pubkey-file",
            public.to_str().unwrap(),
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

    let list_output = run_depot(&[
        "ls",
        "incoming",
        "--server-pubkey-file",
        public.to_str().unwrap(),
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
    ]);
    assert_success(&list_output);
    assert_eq!(stdout_trimmed(&list_output), "notes.txt");

    let import_output = run_depot_in(
        &import_root,
        &[
            "import",
            "incoming/notes.txt",
            "--server-pubkey-file",
            public.to_str().unwrap(),
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
        ],
    );
    assert_success(&import_output);
    assert_eq!(std::fs::read(import_root.join("notes.txt")).unwrap(), b"alpha");
}

#[test]
fn import_absolute_remote_path_surfaces_client_error() {
    let temp = tempdir().unwrap();
    let secret = temp.path().join("server.key");
    let public = temp.path().join("server.pub");
    assert_success(&run_depot(&[
        "keygen",
        "--secret-out",
        secret.to_str().unwrap(),
        "--public-out",
        public.to_str().unwrap(),
    ]));

    let port = allocate_port();
    let mut server = spawn_server(&secret, temp.path(), port);
    wait_for_server(&public, port, &mut server);

    let output = run_depot(&[
        "import",
        "/tmp/file",
        "--server-pubkey-file",
        public.to_str().unwrap(),
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
    ]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("[absolute] absolute remote path not allowed"));
    assert!(stderr.contains("/tmp/file"));
}

#[test]
fn serve_requires_trusted_clients_when_client_auth_is_enabled() {
    let temp = tempdir().unwrap();
    let secret = temp.path().join("server.key");
    let public = temp.path().join("server.pub");
    assert_success(&run_depot(&[
        "keygen",
        "--secret-out",
        secret.to_str().unwrap(),
        "--public-out",
        public.to_str().unwrap(),
    ]));

    let output = run_depot(&[
        "serve",
        "--identity-file",
        secret.to_str().unwrap(),
        "--require-client-auth",
    ]);

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains(
        "client authentication requires at least one trusted client public key"
    ));
}

fn run_depot(args: &[&str]) -> Output {
    run_depot_in(Path::new("."), args)
}

fn run_depot_in(current_dir: &Path, args: &[&str]) -> Output {
    Command::new(depot_bin())
        .current_dir(current_dir)
        .args(args)
        .output()
        .unwrap()
}

fn spawn_server(secret_key: &Path, root: &Path, port: u16) -> ServerGuard {
    let child = Command::new(depot_bin())
        .args([
            "serve",
            "--identity-file",
            secret_key.to_str().unwrap(),
            "--root",
            root.to_str().unwrap(),
            "--listen",
            "127.0.0.1",
            "--port",
            &port.to_string(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    ServerGuard { child }
}

fn wait_for_server(public_key: &Path, port: u16, server: &mut ServerGuard) {
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
                stdout,
                stderr,
            );
        }

        let output = run_depot(&[
            "ls",
            ".",
            "--server-pubkey-file",
            public_key.to_str().unwrap(),
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
        ]);
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

struct ServerGuard {
    child: std::process::Child,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        if self.child.try_wait().unwrap().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
